/// BrainCache — in-memory index cache with per-brain rebuild mutex.
/// Contract: Arc<RwLock<HashMap<String, Arc<BrainIndex>>>> + DashMap for rebuild locks.
/// No thundering herd: double-checked locking + per-brain OwnedMutexGuard.
use chrono::Utc;
use dashmap::DashMap;
use ovca_storage::{list_brain_nodes, parse_brain_node};
use ovca_types::BrainIndex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// Brain name → (package_dir, sub_dir).
/// Mirrors brain_registry.py `_BRAIN_LAYOUT`.
pub const BRAIN_LAYOUT: &[(&str, (&str, &str))] = &[
    ("oracle", ("oracle.brain", "brain")),
    ("coordinator", ("oracle.coordinator", "brain")),
    ("engineer", ("oracle.engineer", "brain")),
    ("reviewer", ("oracle.reviewer", "brain")),
    ("auditor", ("oracle.auditor", "brain")),
];

pub struct BrainCache {
    pub root: PathBuf,
    index: Arc<RwLock<HashMap<String, Arc<BrainIndex>>>>,
    rebuild_locks: DashMap<String, Arc<Mutex<()>>>,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
}

impl BrainCache {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            index: Arc::new(RwLock::new(HashMap::new())),
            rebuild_locks: DashMap::new(),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
        }
    }

    /// Absolute path to a brain's `brain/` directory.
    pub fn brain_dir(&self, brain: &str) -> Option<PathBuf> {
        BRAIN_LAYOUT
            .iter()
            .find(|(name, _)| *name == brain)
            .map(|(_, (pkg, sub))| self.root.join(pkg).join(sub))
    }

    /// Absolute path to a brain's `brain/nodes/` directory.
    pub fn nodes_dir(&self, brain: &str) -> Option<PathBuf> {
        self.brain_dir(brain).map(|d| d.join("nodes"))
    }

    /// All known brain IDs.
    pub fn known_brains(&self) -> Vec<&'static str> {
        BRAIN_LAYOUT.iter().map(|(name, _)| *name).collect()
    }

    /// Get (or load) the cached BrainIndex for a brain.
    /// Uses per-brain rebuild mutex to prevent thundering-herd rebuilds.
    pub async fn get_or_load(&self, brain: &str) -> Arc<BrainIndex> {
        // Fast path: already cached
        {
            let guard = self.index.read().await;
            if let Some(idx) = guard.get(brain) {
                self.hit_count.fetch_add(1, Ordering::Relaxed);
                return Arc::clone(idx);
            }
        }
        self.miss_count.fetch_add(1, Ordering::Relaxed);

        // Per-brain mutex — only one goroutine rebuilds at a time
        let lock = self
            .rebuild_locks
            .entry(brain.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock_owned().await;

        // Double-check: another task may have built while we waited
        {
            let guard = self.index.read().await;
            if let Some(idx) = guard.get(brain) {
                return Arc::clone(idx);
            }
        }

        // Run synchronous file I/O on the blocking thread pool
        let root = self.root.clone();
        let brain_str = brain.to_string();
        let new_idx = tokio::task::spawn_blocking(move || build_index_sync(&root, &brain_str))
            .await
            .unwrap_or_default();

        let arc_idx = Arc::new(new_idx);
        {
            let mut guard = self.index.write().await;
            guard.insert(brain.to_string(), Arc::clone(&arc_idx));
        }
        arc_idx
    }

    /// Invalidate a brain's cached index — next get_or_load rebuilds from disk.
    pub async fn invalidate(&self, brain: &str) {
        let mut guard = self.index.write().await;
        guard.remove(brain);
        tracing::debug!(brain, "cache invalidated");
    }

    pub fn metrics_snapshot(&self) -> Value {
        let hits = self.hit_count.load(Ordering::Relaxed);
        let misses = self.miss_count.load(Ordering::Relaxed);
        let total = hits + misses;
        let ratio = if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        };
        json!({
            "cache_hits": hits,
            "cache_misses": misses,
            "cache_hit_ratio": ratio,
        })
    }
}

// ── Index builder (sync, runs in spawn_blocking) ────────────────────────────

fn build_index_sync(root: &Path, brain: &str) -> BrainIndex {
    let brain_dir = match BRAIN_LAYOUT.iter().find(|(name, _)| *name == brain) {
        Some((_, (pkg, sub))) => root.join(pkg).join(sub),
        None => {
            warn!(brain, "unknown brain in build_index_sync");
            return BrainIndex {
                version: "s42".to_string(),
                brain: brain.to_string(),
                generated_at: Utc::now().to_rfc3339(),
                ..Default::default()
            };
        }
    };

    let index_path = brain_dir.join("brain_index.json");
    if let Ok(raw) = fs::read_to_string(&index_path) {
        match parse_brain_index_artifact(&raw) {
            Ok(mut index) => {
                if index.brain.trim().is_empty() {
                    index.brain = brain.to_string();
                }
                if index.generated_at.trim().is_empty() {
                    index.generated_at = Utc::now().to_rfc3339();
                }
                if index.version.trim().is_empty() {
                    index.version = "s42".to_string();
                }
                index.node_count = index.nodes.len();
                info!(
                    brain,
                    node_count = index.node_count,
                    source = %index_path.display(),
                    "brain index loaded from artifact"
                );
                return index;
            }
            Err(error) => {
                warn!(
                    brain,
                    path = %index_path.display(),
                    error = %error,
                    "failed to parse brain_index.json; falling back to nodes/"
                );
            }
        }
    }

    let nodes_dir = brain_dir.join("nodes");
    let files = list_brain_nodes(&nodes_dir);
    let mut nodes = Vec::with_capacity(files.len());
    let mut errors = 0usize;

    for path in &files {
        match parse_brain_node(path) {
            Ok(node) => nodes.push(node),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "parse_brain_node failed");
                errors += 1;
            }
        }
    }

    info!(brain, node_count = nodes.len(), errors, "brain index built");
    BrainIndex {
        version: "s42".to_string(),
        brain: brain.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        node_count: nodes.len(),
        merkle_root: None,
        merkle_root_at: None,
        nodes,
        edges: vec![],
    }
}

fn parse_brain_index_artifact(raw: &str) -> Result<BrainIndex, serde_json::Error> {
    let mut value: Value = serde_json::from_str(raw)?;
    if let Some(nodes) = value.get_mut("nodes").and_then(Value::as_array_mut) {
        for node in nodes {
            let Some(obj) = node.as_object_mut() else {
                continue;
            };
            normalize_confidence(obj);
        }
    }
    serde_json::from_value(value)
}

fn normalize_confidence(obj: &mut Map<String, Value>) {
    let Some(confidence) = obj.get_mut("confidence") else {
        return;
    };
    match confidence {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *confidence = Value::Null;
            } else if let Ok(parsed) = trimmed.parse::<f64>() {
                *confidence = json!(parsed);
            } else {
                *confidence = Value::Null;
            }
        }
        Value::Number(_) | Value::Null => {}
        _ => {
            *confidence = Value::Null;
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ovca_storage::write_brain_node;
    use ovca_types::{BrainEdge, BrainNode};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_oracle_nodes_dir(tmp: &TempDir) -> PathBuf {
        let dir = tmp.path().join("oracle.brain").join("brain").join("nodes");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn get_or_load_empty_brain() {
        let tmp = TempDir::new().unwrap();
        make_oracle_nodes_dir(&tmp);
        let cache = BrainCache::new(tmp.path());
        let idx = cache.get_or_load("oracle").await;
        assert_eq!(idx.brain, "oracle");
        assert_eq!(idx.node_count, 0);
    }

    #[tokio::test]
    async fn get_or_load_caches_on_second_call() {
        let tmp = TempDir::new().unwrap();
        make_oracle_nodes_dir(&tmp);
        let cache = BrainCache::new(tmp.path());
        let idx1 = cache.get_or_load("oracle").await;
        let idx2 = cache.get_or_load("oracle").await;
        // Same Arc pointer — no rebuild happened
        assert!(Arc::ptr_eq(&idx1, &idx2));
    }

    #[tokio::test]
    async fn metrics_snapshot_tracks_hits_and_misses() {
        let tmp = TempDir::new().unwrap();
        make_oracle_nodes_dir(&tmp);
        let cache = BrainCache::new(tmp.path());

        let _ = cache.get_or_load("oracle").await;
        let _ = cache.get_or_load("oracle").await;

        let metrics = cache.metrics_snapshot();
        assert_eq!(metrics["cache_hits"], 1);
        assert_eq!(metrics["cache_misses"], 1);
        assert!(metrics["cache_hit_ratio"].as_f64().unwrap_or(0.0) > 0.0);
    }

    #[tokio::test]
    async fn invalidate_forces_rebuild() {
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_oracle_nodes_dir(&tmp);
        let cache = BrainCache::new(tmp.path());

        let idx1 = cache.get_or_load("oracle").await;
        assert_eq!(idx1.node_count, 0);

        // Write a node and invalidate
        let node = BrainNode {
            id: "inv-001".into(),
            title: "Invalidation Test".into(),
            node_type: "Note".into(),
            brain: "oracle".into(),
            agent: "engineer".into(),
            created: "2026-01-01T00:00:00Z".into(),
            updated: "2026-01-01T00:00:00Z".into(),
            body: "test".into(),
            ..Default::default()
        };
        write_brain_node(&nodes_dir, &node).unwrap();
        cache.invalidate("oracle").await;

        let idx2 = cache.get_or_load("oracle").await;
        assert_eq!(idx2.node_count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cache_no_panic() {
        let tmp = TempDir::new().unwrap();
        make_oracle_nodes_dir(&tmp);
        let cache = Arc::new(BrainCache::new(tmp.path()));

        let mut handles = Vec::with_capacity(20);
        for _ in 0..20 {
            let c = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                let idx = c.get_or_load("oracle").await;
                assert_eq!(idx.brain, "oracle");
            }));
        }
        for h in handles {
            h.await.unwrap(); // no panic, no deadlock
        }
    }

    #[tokio::test]
    async fn get_or_load_prefers_brain_index_artifact() {
        let tmp = TempDir::new().unwrap();
        let brain_dir = tmp.path().join("oracle.brain").join("brain");
        std::fs::create_dir_all(brain_dir.join("nodes")).unwrap();
        let artifact = BrainIndex {
            version: "py".into(),
            brain: "oracle".into(),
            generated_at: "2026-03-13T00:00:00Z".into(),
            node_count: 1,
            merkle_root: None,
            merkle_root_at: None,
            nodes: vec![BrainNode {
                id: "artifact-001".into(),
                title: "Artifact Node".into(),
                node_type: "Note".into(),
                brain: "oracle".into(),
                summary: "artifact summary".into(),
                ..Default::default()
            }],
            edges: vec![BrainEdge {
                from_id: "artifact-001".into(),
                relation: "supports".into(),
                to_id: "artifact-002".into(),
                source_brain: "oracle".into(),
                source_kind: "frontmatter".into(),
                authoritative: true,
            }],
        };
        std::fs::write(
            brain_dir.join("brain_index.json"),
            serde_json::to_string(&artifact).unwrap(),
        )
        .unwrap();

        let cache = BrainCache::new(tmp.path());
        let idx = cache.get_or_load("oracle").await;
        assert_eq!(idx.node_count, 1);
        assert_eq!(idx.nodes[0].summary, "artifact summary");
        assert_eq!(idx.edges.len(), 1);
    }

    #[tokio::test]
    async fn get_or_load_sanitizes_string_confidence_in_artifact() {
        let tmp = TempDir::new().unwrap();
        let brain_dir = tmp.path().join("oracle.brain").join("brain");
        std::fs::create_dir_all(brain_dir.join("nodes")).unwrap();
        std::fs::write(
            brain_dir.join("brain_index.json"),
            serde_json::to_string(&json!({
                "version": "1.0",
                "brain": "oracle",
                "generated_at": "2026-03-13T00:00:00Z",
                "node_count": 1,
                "nodes": [{
                    "id": "artifact-002",
                    "title": "Artifact Confidence",
                    "type": "Note",
                    "brain": "oracle",
                    "confidence": "high",
                    "summary": "artifact summary"
                }],
                "edges": []
            }))
            .unwrap(),
        )
        .unwrap();

        let cache = BrainCache::new(tmp.path());
        let idx = cache.get_or_load("oracle").await;
        assert_eq!(idx.node_count, 1);
        assert_eq!(idx.nodes[0].summary, "artifact summary");
        assert_eq!(idx.nodes[0].confidence, None);
    }
}
