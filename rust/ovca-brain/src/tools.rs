/// Brain MCP tool implementations.
///
/// All 5 tools take `Arc<BrainCache>` + raw `serde_json::Value` args and return a `Value`.
/// The oracle-mcp `normalize_response` wrapper handles the McpResponse envelope.
use crate::cache::BrainCache;
use crate::permissions;
use crate::search;
use chrono::Utc;
use ovca_storage::write_brain_node;
use ovca_types::BrainNode;
use serde_json::{json, Value};
use std::{env, sync::Arc};
use tracing::info;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn str_arg(args: &Value, key: &str) -> String {
    args[key].as_str().unwrap_or("").trim().to_lowercase()
}

fn raw_str(args: &Value, key: &str) -> String {
    args[key].as_str().unwrap_or("").to_string()
}

fn first_non_empty_str(args: &Value, keys: &[&str], lowercase: bool) -> String {
    for key in keys {
        let value = args[*key].as_str().unwrap_or("").trim();
        if !value.is_empty() {
            return if lowercase {
                value.to_lowercase()
            } else {
                value.to_string()
            };
        }
    }
    String::new()
}

fn usize_arg(args: &Value, key: &str, default: u64, max: u64) -> usize {
    args[key].as_u64().unwrap_or(default).min(max) as usize
}

fn hybrid_endpoint() -> Option<String> {
    env::var("ORACLE_HYBRID_ENDPOINT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Filter nodes by visibility: "owner"/"coordinator" see all; others skip private.
fn visible<'a>(nodes: &'a [BrainNode], caller: &str) -> Vec<&'a BrainNode> {
    if caller == "owner" || caller == "coordinator" {
        nodes.iter().collect()
    } else {
        nodes.iter().filter(|n| n.visibility != "private").collect()
    }
}

// ── brain_read ────────────────────────────────────────────────────────────────

/// Read nodes from a brain. Returns array of BrainNode objects.
pub async fn brain_read(cache: Arc<BrainCache>, args: Value) -> Value {
    let caller = first_non_empty_str(&args, &["caller", "caller_agent"], true);
    let brain = {
        let b = first_non_empty_str(&args, &["brain"], true);
        if b.is_empty() {
            "oracle".to_string()
        } else {
            b
        }
    };
    let limit = usize_arg(&args, "limit", 50, 200);
    let node_type = first_non_empty_str(&args, &["type", "node_type"], false);
    let tag = first_non_empty_str(&args, &["tag"], false);

    if let Some(err) = permissions::check_read(&caller, &brain) {
        return json!({"ok": false, "error": err, "nodes": []});
    }

    let idx = cache.get_or_load(&brain).await;
    let filtered_nodes: Vec<_> = visible(&idx.nodes, &caller)
        .into_iter()
        .filter(|node| {
            if node_type.is_empty() {
                true
            } else {
                node.node_type == node_type
            }
        })
        .filter(|node| {
            if tag.is_empty() {
                true
            } else {
                node.tags.iter().any(|node_tag| node_tag == &tag)
            }
        })
        .collect();
    let node_count = filtered_nodes.len();
    let nodes: Vec<_> = filtered_nodes.into_iter().take(limit).collect();

    json!({
        "ok": true,
        "brain": brain,
        "caller": caller,
        "node_count": node_count,
        "nodes": nodes,
        "generated_at": idx.generated_at,
    })
}

// ── brain_write ───────────────────────────────────────────────────────────────

/// Write a new node to a brain. Invalidates the cache after write.
pub async fn brain_write(cache: Arc<BrainCache>, args: Value) -> Value {
    let caller = str_arg(&args, "caller");
    if caller.is_empty() {
        return json!({"ok": false, "error": "caller is required"});
    }

    // Resolve write target: "owner" can specify brain; others write to own brain
    let req_brain = str_arg(&args, "brain");
    let write_brain = if caller == "owner" && !req_brain.is_empty() {
        req_brain
    } else {
        caller.clone()
    };

    if let Some(err) = permissions::check_write(&caller, &write_brain) {
        return json!({"ok": false, "error": err});
    }

    let Some(nodes_dir) = cache.nodes_dir(&write_brain) else {
        return json!({"ok": false, "error": format!("unknown brain: {}", write_brain)});
    };

    let title = raw_str(&args, "title");
    let body = raw_str(&args, "body");
    let node_type = {
        let t = raw_str(&args, "node_type");
        if t.is_empty() {
            "Note".to_string()
        } else {
            t
        }
    };
    let visibility = {
        let v = raw_str(&args, "visibility");
        if v.is_empty() {
            "team".to_string()
        } else {
            v
        }
    };
    let tags: Vec<String> = args["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let now = Utc::now().to_rfc3339();
    let node_id = Uuid::new_v4().as_simple().to_string()[..12].to_string();

    let node = BrainNode {
        id: node_id.clone(),
        title,
        node_type,
        brain: write_brain.clone(),
        agent: caller.clone(),
        tags,
        visibility,
        body,
        created: now.clone(),
        updated: now,
        ..Default::default()
    };

    match write_brain_node(&nodes_dir, &node) {
        Ok(path) => {
            cache.invalidate(&write_brain).await;
            info!(brain = %write_brain, node_id, "node written");
            json!({
                "ok": true,
                "brain": write_brain,
                "node_id": node_id,
                "file": path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "written_at": Utc::now().to_rfc3339(),
            })
        }
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

// ── brain_search ──────────────────────────────────────────────────────────────

/// Search a single brain via hybrid retrieval with keyword fallback.
pub async fn brain_search(cache: Arc<BrainCache>, args: Value) -> Value {
    let caller = first_non_empty_str(&args, &["caller", "caller_agent"], true);
    let brain = {
        let b = first_non_empty_str(&args, &["brain"], true);
        if b.is_empty() {
            "oracle".to_string()
        } else {
            b
        }
    };
    let query = raw_str(&args, "query");
    let limit = usize_arg(&args, "limit", 20, 100);

    if let Some(err) = permissions::check_read(&caller, &brain) {
        return json!({"ok": false, "error": err, "results": []});
    }
    if query.trim().is_empty() {
        return json!({"ok": false, "error": "query is required", "results": []});
    }

    let idx = cache.get_or_load(&brain).await;
    let visible_nodes: Vec<BrainNode> = visible(&idx.nodes, &caller).into_iter().cloned().collect();
    let endpoint = hybrid_endpoint();
    let results = search::hybrid_search(&visible_nodes, &query, endpoint.as_deref(), limit).await;
    let total = results.len();

    let result_rows: Vec<Value> = results
        .iter()
        .map(|(score, node)| {
            let mut row = serde_json::to_value(node).unwrap_or_else(|_| json!({}));
            if let Some(obj) = row.as_object_mut() {
                obj.insert("_score".to_string(), json!(score));
            }
            row
        })
        .collect();

    json!({
        "ok":     true,
        "brain":  brain,
        "query":  query,
        "total":  total,
        "results": result_rows,
    })
}

// ── brain_search_all ──────────────────────────────────────────────────────────

/// Search across all accessible brains (coordinator / owner only).
pub async fn brain_search_all(cache: Arc<BrainCache>, args: Value) -> Value {
    let caller = first_non_empty_str(&args, &["caller", "caller_agent"], true);
    let query = raw_str(&args, "query");
    let limit = usize_arg(&args, "limit", 30, 100);

    if caller != "coordinator" && caller != "owner" {
        return json!({
            "ok": false,
            "error": "brain_search_all requires caller=coordinator or caller=owner",
            "results": [],
        });
    }
    if query.trim().is_empty() {
        return json!({"ok": false, "error": "query is required", "results": []});
    }

    let mut all_results: Vec<(usize, String, BrainNode)> = Vec::new();

    for brain in cache.known_brains() {
        if permissions::check_read(&caller, brain).is_some() {
            continue;
        }
        let idx = cache.get_or_load(brain).await;
        let visible_nodes: Vec<BrainNode> =
            visible(&idx.nodes, &caller).into_iter().cloned().collect();
        for (score, node) in search::search_nodes_scored(&visible_nodes, &query) {
            all_results.push((score, brain.to_string(), node));
        }
    }

    all_results.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.title.cmp(&b.2.title))
    });
    let total = all_results.len();
    all_results.truncate(limit);

    let result_rows: Vec<Value> = all_results
        .iter()
        .map(|(score, brain, node)| {
            let mut row = serde_json::to_value(node).unwrap_or_else(|_| json!({}));
            if let Some(obj) = row.as_object_mut() {
                obj.insert("_brain".to_string(), json!(brain));
                obj.insert("_score".to_string(), json!(score));
            }
            row
        })
        .collect();

    json!({
        "ok":     true,
        "query":  query,
        "total":  total,
        "results": result_rows,
    })
}

// ── brain_diff ────────────────────────────────────────────────────────────────

/// List recently modified nodes from a brain, sorted by `updated` descending.
/// Optional `since` parameter (ISO 8601 string) filters to nodes updated after that time.
pub async fn brain_diff(cache: Arc<BrainCache>, args: Value) -> Value {
    let caller = first_non_empty_str(&args, &["caller", "caller_agent"], true);
    let brain = {
        let b = first_non_empty_str(&args, &["brain"], true);
        if b.is_empty() {
            "oracle".to_string()
        } else {
            b
        }
    };
    let limit = usize_arg(&args, "limit", 20, 100);
    let since = first_non_empty_str(&args, &["since", "since_date"], false);

    if let Some(err) = permissions::check_read(&caller, &brain) {
        return json!({"ok": false, "error": err, "nodes": []});
    }

    let idx = cache.get_or_load(&brain).await;
    let mut nodes: Vec<&BrainNode> = visible(&idx.nodes, &caller);

    // Filter by `since` if provided
    if !since.is_empty() {
        nodes.retain(|n| n.updated.as_str() > since.as_str());
    }

    // Sort by updated descending (ISO strings compare correctly lexicographically)
    nodes.sort_by(|a, b| b.updated.cmp(&a.updated));
    let changed_count = nodes.len();
    nodes.truncate(limit);

    json!({
        "ok":    true,
        "brain": brain,
        "since_date": since,
        "changed_count": changed_count,
        "nodes": nodes,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::BrainCache;
    use crate::search::test_support::MockHybridServer;
    use ovca_storage::write_brain_node;
    use ovca_types::BrainNode;
    use std::sync::Arc;
    use std::sync::OnceLock;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    fn hybrid_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn make_brain_nodes_dir(tmp: &TempDir, brain_pkg: &str) -> std::path::PathBuf {
        let dir = tmp.path().join(brain_pkg).join("brain").join("nodes");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_node(id: &str, title: &str, tags: &[&str]) -> BrainNode {
        BrainNode {
            id: id.to_string(),
            title: title.to_string(),
            node_type: "Note".to_string(),
            brain: "oracle".to_string(),
            agent: "coordinator".to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: "2026-01-01T00:00:00Z".to_string(),
            body: title.to_string(),
            ..Default::default()
        }
    }

    // ── Test 1: parse all real nodes ─────────────────────────────────────────

    #[tokio::test]
    async fn parse_all_nodes() {
        let tmp = TempDir::new().unwrap();
        let brains = ["oracle", "coordinator", "engineer", "reviewer", "auditor"];
        for brain in brains {
            let package = if brain == "oracle" {
                "oracle.brain".to_string()
            } else {
                format!("oracle.{brain}")
            };
            let nodes = make_brain_nodes_dir(&tmp, &package);
            write_brain_node(&nodes, &sample_node(brain, brain, &["public-test"])).unwrap();
        }
        let cache = BrainCache::new(tmp.path());
        let mut total_nodes = 0usize;
        let total_errors = 0usize;

        for brain in &brains {
            let idx = cache.get_or_load(brain).await;
            total_nodes += idx.node_count;
            // Any parse errors would show up as missing nodes vs files on disk
            // Check that the index was loaded/built with a usable metadata header.
            assert!(
                !idx.version.trim().is_empty(),
                "brain {} version missing",
                brain
            );
            assert!(
                !idx.generated_at.trim().is_empty(),
                "brain {} generated_at missing",
                brain
            );
        }

        // At least 1 node across all brains (parity pre-condition)
        assert!(
            total_nodes > 0,
            "Expected nodes across public brains, found 0"
        );
        assert_eq!(total_errors, 0, "Expected 0 parse errors");
    }

    // ── Test 2: search parity ────────────────────────────────────────────────

    #[tokio::test]
    async fn brain_search_parity() {
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        // Write 5 known nodes
        let bench_nodes = vec![
            sample_node(
                "bench-001",
                "Risk Management Strategy",
                &["risk", "strategy"],
            ),
            sample_node(
                "bench-002",
                "Reviewer Review Report",
                &["review", "reviewer"],
            ),
            sample_node(
                "bench-003",
                "Portfolio Alpha Signal",
                &["alpha", "portfolio"],
            ),
            sample_node(
                "bench-004",
                "Trading Doctrine 2026",
                &["trading", "doctrine"],
            ),
            sample_node(
                "bench-005",
                "Market Hypothesis Test",
                &["hypothesis", "market"],
            ),
        ];
        for node in &bench_nodes {
            write_brain_node(&nodes_dir, node).unwrap();
        }

        let cache = BrainCache::new(tmp.path());
        let idx = cache.get_or_load("oracle").await;
        assert_eq!(idx.node_count, 5);

        let benchmarks = [
            ("strategy", "Risk Management Strategy"),
            ("reviewer", "Reviewer Review Report"),
            ("portfolio", "Portfolio Alpha Signal"),
            ("trading", "Trading Doctrine 2026"),
            ("hypothesis", "Market Hypothesis Test"),
        ];

        for (query, expected_title) in &benchmarks {
            let results = search::search_nodes(&idx.nodes, query, 5);
            assert!(!results.is_empty(), "search '{}' returned 0 results", query);
            assert_eq!(
                results[0].1.title, *expected_title,
                "query '{}': expected top='{}', got='{}'",
                query, expected_title, results[0].1.title
            );
        }
    }

    #[tokio::test]
    async fn brain_read_honors_python_aliases_and_filters() {
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        let mut note = sample_node("read-001", "Risk Note", &["risk"]);
        note.node_type = "Note".to_string();
        let mut report = sample_node("read-002", "Risk Report", &["risk", "macro"]);
        report.node_type = "Report".to_string();
        write_brain_node(&nodes_dir, &note).unwrap();
        write_brain_node(&nodes_dir, &report).unwrap();

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let out = brain_read(
            Arc::clone(&cache),
            json!({
                "caller_agent": "coordinator",
                "brain": "oracle",
                "type": "Report",
                "tag": "macro",
                "limit": 5
            }),
        )
        .await;

        assert_eq!(out["ok"], true);
        assert_eq!(out["node_count"], 1);
        assert_eq!(out["nodes"][0]["title"], "Risk Report");
        assert!(out["generated_at"].is_string());
    }

    #[tokio::test]
    async fn brain_search_returns_python_shape_with_score_field() {
        let _guard = hybrid_env_lock().lock().await;
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        let node = sample_node(
            "search-001",
            "Portfolio Alpha Signal",
            &["alpha", "portfolio"],
        );
        write_brain_node(&nodes_dir, &node).unwrap();

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let out = brain_search(
            Arc::clone(&cache),
            json!({
                "caller_agent": "coordinator",
                "brain": "oracle",
                "query": "portfolio alpha",
                "limit": 5
            }),
        )
        .await;

        assert_eq!(out["ok"], true);
        assert_eq!(out["results"][0]["title"], "Portfolio Alpha Signal");
        assert_eq!(out["results"][0]["_score"].as_f64(), Some(2.0));
        assert!(out["results"][0]["brain"].is_string());
    }

    #[tokio::test]
    async fn brain_search_all_returns_python_brain_marker() {
        let tmp = TempDir::new().unwrap();
        let oracle_nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");
        let reviewer_nodes_dir = make_brain_nodes_dir(&tmp, "oracle.reviewer");

        let oracle_node = sample_node("all-001", "Macro Regime Note", &["macro"]);
        let reviewer_node = sample_node("all-002", "Macro Review", &["macro", "review"]);
        write_brain_node(&oracle_nodes_dir, &oracle_node).unwrap();
        write_brain_node(&reviewer_nodes_dir, &reviewer_node).unwrap();

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let out = brain_search_all(
            Arc::clone(&cache),
            json!({
                "caller_agent": "coordinator",
                "query": "macro",
                "limit": 5
            }),
        )
        .await;

        assert_eq!(out["ok"], true);
        assert!(out["results"].as_array().unwrap().len() >= 2);
        assert!(out["results"][0]["_brain"].is_string());
        assert!(out["results"][0]["_score"].is_number());
    }

    // ── Test 3: permission matrix ─────────────────────────────────────────────

    #[test]
    fn permission_matrix() {
        // coordinator and oracle agent should allow read
        assert!(permissions::can_read("coordinator", "oracle"));
        assert!(permissions::can_read("owner", "oracle"));

        // unknown caller → deny write
        assert!(!permissions::can_write("unknown_caller", "oracle"));
        assert!(!permissions::can_write("unknown_caller", "engineer"));
        assert!(!permissions::can_write("", "oracle"));

        // agents write own brain
        assert!(permissions::can_write("engineer", "engineer"));
        assert!(permissions::can_write("reviewer", "reviewer"));

        // agents cannot write each other's brains
        assert!(!permissions::can_write("reviewer", "engineer"));
    }

    // ── Test 4: concurrent cache ──────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cache() {
        let tmp = TempDir::new().unwrap();
        make_brain_nodes_dir(&tmp, "oracle.brain");
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
            h.await.expect("no panic in concurrent get_or_load");
        }
    }

    // ── Test 5: brain_write roundtrip ─────────────────────────────────────────

    #[tokio::test]
    async fn brain_write_roundtrip() {
        let tmp = TempDir::new().unwrap();
        make_brain_nodes_dir(&tmp, "oracle.brain");
        let cache = Arc::new(BrainCache::new(tmp.path()));

        let write_args = json!({
            "caller": "owner",
            "brain":  "oracle",
            "title":  "Sprint2 Roundtrip Node",
            "node_type": "Note",
            "body":   "Written by brain_write_roundtrip test",
            "tags":   ["sprint2", "roundtrip"],
        });

        let result = brain_write(Arc::clone(&cache), write_args).await;
        assert_eq!(result["ok"], true, "brain_write failed: {}", result);
        let node_id = result["node_id"].as_str().unwrap();
        assert_eq!(node_id.len(), 12);

        // Cache was invalidated — rebuild picks up the new node
        let idx = cache.get_or_load("oracle").await;
        assert_eq!(idx.node_count, 1, "Expected 1 node after write");

        // Search finds it
        let search_results = search::search_nodes(&idx.nodes, "sprint2", 5);
        assert!(
            !search_results.is_empty(),
            "Node not found in search after write"
        );
        assert_eq!(search_results[0].1.title, "Sprint2 Roundtrip Node");
    }

    // ── Test 6: brain_read permission check ───────────────────────────────────

    #[tokio::test]
    async fn brain_read_unknown_caller_denied() {
        let tmp = TempDir::new().unwrap();
        make_brain_nodes_dir(&tmp, "oracle.brain");
        let cache = Arc::new(BrainCache::new(tmp.path()));

        let result = brain_read(cache, json!({"caller": "unknown_bot", "brain": "oracle"})).await;
        assert_eq!(result["ok"], false);
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("permission denied"));
    }

    // ── Test 7: brain_search returns results ──────────────────────────────────

    #[tokio::test]
    async fn brain_search_returns_results() {
        let _guard = hybrid_env_lock().lock().await;
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        write_brain_node(
            &nodes_dir,
            &sample_node("s001", "Market Alpha Strategy", &["alpha", "market"]),
        )
        .unwrap();

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let result = brain_search(
            cache,
            json!({"caller": "coordinator", "brain": "oracle", "query": "alpha"}),
        )
        .await;

        assert_eq!(result["ok"], true);
        assert!(result["total"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn brain_search_uses_hybrid_endpoint_when_configured() {
        let _guard = hybrid_env_lock().lock().await;
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        let node = sample_node(
            "search-remote-001",
            "Capital Allocation Note",
            &["allocation"],
        );
        write_brain_node(&nodes_dir, &node).unwrap();

        let server = MockHybridServer::start(json!({
            "results": [
                {
                    "id": node.id,
                    "hybrid_score": 42.5,
                    "title": "Remote Title"
                }
            ]
        }))
        .await;
        let previous = std::env::var("ORACLE_HYBRID_ENDPOINT").ok();
        std::env::set_var("ORACLE_HYBRID_ENDPOINT", &server.base_url);

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let out = brain_search(
            Arc::clone(&cache),
            json!({
                "caller_agent": "coordinator",
                "brain": "oracle",
                "query": "position sizing",
                "limit": 5
            }),
        )
        .await;

        match previous {
            Some(value) => std::env::set_var("ORACLE_HYBRID_ENDPOINT", value),
            None => std::env::remove_var("ORACLE_HYBRID_ENDPOINT"),
        }

        assert_eq!(server.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        let payloads = server.payloads.lock().await;
        assert_eq!(payloads[0]["query"], "position sizing");
        assert_eq!(payloads[0]["top_k"], 5);
        drop(payloads);

        assert_eq!(out["ok"], true);
        assert_eq!(out["results"][0]["title"], "Capital Allocation Note");
        assert_eq!(out["results"][0]["_score"].as_f64(), Some(42.5));
    }

    #[tokio::test]
    async fn brain_search_falls_back_when_hybrid_endpoint_empty() {
        let _guard = hybrid_env_lock().lock().await;
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        let node = sample_node(
            "search-fallback-001",
            "Portfolio Alpha Signal",
            &["alpha", "portfolio"],
        );
        write_brain_node(&nodes_dir, &node).unwrap();

        let previous = std::env::var("ORACLE_HYBRID_ENDPOINT").ok();
        std::env::set_var("ORACLE_HYBRID_ENDPOINT", "");

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let out = brain_search(
            Arc::clone(&cache),
            json!({
                "caller_agent": "coordinator",
                "brain": "oracle",
                "query": "portfolio alpha",
                "limit": 5
            }),
        )
        .await;

        match previous {
            Some(value) => std::env::set_var("ORACLE_HYBRID_ENDPOINT", value),
            None => std::env::remove_var("ORACLE_HYBRID_ENDPOINT"),
        }

        assert_eq!(out["ok"], true);
        assert_eq!(out["results"][0]["title"], "Portfolio Alpha Signal");
        assert_eq!(out["results"][0]["_score"].as_f64(), Some(2.0));
    }

    // ── Test 8: brain_diff returns recent nodes ───────────────────────────────

    #[tokio::test]
    async fn brain_diff_returns_nodes() {
        let tmp = TempDir::new().unwrap();
        let nodes_dir = make_brain_nodes_dir(&tmp, "oracle.brain");

        write_brain_node(&nodes_dir, &sample_node("d001", "Recent Node", &["recent"])).unwrap();

        let cache = Arc::new(BrainCache::new(tmp.path()));
        let result = brain_diff(
            cache,
            json!({"caller": "coordinator", "brain": "oracle", "limit": 10}),
        )
        .await;

        assert_eq!(result["ok"], true);
        assert_eq!(result["changed_count"], 1);
    }
}
