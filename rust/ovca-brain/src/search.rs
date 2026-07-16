/// Brain search — Thai-aware tokenizer + keyword-hit scoring.
///
/// Tokenizer: split on `[^a-z0-9_\u{0E00}-\u{0E7F}]+` (identical to brain_server.py).
/// Score:     count query tokens that appear in the searchable text.
use ovca_types::BrainNode;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^a-z0-9_\x{0E00}-\x{0E7F}]+").expect("tokenize regex"))
}

/// Tokenize text: lowercase + split on non-word separators (Thai-aware).
pub fn tokenize(text: &str) -> HashSet<String> {
    let lower = text.to_lowercase();
    token_re()
        .split(&lower)
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Count query tokens present in the searchable text.
/// Mirrors Python `brain_server._search_nodes`.
pub fn score_node(query_tokens: &HashSet<String>, node: &BrainNode) -> usize {
    let searchable = format!(
        "{} {} {} {} {}",
        node.title,
        node.summary,
        node.node_type,
        node.tags.join(" "),
        node.aliases.join(" "),
    )
    .to_lowercase();
    if query_tokens.is_empty() || searchable.trim().is_empty() {
        return 0;
    }
    query_tokens
        .iter()
        .filter(|token| searchable.contains(token.as_str()))
        .count()
}

/// Score all matching nodes by keyword-hit score, sorted by score desc.
pub fn search_nodes_scored(nodes: &[BrainNode], query: &str) -> Vec<(usize, BrainNode)> {
    let q_tokens = tokenize(query);
    if q_tokens.is_empty() {
        return vec![];
    }

    let mut scored: Vec<(usize, BrainNode)> = nodes
        .iter()
        .filter_map(|n| {
            let s = score_node(&q_tokens, n);
            if s > 0 {
                Some((s, n.clone()))
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
    scored
}

/// Search nodes by keyword-hit score.
/// Returns at most `limit` results as `(score, node)` pairs sorted by score desc.
pub fn search_nodes(nodes: &[BrainNode], query: &str, limit: usize) -> Vec<(usize, BrainNode)> {
    let mut scored = search_nodes_scored(nodes, query);
    scored.truncate(limit);
    scored
}

fn fallback_search(nodes: &[BrainNode], query: &str, limit: usize) -> Vec<(f64, BrainNode)> {
    let mut scored: Vec<(f64, BrainNode)> = search_nodes_scored(nodes, query)
        .into_iter()
        .map(|(score, node)| (score as f64, node))
        .collect();
    scored.truncate(limit);
    scored
}

fn score_from_row(row: &Value) -> f64 {
    for key in ["hybrid_score", "score", "_score"] {
        let Some(value) = row.get(key) else {
            continue;
        };
        if let Some(score) = value.as_f64() {
            return score;
        }
        if let Some(score) = value.as_i64() {
            return score as f64;
        }
        if let Some(score) = value.as_u64() {
            return score as f64;
        }
        if let Some(score) = value.as_str().and_then(|s| s.parse::<f64>().ok()) {
            return score;
        }
    }
    0.0
}

fn hybrid_search_url(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.ends_with("/search") {
        return Some(trimmed.to_string());
    }
    Some(format!("{}/search", trimmed.trim_end_matches('/')))
}

async fn search_remote(
    nodes: &[BrainNode],
    query: &str,
    endpoint: &str,
    limit: usize,
) -> Option<Vec<(f64, BrainNode)>> {
    let search_url = hybrid_search_url(endpoint)?;
    let brain = nodes
        .iter()
        .find_map(|node| {
            let trimmed = node.brain.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .unwrap_or_else(|| "oracle".to_string());
    let visible_nodes: HashMap<String, BrainNode> = nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let response = client
        .post(search_url)
        .json(&json!({
            "query": query,
            "brain": brain,
            "top_k": limit,
        }))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }

    let body: Value = response.json().await.ok()?;
    let rows = body.get("results")?.as_array()?;
    let mut results = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(node_id) = row.get("id").and_then(Value::as_str) else {
            continue;
        };
        if let Some(node) = visible_nodes.get(node_id) {
            results.push((score_from_row(row), node.clone()));
        }
    }

    results.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
    results.truncate(limit);
    Some(results)
}

/// Search nodes via hybrid endpoint when configured; otherwise fall back to keyword scoring.
pub async fn hybrid_search(
    nodes: &[BrainNode],
    query: &str,
    hybrid_endpoint: Option<&str>,
    limit: usize,
) -> Vec<(f64, BrainNode)> {
    if nodes.is_empty() {
        return vec![];
    }

    if let Some(endpoint) = hybrid_endpoint {
        if let Some(results) = search_remote(nodes, query, endpoint, limit).await {
            return results;
        }
    }

    fallback_search(nodes, query, limit)
}

#[cfg(test)]
pub(crate) mod test_support {
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::Value;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct MockState {
        hits: Arc<AtomicUsize>,
        payloads: Arc<Mutex<Vec<Value>>>,
        response: Value,
    }

    pub(crate) struct MockHybridServer {
        pub(crate) base_url: String,
        pub(crate) hits: Arc<AtomicUsize>,
        pub(crate) payloads: Arc<Mutex<Vec<Value>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl MockHybridServer {
        pub(crate) async fn start(response: Value) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let payloads = Arc::new(Mutex::new(Vec::new()));
            let state = MockState {
                hits: Arc::clone(&hits),
                payloads: Arc::clone(&payloads),
                response,
            };
            let app = Router::new()
                .route(
                    "/search",
                    post(
                        |State(state): State<MockState>, Json(payload): Json<Value>| async move {
                            state.hits.fetch_add(1, Ordering::SeqCst);
                            state.payloads.lock().await.push(payload);
                            Json(state.response)
                        },
                    ),
                )
                .with_state(state);
            let handle = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            Self {
                base_url,
                hits,
                payloads,
                handle,
            }
        }
    }

    impl Drop for MockHybridServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ovca_types::BrainNode;
    use serde_json::json;
    use std::sync::atomic::Ordering;

    fn node(title: &str, tags: &[&str]) -> BrainNode {
        BrainNode {
            id: title.to_lowercase().replace(' ', "-"),
            title: title.to_string(),
            node_type: "Note".to_string(),
            brain: "oracle".to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn tokenize_basic() {
        let t = tokenize("Risk Management Strategy");
        assert!(t.contains("risk"));
        assert!(t.contains("management"));
        assert!(t.contains("strategy"));
    }

    #[test]
    fn tokenize_thai() {
        let t = tokenize("กลยุทธ์ oracle strategy");
        // Thai chars should not be split from each other but split from ascii
        assert!(t.contains("strategy"));
        assert!(t.contains("oracle"));
    }

    #[test]
    fn score_node_exact_match() {
        let n = node("Strategy Alpha", &["trading"]);
        let q = tokenize("strategy");
        let score = score_node(&q, &n);
        assert!(
            score > 0,
            "expected score > 0 for 'strategy' in '{}'",
            n.title
        );
    }

    #[test]
    fn score_node_no_match() {
        let n = node("Portfolio Position", &["risk"]);
        let q = tokenize("coordinator");
        let score = score_node(&q, &n);
        assert_eq!(score, 0);
    }

    #[test]
    fn score_node_counts_keyword_hits() {
        let n = node("Strategy", &[]);
        let q = tokenize("strategy");
        let score = score_node(&q, &n);
        assert_eq!(score, 1);

        let n2 = node("Strategy Note", &[]);
        let q2 = tokenize("strategy note");
        let score2 = score_node(&q2, &n2);
        assert_eq!(score2, 2);
    }

    #[test]
    fn search_nodes_returns_top_result() {
        let nodes = vec![
            node("Risk Management Strategy", &["risk"]),
            node("Portfolio Alpha Signal", &["alpha", "trading"]),
            node("Reviewer Review", &["review"]),
        ];
        let results = search_nodes(&nodes, "risk", 5);
        assert!(!results.is_empty());
        assert_eq!(results[0].1.title, "Risk Management Strategy");
    }

    #[test]
    fn search_nodes_empty_query() {
        let nodes = vec![node("Some Node", &[])];
        let results = search_nodes(&nodes, "", 5);
        assert!(results.is_empty());
    }

    #[test]
    fn search_nodes_limit_respected() {
        let nodes: Vec<BrainNode> = (0..10)
            .map(|i| node(&format!("Note {}", i), &["note"]))
            .collect();
        let results = search_nodes(&nodes, "note", 3);
        assert!(results.len() <= 3);
    }

    #[tokio::test]
    async fn hybrid_search_uses_http_results() {
        let local_node = node("Capital Allocation Note", &["allocation"]);
        let server = test_support::MockHybridServer::start(json!({
            "results": [
                {
                    "id": local_node.id,
                    "hybrid_score": 9.75,
                    "title": "Remote Title Should Not Override Local"
                }
            ]
        }))
        .await;

        let results = hybrid_search(
            std::slice::from_ref(&local_node),
            "position sizing",
            Some(&server.base_url),
            5,
        )
        .await;

        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
        let payloads = server.payloads.lock().await;
        assert_eq!(payloads[0]["query"], "position sizing");
        assert_eq!(payloads[0]["brain"], "oracle");
        assert_eq!(payloads[0]["top_k"], 5);
        drop(payloads);

        assert_eq!(results.len(), 1);
        assert!((results[0].0 - 9.75).abs() < f64::EPSILON);
        assert_eq!(results[0].1.title, "Capital Allocation Note");
    }

    #[tokio::test]
    async fn hybrid_search_falls_back_when_endpoint_unreachable() {
        let local_node = node("Risk Management Strategy", &["risk"]);
        let results = hybrid_search(
            std::slice::from_ref(&local_node),
            "risk",
            Some("http://127.0.0.1:1"),
            5,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1.0);
        assert_eq!(results[0].1.title, local_node.title);
    }

    #[tokio::test]
    async fn hybrid_search_falls_back_without_endpoint() {
        let local_node = node("Risk Management Strategy", &["risk"]);
        let results = hybrid_search(std::slice::from_ref(&local_node), "risk", None, 5).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1.0);
        assert_eq!(results[0].1.title, local_node.title);
    }
}
