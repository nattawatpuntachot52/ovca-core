use anyhow::Result;
use ovca_llm_client::{display_path, now_iso, parse_args, port_from_env, safe_json, trim_text};
use ovca_mcp::init_tracing;
use ovca_mcp::server::{BoxFuture, McpServer};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::info;

const DEFAULT_PORT: u16 = 18785;

#[derive(Debug, Clone)]
struct EvidenceCandidate {
    path: PathBuf,
    modified: SystemTime,
}

fn candidate_roots(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("tasks").join("audits"),
        root.join("tasks").join("outbox"),
        root.join("tasks").join("inbox"),
    ]
}

fn matches_reviewer_path(path: &Path) -> bool {
    let text = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    text.contains("reviewer") || text.contains("review-e2e")
}

fn collect_candidates(root: &Path) -> Vec<EvidenceCandidate> {
    let mut candidates = Vec::new();
    for dir in candidate_roots(root) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !matches_reviewer_path(&path) {
                continue;
            }
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            candidates.push(EvidenceCandidate { path, modified });
        }
    }
    candidates.sort_by_key(|candidate| candidate.modified);
    candidates.reverse();
    candidates
}

fn first_existing(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|path| path.exists()).cloned()
}

fn status_from_payload(payload: &Value) -> String {
    for pointer in [
        "/overall_status",
        "/status",
        "/verdict",
        "/result/overall_status",
        "/latest/overall_status",
    ] {
        if let Some(status) = payload.pointer(pointer).and_then(Value::as_str) {
            let status = status.trim();
            if !status.is_empty() {
                return status.to_ascii_lowercase();
            }
        }
    }
    "unknown".to_string()
}

fn latest_from_candidate(root: &Path, candidate: &EvidenceCandidate) -> Value {
    let status_path = candidate.path.join("status.json");
    let review_path = first_existing(&[
        candidate.path.join("result.md"),
        candidate.path.join("review.md"),
        candidate.path.join("TASK-handoff.md"),
    ]);
    let status_payload = safe_json(&status_path, json!({}));
    let mut summary = String::new();
    let mut source = if status_path.exists() {
        Some(status_path.clone())
    } else {
        None
    };

    if let Some(path) = review_path {
        summary = std::fs::read_to_string(&path)
            .map(|raw| trim_text(&raw, 360))
            .unwrap_or_default();
        source = Some(path);
    }

    if summary.is_empty() {
        summary = status_payload
            .get("summary")
            .or_else(|| status_payload.get("message"))
            .and_then(Value::as_str)
            .map(|text| trim_text(text, 360))
            .unwrap_or_else(|| {
                "Reviewer review artifact found without a readable summary.".to_string()
            });
    }

    let overall_status = status_from_payload(&status_payload);
    json!({
        "overall_status": overall_status.clone(),
        "status": overall_status,
        "summary": summary,
        "source": source.map(|path| display_path(&path, root)),
        "artifact": display_path(&candidate.path, root),
        "status_payload": if status_payload.is_object() { status_payload } else { json!({}) },
    })
}

fn reviewer_review_status(root: &Path, args: Value) -> Value {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let limit = args
        .get("limit_history")
        .and_then(Value::as_u64)
        .unwrap_or(5) as usize;
    let candidates = collect_candidates(root);
    let latest = candidates
        .first()
        .map(|candidate| latest_from_candidate(root, candidate))
        .unwrap_or_else(|| {
            json!({
                "overall_status": "unknown",
                "status": "unknown",
                "summary": "No Reviewer review artifacts found in tasks/audits, tasks/outbox, or tasks/inbox.",
                "source": Value::Null,
                "artifact": Value::Null,
                "status_payload": {},
            })
        });
    let overall_status = latest
        .get("overall_status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let history = candidates
        .iter()
        .take(limit.clamp(1, 25))
        .map(|candidate| {
            json!({
                "artifact": display_path(&candidate.path, root),
            })
        })
        .collect::<Vec<_>>();
    let finding_summary = latest
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("No Reviewer review evidence available.")
        .to_string();
    let severity = if overall_status == "unknown" {
        "info"
    } else {
        "review"
    };

    json!({
        "ok": true,
        "agent": "reviewer",
        "tool": "reviewer_review_status",
        "overall_status": overall_status.clone(),
        "status": overall_status,
        "latest": latest,
        "findings": [{
            "severity": severity,
            "summary": finding_summary,
            "evidence": "read-only task artifact scan",
        }],
        "review_evidence": history,
        "query": if query.is_empty() { Value::Null } else { Value::String(query) },
        "checked_at": now_iso(),
    })
}

fn build_router(root: PathBuf) -> axum::Router {
    let schema = json!({
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit_history": {"type": "integer"}
        }
    });
    let (router, _state) = McpServer::builder("oracle-reviewer-mcp", "reviewer")
        .tool(
            "reviewer_review_status",
            "Read Reviewer review/e2e status from task review artifacts.",
            schema,
            move |args: Value| {
                let root = root.clone();
                Box::pin(async move { reviewer_review_status(&root, args) }) as BoxFuture<Value>
            },
        )
        .into_router();
    router
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("info");
    dotenvy::dotenv().ok();

    let default_port = port_from_env("MCP_REVIEWER_PORT", DEFAULT_PORT);
    let (port, root) = parse_args(default_port);
    info!(port, root = %root.display(), "oracle-reviewer-server starting");

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("listening on http://{}", addr);
    axum::serve(listener, build_router(root)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http};
    use tempfile::TempDir;
    use tower::util::ServiceExt;

    fn seed_root() -> TempDir {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp
            .path()
            .join("tasks")
            .join("audits")
            .join("demo__p01__reviewer__review-e2e");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(
            dir.join("status.json"),
            r#"{"overall_status":"ok","summary":"Reviewer review passed"}"#,
        )
        .expect("write status");
        std::fs::write(
            dir.join("result.md"),
            "Reviewer review result: no findings.",
        )
        .expect("write result");
        temp
    }

    async fn call(app: axum::Router, req: http::Request<Body>) -> (http::StatusCode, Value) {
        let resp: http::Response<Body> = ServiceExt::<http::Request<Body>>::oneshot(app, req)
            .await
            .expect("router response");
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, json)
    }

    #[test]
    fn status_tolerates_missing_artifacts() {
        let root = tempfile::tempdir().expect("temp dir");
        let payload = reviewer_review_status(root.path(), json!({}));
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["overall_status"], "unknown");
        assert_eq!(payload["latest"]["overall_status"], "unknown");
        assert!(payload["findings"].is_array());
    }

    #[test]
    fn status_reads_latest_artifact() {
        let root = seed_root();
        let payload = reviewer_review_status(root.path(), json!({"limit_history": 5}));
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["overall_status"], "ok");
        assert!(payload["latest"]["source"]
            .as_str()
            .unwrap()
            .ends_with("result.md"));
    }

    #[tokio::test]
    async fn router_registers_reviewer_tool() {
        let root = seed_root();
        let req = http::Request::builder()
            .uri("/tools/list")
            .body(Body::empty())
            .expect("request");
        let (status, json) = call(build_router(root.path().to_path_buf()), req).await;
        assert_eq!(status, http::StatusCode::OK);
        let tools = json["tools"].as_array().expect("tools array");
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "reviewer_review_status"));
    }

    #[tokio::test]
    async fn router_calls_reviewer_tool() {
        let root = seed_root();
        let payload = json!({"name": "reviewer_review_status", "arguments": {"query": "demo"}});
        let req = http::Request::builder()
            .method("POST")
            .uri("/tools/call")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request");
        let (status, json) = call(build_router(root.path().to_path_buf()), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["result"]["overall_status"], "ok");
    }
}
