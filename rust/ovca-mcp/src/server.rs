/// McpServer — Axum router factory.
/// Builder pattern: McpServer::builder("brain", "brain").tool(...).into_router()
use crate::sse::{broadcast_to_sse_stream, make_sse_channel};
use axum::{
    extract::State,
    middleware,
    response::{
        sse::{KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use ovca_observability::{track_http_metrics, HttpMetrics};
use ovca_types::{McpResponse, McpToolCall};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Instant};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;
use tracing::info;

// ── Handler types ─────────────────────────────────────────────────────────

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type ToolHandler = Arc<dyn Fn(Value) -> BoxFuture<Value> + Send + Sync>;
pub type MetricsProvider = Arc<dyn Fn() -> Value + Send + Sync>;

// ── Spec types (match Python registry format) ─────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(skip)]
    pub handler: Option<ToolHandler>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub name: String,
    pub description: String,
    pub uri: String,
    #[serde(skip)]
    pub handler: Option<ToolHandler>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PromptSpec {
    pub name: String,
    pub description: String,
    #[serde(skip)]
    pub handler: Option<ToolHandler>,
}

// ── Shared state ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct McpServerState {
    pub name: String,
    pub agent_id: String,
    pub metrics: HttpMetrics,
    pub tools: Arc<RwLock<HashMap<String, ToolSpec>>>,
    pub resources: Arc<RwLock<HashMap<String, ResourceSpec>>>,
    pub prompts: Arc<RwLock<HashMap<String, PromptSpec>>>,
    pub metrics_provider: Option<MetricsProvider>,
    pub sse_tx: broadcast::Sender<String>,
}

impl McpServerState {
    pub async fn publish_event(&self, event: Value) {
        let s = event.to_string();
        let _ = self.sse_tx.send(s);
    }
}

// ── Builder ───────────────────────────────────────────────────────────────

pub struct McpServerBuilder {
    name: String,
    agent_id: String,
    tools: HashMap<String, ToolSpec>,
    resources: HashMap<String, ResourceSpec>,
    prompts: HashMap<String, PromptSpec>,
    metrics_provider: Option<MetricsProvider>,
}

impl McpServerBuilder {
    pub fn new(name: &str, agent_id: &str) -> Self {
        Self {
            name: name.to_string(),
            agent_id: agent_id.to_string(),
            tools: HashMap::new(),
            resources: HashMap::new(),
            prompts: HashMap::new(),
            metrics_provider: None,
        }
    }

    pub fn tool(
        mut self,
        name: &str,
        description: &str,
        input_schema: Value,
        handler: impl Fn(Value) -> BoxFuture<Value> + Send + Sync + 'static,
    ) -> Self {
        self.tools.insert(
            name.to_string(),
            ToolSpec {
                name: name.to_string(),
                description: description.to_string(),
                input_schema,
                handler: Some(Arc::new(handler)),
            },
        );
        self
    }

    pub fn resource(
        mut self,
        name: &str,
        description: &str,
        uri: &str,
        handler: impl Fn(Value) -> BoxFuture<Value> + Send + Sync + 'static,
    ) -> Self {
        self.resources.insert(
            name.to_string(),
            ResourceSpec {
                name: name.to_string(),
                description: description.to_string(),
                uri: uri.to_string(),
                handler: Some(Arc::new(handler)),
            },
        );
        self
    }

    pub fn prompt(
        mut self,
        name: &str,
        description: &str,
        handler: impl Fn(Value) -> BoxFuture<Value> + Send + Sync + 'static,
    ) -> Self {
        self.prompts.insert(
            name.to_string(),
            PromptSpec {
                name: name.to_string(),
                description: description.to_string(),
                handler: Some(Arc::new(handler)),
            },
        );
        self
    }

    pub fn metrics_provider(
        mut self,
        provider: impl Fn() -> Value + Send + Sync + 'static,
    ) -> Self {
        self.metrics_provider = Some(Arc::new(provider));
        self
    }

    pub fn into_router(self) -> (Router, McpServerState) {
        let (sse_tx, _) = make_sse_channel();
        let state = McpServerState {
            metrics: HttpMetrics::new(self.name.clone()),
            name: self.name,
            agent_id: self.agent_id,
            tools: Arc::new(RwLock::new(self.tools)),
            resources: Arc::new(RwLock::new(self.resources)),
            prompts: Arc::new(RwLock::new(self.prompts)),
            metrics_provider: self.metrics_provider,
            sse_tx,
        };
        let router = build_router(state.clone());
        (router, state)
    }
}

pub struct McpServer;
impl McpServer {
    pub fn builder(name: &str, agent_id: &str) -> McpServerBuilder {
        McpServerBuilder::new(name, agent_id)
    }
}

// ── Routes ────────────────────────────────────────────────────────────────

fn build_router(state: McpServerState) -> Router {
    let metrics = state.metrics.clone();
    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/registry", get(registry_handler))
        .route("/tools/call", post(tools_call_handler))
        .route("/tools/list", get(tools_list_handler))
        .route("/resources/get", post(resources_get_handler))
        .route("/resources/list", get(resources_list_handler))
        .route("/prompts/get", post(prompts_get_handler))
        .route("/prompts/list", get(prompts_list_handler))
        .route("/sse", get(sse_handler))
        .with_state(state)
        .route_layer(middleware::from_fn_with_state(metrics, track_http_metrics))
        .layer(CorsLayer::permissive())
}

// ── Handlers ──────────────────────────────────────────────────────────────

async fn health_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let tools = s.tools.read().await.len();
    let resources = s.resources.read().await.len();
    let prompts = s.prompts.read().await.len();
    Json(serde_json::json!({
        "ok": true,
        "name": s.name,
        "agent_id": s.agent_id,
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }))
}

async fn registry_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let tools_map = s.tools.read().await;
    let resources_map = s.resources.read().await;
    let prompts_map = s.prompts.read().await;
    let tools: Vec<_> = tools_map.keys().cloned().collect();
    let resources: Vec<_> = resources_map.keys().cloned().collect();
    let prompts: Vec<_> = prompts_map.keys().cloned().collect();
    Json(serde_json::json!({
        "ok": true,
        "name": s.name,
        "counts": {
            "tools": tools.len(),
            "resources": resources.len(),
            "prompts": prompts.len(),
        },
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }))
}

async fn metrics_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let mut payload = s.metrics.snapshot_json();
    if let Some(provider) = &s.metrics_provider {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("extra".to_string(), provider());
        }
    }
    Json(payload)
}

async fn tools_call_handler(
    State(s): State<McpServerState>,
    Json(call): Json<McpToolCall>,
) -> impl IntoResponse {
    let handler = {
        let tools = s.tools.read().await;
        tools.get(&call.name).and_then(|t| t.handler.clone())
    };
    let started_at = Instant::now();
    let response = match handler {
        Some(h) => {
            let raw = h(call.arguments).await;
            normalize_response(&call.name, "tool_result", raw)
        }
        None => McpResponse::err(&call.name, &format!("unknown_tool:{}", call.name)),
    };
    info!(
        agent = %s.agent_id,
        tool = %call.name,
        ok = response.ok,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "tool call completed"
    );
    s.publish_event(serde_json::json!({
        "event": "tool_called",
        "name": call.name,
        "ok": response.ok,
    }))
    .await;
    Json(response)
}

async fn tools_list_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let tools: Vec<_> = s
        .tools
        .read()
        .await
        .values()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            })
        })
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "count": tools.len(),
        "tools": tools,
    }))
}

#[derive(Deserialize)]
struct ResourceCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

async fn resources_get_handler(
    State(s): State<McpServerState>,
    Json(call): Json<ResourceCall>,
) -> impl IntoResponse {
    let started_at = Instant::now();
    let handler = {
        let resources = s.resources.read().await;
        resources.get(&call.name).and_then(|r| r.handler.clone())
    };
    let response = match handler {
        Some(h) => normalize_response(&call.name, "resource_result", h(call.arguments).await),
        None => McpResponse::err(&call.name, &format!("unknown_resource:{}", call.name)),
    };
    info!(
        agent = %s.agent_id,
        resource = %call.name,
        ok = response.ok,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "resource call completed"
    );
    Json(response)
}

async fn resources_list_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let resources: Vec<_> = s
        .resources
        .read()
        .await
        .values()
        .map(|r| serde_json::json!({"name": r.name, "uri": r.uri, "description": r.description}))
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "count": resources.len(),
        "resources": resources,
    }))
}

async fn prompts_get_handler(
    State(s): State<McpServerState>,
    Json(call): Json<ResourceCall>,
) -> impl IntoResponse {
    let started_at = Instant::now();
    let handler = {
        let prompts = s.prompts.read().await;
        prompts.get(&call.name).and_then(|p| p.handler.clone())
    };
    let response = match handler {
        Some(h) => normalize_response(&call.name, "prompt_result", h(call.arguments).await),
        None => McpResponse::err(&call.name, &format!("unknown_prompt:{}", call.name)),
    };
    info!(
        agent = %s.agent_id,
        prompt = %call.name,
        ok = response.ok,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "prompt call completed"
    );
    Json(response)
}

async fn prompts_list_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let prompts: Vec<_> = s
        .prompts
        .read()
        .await
        .values()
        .map(|p| serde_json::json!({"name": p.name, "description": p.description}))
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "count": prompts.len(),
        "prompts": prompts,
    }))
}

async fn sse_handler(State(s): State<McpServerState>) -> impl IntoResponse {
    let rx = s.sse_tx.subscribe();
    let stream = broadcast_to_sse_stream(rx);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── normalize_response ────────────────────────────────────────────────────

/// Wraps a raw handler Value into a full McpResponse envelope.
/// Mirrors Python base_server.py normalize_response() exactly.
pub fn normalize_response(name: &str, kind: &str, raw: Value) -> McpResponse {
    // If handler returned an already-normalized dict, pass through
    if let Some(obj) = raw.as_object() {
        if obj.contains_key("ok") && obj.contains_key("result") {
            let ok = obj.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let errors = obj
                .get("errors")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return McpResponse {
                ok,
                name: name.to_string(),
                kind: kind.to_string(),
                result: obj.get("result").cloned().unwrap_or(Value::Null),
                trace: obj.get("trace").cloned().unwrap_or(Value::Null),
                errors,
                confidence: obj
                    .get("confidence")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                evidence: obj
                    .get("evidence")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default(),
            };
        }
    }
    McpResponse::ok(name, raw)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http};
    use tower::util::ServiceExt;

    fn make_test_server() -> Router<()> {
        let (router, _state) = McpServer::builder("test-server", "test")
            .tool(
                "echo",
                "Echo arguments back",
                serde_json::json!({"type": "object"}),
                |args: Value| Box::pin(async move { args }),
            )
            .into_router();
        router
    }

    async fn call(app: Router<()>, req: http::Request<Body>) -> (http::StatusCode, Value) {
        let resp: http::Response<Body> = ServiceExt::<http::Request<Body>>::oneshot(app, req)
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let req = http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(make_test_server(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["tools"], 1);
    }

    #[tokio::test]
    async fn metrics_route_tracks_requests() {
        let app = make_test_server();

        let req = http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let _ = call(app.clone(), req).await;

        let req = http::Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(app, req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert!(json["request_count"].as_u64().unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn tools_call_known_tool() {
        let payload = serde_json::json!({"name": "echo", "arguments": {"x": 99}});
        let req = http::Request::builder()
            .method("POST")
            .uri("/tools/call")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let (status, json) = call(make_test_server(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["name"], "echo");
    }

    #[tokio::test]
    async fn tools_call_unknown_tool_returns_error() {
        let payload = serde_json::json!({"name": "nonexistent", "arguments": {}});
        let req = http::Request::builder()
            .method("POST")
            .uri("/tools/call")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let (_status, json) = call(make_test_server(), req).await;
        assert_eq!(json["ok"], false);
    }

    #[test]
    fn normalize_response_plain_value() {
        let raw = serde_json::json!({"nodes": [1, 2, 3]});
        let resp = normalize_response("brain_read", "tool_result", raw);
        assert!(resp.ok);
        assert_eq!(resp.result["nodes"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn normalize_response_already_normalized() {
        let raw = serde_json::json!({
            "ok": false,
            "result": null,
            "errors": ["permission_denied"]
        });
        let resp = normalize_response("brain_write", "tool_result", raw);
        assert!(!resp.ok);
        assert_eq!(resp.errors[0], "permission_denied");
    }
}
