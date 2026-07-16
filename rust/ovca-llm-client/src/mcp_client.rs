use crate::agent_utils::resolve_agent_base_url;
use anyhow::{anyhow, Context, Result};
use ovca_types::MCP_PORTS;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

#[derive(Clone)]
pub struct McpHttpClient {
    client: Client,
    base_urls: HashMap<String, String>,
    timeout: Duration,
}

impl McpHttpClient {
    pub fn new<I, S>(agent_ports: I, timeout: Duration) -> Result<Self>
    where
        I: IntoIterator<Item = (S, u16)>,
        S: Into<String>,
    {
        let host = std::env::var("MCP_AGENT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let base_urls = agent_ports
            .into_iter()
            .map(|(agent_id, port)| {
                let agent_id = agent_id.into();
                let url = resolve_agent_base_url(&agent_id)
                    .unwrap_or_else(|| format!("http://{}:{}", host, port));
                (agent_id, url)
            })
            .collect();

        Self::with_base_urls(base_urls, timeout)
    }

    pub fn from_env(timeout: Duration) -> Result<Self> {
        let ports = MCP_PORTS
            .iter()
            .map(|(agent_id, port)| ((*agent_id).to_string(), *port));
        Self::new(ports, timeout)
    }

    pub fn with_base_urls(base_urls: HashMap<String, String>, timeout: Duration) -> Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(timeout)
            .build()
            .context("build MCP HTTP client")?;

        Ok(Self {
            client,
            base_urls: base_urls
                .into_iter()
                .map(|(agent_id, url)| {
                    (
                        agent_id.to_ascii_lowercase(),
                        url.trim_end_matches('/').to_string(),
                    )
                })
                .collect(),
            timeout,
        })
    }

    pub fn base_url_for(&self, agent_id: &str) -> Option<&str> {
        self.base_urls
            .get(&agent_id.trim().to_ascii_lowercase())
            .map(String::as_str)
    }

    pub async fn call_tool(&self, agent_id: &str, tool: &str, args: Value) -> Result<Value> {
        let normalized = agent_id.trim().to_ascii_lowercase();
        let tool_name = tool.trim().to_string();
        let Some(base_url) = self.base_url_for(&normalized) else {
            return Err(anyhow!("unknown_mcp_agent:{}", normalized));
        };
        let url = format!("{}/tools/call", base_url);
        let payload = json!({
            "name": tool_name,
            "arguments": args,
        });

        debug!(agent = %normalized, tool = %tool_name, url = %url, "mcp tool call");

        let response = match self.client.post(&url).json(&payload).send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() || error.is_timeout() => {
                return Ok(offline_result(&normalized, Some(error.to_string())));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("mcp call failed: agent={} tool={}", normalized, tool_name)
                });
            }
        };

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Ok(json!({
                "ok": false,
                "agent": normalized,
                "error": format!("http_{}", status.as_u16()),
                "detail": body,
                "offline": true,
                "result": {
                    "offline": true,
                },
            }));
        }

        let parsed: Value = match serde_json::from_str(&body) {
            Ok(value) => value,
            Err(_) => {
                return Ok(json!({
                    "ok": false,
                    "agent": normalized,
                    "error": "invalid_agent_response",
                    "offline": false,
                    "result": {
                        "offline": false,
                    },
                }));
            }
        };

        if parsed.is_object() {
            Ok(parsed)
        } else {
            Ok(json!({
                "ok": false,
                "agent": normalized,
                "error": "invalid_agent_response",
                "offline": false,
                "result": {
                    "offline": false,
                },
            }))
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

fn offline_result(agent_id: &str, detail: Option<String>) -> Value {
    let mut payload = json!({
        "ok": false,
        "agent": agent_id,
        "error": "mcp_offline",
        "offline": true,
        "result": {
            "offline": true,
        },
    });
    if let Some(detail) = detail {
        payload["detail"] = Value::String(detail);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn offline_port_returns_mcp_offline_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut base_urls = HashMap::new();
        base_urls.insert("engineer".to_string(), format!("http://{}", addr));
        let client = McpHttpClient::with_base_urls(base_urls, Duration::from_millis(250)).unwrap();

        let payload = client
            .call_tool("engineer", "engineer_automation_status", json!({}))
            .await
            .unwrap();

        assert_eq!(payload["ok"], false);
        assert_eq!(payload["error"], "mcp_offline");
        assert_eq!(payload["result"]["offline"], true);
    }

    #[tokio::test]
    async fn success_passthrough_returns_agent_payload() {
        use axum::{routing::post, Json, Router};

        let app = Router::new().route(
            "/tools/call",
            post(|| async { Json(json!({"ok": true, "result": {"macro_regime": "risk_off"}})) }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut base_urls = HashMap::new();
        base_urls.insert("reviewer".to_string(), format!("http://{}", addr));
        let client = McpHttpClient::with_base_urls(base_urls, Duration::from_secs(2)).unwrap();

        let payload = client
            .call_tool("reviewer", "reviewer_review_status", json!({}))
            .await
            .unwrap();

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["result"]["macro_regime"], "risk_off");
    }
}
