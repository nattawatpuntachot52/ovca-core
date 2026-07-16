use anyhow::{anyhow, Context, Result};
use futures_util::{stream, Stream};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::pin::Pin;
use std::time::Duration;

pub type ChatStream = Pin<Box<dyn Stream<Item = Result<String>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new("system", content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new("user", content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new("assistant", content)
    }
}

#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    base_url: String,
    api_key: String,
    default_model: String,
    timeout: Duration,
}

impl LlmClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        default_model: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(timeout)
            .build()
            .context("build llm http client")?;

        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            default_model: default_model.into(),
            timeout,
        })
    }

    pub fn from_env(timeout: Duration) -> Result<Self> {
        dotenvy::dotenv().ok();
        let base_url = std::env::var("CLAUDE_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8000/v1/chat/completions".to_string());
        let api_key = std::env::var("CLAUDE_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .unwrap_or_default();
        let default_model = std::env::var("LLM_MODEL")
            .or_else(|_| std::env::var("CLAUDE_MODEL"))
            .unwrap_or_else(|_| "local-model".to_string());
        Self::new(base_url, api_key, default_model, timeout)
    }

    pub async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        temperature: f32,
        model: Option<&str>,
    ) -> Result<String> {
        let url = self.chat_completions_url();
        let request_body = json!({
            "model": model.unwrap_or(&self.default_model),
            "messages": messages,
            "temperature": temperature,
            "stream": false,
        });

        let mut request = self.client.post(url).json(&request_body);
        if !self.api_key.trim().is_empty() {
            request = request.bearer_auth(self.api_key.trim());
        }

        let response = request.send().await.context("send llm chat request")?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("llm_http_{}: {}", status.as_u16(), body));
        }

        let payload: Value = serde_json::from_str(&body).context("parse llm response json")?;
        extract_message_content(&payload).ok_or_else(|| anyhow!("missing_llm_message_content"))
    }

    pub async fn chat_stream(&self, messages: Vec<ChatMessage>) -> Result<ChatStream> {
        // Compatibility wrapper for Sprint 4: consumers can treat this as a one-chunk stream.
        let text = self.chat(messages, 0.2, None).await?;
        Ok(Box::pin(stream::once(async move { Ok(text) })))
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    fn chat_completions_url(&self) -> String {
        if self.base_url.ends_with("/chat/completions") {
            return self.base_url.clone();
        }
        if self.base_url.ends_with("/v1") {
            return format!("{}/chat/completions", self.base_url);
        }
        format!("{}/v1/chat/completions", self.base_url)
    }
}

fn extract_message_content(payload: &Value) -> Option<String> {
    let content = payload
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?;

    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }

    let pieces = content.as_array()?;
    let mut out = String::new();
    for piece in pieces {
        if let Some(text) = piece.get("text").and_then(Value::as_str) {
            out.push_str(text);
        } else if let Some(text) = piece.as_str() {
            out.push_str(text);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    struct CapturedRequest {
        authorization: Arc<Mutex<Option<String>>>,
        body: Arc<Mutex<Option<Value>>>,
    }

    #[tokio::test]
    async fn chat_sends_expected_payload_and_auth_header() {
        async fn handler(
            State(captured): State<CapturedRequest>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            *captured.authorization.lock().unwrap() = auth;
            *captured.body.lock().unwrap() = Some(body);
            Json(json!({
                "choices": [
                    {
                        "message": {
                            "content": "pong"
                        }
                    }
                ]
            }))
        }

        let captured = CapturedRequest::default();
        let app = Router::new()
            .route("/v1/chat/completions", post(handler))
            .with_state(captured.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = LlmClient::new(
            format!("http://{}", addr),
            "test-api-key",
            "test-model",
            Duration::from_secs(2),
        )
        .unwrap();

        let text = client
            .chat(vec![ChatMessage::user("ping")], 0.4, None)
            .await
            .unwrap();

        assert_eq!(text, "pong");
        assert_eq!(
            captured.authorization.lock().unwrap().clone(),
            Some("Bearer test-api-key".to_string())
        );
        let body = captured.body.lock().unwrap().clone().unwrap();
        assert_eq!(body["model"], "test-model");
        assert!((body["temperature"].as_f64().unwrap() - 0.4).abs() < 1e-6);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "ping");
    }
}
