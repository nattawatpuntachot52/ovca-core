use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;
use tracing_subscriber::EnvFilter;

const LATENCY_WINDOW: usize = 512;

#[derive(Debug)]
struct HttpMetricsInner {
    request_count: AtomicU64,
    error_count: AtomicU64,
    latencies_ms: Mutex<VecDeque<u64>>,
}

#[derive(Clone, Debug)]
pub struct HttpMetrics {
    service: Arc<str>,
    inner: Arc<HttpMetricsInner>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HttpMetricsSnapshot {
    pub ok: bool,
    pub service: String,
    pub request_count: u64,
    pub error_count: u64,
    pub request_latency_p99_ms: u64,
    pub latency_sample_size: usize,
}

impl HttpMetrics {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: Arc::<str>::from(service.into()),
            inner: Arc::new(HttpMetricsInner {
                request_count: AtomicU64::new(0),
                error_count: AtomicU64::new(0),
                latencies_ms: Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW)),
            }),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn record(&self, status_code: u16, duration_ms: u64) {
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        if status_code >= 400 {
            self.inner.error_count.fetch_add(1, Ordering::Relaxed);
        }

        let mut latencies = self.inner.latencies_ms.lock().unwrap();
        if latencies.len() >= LATENCY_WINDOW {
            latencies.pop_front();
        }
        latencies.push_back(duration_ms);
    }

    pub fn snapshot(&self) -> HttpMetricsSnapshot {
        let latencies = self.inner.latencies_ms.lock().unwrap();
        let p99 = percentile_99(&latencies);
        HttpMetricsSnapshot {
            ok: true,
            service: self.service.to_string(),
            request_count: self.inner.request_count.load(Ordering::Relaxed),
            error_count: self.inner.error_count.load(Ordering::Relaxed),
            request_latency_p99_ms: p99,
            latency_sample_size: latencies.len(),
        }
    }

    pub fn snapshot_json(&self) -> Value {
        serde_json::to_value(self.snapshot()).unwrap_or_else(|_| json!({"ok": false}))
    }
}

pub fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let format = std::env::var("ORACLE_LOG_FORMAT")
        .unwrap_or_else(|_| "json".to_string())
        .to_ascii_lowercase();

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    let _ = if format == "compact" {
        builder.compact().try_init()
    } else {
        builder
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .try_init()
    };
}

pub async fn track_http_metrics(
    State(metrics): State<HttpMetrics>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| req.uri().path())
        .to_string();
    let started_at = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let duration_ms = started_at.elapsed().as_millis() as u64;
    metrics.record(status, duration_ms);
    info!(
        service = %metrics.service(),
        method = %method,
        path = %path,
        status = status,
        duration_ms = duration_ms,
        "http request"
    );
    response
}

fn percentile_99(samples: &VecDeque<u64>) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut values = samples.iter().copied().collect::<Vec<_>>();
    values.sort_unstable();
    let idx = (((values.len() as f64) * 0.99).ceil() as usize).saturating_sub(1);
    values[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_snapshot_tracks_counts_and_p99() {
        let metrics = HttpMetrics::new("test-service");
        for (status, duration) in [(200, 4), (200, 8), (500, 50), (200, 13)] {
            metrics.record(status, duration);
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.service, "test-service");
        assert_eq!(snapshot.request_count, 4);
        assert_eq!(snapshot.error_count, 1);
        assert_eq!(snapshot.request_latency_p99_ms, 50);
        assert_eq!(snapshot.latency_sample_size, 4);
    }
}
