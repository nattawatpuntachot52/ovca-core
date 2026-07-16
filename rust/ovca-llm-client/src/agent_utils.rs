use anyhow::Result;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use ovca_storage::{append_jsonl, read_json, read_jsonl, read_jsonl_tail};
use ovca_types::resolve_mcp_port;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};

pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

pub fn now_iso() -> String {
    now_utc().to_rfc3339()
}

fn guess_oracle_root() -> PathBuf {
    if let Ok(root) = env::var("AGENT_ROOT") {
        let path = PathBuf::from(root);
        if path.exists() {
            return path;
        }
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if cwd.join("scripts").exists() && cwd.join("memory").exists() {
        return cwd;
    }
    if let Some(parent) = cwd.parent() {
        if parent.join("scripts").exists() && parent.join("memory").exists() {
            return parent.to_path_buf();
        }
    }
    cwd
}

pub fn port_from_env(env_name: &str, default_port: u16) -> u16 {
    env::var(env_name)
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(default_port)
}

pub fn parse_args(default_port: u16) -> (u16, PathBuf) {
    let argv: Vec<String> = env::args().collect();
    let mut port = default_port;
    let mut root = guess_oracle_root();

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" => {
                if let Some(raw) = argv.get(i + 1) {
                    port = raw.parse::<u16>().unwrap_or(default_port);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--root" => {
                if let Some(raw) = argv.get(i + 1) {
                    root = PathBuf::from(raw);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    (port, root)
}

pub fn safe_json(path: &Path, default: Value) -> Value {
    read_json::<Value>(path).unwrap_or(default)
}

pub fn load_jsonl_values(path: &Path) -> Vec<Value> {
    read_jsonl::<Value>(path)
}

pub fn read_jsonl_tail_values(path: &Path, limit: usize) -> Vec<Value> {
    let cap = limit.clamp(1, 500);
    read_jsonl_tail::<Value>(path, cap)
}

pub fn append_jsonl_value(path: &Path, value: &Value) -> Result<()> {
    append_jsonl(path, value)
}

pub fn list_files_by_name(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(suffix))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

pub fn latest_file_by_mtime(dir: &Path, suffix: &str) -> Option<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return None;
    };

    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(suffix))
                .unwrap_or(false)
        })
        .filter_map(|path| {
            let mtime = path.metadata().ok()?.modified().ok()?;
            Some((mtime, path))
        })
        .max_by_key(|(mtime, _)| *mtime)
        .map(|(_, path)| path)
}

pub fn parse_timestamp(text: &str) -> Option<DateTime<Utc>> {
    let raw = text.trim();
    if raw.is_empty() {
        return None;
    }

    if let Ok(ts) = DateTime::parse_from_rfc3339(raw) {
        return Some(ts.with_timezone(&Utc));
    }
    if let Ok(ts) = DateTime::parse_from_rfc2822(raw) {
        return Some(ts.with_timezone(&Utc));
    }
    if let Ok(ts) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc));
    }
    if let Ok(ts) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let naive = ts.and_hms_opt(0, 0, 0)?;
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    None
}

pub fn parse_timestamp_value(value: &Value) -> Option<DateTime<Utc>> {
    value.as_str().and_then(parse_timestamp)
}

pub fn trim_text(text: &str, max_chars: usize) -> String {
    let cleaned = text.trim().replace(['\r', '\n'], " ");
    if cleaned.chars().count() <= max_chars {
        return cleaned;
    }

    let take = max_chars.saturating_sub(3);
    let mut trimmed: String = cleaned.chars().take(take).collect();
    trimmed = trimmed.trim_end().to_string();
    trimmed.push_str("...");
    trimmed
}

pub fn display_path(path: &Path, root: &Path) -> String {
    let fallback = path.to_string_lossy().replace('\\', "/");

    if let Ok(rel) = path.strip_prefix(root) {
        return rel.to_string_lossy().replace('\\', "/");
    }

    let canonical_path = path.canonicalize().ok();
    let canonical_root = root.canonicalize().ok();
    if let (Some(abs), Some(base)) = (canonical_path, canonical_root) {
        if let Ok(rel) = abs.strip_prefix(base) {
            return rel.to_string_lossy().replace('\\', "/");
        }
    }

    fallback
}

pub fn resolve_agent_port(agent_id: &str) -> Option<u16> {
    let normalized = agent_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let env_name = format!("MCP_{}_PORT", normalized.to_ascii_uppercase());
    if let Ok(raw) = env::var(&env_name) {
        if let Ok(port) = raw.parse::<u16>() {
            return Some(port);
        }
    }

    resolve_mcp_port(&normalized)
}

pub fn resolve_agent_base_url(agent_id: &str) -> Option<String> {
    let normalized = agent_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let explicit_env = format!("MCP_{}_BASE_URL", normalized.to_ascii_uppercase());
    if let Ok(raw) = env::var(explicit_env) {
        let trimmed = raw.trim().trim_end_matches('/').to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    let port = resolve_agent_port(&normalized)?;
    let host = env::var("MCP_AGENT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let host = host.trim();
    Some(format!(
        "http://{}:{}",
        if host.is_empty() { "127.0.0.1" } else { host },
        port
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timestamp_supports_multiple_formats() {
        assert!(parse_timestamp("2026-03-13T08:48:01+00:00").is_some());
        assert!(parse_timestamp("Thu, 12 Mar 2026 16:50:00 GMT").is_some());
        assert!(parse_timestamp("2026-03-12 16:54:51").is_some());
        assert!(parse_timestamp("2026-03-12").is_some());
    }

    #[test]
    fn trim_text_adds_ellipsis() {
        let trimmed = trim_text("abcdef", 5);
        assert_eq!(trimmed, "ab...");
    }
}
