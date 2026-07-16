/// JSONL append-safe read/write.
/// append_jsonl: O_APPEND writes are atomic on POSIX for lines < page size (4KB).
/// On Windows, uses a per-path Mutex to serialize writers.
use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

// Per-path write locks for Windows safety (no-op cost on POSIX).
fn write_locks() -> &'static DashMap<PathBuf, Arc<Mutex<()>>> {
    static LOCKS: OnceLock<DashMap<PathBuf, Arc<Mutex<()>>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

pub fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let line = serde_json::to_string(value).context("append_jsonl: serialize")?;
    let line = format!("{}\n", line);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("append_jsonl mkdir: {}", parent.display()))?;
    }

    let lock = write_locks()
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let _guard = lock.lock().expect("append_jsonl mutex poisoned");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("append_jsonl open: {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("append_jsonl write: {}", path.display()))?;
    Ok(())
}

pub fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Read last `n` records from JSONL by scanning tail bytes.
/// Reads at most TAIL_SCAN_BYTES from end of file to avoid loading full log.
pub fn read_jsonl_tail<T: DeserializeOwned>(path: &Path, n: usize) -> Vec<T> {
    use std::io::{Read, Seek, SeekFrom};

    const TAIL_SCAN_BYTES: u64 = 32_768; // 32 KB — enough for ~200 scheduler records

    let Ok(mut file) = fs::File::open(path) else {
        return vec![];
    };
    let Ok(size) = file.seek(SeekFrom::End(0)) else {
        return vec![];
    };
    let start = size.saturating_sub(TAIL_SCAN_BYTES);
    let _ = file.seek(SeekFrom::Start(start));

    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);

    // Find first complete line boundary after seek point
    let buf = if start > 0 {
        match buf.find('\n') {
            Some(i) => &buf[i + 1..],
            None => buf.as_str(),
        }
    } else {
        buf.as_str()
    };

    let records: Vec<T> = buf
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    // Return last n
    let skip = records.len().saturating_sub(n);
    records.into_iter().skip(skip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use tempfile::TempDir;

    #[test]
    fn append_and_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        append_jsonl(&path, &json!({"id": 1})).unwrap();
        append_jsonl(&path, &json!({"id": 2})).unwrap();
        append_jsonl(&path, &json!({"id": 3})).unwrap();
        let records: Vec<Value> = read_jsonl(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["id"], 3);
    }

    #[test]
    fn read_tail_returns_last_n() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("log.jsonl");
        for i in 0..20 {
            append_jsonl(&path, &json!({"seq": i})).unwrap();
        }
        let tail: Vec<Value> = read_jsonl_tail(&path, 5);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[4]["seq"], 19);
    }

    #[test]
    fn read_missing_file_returns_empty() {
        let records: Vec<serde_json::Value> = read_jsonl(Path::new("/nonexistent.jsonl"));
        assert!(records.is_empty());
    }

    #[test]
    fn concurrent_appends_no_corruption() {
        use std::thread;
        let dir = TempDir::new().unwrap();
        let path = Arc::new(dir.path().join("concurrent.jsonl"));
        let mut handles = vec![];
        for i in 0..20 {
            let p = path.clone();
            handles.push(thread::spawn(move || {
                append_jsonl(&p, &json!({"i": i})).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let records: Vec<serde_json::Value> = read_jsonl(&path);
        assert_eq!(records.len(), 20);
    }
}
