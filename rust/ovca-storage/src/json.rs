/// Atomic JSON read/write.
/// write_json_atomic: writes to .tmp then renames — safe on all OSes.
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::Path;

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        fs::read_to_string(path).with_context(|| format!("read_json: {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("read_json parse: {}", path.display()))
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("write_json_atomic: serialize")?;

    // Write to .tmp then rename — atomic on POSIX and Windows NTFS.
    let tmp = path.with_extension("json.tmp");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("write_json_atomic mkdir: {}", parent.display()))?;
    }
    fs::write(&tmp, json.as_bytes())
        .with_context(|| format!("write_json_atomic write tmp: {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("write_json_atomic rename: {}", path.display()))?;
    Ok(())
}

/// List files in `dir` matching `{prefix}*{ext}`, sorted newest-first by filename.
pub fn list_date_files(dir: &Path, prefix: &str, ext: &str) -> Vec<std::path::PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return vec![];
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with(prefix) && name.ends_with(ext)
        })
        .collect();
    files.sort_by(|a, b| b.cmp(a)); // lexicographic descending = newest first for YYYYMMDD
    files
}

pub fn latest_date_file(dir: &Path, prefix: &str, ext: &str) -> Option<std::path::PathBuf> {
    list_date_files(dir, prefix, ext).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.json");
        let data = json!({"foo": 42, "bar": "baz"});
        write_json_atomic(&path, &data).unwrap();
        let out: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(out["foo"], 42);
    }

    #[test]
    fn atomic_write_no_partial_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data.json");
        // Write initial
        write_json_atomic(&path, &json!({"v": 1})).unwrap();
        // Overwrite — should not leave tmp file behind
        write_json_atomic(&path, &json!({"v": 2})).unwrap();
        assert!(!dir.path().join("data.json.tmp").exists());
        let out: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(out["v"], 2);
    }
}
