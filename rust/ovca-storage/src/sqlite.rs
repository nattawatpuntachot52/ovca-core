/// SQLite helpers — task coordination locks, WAL mode.
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

pub fn open_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("open_db mkdir: {}", parent.display()))?;
    }
    let conn = Connection::open(path).with_context(|| format!("open_db: {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS task_locks (
             task_id   TEXT PRIMARY KEY,
             locked_at INTEGER NOT NULL
         );",
    )
    .context("open_db: init schema")?;
    Ok(conn)
}

/// Returns true if lock was acquired (task_id not already locked).
pub fn acquire_task_lock(conn: &Connection, task_id: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT OR IGNORE INTO task_locks (task_id, locked_at) VALUES (?1, ?2)",
        params![task_id, now],
    )
    .map(|rows| rows == 1)
    .unwrap_or(false)
}

pub fn release_task_lock(conn: &Connection, task_id: &str) {
    let _ = conn.execute(
        "DELETE FROM task_locks WHERE task_id = ?1",
        params![task_id],
    );
}

/// Remove locks older than `stale_secs` (default: 7200s = 2h, matching Python).
pub fn cleanup_stale_locks(conn: &Connection, stale_secs: i64) {
    let cutoff = chrono::Utc::now().timestamp() - stale_secs;
    let _ = conn.execute(
        "DELETE FROM task_locks WHERE locked_at < ?1",
        params![cutoff],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn acquire_and_release() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("coord.sqlite")).unwrap();
        assert!(acquire_task_lock(&conn, "task_a"));
        assert!(!acquire_task_lock(&conn, "task_a")); // already locked
        release_task_lock(&conn, "task_a");
        assert!(acquire_task_lock(&conn, "task_a")); // re-acquired after release
    }

    #[test]
    fn stale_lock_cleanup() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("coord.sqlite")).unwrap();
        // Insert a lock with an old timestamp directly
        conn.execute(
            "INSERT INTO task_locks (task_id, locked_at) VALUES ('old_task', 1000)",
            [],
        )
        .unwrap();
        cleanup_stale_locks(&conn, 7200);
        // Old lock gone
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM task_locks WHERE task_id='old_task'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
