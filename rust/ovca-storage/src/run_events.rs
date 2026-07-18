//! Strict, durable JSONL storage for [`RunEvent`] values.

use dashmap::DashMap;
use ovca_types::{RunEvent, RunId};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;

/// The fixed location of the run-event log beneath its caller-supplied root.
pub const RUN_EVENT_LOG_RELATIVE_PATH: &str = "run-events/events.jsonl";

/// A strict, durable log of typed run events.
///
/// Every instance uses one fixed path beneath the supplied root. Run IDs are
/// data only and are never interpreted as path components.
#[derive(Debug, Clone)]
pub struct RunEventLog {
    path: PathBuf,
}

/// Structured failures produced by [`RunEventLog`].
#[derive(Debug, Error)]
pub enum RunEventLogError {
    #[error("failed to serialize run event: {source}")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to create run-event log directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("run-event log write lock is poisoned for {path}")]
    WriteLockPoisoned { path: PathBuf },
    #[error("failed to open run-event log {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write run-event log {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to flush run-event log {path}: {source}")]
    Flush {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to sync run-event log {path}: {source}")]
    Sync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read run-event log {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed run-event JSONL at {path}, line {line}: {source}")]
    MalformedLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

fn write_locks() -> &'static DashMap<PathBuf, Arc<Mutex<()>>> {
    static LOCKS: OnceLock<DashMap<PathBuf, Arc<Mutex<()>>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

impl RunEventLog {
    /// Creates a log handle rooted at `root` without touching the filesystem.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            path: root.as_ref().join(RUN_EVENT_LOG_RELATIVE_PATH),
        }
    }

    /// Returns the fixed path used by this log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one event and durably syncs the file before returning success.
    pub fn append(&self, event: &RunEvent) -> Result<(), RunEventLogError> {
        let mut line =
            serde_json::to_vec(event).map_err(|source| RunEventLogError::Serialize { source })?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| RunEventLogError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let lock = write_locks()
            .entry(self.path.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock
            .lock()
            .map_err(|_| RunEventLogError::WriteLockPoisoned {
                path: self.path.clone(),
            })?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| RunEventLogError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&line)
            .map_err(|source| RunEventLogError::Write {
                path: self.path.clone(),
                source,
            })?;
        file.flush().map_err(|source| RunEventLogError::Flush {
            path: self.path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| RunEventLogError::Sync {
            path: self.path.clone(),
            source,
        })?;

        Ok(())
    }

    /// Loads every event in append order.
    ///
    /// A missing log is empty. Any non-empty malformed row fails the complete
    /// load and reports its one-based line number.
    pub fn load_all(&self) -> Result<Vec<RunEvent>, RunEventLogError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(RunEventLogError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        text.lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                serde_json::from_str(line).map_err(|source| RunEventLogError::MalformedLine {
                    path: self.path.clone(),
                    line: index + 1,
                    source,
                })
            })
            .collect()
    }

    /// Loads events for `run_id` while preserving their relative append order.
    pub fn load_run(&self, run_id: &RunId) -> Result<Vec<RunEvent>, RunEventLogError> {
        Ok(self
            .load_all()?
            .into_iter()
            .filter(|event| &event.run_id == run_id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use ovca_types::{ContractVersion, EventId, Role, RunEventPayload};
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn timestamp(second: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-01-02T03:04:{second:02}Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    fn event(run_id: &str, event_id: &str, sequence: u64, second: u32) -> RunEvent {
        RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from(event_id),
            run_id: RunId::from(run_id),
            sequence,
            previous_event_id: None,
            occurred_at: timestamp(second),
            producer_role: Role::Engineer,
            payload: RunEventPayload::NoteRecorded {
                message: format!("event {event_id}"),
            },
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn append_and_fresh_instance_reopen_preserve_order_and_typed_bytes() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            event("run-1", "event-1", 0, 5),
            event("run-1", "event-2", 1, 6),
        ];

        let log = RunEventLog::new(dir.path());
        for event in &events {
            log.append(event).unwrap();
        }
        drop(log);

        let reopened = RunEventLog::new(dir.path());
        let loaded = reopened.load_all().unwrap();
        assert_eq!(loaded, events);

        let expected_bytes: Vec<_> = events
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap())
            .collect();
        let loaded_bytes: Vec<_> = loaded
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap())
            .collect();
        assert_eq!(loaded_bytes, expected_bytes);
    }

    #[test]
    fn multiple_run_filter_preserves_relative_order() {
        let dir = TempDir::new().unwrap();
        let log = RunEventLog::new(dir.path());
        let events = vec![
            event("run-a", "a-0", 0, 5),
            event("run-b", "b-0", 0, 6),
            event("run-a", "a-1", 1, 7),
            event("run-b", "b-1", 1, 8),
        ];
        for event in &events {
            log.append(event).unwrap();
        }

        assert_eq!(log.load_all().unwrap(), events);
        assert_eq!(
            log.load_run(&RunId::from("run-a")).unwrap(),
            vec![events[0].clone(), events[2].clone()]
        );
    }

    #[test]
    fn malformed_non_empty_row_returns_line_aware_error() {
        let dir = TempDir::new().unwrap();
        let log = RunEventLog::new(dir.path());
        fs::create_dir_all(log.path().parent().unwrap()).unwrap();
        let valid = serde_json::to_string(&event("run-1", "event-1", 0, 5)).unwrap();
        fs::write(log.path(), format!("{valid}\n\nnot-json\n")).unwrap();

        let error = log.load_all().unwrap_err();
        match error {
            RunEventLogError::MalformedLine { path, line, .. } => {
                assert_eq!(path, log.path());
                assert_eq!(line, 3);
            }
            other => panic!("expected malformed-line error, got {other:?}"),
        }
    }

    #[test]
    fn traversal_like_run_id_cannot_change_fixed_log_path() {
        let dir = TempDir::new().unwrap();
        let log = RunEventLog::new(dir.path());
        let traversal_id = "../../outside/run";

        log.append(&event(traversal_id, "event-1", 0, 5)).unwrap();

        assert_eq!(
            log.path(),
            dir.path().join(RUN_EVENT_LOG_RELATIVE_PATH).as_path()
        );
        assert_eq!(log.load_run(&RunId::from(traversal_id)).unwrap().len(), 1);
    }
}
