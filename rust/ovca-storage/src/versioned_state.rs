use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// The database location below the root supplied to [`VersionedStateStore::new`].
pub const VERSIONED_STATE_DB_RELATIVE_PATH: &str = "state/versioned-state.sqlite3";

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CREATE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS versioned_state (
        entity_key TEXT PRIMARY KEY NOT NULL,
        payload BLOB NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 0)
    );
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedState {
    pub payload: Vec<u8>,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitializeOutcome {
    Initialized(VersionedState),
    Existing(VersionedState),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareAndSwapOutcome {
    Applied(VersionedState),
    Conflict(VersionedState),
}

#[derive(Debug, Error)]
pub enum VersionedStateError {
    #[error("failed to create versioned-state database directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open versioned-state database {path}")]
    OpenDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to configure versioned-state database")]
    ConfigureDatabase(#[source] rusqlite::Error),
    #[error("failed to initialize versioned-state schema")]
    InitializeSchema(#[source] rusqlite::Error),
    #[error("versioned-state operation {operation} failed")]
    Database {
        operation: &'static str,
        #[source]
        source: rusqlite::Error,
    },
    #[error("entity {entity_key:?} has a negative stored revision {revision}")]
    NegativeRevision { entity_key: String, revision: i64 },
    #[error("revision {revision} exceeds SQLite's nonnegative integer range")]
    RevisionOutOfRange { revision: u64 },
    #[error("revision {revision} cannot be incremented")]
    RevisionOverflow { revision: u64 },
    #[error("entity {entity_key:?} does not exist")]
    EntityNotFound { entity_key: String },
    #[error("entity {entity_key:?} disappeared during compare-and-swap")]
    ConcurrentRowRemoval { entity_key: String },
}

#[derive(Clone, Debug)]
pub struct VersionedStateStore {
    root: PathBuf,
}

impl VersionedStateStore {
    /// Records the root without opening the database or touching the filesystem.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn database_path(&self) -> PathBuf {
        self.root.join(VERSIONED_STATE_DB_RELATIVE_PATH)
    }

    pub fn initialize(
        &self,
        entity_key: &str,
        payload: impl AsRef<[u8]>,
    ) -> Result<InitializeOutcome, VersionedStateError> {
        let conn = self.open_connection()?;
        let payload = payload.as_ref();
        let inserted =
            conn.execute(
                "INSERT INTO versioned_state (entity_key, payload, revision) \
                 VALUES (?1, ?2, 0) ON CONFLICT(entity_key) DO NOTHING",
                params![entity_key, payload],
            )
            .map_err(|source| VersionedStateError::Database {
                operation: "initialize",
                source,
            })? == 1;
        if inserted {
            return Ok(InitializeOutcome::Initialized(VersionedState {
                payload: payload.to_vec(),
                revision: 0,
            }));
        }

        let state = load_from_connection(&conn, entity_key, "load existing initialized state")?
            .ok_or_else(|| VersionedStateError::EntityNotFound {
                entity_key: entity_key.to_owned(),
            })?;
        Ok(InitializeOutcome::Existing(state))
    }

    pub fn load(&self, entity_key: &str) -> Result<Option<VersionedState>, VersionedStateError> {
        let conn = self.open_connection()?;
        load_from_connection(&conn, entity_key, "load")
    }

    pub fn compare_and_swap(
        &self,
        entity_key: &str,
        expected_revision: u64,
        payload: impl AsRef<[u8]>,
    ) -> Result<CompareAndSwapOutcome, VersionedStateError> {
        let expected_revision = sqlite_revision(expected_revision)?;
        let mut conn = self.open_connection()?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| VersionedStateError::Database {
                operation: "begin immediate compare-and-swap transaction",
                source,
            })?;

        let current = load_from_connection(&transaction, entity_key, "load for compare-and-swap")?
            .ok_or_else(|| VersionedStateError::EntityNotFound {
                entity_key: entity_key.to_owned(),
            })?;
        if current.revision != expected_revision as u64 {
            transaction
                .commit()
                .map_err(|source| VersionedStateError::Database {
                    operation: "commit compare-and-swap conflict",
                    source,
                })?;
            return Ok(CompareAndSwapOutcome::Conflict(current));
        }

        let next_revision =
            current
                .revision
                .checked_add(1)
                .ok_or(VersionedStateError::RevisionOverflow {
                    revision: current.revision,
                })?;
        let next_sqlite_revision = sqlite_revision(next_revision)?;
        let updated = transaction
            .execute(
                "UPDATE versioned_state SET payload = ?1, revision = ?2 \
                 WHERE entity_key = ?3 AND revision = ?4",
                params![
                    payload.as_ref(),
                    next_sqlite_revision,
                    entity_key,
                    expected_revision
                ],
            )
            .map_err(|source| VersionedStateError::Database {
                operation: "apply compare-and-swap",
                source,
            })?;
        if updated != 1 {
            return Err(VersionedStateError::ConcurrentRowRemoval {
                entity_key: entity_key.to_owned(),
            });
        }
        transaction
            .commit()
            .map_err(|source| VersionedStateError::Database {
                operation: "commit compare-and-swap",
                source,
            })?;

        Ok(CompareAndSwapOutcome::Applied(VersionedState {
            payload: payload.as_ref().to_vec(),
            revision: next_revision,
        }))
    }

    fn open_connection(&self) -> Result<Connection, VersionedStateError> {
        let path = self.database_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| {
                VersionedStateError::CreateDirectory {
                    path: parent.to_owned(),
                    source,
                }
            })?;
        }
        let conn = Connection::open(&path).map_err(|source| VersionedStateError::OpenDatabase {
            path: path.clone(),
            source,
        })?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(VersionedStateError::ConfigureDatabase)?;
        conn.execute_batch(CREATE_SCHEMA)
            .map_err(VersionedStateError::InitializeSchema)?;
        Ok(conn)
    }
}

fn load_from_connection(
    conn: &Connection,
    entity_key: &str,
    operation: &'static str,
) -> Result<Option<VersionedState>, VersionedStateError> {
    let row = conn
        .query_row(
            "SELECT payload, revision FROM versioned_state WHERE entity_key = ?1",
            [entity_key],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|source| VersionedStateError::Database { operation, source })?;

    row.map(|(payload, revision)| {
        let revision =
            u64::try_from(revision).map_err(|_| VersionedStateError::NegativeRevision {
                entity_key: entity_key.to_owned(),
                revision,
            })?;
        Ok(VersionedState { payload, revision })
    })
    .transpose()
}

fn sqlite_revision(revision: u64) -> Result<i64, VersionedStateError> {
    i64::try_from(revision).map_err(|_| VersionedStateError::RevisionOutOfRange { revision })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn constructor_uses_fixed_path_without_filesystem_side_effects() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("missing-root");
        let store = VersionedStateStore::new(&root);

        assert_eq!(
            store.database_path(),
            root.join(VERSIONED_STATE_DB_RELATIVE_PATH)
        );
        assert!(!root.exists());
    }

    #[test]
    fn path_like_entity_key_remains_sql_data() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("store");
        let store = VersionedStateStore::new(&root);
        let entity_key = "../../escaped/entity";

        store.initialize(entity_key, b"payload").unwrap();

        assert_eq!(store.load(entity_key).unwrap().unwrap().payload, b"payload");
        assert!(!temp.path().join("escaped").exists());
        assert!(store.database_path().is_file());
    }

    #[test]
    fn initialize_and_load_preserve_payload_at_revision_zero() {
        let temp = TempDir::new().unwrap();
        let store = VersionedStateStore::new(temp.path());
        let expected = VersionedState {
            payload: vec![0, 1, 2, 255],
            revision: 0,
        };

        assert_eq!(
            store.initialize("entity", &expected.payload).unwrap(),
            InitializeOutcome::Initialized(expected.clone())
        );
        assert_eq!(store.load("entity").unwrap(), Some(expected));
    }

    #[test]
    fn duplicate_initialize_preserves_first_state() {
        let temp = TempDir::new().unwrap();
        let store = VersionedStateStore::new(temp.path());
        store.initialize("entity", b"first").unwrap();

        assert_eq!(
            store.initialize("entity", b"second").unwrap(),
            InitializeOutcome::Existing(VersionedState {
                payload: b"first".to_vec(),
                revision: 0,
            })
        );
    }

    #[test]
    fn compare_and_swap_increments_revision_once() {
        let temp = TempDir::new().unwrap();
        let store = VersionedStateStore::new(temp.path());
        store.initialize("entity", b"before").unwrap();

        let applied = store.compare_and_swap("entity", 0, b"after").unwrap();

        assert_eq!(
            applied,
            CompareAndSwapOutcome::Applied(VersionedState {
                payload: b"after".to_vec(),
                revision: 1,
            })
        );
        assert_eq!(
            store.load("entity").unwrap().unwrap(),
            VersionedState {
                payload: b"after".to_vec(),
                revision: 1,
            }
        );
    }

    #[test]
    fn stale_compare_and_swap_returns_current_state_without_mutation() {
        let temp = TempDir::new().unwrap();
        let store = VersionedStateStore::new(temp.path());
        store.initialize("entity", b"zero").unwrap();
        store.compare_and_swap("entity", 0, b"one").unwrap();

        assert_eq!(
            store.compare_and_swap("entity", 0, b"stale").unwrap(),
            CompareAndSwapOutcome::Conflict(VersionedState {
                payload: b"one".to_vec(),
                revision: 1,
            })
        );
        assert_eq!(store.load("entity").unwrap().unwrap().payload, b"one");
    }

    #[test]
    fn independent_stores_racing_same_revision_have_one_winner() {
        let temp = TempDir::new().unwrap();
        let first = VersionedStateStore::new(temp.path());
        let second = VersionedStateStore::new(temp.path());
        first.initialize("entity", b"initial").unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = [(first, b"first".to_vec()), (second, b"second".to_vec())]
            .into_iter()
            .map(|(store, payload)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.compare_and_swap("entity", 0, payload)
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CompareAndSwapOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CompareAndSwapOutcome::Conflict(_)))
                .count(),
            1
        );
        assert!(outcomes.iter().all(|outcome| match outcome {
            CompareAndSwapOutcome::Applied(state) | CompareAndSwapOutcome::Conflict(state) =>
                state.revision == 1,
        }));
    }

    #[test]
    fn reopening_store_preserves_exact_state() {
        let temp = TempDir::new().unwrap();
        let expected = VersionedState {
            payload: vec![7, 0, 8, 255],
            revision: 1,
        };
        {
            let store = VersionedStateStore::new(temp.path());
            store.initialize("entity", b"initial").unwrap();
            store
                .compare_and_swap("entity", 0, &expected.payload)
                .unwrap();
        }

        let reopened = VersionedStateStore::new(temp.path());
        assert_eq!(reopened.load("entity").unwrap(), Some(expected));
    }

    #[test]
    fn negative_stored_revision_is_rejected() {
        let temp = TempDir::new().unwrap();
        let store = VersionedStateStore::new(temp.path());
        store.initialize("entity", b"payload").unwrap();
        let conn = Connection::open(store.database_path()).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        conn.execute(
            "UPDATE versioned_state SET revision = -1 WHERE entity_key = 'entity'",
            [],
        )
        .unwrap();

        assert!(matches!(
            store.load("entity"),
            Err(VersionedStateError::NegativeRevision { revision: -1, .. })
        ));
    }
}
