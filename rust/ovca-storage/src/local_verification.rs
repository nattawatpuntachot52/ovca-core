//! Local, durable storage for verified-goal-runtime contracts.
//!
//! Immutable records are facts. Current and stale rows are projections supplied
//! by an authoritative caller; this module never infers current state.

pub mod operations;
pub mod targeted_rerun;
pub use operations::*;

use ovca_types::{
    verification_command_set_digest, verification_policy_digest,
    verification_selected_capability_set_digest, CapabilityDefinition, GoalId, RunId,
    SelectedCapability, TaskId, VerificationBundle, VerificationFingerprints,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

pub const LOCAL_VERIFICATION_DB_RELATIVE_PATH: &str = "local-verification/store.sqlite3";
pub const LOCAL_VERIFICATION_STORAGE_SCHEMA_VERSION: u32 = 1;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS local_verification_metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0)
);
INSERT OR IGNORE INTO local_verification_metadata (singleton, schema_version) VALUES (1, 1);

CREATE TABLE IF NOT EXISTS capability_records (
    capability_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    digest TEXT NOT NULL UNIQUE,
    canonical_json BLOB NOT NULL,
    PRIMARY KEY (capability_id, revision),
    UNIQUE (capability_id, revision, digest)
);
CREATE TABLE IF NOT EXISTS bundle_records (
    bundle_id TEXT PRIMARY KEY NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    canonical_json BLOB NOT NULL,
    UNIQUE (bundle_id, digest, run_id, goal_id, task_id)
);

CREATE TABLE IF NOT EXISTS capability_generations (
    capability_id TEXT PRIMARY KEY NOT NULL,
    max_generation INTEGER NOT NULL CHECK (max_generation > 0),
    state_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bundle_generations (
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    max_generation INTEGER NOT NULL CHECK (max_generation > 0),
    state_digest TEXT NOT NULL,
    PRIMARY KEY (run_id, goal_id, task_id)
);

CREATE TABLE IF NOT EXISTS capability_current (
    capability_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL,
    record_digest TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state_digest TEXT NOT NULL,
    FOREIGN KEY (capability_id, revision, record_digest)
        REFERENCES capability_records (capability_id, revision, digest)
);
CREATE TABLE IF NOT EXISTS bundle_current (
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    freshness_json BLOB NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state_digest TEXT NOT NULL,
    PRIMARY KEY (run_id, goal_id, task_id),
    FOREIGN KEY (bundle_id, record_digest, run_id, goal_id, task_id)
        REFERENCES bundle_records (bundle_id, digest, run_id, goal_id, task_id)
);
"#;

pub type LocalVerificationStoreResult<T> = Result<T, LocalVerificationStoreError>;

#[derive(Debug, Error)]
pub enum LocalVerificationStoreError {
    #[error("invalid local durable root {path}: {reason}")]
    InvalidRoot { path: PathBuf, reason: &'static str },
    #[error("failed to create local-verification database directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open local-verification database {path}")]
    OpenDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to configure local-verification database")]
    ConfigureDatabase(#[source] rusqlite::Error),
    #[error("failed to initialize local-verification schema")]
    InitializeSchema(#[source] rusqlite::Error),
    #[error("unsupported local-verification storage schema version {0}")]
    UnsupportedSchemaVersion(i64),
    #[error("database operation {operation} failed")]
    Database {
        operation: &'static str,
        #[source]
        source: rusqlite::Error,
    },
    #[error("{contract} contract is invalid: {detail}")]
    InvalidContract {
        contract: &'static str,
        detail: String,
    },
    #[error("failed to serialize {kind}: {source}")]
    Serialize {
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to deserialize {kind}: {source}")]
    Deserialize {
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid lowercase SHA-256 digest for {field}: {digest}")]
    InvalidDigest { field: &'static str, digest: String },
    #[error("immutable {kind} identity {identity} already has different bytes")]
    ImmutableConflict {
        kind: &'static str,
        identity: String,
    },
    #[error("corrupt {kind} record {identity}: {reason}")]
    CorruptRecord {
        kind: &'static str,
        identity: String,
        reason: &'static str,
    },
    #[error("missing {kind} record {identity}")]
    MissingRecord {
        kind: &'static str,
        identity: String,
    },
    #[error("projection binding does not match immutable record: {0}")]
    BindingMismatch(String),
    #[error("CAS generation {0} cannot be represented by SQLite")]
    GenerationOutOfRange(u64),
    #[error("CAS generation {0} cannot be incremented")]
    GenerationOverflow(u64),
    #[error("stale projection requires at least one closed stale cause")]
    EmptyStaleCauses,
    #[error("a stale projection cannot select the same immutable verification bundle again")]
    StaleRevivalRequiresDifferentBundle,
    #[error("authoritative projection selection is invalid: {0}")]
    InvalidProjectionSelection(String),
    #[error("authoritative generation {selected} is below durable generation {durable} for {key}")]
    NonMonotonicGeneration {
        key: String,
        selected: u64,
        durable: u64,
    },
    #[error("CAS write lost its validated projection token for {0}")]
    CasWriteLost(String),
    #[error("injected transactional failure")]
    InjectedFailure,
    #[error("capability seed policy rejected the request: {0}")]
    CapabilitySeedPolicy(String),
    #[error("local-verification archive operation {operation} failed")]
    ArchiveIo {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("local-verification archive is invalid: {0}")]
    InvalidArchive(String),
    #[error("local-verification archive exceeds its bounded size")]
    ArchiveTooLarge,
    #[error(
        "recovery generation {selected} is not newer than durable generation {durable} for {key}"
    )]
    RecoveryRequiresFreshGeneration {
        key: String,
        selected: u64,
        durable: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome<T> {
    Inserted(T),
    ExistingIdentical(T),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome<T> {
    Applied(T),
    Conflict(Option<T>),
    Unchanged(T),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasToken {
    pub generation: u64,
    pub state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub definition: CapabilityDefinition,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRecord {
    pub bundle: VerificationBundle,
    pub digest: String,
    pub logical_reference: String,
}

/// One integrity-checked current capability row and its immutable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionAdmissionCapability {
    pub current: CapabilityCurrent,
    pub record: CapabilityRecord,
}

/// One integrity-checked current evidence row and its immutable bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionAdmissionBundle {
    pub current: EvidenceCurrent,
    pub record: BundleRecord,
}

/// The complete current capability projection plus the exact requested evidence set.
///
/// Values are owned so callers cannot retain a SQLite handle. The corresponding
/// `BEGIN IMMEDIATE` writer reservation remains live only while the callback in
/// [`EvidenceBank::with_completion_admission_lease`] is executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionAdmissionSnapshot {
    pub capabilities: Vec<CompletionAdmissionCapability>,
    pub bundles: Vec<CompletionAdmissionBundle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleCause {
    Behavior,
    CapabilitySet,
    CapabilityDefinition,
    Command,
    Policy,
    Source,
    Environment,
    Integrity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceFreshness {
    Current,
    Stale { causes: BTreeSet<StaleCause> },
}

impl EvidenceFreshness {
    fn validate(&self) -> LocalVerificationStoreResult<()> {
        if matches!(self, Self::Stale { causes } if causes.is_empty()) {
            return Err(LocalVerificationStoreError::EmptyStaleCauses);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCurrent {
    pub capability_id: String,
    pub revision: u64,
    pub record_digest: String,
    pub token: CasToken,
}

impl CapabilityCurrent {
    pub fn new(
        capability_id: impl Into<String>,
        revision: u64,
        record_digest: impl Into<String>,
        generation: u64,
    ) -> LocalVerificationStoreResult<Self> {
        let mut value = Self {
            capability_id: capability_id.into(),
            revision,
            record_digest: record_digest.into(),
            token: CasToken {
                generation,
                state_digest: String::new(),
            },
        };
        value.token.state_digest = capability_state_digest(&value)?;
        Ok(value)
    }

    pub fn validate_state_digest(&self) -> LocalVerificationStoreResult<()> {
        validate_digest(&self.record_digest, "capability record digest")?;
        validate_generation(self.token.generation)?;
        validate_digest(&self.token.state_digest, "capability state digest")?;
        if capability_state_digest(self)? != self.token.state_digest {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                format!("bad capability state digest for {}", self.capability_id),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKey {
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCurrent {
    pub key: EvidenceKey,
    pub bundle_id: String,
    pub record_digest: String,
    pub freshness: EvidenceFreshness,
    pub token: CasToken,
}

impl EvidenceCurrent {
    pub fn new(
        key: EvidenceKey,
        bundle_id: impl Into<String>,
        record_digest: impl Into<String>,
        freshness: EvidenceFreshness,
        generation: u64,
    ) -> LocalVerificationStoreResult<Self> {
        freshness.validate()?;
        let mut value = Self {
            key,
            bundle_id: bundle_id.into(),
            record_digest: record_digest.into(),
            freshness,
            token: CasToken {
                generation,
                state_digest: String::new(),
            },
        };
        value.token.state_digest = evidence_state_digest(&value)?;
        Ok(value)
    }

    pub fn validate_state_digest(&self) -> LocalVerificationStoreResult<()> {
        self.freshness.validate()?;
        validate_digest(&self.record_digest, "bundle record digest")?;
        validate_generation(self.token.generation)?;
        validate_digest(&self.token.state_digest, "bundle state digest")?;
        if evidence_state_digest(self)? != self.token.state_digest {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                format!(
                    "bad bundle state digest for {}",
                    evidence_key_label(&self.key)
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionRebuildIntent {
    Replace,
    Genesis,
    Reset,
}

/// Caller-supplied projection assertions used only for deterministic rebuild.
///
/// This store validates the selection and referenced immutable rows but never
/// derives authority from existing mutable projections, insertion order, or
/// record metadata. The canonical RunEventLog remains the source of history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeProjectionSelection {
    pub intent: ProjectionRebuildIntent,
    pub capabilities: Vec<CapabilityCurrent>,
    pub bundles: Vec<EvidenceCurrent>,
    pub selection_set_digest: String,
}

impl AuthoritativeProjectionSelection {
    pub fn new(
        intent: ProjectionRebuildIntent,
        capabilities: Vec<CapabilityCurrent>,
        bundles: Vec<EvidenceCurrent>,
    ) -> LocalVerificationStoreResult<Self> {
        let mut value = Self {
            intent,
            capabilities,
            bundles,
            selection_set_digest: String::new(),
        };
        value.validate_shape()?;
        value.selection_set_digest = projection_selection_digest(&value)?;
        Ok(value)
    }

    pub fn validate(&self) -> LocalVerificationStoreResult<()> {
        self.validate_shape()?;
        validate_digest(&self.selection_set_digest, "selection set digest")?;
        if projection_selection_digest(self)? != self.selection_set_digest {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                "selection set digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> LocalVerificationStoreResult<()> {
        let empty = self.capabilities.is_empty() && self.bundles.is_empty();
        if empty
            && !matches!(
                self.intent,
                ProjectionRebuildIntent::Genesis | ProjectionRebuildIntent::Reset
            )
        {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                "empty rebuild requires explicit genesis or reset intent".to_owned(),
            ));
        }
        if !empty && self.intent != ProjectionRebuildIntent::Replace {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                "nonempty rebuild requires replace intent".to_owned(),
            ));
        }
        for value in &self.capabilities {
            value.validate_state_digest()?;
        }
        for pair in self.capabilities.windows(2) {
            if pair[0].capability_id >= pair[1].capability_id {
                return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                    "capability selections must be strictly sorted and unique".to_owned(),
                ));
            }
        }
        for value in &self.bundles {
            value.validate_state_digest()?;
        }
        for pair in self.bundles.windows(2) {
            if pair[0].key >= pair[1].key {
                return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                    "bundle selections must be strictly sorted and unique".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionExpectation {
    Absent,
    Token(CasToken),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishAndCasOutcome {
    pub publication: PublishOutcome<BundleRecord>,
    pub projection: CasOutcome<EvidenceCurrent>,
}

#[derive(Clone, Debug)]
pub struct CapabilityRegistry {
    database_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct EvidenceBank {
    database_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct LocalVerificationStore {
    database_path: PathBuf,
}

macro_rules! store_constructor {
    ($type:ty) => {
        impl $type {
            pub fn try_new(root: impl AsRef<Path>) -> LocalVerificationStoreResult<Self> {
                Ok(Self {
                    database_path: validated_database_path(root.as_ref())?,
                })
            }

            pub fn database_path(&self) -> &Path {
                &self.database_path
            }
        }
    };
}

store_constructor!(CapabilityRegistry);
store_constructor!(EvidenceBank);
store_constructor!(LocalVerificationStore);

impl LocalVerificationStore {
    pub fn capability_registry(&self) -> CapabilityRegistry {
        CapabilityRegistry {
            database_path: self.database_path.clone(),
        }
    }

    pub fn evidence_bank(&self) -> EvidenceBank {
        EvidenceBank {
            database_path: self.database_path.clone(),
        }
    }

    pub fn rebuild_projections(
        &self,
        selection: &AuthoritativeProjectionSelection,
    ) -> LocalVerificationStoreResult<()> {
        selection.validate()?;
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin projection rebuild")?;

        for current in &selection.capabilities {
            validate_capability_selection(&transaction, current)?;
            ensure_monotonic_capability_generation(&transaction, current)?;
        }
        for current in &selection.bundles {
            validate_bundle_selection(&transaction, current)?;
            ensure_monotonic_bundle_generation(&transaction, current)?;
        }

        transaction
            .execute("DELETE FROM capability_current", [])
            .map_err(|source| db("clear capability projection", source))?;
        transaction
            .execute("DELETE FROM bundle_current", [])
            .map_err(|source| db("clear bundle projection", source))?;

        for current in &selection.capabilities {
            write_capability_current(&transaction, current)?;
            persist_capability_generation(&transaction, current)?;
        }
        for current in &selection.bundles {
            write_bundle_current(&transaction, current)?;
            persist_bundle_generation(&transaction, current)?;
        }

        transaction
            .commit()
            .map_err(|source| db("commit projection rebuild", source))
    }
}

impl CapabilityRegistry {
    pub fn publish(
        &self,
        definition: &CapabilityDefinition,
    ) -> LocalVerificationStoreResult<PublishOutcome<CapabilityRecord>> {
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin capability publication")?;
        let outcome = publish_capability_tx(&transaction, definition)?;
        transaction
            .commit()
            .map_err(|source| db("commit capability publication", source))?;
        Ok(outcome)
    }

    pub fn load(
        &self,
        capability_id: &str,
        revision: u64,
    ) -> LocalVerificationStoreResult<Option<CapabilityRecord>> {
        let connection = open_connection(&self.database_path)?;
        load_capability(&connection, capability_id, revision)
    }

    pub fn load_current(
        &self,
        capability_id: &str,
    ) -> LocalVerificationStoreResult<Option<CapabilityCurrent>> {
        let connection = open_connection(&self.database_path)?;
        load_capability_current(&connection, capability_id)
    }

    pub fn compare_and_swap_current(
        &self,
        capability_id: &str,
        revision: u64,
        record_digest: &str,
        expectation: &ProjectionExpectation,
    ) -> LocalVerificationStoreResult<CasOutcome<CapabilityCurrent>> {
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin capability CAS")?;
        let record = load_capability(&transaction, capability_id, revision)?.ok_or_else(|| {
            LocalVerificationStoreError::MissingRecord {
                kind: "capability",
                identity: format!("{capability_id}@{revision}"),
            }
        })?;
        if record.digest != record_digest {
            return Err(LocalVerificationStoreError::BindingMismatch(format!(
                "capability {capability_id}@{revision} digest"
            )));
        }
        let current = load_capability_current(&transaction, capability_id)?;
        if !expectation_matches(expectation, current.as_ref().map(|value| &value.token)) {
            transaction
                .commit()
                .map_err(|source| db("commit capability CAS conflict", source))?;
            return Ok(CasOutcome::Conflict(current));
        }
        let generation = next_capability_generation(&transaction, capability_id)?;
        let next = CapabilityCurrent::new(capability_id, revision, record_digest, generation)?;
        write_capability_current_cas(&transaction, &next, expectation)?;
        persist_capability_generation(&transaction, &next)?;
        transaction
            .commit()
            .map_err(|source| db("commit capability CAS", source))?;
        Ok(CasOutcome::Applied(next))
    }
}

impl EvidenceBank {
    /// Reads authoritative completion inputs under one SQLite writer reservation.
    ///
    /// `keys` must be nonempty, strictly sorted, and unique. The complete
    /// capability-current projection and the exact bundle-current rows are
    /// revalidated against their immutable records and generation allocators in
    /// one `BEGIN IMMEDIATE` transaction. The reservation is held through the
    /// callback, allowing a caller to perform its final durable JSONL append
    /// before current evidence can be changed by another writer.
    ///
    /// SQLite and the caller's JSONL log are separate durable media. In
    /// particular, a commit/release error after a callback has synced JSONL is
    /// ambiguous and must be recovered by reloading/replaying the event log
    /// before retrying.
    pub fn with_completion_admission_lease<T, E, F>(
        &self,
        keys: &[EvidenceKey],
        callback: F,
    ) -> Result<T, E>
    where
        E: From<LocalVerificationStoreError>,
        F: FnOnce(&CompletionAdmissionSnapshot) -> Result<T, E>,
    {
        validate_completion_admission_keys(keys).map_err(E::from)?;

        let mut connection = open_connection(&self.database_path).map_err(E::from)?;
        let transaction = begin_immediate(&mut connection, "begin completion admission lease")
            .map_err(E::from)?;

        let capability_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT capability_id FROM capability_current \
                     ORDER BY capability_id COLLATE BINARY ASC",
                )
                .map_err(|source| E::from(db("prepare completion capability snapshot", source)))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|source| E::from(db("query completion capability snapshot", source)))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row.map_err(|source| {
                    E::from(db("read completion capability snapshot row", source))
                })?);
            }
            ids
        };

        let mut capabilities = Vec::with_capacity(capability_ids.len());
        for capability_id in capability_ids {
            let current = load_capability_current(&transaction, &capability_id)
                .map_err(E::from)?
                .ok_or_else(|| {
                    E::from(LocalVerificationStoreError::MissingRecord {
                        kind: "capability projection",
                        identity: capability_id.clone(),
                    })
                })?;
            let record = load_capability(&transaction, &capability_id, current.revision)
                .map_err(E::from)?
                .ok_or_else(|| {
                    E::from(LocalVerificationStoreError::MissingRecord {
                        kind: "capability",
                        identity: format!("{capability_id}@{}", current.revision),
                    })
                })?;
            if record.digest != current.record_digest {
                return Err(E::from(LocalVerificationStoreError::BindingMismatch(
                    format!("current capability {capability_id}@{}", current.revision),
                )));
            }
            capabilities.push(CompletionAdmissionCapability { current, record });
        }

        let mut bundles = Vec::with_capacity(keys.len());
        for key in keys {
            let current = load_bundle_current(&transaction, key)
                .map_err(E::from)?
                .ok_or_else(|| {
                    E::from(LocalVerificationStoreError::MissingRecord {
                        kind: "bundle projection",
                        identity: evidence_key_label(key),
                    })
                })?;
            if current.freshness != EvidenceFreshness::Current {
                return Err(E::from(
                    LocalVerificationStoreError::InvalidProjectionSelection(format!(
                        "completion evidence is not current for {}",
                        evidence_key_label(key)
                    )),
                ));
            }
            let record = load_bundle_by_digest(&transaction, &current.record_digest)
                .map_err(E::from)?
                .ok_or_else(|| {
                    E::from(LocalVerificationStoreError::MissingRecord {
                        kind: "bundle",
                        identity: current.record_digest.clone(),
                    })
                })?;
            if record.digest != current.record_digest
                || record.bundle.bundle_id != current.bundle_id
                || record.bundle.run_id != current.key.run_id
                || record.bundle.goal_id != current.key.goal_id
                || record.bundle.task_id != current.key.task_id
            {
                return Err(E::from(LocalVerificationStoreError::BindingMismatch(
                    evidence_key_label(key),
                )));
            }
            bundles.push(CompletionAdmissionBundle { current, record });
        }

        let snapshot = CompletionAdmissionSnapshot {
            capabilities,
            bundles,
        };
        let result = callback(&snapshot)?;
        transaction
            .commit()
            .map_err(|source| E::from(db("commit completion admission lease", source)))?;
        Ok(result)
    }

    pub fn publish_bundle(
        &self,
        bundle: &VerificationBundle,
    ) -> LocalVerificationStoreResult<PublishOutcome<BundleRecord>> {
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin bundle publication")?;
        let outcome = publish_bundle_tx(&transaction, bundle)?;
        transaction
            .commit()
            .map_err(|source| db("commit bundle publication", source))?;
        Ok(outcome)
    }

    pub fn load_bundle(&self, digest: &str) -> LocalVerificationStoreResult<Option<BundleRecord>> {
        validate_digest(digest, "bundle digest")?;
        let connection = open_connection(&self.database_path)?;
        load_bundle_by_digest(&connection, digest)
    }

    pub fn load_current(
        &self,
        key: &EvidenceKey,
    ) -> LocalVerificationStoreResult<Option<EvidenceCurrent>> {
        let connection = open_connection(&self.database_path)?;
        load_bundle_current(&connection, key)
    }

    pub fn compare_and_swap_current(
        &self,
        record_digest: &str,
        expectation: &ProjectionExpectation,
    ) -> LocalVerificationStoreResult<CasOutcome<EvidenceCurrent>> {
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin bundle CAS")?;
        let record = load_bundle_by_digest(&transaction, record_digest)?.ok_or_else(|| {
            LocalVerificationStoreError::MissingRecord {
                kind: "bundle",
                identity: record_digest.to_owned(),
            }
        })?;
        let outcome = apply_bundle_cas(
            &transaction,
            &record,
            expectation,
            EvidenceFreshness::Current,
        )?;
        transaction
            .commit()
            .map_err(|source| db("commit bundle CAS", source))?;
        Ok(outcome)
    }

    pub fn publish_bundle_and_cas(
        &self,
        bundle: &VerificationBundle,
        expectation: &ProjectionExpectation,
    ) -> LocalVerificationStoreResult<PublishAndCasOutcome> {
        self.publish_bundle_and_cas_inner(bundle, expectation, false)
    }

    fn publish_bundle_and_cas_inner(
        &self,
        bundle: &VerificationBundle,
        expectation: &ProjectionExpectation,
        fail_after_publish: bool,
    ) -> LocalVerificationStoreResult<PublishAndCasOutcome> {
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin atomic bundle publish and CAS")?;
        let publication = publish_bundle_tx(&transaction, bundle)?;
        if fail_after_publish {
            return Err(LocalVerificationStoreError::InjectedFailure);
        }
        let record = match &publication {
            PublishOutcome::Inserted(record) | PublishOutcome::ExistingIdentical(record) => record,
        };
        let projection = apply_bundle_cas(
            &transaction,
            record,
            expectation,
            EvidenceFreshness::Current,
        )?;
        transaction
            .commit()
            .map_err(|source| db("commit atomic bundle publish and CAS", source))?;
        Ok(PublishAndCasOutcome {
            publication,
            projection,
        })
    }

    pub fn mark_stale(
        &self,
        key: &EvidenceKey,
        expected: &CasToken,
        causes: BTreeSet<StaleCause>,
    ) -> LocalVerificationStoreResult<CasOutcome<EvidenceCurrent>> {
        if causes.is_empty() {
            return Err(LocalVerificationStoreError::EmptyStaleCauses);
        }
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin stale transition")?;
        let Some(current) = load_bundle_current(&transaction, key)? else {
            transaction
                .commit()
                .map_err(|source| db("commit missing stale conflict", source))?;
            return Ok(CasOutcome::Conflict(None));
        };
        if &current.token != expected {
            transaction
                .commit()
                .map_err(|source| db("commit stale CAS conflict", source))?;
            return Ok(CasOutcome::Conflict(Some(current)));
        }
        let merged = match &current.freshness {
            EvidenceFreshness::Current => causes,
            EvidenceFreshness::Stale { causes: existing } => {
                existing.union(&causes).copied().collect()
            }
        };
        if matches!(&current.freshness, EvidenceFreshness::Stale { causes } if causes == &merged) {
            transaction
                .commit()
                .map_err(|source| db("commit unchanged stale transition", source))?;
            return Ok(CasOutcome::Unchanged(current));
        }
        let generation = next_bundle_generation(&transaction, key)?;
        let next = EvidenceCurrent::new(
            key.clone(),
            current.bundle_id,
            current.record_digest,
            EvidenceFreshness::Stale { causes: merged },
            generation,
        )?;
        write_bundle_current_cas(
            &transaction,
            &next,
            &ProjectionExpectation::Token(expected.clone()),
        )?;
        persist_bundle_generation(&transaction, &next)?;
        transaction
            .commit()
            .map_err(|source| db("commit stale transition", source))?;
        Ok(CasOutcome::Applied(next))
    }

    pub fn mark_stale_if_fingerprints_changed(
        &self,
        key: &EvidenceKey,
        expected_token: &CasToken,
        expected: &VerificationFingerprints,
    ) -> LocalVerificationStoreResult<CasOutcome<EvidenceCurrent>> {
        let Some(current) = self.load_current(key)? else {
            return Ok(CasOutcome::Conflict(None));
        };
        if &current.token != expected_token {
            return Ok(CasOutcome::Conflict(Some(current)));
        }
        let record = self.load_bundle(&current.record_digest)?.ok_or_else(|| {
            LocalVerificationStoreError::MissingRecord {
                kind: "bundle",
                identity: current.record_digest.clone(),
            }
        })?;
        let actual = &record.bundle.fingerprints;
        let mut causes = BTreeSet::new();
        if actual.behavior_contract != expected.behavior_contract {
            causes.insert(StaleCause::Behavior);
        }
        if actual.capability_set != expected.capability_set {
            causes.insert(StaleCause::CapabilitySet);
        }
        if actual.command != expected.command {
            causes.insert(StaleCause::Command);
        }
        if actual.policy != expected.policy {
            causes.insert(StaleCause::Policy);
        }
        if actual.source_pre != expected.source_pre || actual.source_post != expected.source_post {
            causes.insert(StaleCause::Source);
        }
        if actual.environment != expected.environment {
            causes.insert(StaleCause::Environment);
        }
        if causes.is_empty() {
            return Ok(CasOutcome::Unchanged(current));
        }
        self.mark_stale(key, expected_token, causes)
    }
}

fn validate_completion_admission_keys(keys: &[EvidenceKey]) -> LocalVerificationStoreResult<()> {
    if keys.is_empty() {
        return Err(LocalVerificationStoreError::InvalidContract {
            contract: "completion_admission_keys",
            detail: "at least one evidence key is required".to_owned(),
        });
    }
    for key in keys {
        if key.run_id.as_str().trim().is_empty()
            || key.goal_id.as_str().trim().is_empty()
            || key.task_id.as_str().trim().is_empty()
        {
            return Err(LocalVerificationStoreError::InvalidContract {
                contract: "completion_admission_keys",
                detail: "run, goal, and task IDs must be nonempty".to_owned(),
            });
        }
    }
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(LocalVerificationStoreError::InvalidContract {
            contract: "completion_admission_keys",
            detail: "evidence keys must be strictly sorted and unique".to_owned(),
        });
    }
    Ok(())
}

fn validated_database_path(root: &Path) -> LocalVerificationStoreResult<PathBuf> {
    let text = root.as_os_str().to_string_lossy();
    if !root.is_absolute() {
        return Err(LocalVerificationStoreError::InvalidRoot {
            path: root.to_path_buf(),
            reason: "root must be absolute",
        });
    }
    if text.starts_with("\\\\") || text.starts_with("//") {
        return Err(LocalVerificationStoreError::InvalidRoot {
            path: root.to_path_buf(),
            reason: "UNC roots are forbidden",
        });
    }
    if text.contains("://") || text.to_ascii_lowercase().starts_with("file:") {
        return Err(LocalVerificationStoreError::InvalidRoot {
            path: root.to_path_buf(),
            reason: "URL roots are forbidden",
        });
    }
    Ok(root.join(LOCAL_VERIFICATION_DB_RELATIVE_PATH))
}

fn open_connection(path: &Path) -> LocalVerificationStoreResult<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| {
            LocalVerificationStoreError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    }
    let connection =
        Connection::open(path).map_err(|source| LocalVerificationStoreError::OpenDatabase {
            path: path.to_path_buf(),
            source,
        })?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(LocalVerificationStoreError::ConfigureDatabase)?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .map_err(LocalVerificationStoreError::ConfigureDatabase)?;
    connection
        .execute_batch(CREATE_SCHEMA)
        .map_err(LocalVerificationStoreError::InitializeSchema)?;
    let version: i64 = connection
        .query_row(
            "SELECT schema_version FROM local_verification_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(LocalVerificationStoreError::InitializeSchema)?;
    if version != i64::from(LOCAL_VERIFICATION_STORAGE_SCHEMA_VERSION) {
        return Err(LocalVerificationStoreError::UnsupportedSchemaVersion(
            version,
        ));
    }
    Ok(connection)
}

fn begin_immediate<'a>(
    connection: &'a mut Connection,
    operation: &'static str,
) -> LocalVerificationStoreResult<Transaction<'a>> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| db(operation, source))
}

fn db(operation: &'static str, source: rusqlite::Error) -> LocalVerificationStoreError {
    LocalVerificationStoreError::Database { operation, source }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_digest(digest: &str, field: &'static str) -> LocalVerificationStoreResult<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LocalVerificationStoreError::InvalidDigest {
            field,
            digest: digest.to_owned(),
        });
    }
    Ok(())
}

fn validate_generation(generation: u64) -> LocalVerificationStoreResult<i64> {
    if generation == 0 {
        return Err(LocalVerificationStoreError::GenerationOutOfRange(
            generation,
        ));
    }
    i64::try_from(generation)
        .map_err(|_| LocalVerificationStoreError::GenerationOutOfRange(generation))
}

fn stored_generation(value: i64) -> LocalVerificationStoreResult<u64> {
    u64::try_from(value).map_err(|_| LocalVerificationStoreError::GenerationOutOfRange(0))
}

fn canonical_capability(
    definition: &CapabilityDefinition,
) -> LocalVerificationStoreResult<Vec<u8>> {
    definition.canonical_json_bytes().map_err(|error| {
        LocalVerificationStoreError::InvalidContract {
            contract: "capability_definition",
            detail: error.to_string(),
        }
    })
}

fn canonical_bundle(bundle: &VerificationBundle) -> LocalVerificationStoreResult<Vec<u8>> {
    bundle
        .canonical_json_bytes()
        .map_err(|error| LocalVerificationStoreError::InvalidContract {
            contract: "verification_bundle",
            detail: error.to_string(),
        })
}

fn publish_capability_tx(
    transaction: &Transaction<'_>,
    definition: &CapabilityDefinition,
) -> LocalVerificationStoreResult<PublishOutcome<CapabilityRecord>> {
    let canonical = canonical_capability(definition)?;
    let digest = sha256_hex(&canonical);
    if let Some(existing) =
        load_capability(transaction, &definition.capability_id, definition.revision)?
    {
        if existing.digest == digest && canonical_capability(&existing.definition)? == canonical {
            return Ok(PublishOutcome::ExistingIdentical(existing));
        }
        return Err(LocalVerificationStoreError::ImmutableConflict {
            kind: "capability",
            identity: format!("{}@{}", definition.capability_id, definition.revision),
        });
    }
    let digest_owner: Option<(String, i64)> = transaction
        .query_row(
            "SELECT capability_id, revision FROM capability_records WHERE digest=?1",
            [&digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| db("check capability digest owner", source))?;
    if digest_owner.is_some() {
        return Err(LocalVerificationStoreError::ImmutableConflict {
            kind: "capability_digest",
            identity: digest,
        });
    }
    transaction
        .execute(
            "INSERT INTO capability_records (capability_id, revision, digest, canonical_json) VALUES (?1, ?2, ?3, ?4)",
            params![definition.capability_id, sqlite_u64(definition.revision)?, digest, canonical],
        )
        .map_err(|source| db("insert capability record", source))?;
    Ok(PublishOutcome::Inserted(CapabilityRecord {
        definition: definition.clone(),
        digest,
    }))
}

fn publish_bundle_tx(
    transaction: &Transaction<'_>,
    bundle: &VerificationBundle,
) -> LocalVerificationStoreResult<PublishOutcome<BundleRecord>> {
    let canonical = canonical_bundle(bundle)?;
    let digest = sha256_hex(&canonical);
    if let Some(existing) = load_bundle_by_id(transaction, &bundle.bundle_id)? {
        if existing.digest == digest && canonical_bundle(&existing.bundle)? == canonical {
            return Ok(PublishOutcome::ExistingIdentical(existing));
        }
        return Err(LocalVerificationStoreError::ImmutableConflict {
            kind: "bundle",
            identity: bundle.bundle_id.clone(),
        });
    }
    let digest_owner: Option<String> = transaction
        .query_row(
            "SELECT bundle_id FROM bundle_records WHERE digest=?1",
            [&digest],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| db("check bundle digest owner", source))?;
    if digest_owner.is_some() {
        return Err(LocalVerificationStoreError::ImmutableConflict {
            kind: "bundle_digest",
            identity: digest,
        });
    }
    transaction
        .execute(
            "INSERT INTO bundle_records (bundle_id, digest, run_id, goal_id, task_id, canonical_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![bundle.bundle_id, digest, bundle.run_id.as_str(), bundle.goal_id.as_str(), bundle.task_id.as_str(), canonical],
        )
        .map_err(|source| db("insert bundle record", source))?;
    Ok(PublishOutcome::Inserted(bundle_record(
        bundle.clone(),
        digest,
    )))
}

fn load_capability(
    connection: &Connection,
    capability_id: &str,
    revision: u64,
) -> LocalVerificationStoreResult<Option<CapabilityRecord>> {
    let row: Option<(String, i64, String, Vec<u8>)> = connection
        .query_row(
            "SELECT capability_id, revision, digest, canonical_json FROM capability_records WHERE capability_id=?1 AND revision=?2",
            params![capability_id, sqlite_u64(revision)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|source| db("load capability record", source))?;
    row.map(|(stored_id, stored_revision, digest, bytes)| {
        let identity = format!("{stored_id}@{stored_revision}");
        validate_digest(&digest, "stored capability digest")?;
        if sha256_hex(&bytes) != digest {
            return Err(corrupt("capability", identity, "checksum mismatch"));
        }
        let definition: CapabilityDefinition =
            serde_json::from_slice(&bytes).map_err(|source| {
                LocalVerificationStoreError::Deserialize {
                    kind: "capability record",
                    source,
                }
            })?;
        let canonical = canonical_capability(&definition)?;
        if canonical != bytes {
            return Err(corrupt("capability", identity, "noncanonical bytes"));
        }
        if definition.capability_id != stored_id
            || definition.revision != stored_generation(stored_revision)?
            || definition.capability_id != capability_id
            || definition.revision != revision
        {
            return Err(corrupt("capability", identity, "identity-column mismatch"));
        }
        Ok(CapabilityRecord { definition, digest })
    })
    .transpose()
}

fn load_bundle_by_id(
    connection: &Connection,
    bundle_id: &str,
) -> LocalVerificationStoreResult<Option<BundleRecord>> {
    load_bundle_row(connection, "bundle_id=?1", bundle_id)
}

fn load_bundle_by_digest(
    connection: &Connection,
    digest: &str,
) -> LocalVerificationStoreResult<Option<BundleRecord>> {
    validate_digest(digest, "bundle digest")?;
    load_bundle_row(connection, "digest=?1", digest)
}

fn load_bundle_row(
    connection: &Connection,
    predicate: &'static str,
    value: &str,
) -> LocalVerificationStoreResult<Option<BundleRecord>> {
    let sql = format!("SELECT bundle_id, digest, run_id, goal_id, task_id, canonical_json FROM bundle_records WHERE {predicate}");
    let row: Option<(String, String, String, String, String, Vec<u8>)> = connection
        .query_row(&sql, [value], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()
        .map_err(|source| db("load bundle record", source))?;
    row.map(|(bundle_id, digest, run_id, goal_id, task_id, bytes)| {
        validate_digest(&digest, "stored bundle digest")?;
        if sha256_hex(&bytes) != digest {
            return Err(corrupt("bundle", bundle_id, "checksum mismatch"));
        }
        let bundle: VerificationBundle = serde_json::from_slice(&bytes).map_err(|source| {
            LocalVerificationStoreError::Deserialize {
                kind: "bundle record",
                source,
            }
        })?;
        let canonical = canonical_bundle(&bundle)?;
        if canonical != bytes {
            return Err(corrupt("bundle", bundle_id, "noncanonical bytes"));
        }
        if bundle.bundle_id != bundle_id
            || bundle.run_id.as_str() != run_id
            || bundle.goal_id.as_str() != goal_id
            || bundle.task_id.as_str() != task_id
        {
            return Err(corrupt("bundle", bundle_id, "identity-column mismatch"));
        }
        Ok(bundle_record(bundle, digest))
    })
    .transpose()
}

fn bundle_record(bundle: VerificationBundle, digest: String) -> BundleRecord {
    BundleRecord {
        bundle,
        logical_reference: format!("verification-bundles/sha256/{digest}"),
        digest,
    }
}

fn corrupt(
    kind: &'static str,
    identity: impl Into<String>,
    reason: &'static str,
) -> LocalVerificationStoreError {
    LocalVerificationStoreError::CorruptRecord {
        kind,
        identity: identity.into(),
        reason,
    }
}

fn load_capability_current(
    connection: &Connection,
    capability_id: &str,
) -> LocalVerificationStoreResult<Option<CapabilityCurrent>> {
    let row: Option<(i64, String, i64, String)> = connection
        .query_row(
            "SELECT revision, record_digest, generation, state_digest FROM capability_current WHERE capability_id=?1",
            [capability_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|source| db("load capability current", source))?;
    row.map(|(revision, record_digest, generation, state_digest)| {
        let current = CapabilityCurrent {
            capability_id: capability_id.to_owned(),
            revision: stored_generation(revision)?,
            record_digest,
            token: CasToken {
                generation: stored_generation(generation)?,
                state_digest,
            },
        };
        current.validate_state_digest()?;
        validate_capability_selection(connection, &current)?;
        validate_allocator_at_least_capability(connection, &current)?;
        Ok(current)
    })
    .transpose()
}

fn load_bundle_current(
    connection: &Connection,
    key: &EvidenceKey,
) -> LocalVerificationStoreResult<Option<EvidenceCurrent>> {
    let row: Option<(String, String, Vec<u8>, i64, String)> = connection
        .query_row(
            "SELECT bundle_id, record_digest, freshness_json, generation, state_digest FROM bundle_current WHERE run_id=?1 AND goal_id=?2 AND task_id=?3",
            params![key.run_id.as_str(), key.goal_id.as_str(), key.task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(|source| db("load bundle current", source))?;
    row.map(
        |(bundle_id, record_digest, freshness_json, generation, state_digest)| {
            let freshness: EvidenceFreshness =
                serde_json::from_slice(&freshness_json).map_err(|source| {
                    LocalVerificationStoreError::Deserialize {
                        kind: "bundle freshness",
                        source,
                    }
                })?;
            if canonical_json(&freshness, "bundle freshness")? != freshness_json {
                return Err(corrupt(
                    "bundle_projection",
                    evidence_key_label(key),
                    "noncanonical freshness",
                ));
            }
            let current = EvidenceCurrent {
                key: key.clone(),
                bundle_id,
                record_digest,
                freshness,
                token: CasToken {
                    generation: stored_generation(generation)?,
                    state_digest,
                },
            };
            current.validate_state_digest()?;
            validate_bundle_selection(connection, &current)?;
            validate_allocator_at_least_bundle(connection, &current)?;
            Ok(current)
        },
    )
    .transpose()
}

fn validate_capability_selection(
    connection: &Connection,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    current.validate_state_digest()?;
    let record = load_capability(connection, &current.capability_id, current.revision)?
        .ok_or_else(|| LocalVerificationStoreError::MissingRecord {
            kind: "capability",
            identity: format!("{}@{}", current.capability_id, current.revision),
        })?;
    if record.digest != current.record_digest {
        return Err(LocalVerificationStoreError::BindingMismatch(format!(
            "capability {}@{}",
            current.capability_id, current.revision
        )));
    }
    Ok(())
}

fn validate_bundle_selection(
    connection: &Connection,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    current.validate_state_digest()?;
    let record = load_bundle_by_digest(connection, &current.record_digest)?.ok_or_else(|| {
        LocalVerificationStoreError::MissingRecord {
            kind: "bundle",
            identity: current.record_digest.clone(),
        }
    })?;
    if record.bundle.bundle_id != current.bundle_id
        || record.bundle.run_id != current.key.run_id
        || record.bundle.goal_id != current.key.goal_id
        || record.bundle.task_id != current.key.task_id
    {
        return Err(LocalVerificationStoreError::BindingMismatch(
            evidence_key_label(&current.key),
        ));
    }
    Ok(())
}

fn apply_bundle_cas(
    transaction: &Transaction<'_>,
    record: &BundleRecord,
    expectation: &ProjectionExpectation,
    freshness: EvidenceFreshness,
) -> LocalVerificationStoreResult<CasOutcome<EvidenceCurrent>> {
    let key = EvidenceKey {
        run_id: record.bundle.run_id.clone(),
        goal_id: record.bundle.goal_id.clone(),
        task_id: record.bundle.task_id.clone(),
    };
    let current = load_bundle_current(transaction, &key)?;
    if !expectation_matches(expectation, current.as_ref().map(|value| &value.token)) {
        return Ok(CasOutcome::Conflict(current));
    }
    if current.as_ref().is_some_and(|value| {
        matches!(value.freshness, EvidenceFreshness::Stale { .. })
            && value.record_digest == record.digest
    }) {
        return Err(LocalVerificationStoreError::StaleRevivalRequiresDifferentBundle);
    }
    let generation = next_bundle_generation(transaction, &key)?;
    let next = EvidenceCurrent::new(
        key,
        record.bundle.bundle_id.clone(),
        record.digest.clone(),
        freshness,
        generation,
    )?;
    write_bundle_current_cas(transaction, &next, expectation)?;
    persist_bundle_generation(transaction, &next)?;
    Ok(CasOutcome::Applied(next))
}

fn expectation_matches(expectation: &ProjectionExpectation, current: Option<&CasToken>) -> bool {
    match (expectation, current) {
        (ProjectionExpectation::Absent, None) => true,
        (ProjectionExpectation::Token(expected), Some(current)) => expected == current,
        _ => false,
    }
}

fn write_capability_current(
    transaction: &Transaction<'_>,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    transaction
        .execute(
            "INSERT INTO capability_current (capability_id, revision, record_digest, generation, state_digest) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(capability_id) DO UPDATE SET revision=excluded.revision, record_digest=excluded.record_digest, generation=excluded.generation, state_digest=excluded.state_digest",
            params![current.capability_id, sqlite_u64(current.revision)?, current.record_digest, sqlite_u64(current.token.generation)?, current.token.state_digest],
        )
        .map_err(|source| db("write capability current", source))?;
    Ok(())
}

fn write_capability_current_cas(
    transaction: &Transaction<'_>,
    current: &CapabilityCurrent,
    expectation: &ProjectionExpectation,
) -> LocalVerificationStoreResult<()> {
    let changed = match expectation {
        ProjectionExpectation::Absent => transaction
            .execute(
                "INSERT OR IGNORE INTO capability_current (capability_id, revision, record_digest, generation, state_digest) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![current.capability_id, sqlite_u64(current.revision)?, current.record_digest, sqlite_u64(current.token.generation)?, current.token.state_digest],
            )
            .map_err(|source| db("insert absent capability current", source))?,
        ProjectionExpectation::Token(expected) => transaction
            .execute(
                "UPDATE capability_current SET revision=?1, record_digest=?2, generation=?3, state_digest=?4 WHERE capability_id=?5 AND generation=?6 AND state_digest=?7",
                params![sqlite_u64(current.revision)?, current.record_digest, sqlite_u64(current.token.generation)?, current.token.state_digest, current.capability_id, sqlite_u64(expected.generation)?, expected.state_digest],
            )
            .map_err(|source| db("CAS update capability current", source))?,
    };
    if changed != 1 {
        return Err(LocalVerificationStoreError::CasWriteLost(format!(
            "capability:{}",
            current.capability_id
        )));
    }
    Ok(())
}

fn write_bundle_current(
    transaction: &Transaction<'_>,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    let freshness = canonical_json(&current.freshness, "bundle freshness")?;
    transaction
        .execute(
            "INSERT INTO bundle_current (run_id, goal_id, task_id, bundle_id, record_digest, freshness_json, generation, state_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(run_id, goal_id, task_id) DO UPDATE SET bundle_id=excluded.bundle_id, record_digest=excluded.record_digest, freshness_json=excluded.freshness_json, generation=excluded.generation, state_digest=excluded.state_digest",
            params![current.key.run_id.as_str(), current.key.goal_id.as_str(), current.key.task_id.as_str(), current.bundle_id, current.record_digest, freshness, sqlite_u64(current.token.generation)?, current.token.state_digest],
        )
        .map_err(|source| db("write bundle current", source))?;
    Ok(())
}

fn write_bundle_current_cas(
    transaction: &Transaction<'_>,
    current: &EvidenceCurrent,
    expectation: &ProjectionExpectation,
) -> LocalVerificationStoreResult<()> {
    let freshness = canonical_json(&current.freshness, "bundle freshness")?;
    let changed = match expectation {
        ProjectionExpectation::Absent => transaction
            .execute(
                "INSERT OR IGNORE INTO bundle_current (run_id, goal_id, task_id, bundle_id, record_digest, freshness_json, generation, state_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![current.key.run_id.as_str(), current.key.goal_id.as_str(), current.key.task_id.as_str(), current.bundle_id, current.record_digest, freshness, sqlite_u64(current.token.generation)?, current.token.state_digest],
            )
            .map_err(|source| db("insert absent bundle current", source))?,
        ProjectionExpectation::Token(expected) => transaction
            .execute(
                "UPDATE bundle_current SET bundle_id=?1, record_digest=?2, freshness_json=?3, generation=?4, state_digest=?5 WHERE run_id=?6 AND goal_id=?7 AND task_id=?8 AND generation=?9 AND state_digest=?10",
                params![current.bundle_id, current.record_digest, freshness, sqlite_u64(current.token.generation)?, current.token.state_digest, current.key.run_id.as_str(), current.key.goal_id.as_str(), current.key.task_id.as_str(), sqlite_u64(expected.generation)?, expected.state_digest],
            )
            .map_err(|source| db("CAS update bundle current", source))?,
    };
    if changed != 1 {
        return Err(LocalVerificationStoreError::CasWriteLost(format!(
            "bundle:{}",
            evidence_key_label(&current.key)
        )));
    }
    Ok(())
}

fn next_capability_generation(
    transaction: &Transaction<'_>,
    capability_id: &str,
) -> LocalVerificationStoreResult<u64> {
    increment_generation(
        load_capability_generation(transaction, capability_id)?.map(|binding| binding.generation),
    )
}

fn next_bundle_generation(
    transaction: &Transaction<'_>,
    key: &EvidenceKey,
) -> LocalVerificationStoreResult<u64> {
    increment_generation(
        load_bundle_generation(transaction, key)?.map(|binding| binding.generation),
    )
}

fn increment_generation(current: Option<u64>) -> LocalVerificationStoreResult<u64> {
    let current = current.unwrap_or(0);
    current
        .checked_add(1)
        .ok_or(LocalVerificationStoreError::GenerationOverflow(current))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableGenerationBinding {
    generation: u64,
    state_digest: String,
}

fn load_capability_generation(
    connection: &Connection,
    capability_id: &str,
) -> LocalVerificationStoreResult<Option<DurableGenerationBinding>> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT max_generation, state_digest FROM capability_generations WHERE capability_id=?1",
            [capability_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| db("load capability generation binding", source))?;
    row.map(|(generation, state_digest)| {
        validate_digest(&state_digest, "capability generation state digest")?;
        Ok(DurableGenerationBinding {
            generation: stored_generation(generation)?,
            state_digest,
        })
    })
    .transpose()
}

fn load_bundle_generation(
    connection: &Connection,
    key: &EvidenceKey,
) -> LocalVerificationStoreResult<Option<DurableGenerationBinding>> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT max_generation, state_digest FROM bundle_generations WHERE run_id=?1 AND goal_id=?2 AND task_id=?3",
            params![key.run_id.as_str(), key.goal_id.as_str(), key.task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| db("load bundle generation binding", source))?;
    row.map(|(generation, state_digest)| {
        validate_digest(&state_digest, "bundle generation state digest")?;
        Ok(DurableGenerationBinding {
            generation: stored_generation(generation)?,
            state_digest,
        })
    })
    .transpose()
}

fn persist_capability_generation(
    transaction: &Transaction<'_>,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    current.validate_state_digest()?;
    let key = format!("capability:{}", current.capability_id);
    let durable = load_capability_generation(transaction, &current.capability_id)?;
    validate_generation_transition(&key, &current.token, durable.as_ref())?;
    if durable.as_ref().is_some_and(|binding| {
        binding.generation == current.token.generation
            && binding.state_digest == current.token.state_digest
    }) {
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO capability_generations (capability_id, max_generation, state_digest) VALUES (?1, ?2, ?3) ON CONFLICT(capability_id) DO UPDATE SET max_generation=excluded.max_generation, state_digest=excluded.state_digest",
            params![current.capability_id, sqlite_u64(current.token.generation)?, current.token.state_digest],
        )
        .map_err(|source| db("persist capability generation binding", source))?;
    Ok(())
}

fn persist_bundle_generation(
    transaction: &Transaction<'_>,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    current.validate_state_digest()?;
    let key_label = format!("bundle:{}", evidence_key_label(&current.key));
    let durable = load_bundle_generation(transaction, &current.key)?;
    validate_generation_transition(&key_label, &current.token, durable.as_ref())?;
    if durable.as_ref().is_some_and(|binding| {
        binding.generation == current.token.generation
            && binding.state_digest == current.token.state_digest
    }) {
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO bundle_generations (run_id, goal_id, task_id, max_generation, state_digest) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(run_id, goal_id, task_id) DO UPDATE SET max_generation=excluded.max_generation, state_digest=excluded.state_digest",
            params![current.key.run_id.as_str(), current.key.goal_id.as_str(), current.key.task_id.as_str(), sqlite_u64(current.token.generation)?, current.token.state_digest],
        )
        .map_err(|source| db("persist bundle generation binding", source))?;
    Ok(())
}

fn ensure_monotonic_capability_generation(
    transaction: &Transaction<'_>,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    validate_generation_transition(
        &format!("capability:{}", current.capability_id),
        &current.token,
        load_capability_generation(transaction, &current.capability_id)?.as_ref(),
    )
}

fn ensure_monotonic_bundle_generation(
    transaction: &Transaction<'_>,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    validate_generation_transition(
        &format!("bundle:{}", evidence_key_label(&current.key)),
        &current.token,
        load_bundle_generation(transaction, &current.key)?.as_ref(),
    )
}

fn validate_generation_transition(
    key: &str,
    selected: &CasToken,
    durable: Option<&DurableGenerationBinding>,
) -> LocalVerificationStoreResult<()> {
    if let Some(binding) = durable {
        if selected.generation < binding.generation {
            return Err(LocalVerificationStoreError::NonMonotonicGeneration {
                key: key.to_owned(),
                selected: selected.generation,
                durable: binding.generation,
            });
        }
        if selected.generation == binding.generation
            && selected.state_digest != binding.state_digest
        {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                format!(
                    "{key} reuses generation {} with different state digest",
                    selected.generation
                ),
            ));
        }
    }
    Ok(())
}

fn validate_allocator_at_least_capability(
    connection: &Connection,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    let durable = load_capability_generation(connection, &current.capability_id)?;
    if !durable.as_ref().is_some_and(|binding| {
        binding.generation == current.token.generation
            && binding.state_digest == current.token.state_digest
    }) {
        return Err(corrupt(
            "capability_projection",
            &current.capability_id,
            "generation binding does not match projection",
        ));
    }
    Ok(())
}

fn validate_allocator_at_least_bundle(
    connection: &Connection,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    let durable = load_bundle_generation(connection, &current.key)?;
    if !durable.as_ref().is_some_and(|binding| {
        binding.generation == current.token.generation
            && binding.state_digest == current.token.state_digest
    }) {
        return Err(corrupt(
            "bundle_projection",
            evidence_key_label(&current.key),
            "generation binding does not match projection",
        ));
    }
    Ok(())
}

fn sqlite_u64(value: u64) -> LocalVerificationStoreResult<i64> {
    i64::try_from(value).map_err(|_| LocalVerificationStoreError::GenerationOutOfRange(value))
}

fn capability_state_digest(value: &CapabilityCurrent) -> LocalVerificationStoreResult<String> {
    #[derive(Serialize)]
    struct State<'a> {
        capability_id: &'a str,
        revision: u64,
        record_digest: &'a str,
        generation: u64,
    }
    Ok(sha256_hex(&canonical_json(
        &State {
            capability_id: &value.capability_id,
            revision: value.revision,
            record_digest: &value.record_digest,
            generation: value.token.generation,
        },
        "capability state",
    )?))
}

fn evidence_state_digest(value: &EvidenceCurrent) -> LocalVerificationStoreResult<String> {
    #[derive(Serialize)]
    struct State<'a> {
        key: &'a EvidenceKey,
        bundle_id: &'a str,
        record_digest: &'a str,
        freshness: &'a EvidenceFreshness,
        generation: u64,
    }
    Ok(sha256_hex(&canonical_json(
        &State {
            key: &value.key,
            bundle_id: &value.bundle_id,
            record_digest: &value.record_digest,
            freshness: &value.freshness,
            generation: value.token.generation,
        },
        "bundle state",
    )?))
}

fn projection_selection_digest(
    selection: &AuthoritativeProjectionSelection,
) -> LocalVerificationStoreResult<String> {
    #[derive(Serialize)]
    struct Selection<'a> {
        intent: ProjectionRebuildIntent,
        capabilities: &'a [CapabilityCurrent],
        bundles: &'a [EvidenceCurrent],
    }
    Ok(sha256_hex(&canonical_json(
        &Selection {
            intent: selection.intent,
            capabilities: &selection.capabilities,
            bundles: &selection.bundles,
        },
        "projection selection",
    )?))
}

fn canonical_json<T: Serialize>(
    value: &T,
    kind: &'static str,
) -> LocalVerificationStoreResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|source| LocalVerificationStoreError::Serialize { kind, source })
}

fn evidence_key_label(key: &EvidenceKey) -> String {
    format!("{}:{}:{}", key.run_id, key.goal_id, key.task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ovca_types::{
        ChangedPathSelector, CriterionResult, CriterionResultVerdict, DeniedAccess,
        DigestAlgorithm, FailureConfirmation, LocalMachinePolicy, PathSelectorKind, ShellPolicy,
        VerificationCommand, VerificationFailure, VerificationFailureCategory, VerificationVerdict,
        WorkerId, WorkingDirectory, LOCAL_VERIFICATION_CONTRACT_VERSION,
    };
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn fingerprints() -> VerificationFingerprints {
        VerificationFingerprints {
            source_pre: digest('a'),
            source_post: digest('a'),
            behavior_contract: digest('b'),
            capability_set: digest('c'),
            command: digest('d'),
            policy: digest('e'),
            environment: digest('f'),
        }
    }

    fn capability(id: &str, revision: u64, argument: &str) -> CapabilityDefinition {
        CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: id.to_owned(),
            revision,
            criterion_ids: vec!["criterion.one".to_owned()],
            dependencies: vec![],
            changed_path_selectors: vec![ChangedPathSelector {
                kind: PathSelectorKind::Prefix,
                path: "rust/ovca-storage".to_owned(),
            }],
            policy: LocalMachinePolicy {
                local_only: true,
                network: DeniedAccess::Denied,
                provider: DeniedAccess::Denied,
                telemetry: DeniedAccess::Denied,
                egress: DeniedAccess::Denied,
                external_evidence: DeniedAccess::Denied,
                external_storage: DeniedAccess::Denied,
                raw_shell: ShellPolicy::Forbidden,
                inherit_environment: false,
                fingerprint_algorithm: DigestAlgorithm::Sha256,
                allowed_executable_ids: ["cargo".to_owned()].into_iter().collect(),
                allowed_environment_names: BTreeSet::new(),
            },
            commands: vec![VerificationCommand {
                command_id: "command.storage-test".to_owned(),
                executable_id: "cargo".to_owned(),
                argv: vec!["test".to_owned(), argument.to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: BTreeSet::new(),
            }],
        }
    }

    fn failure_for(verdict: VerificationVerdict) -> Option<VerificationFailure> {
        let category = match verdict {
            VerificationVerdict::Pass => return None,
            VerificationVerdict::Fail => VerificationFailureCategory::TestFailedUnclassified,
            VerificationVerdict::Blocked => VerificationFailureCategory::PolicyBlock,
            VerificationVerdict::Timeout => VerificationFailureCategory::Timeout,
            VerificationVerdict::Invalid => VerificationFailureCategory::ContractViolation,
        };
        Some(VerificationFailure {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            failure_id: "failure.one".to_owned(),
            category,
            confirmation: FailureConfirmation::Confirmed,
            supersedes_failure_id: None,
            criterion_id: Some("criterion.one".to_owned()),
            summary: "deterministic failure".to_owned(),
            recorded_at: Utc.with_ymd_and_hms(2026, 8, 10, 1, 2, 3).single().unwrap(),
        })
    }

    fn bundle(id: &str, verdict: VerificationVerdict) -> VerificationBundle {
        let result_verdict = match verdict {
            VerificationVerdict::Pass => CriterionResultVerdict::Pass,
            VerificationVerdict::Fail => CriterionResultVerdict::Fail,
            VerificationVerdict::Blocked => CriterionResultVerdict::Blocked,
            VerificationVerdict::Timeout => CriterionResultVerdict::Timeout,
            VerificationVerdict::Invalid => CriterionResultVerdict::Invalid,
        };
        VerificationBundle {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            bundle_id: id.to_owned(),
            run_id: RunId::from("run.v1"),
            goal_id: GoalId::from("goal.v1"),
            task_id: TaskId::from("task.v1"),
            behavior_contract_id: "behavior.v1".to_owned(),
            capability_ids: vec!["cap.v1".to_owned()],
            implementation_actor: WorkerId::from("engineer.v1"),
            verifier_actor: WorkerId::from("reviewer.v1"),
            fingerprints: fingerprints(),
            criterion_results: vec![CriterionResult {
                criterion_id: "criterion.one".to_owned(),
                order: 0,
                kind: ovca_types::BehaviorKind::Verification,
                text: "Storage preserves exact evidence".to_owned(),
                verdict: result_verdict,
            }],
            failures: failure_for(verdict).into_iter().collect(),
            verdict,
            created_at: Utc.with_ymd_and_hms(2026, 8, 10, 1, 2, 3).single().unwrap(),
        }
    }

    fn key() -> EvidenceKey {
        EvidenceKey {
            run_id: RunId::from("run.v1"),
            goal_id: GoalId::from("goal.v1"),
            task_id: TaskId::from("task.v1"),
        }
    }

    fn inserted<T>(outcome: PublishOutcome<T>) -> T {
        match outcome {
            PublishOutcome::Inserted(value) => value,
            PublishOutcome::ExistingIdentical(_) => panic!("expected inserted record"),
        }
    }

    fn applied<T: std::fmt::Debug>(outcome: CasOutcome<T>) -> T {
        match outcome {
            CasOutcome::Applied(value) => value,
            other => panic!("expected applied CAS, got {other:?}"),
        }
    }

    fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
        matches!(
            error,
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        )
    }

    #[test]
    fn completion_admission_lease_is_atomic_current_and_blocks_writers_through_callback() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        let bank = store.evidence_bank();

        let cap_v1 = capability("cap.v1", 1, "first");
        let cap_v1_record = inserted(registry.publish(&cap_v1).unwrap());
        let cap_current = applied(
            registry
                .compare_and_swap_current(
                    &cap_v1.capability_id,
                    cap_v1.revision,
                    &cap_v1_record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );
        let bundle_v1 = bundle("bundle.lease.first", VerificationVerdict::Pass);
        let publication = bank
            .publish_bundle_and_cas(&bundle_v1, &ProjectionExpectation::Absent)
            .unwrap();
        let bundle_current = applied(publication.projection);

        let cap_v2 = capability("cap.v1", 2, "second");
        let cap_v2_record = inserted(registry.publish(&cap_v2).unwrap());
        let bundle_v2 = bundle("bundle.lease.second", VerificationVerdict::Pass);
        bank.publish_bundle(&bundle_v2).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (capability_done_tx, capability_done_rx) = mpsc::channel();
        let (bundle_done_tx, bundle_done_rx) = mpsc::channel();
        let mut capability_writer = None;
        let mut bundle_writer = None;
        let mut callback_reached_final_boundary = false;
        bank.with_completion_admission_lease(&[key()], |snapshot| {
            assert_eq!(snapshot.capabilities.len(), 1);
            assert_eq!(snapshot.capabilities[0].current, cap_current);
            assert_eq!(snapshot.capabilities[0].record, cap_v1_record);
            assert_eq!(snapshot.bundles.len(), 1);
            assert_eq!(snapshot.bundles[0].current, bundle_current);
            assert_eq!(snapshot.bundles[0].record.bundle, bundle_v1);

            for _ in 0..2 {
                let mut contender = Connection::open(bank.database_path()).unwrap();
                contender.busy_timeout(Duration::ZERO).unwrap();
                let error = contender
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap_err();
                assert!(sqlite_is_busy(&error), "unexpected lock result: {error}");
            }

            let writer_registry = registry.clone();
            let capability_definition = cap_v2.clone();
            let capability_record = cap_v2_record.clone();
            let capability_expectation = cap_current.token.clone();
            let capability_started = started_tx.clone();
            capability_writer = Some(thread::spawn(move || {
                capability_started.send(()).unwrap();
                capability_done_tx
                    .send(writer_registry.compare_and_swap_current(
                        &capability_definition.capability_id,
                        capability_definition.revision,
                        &capability_record.digest,
                        &ProjectionExpectation::Token(capability_expectation),
                    ))
                    .unwrap();
            }));

            let writer_bank = bank.clone();
            let bundle = bundle_v2.clone();
            let bundle_expectation = bundle_current.token.clone();
            let bundle_started = started_tx.clone();
            bundle_writer = Some(thread::spawn(move || {
                bundle_started.send(()).unwrap();
                bundle_done_tx
                    .send(writer_bank.publish_bundle_and_cas(
                        &bundle,
                        &ProjectionExpectation::Token(bundle_expectation),
                    ))
                    .unwrap();
            }));

            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(capability_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err());
            assert!(bundle_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err());
            callback_reached_final_boundary = true;
            Ok::<(), LocalVerificationStoreError>(())
        })
        .unwrap();
        assert!(callback_reached_final_boundary);

        assert!(matches!(
            capability_done_rx
                .recv_timeout(Duration::from_secs(6))
                .unwrap()
                .unwrap(),
            CasOutcome::Applied(_)
        ));
        assert!(matches!(
            bundle_done_rx
                .recv_timeout(Duration::from_secs(6))
                .unwrap()
                .unwrap()
                .projection,
            CasOutcome::Applied(_)
        ));
        capability_writer.take().unwrap().join().unwrap();
        bundle_writer.take().unwrap().join().unwrap();
    }

    #[test]
    fn completion_admission_lease_rejects_bad_keys_and_releases_after_callback_error() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        let bank = store.evidence_bank();
        let definition = capability("cap.v1", 1, "first");
        let record = inserted(registry.publish(&definition).unwrap());
        let current = applied(
            registry
                .compare_and_swap_current(
                    &definition.capability_id,
                    definition.revision,
                    &record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );
        let first_bundle = bundle("bundle.release.first", VerificationVerdict::Pass);
        let published = bank
            .publish_bundle_and_cas(&first_bundle, &ProjectionExpectation::Absent)
            .unwrap();

        let empty = bank
            .with_completion_admission_lease(&[], |_| Ok::<(), LocalVerificationStoreError>(()));
        assert!(matches!(
            empty,
            Err(LocalVerificationStoreError::InvalidContract {
                contract: "completion_admission_keys",
                ..
            })
        ));
        let duplicate = [key(), key()];
        assert!(bank
            .with_completion_admission_lease(&duplicate, |_| {
                Ok::<(), LocalVerificationStoreError>(())
            })
            .is_err());

        let callback_error = bank.with_completion_admission_lease(&[key()], |_| {
            Err::<(), _>(LocalVerificationStoreError::InjectedFailure)
        });
        assert!(matches!(
            callback_error,
            Err(LocalVerificationStoreError::InjectedFailure)
        ));

        let next = capability("cap.v1", 2, "after-error");
        let next_record = inserted(registry.publish(&next).unwrap());
        assert!(matches!(
            registry
                .compare_and_swap_current(
                    &next.capability_id,
                    next.revision,
                    &next_record.digest,
                    &ProjectionExpectation::Token(current.token)
                )
                .unwrap(),
            CasOutcome::Applied(_)
        ));
        assert!(matches!(published.projection, CasOutcome::Applied(_)));
    }

    #[test]
    fn constructor_is_side_effect_free_and_rejects_nonlocal_roots() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("missing-durable-root");
        let store = LocalVerificationStore::try_new(&root).unwrap();
        assert_eq!(
            store.database_path(),
            root.join(LOCAL_VERIFICATION_DB_RELATIVE_PATH)
        );
        assert!(!root.exists());

        for unsafe_root in [
            Path::new("relative/root"),
            Path::new(r"\\server\share"),
            Path::new("https://example.test/store"),
        ] {
            assert!(matches!(
                LocalVerificationStore::try_new(unsafe_root),
                Err(LocalVerificationStoreError::InvalidRoot { .. })
            ));
        }
    }

    #[test]
    fn capability_records_are_versioned_immutable_and_reopen_exactly() {
        let temp = TempDir::new().unwrap();
        let registry = CapabilityRegistry::try_new(temp.path()).unwrap();
        let definition = capability("cap.path..token", 1, "first");
        let record = inserted(registry.publish(&definition).unwrap());
        assert!(matches!(
            registry.publish(&definition).unwrap(),
            PublishOutcome::ExistingIdentical(_)
        ));

        let changed = capability("cap.path..token", 1, "second");
        assert!(matches!(
            registry.publish(&changed),
            Err(LocalVerificationStoreError::ImmutableConflict { .. })
        ));

        let current = applied(
            registry
                .compare_and_swap_current(
                    &definition.capability_id,
                    definition.revision,
                    &record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );
        assert_eq!(current.token.generation, 1);
        drop(registry);

        let reopened = CapabilityRegistry::try_new(temp.path()).unwrap();
        assert_eq!(
            reopened
                .load(&definition.capability_id, 1)
                .unwrap()
                .unwrap(),
            record
        );
        assert_eq!(
            reopened
                .load_current(&definition.capability_id)
                .unwrap()
                .unwrap(),
            current
        );
        assert!(!temp.path().join("cap.path..token").exists());
    }

    #[test]
    fn every_bundle_verdict_is_retained_under_identical_rules() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let verdicts = [
            VerificationVerdict::Pass,
            VerificationVerdict::Fail,
            VerificationVerdict::Blocked,
            VerificationVerdict::Timeout,
            VerificationVerdict::Invalid,
        ];
        for (index, verdict) in verdicts.into_iter().enumerate() {
            let value = bundle(&format!("bundle.verdict.{index}"), verdict);
            let record = inserted(bank.publish_bundle(&value).unwrap());
            assert_eq!(
                bank.load_bundle(&record.digest)
                    .unwrap()
                    .unwrap()
                    .bundle
                    .verdict,
                verdict
            );
        }

        let original = bundle("bundle.immutable", VerificationVerdict::Pass);
        inserted(bank.publish_bundle(&original).unwrap());
        assert!(matches!(
            bank.publish_bundle(&original).unwrap(),
            PublishOutcome::ExistingIdentical(_)
        ));
        let mut changed = original;
        changed.created_at = Utc.with_ymd_and_hms(2026, 8, 10, 1, 2, 4).single().unwrap();
        assert!(matches!(
            bank.publish_bundle(&changed),
            Err(LocalVerificationStoreError::ImmutableConflict { .. })
        ));

        let reopen_bundle = inserted(
            bank.publish_bundle(&bundle("bundle.reopen", VerificationVerdict::Pass))
                .unwrap(),
        );
        let reopen_current = applied(
            bank.compare_and_swap_current(&reopen_bundle.digest, &ProjectionExpectation::Absent)
                .unwrap(),
        );
        drop(bank);
        let reopened = EvidenceBank::try_new(temp.path()).unwrap();
        assert_eq!(
            reopened
                .load_bundle(&reopen_bundle.digest)
                .unwrap()
                .unwrap(),
            reopen_bundle
        );
        assert_eq!(
            reopened.load_current(&key()).unwrap().unwrap(),
            reopen_current
        );
    }

    #[test]
    fn independent_connections_racing_one_token_have_one_winner() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let initial = inserted(
            bank.publish_bundle(&bundle("bundle.race.initial", VerificationVerdict::Pass))
                .unwrap(),
        );
        let current = applied(
            bank.compare_and_swap_current(&initial.digest, &ProjectionExpectation::Absent)
                .unwrap(),
        );
        let first = inserted(
            bank.publish_bundle(&bundle("bundle.race.first", VerificationVerdict::Pass))
                .unwrap(),
        );
        let second = inserted(
            bank.publish_bundle(&bundle("bundle.race.second", VerificationVerdict::Pass))
                .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [first.digest, second.digest]
            .into_iter()
            .map(|digest| {
                let root = temp.path().to_path_buf();
                let expected = current.token.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let bank = EvidenceBank::try_new(root).unwrap();
                    barrier.wait();
                    bank.compare_and_swap_current(&digest, &ProjectionExpectation::Token(expected))
                        .unwrap()
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| matches!(value, CasOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| matches!(value, CasOutcome::Conflict(_)))
                .count(),
            1
        );
        let winner = outcomes
            .iter()
            .find_map(|value| match value {
                CasOutcome::Applied(current) => Some(current),
                _ => None,
            })
            .unwrap();
        assert_eq!(winner.token.generation, 2);
    }

    #[test]
    fn aba_generations_and_stale_conflicts_fail_closed() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let first = bundle("bundle.aba.first", VerificationVerdict::Pass);
        let first_outcome = bank
            .publish_bundle_and_cas(&first, &ProjectionExpectation::Absent)
            .unwrap();
        let generation_one = applied(first_outcome.projection);
        assert_eq!(generation_one.token.generation, 1);

        let stale = applied(
            bank.mark_stale(
                &key(),
                &generation_one.token,
                [StaleCause::Source].into_iter().collect(),
            )
            .unwrap(),
        );
        assert_eq!(stale.token.generation, 2);
        assert!(matches!(
            bank.mark_stale(
                &key(),
                &generation_one.token,
                [StaleCause::Policy].into_iter().collect(),
            )
            .unwrap(),
            CasOutcome::Conflict(Some(_))
        ));
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), stale);

        assert!(matches!(
            bank.compare_and_swap_current(
                &stale.record_digest,
                &ProjectionExpectation::Token(stale.token.clone()),
            ),
            Err(LocalVerificationStoreError::StaleRevivalRequiresDifferentBundle)
        ));

        let next = bundle("bundle.aba.next", VerificationVerdict::Pass);
        let generation_three = applied(
            bank.publish_bundle_and_cas(&next, &ProjectionExpectation::Token(stale.token.clone()))
                .unwrap()
                .projection,
        );
        assert_eq!(generation_three.token.generation, 3);

        let old_token_attempt = bank
            .compare_and_swap_current(
                &generation_three.record_digest,
                &ProjectionExpectation::Token(generation_one.token),
            )
            .unwrap();
        assert!(matches!(old_token_attempt, CasOutcome::Conflict(Some(_))));
    }

    #[test]
    fn retained_bundle_retry_uses_record_identity_and_does_not_burn_generation() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let first = bundle("bundle.retry.first", VerificationVerdict::Pass);
        let first_current = applied(
            bank.publish_bundle_and_cas(&first, &ProjectionExpectation::Absent)
                .unwrap()
                .projection,
        );
        let stale = applied(
            bank.mark_stale(
                &key(),
                &first_current.token,
                [StaleCause::Source].into_iter().collect(),
            )
            .unwrap(),
        );
        assert_eq!(stale.token.generation, 2);

        let retained = bundle("bundle.retry.retained", VerificationVerdict::Fail);
        let wrong_token = CasToken {
            generation: stale.token.generation,
            state_digest: digest('0'),
        };
        let conflict = bank
            .publish_bundle_and_cas(&retained, &ProjectionExpectation::Token(wrong_token))
            .unwrap();
        let retained_record = match conflict.publication {
            PublishOutcome::Inserted(record) => record,
            other => panic!("expected retained insertion, got {other:?}"),
        };
        assert!(matches!(
            conflict.projection,
            CasOutcome::Conflict(Some(ref current)) if current == &stale
        ));
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), stale);
        assert!(bank.load_bundle(&retained_record.digest).unwrap().is_some());

        assert!(matches!(
            bank.publish_bundle_and_cas(
                &first,
                &ProjectionExpectation::Token(stale.token.clone()),
            ),
            Err(LocalVerificationStoreError::StaleRevivalRequiresDifferentBundle)
        ));
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), stale);

        let retry = bank
            .publish_bundle_and_cas(
                &retained,
                &ProjectionExpectation::Token(stale.token.clone()),
            )
            .unwrap();
        assert!(matches!(
            retry.publication,
            PublishOutcome::ExistingIdentical(ref record) if record.digest == retained_record.digest
        ));
        let promoted = applied(retry.projection);
        assert_eq!(promoted.record_digest, retained_record.digest);
        assert_eq!(promoted.token.generation, 3);
    }

    #[test]
    fn durable_generation_state_survives_reset_and_selection_omission() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        let bank = store.evidence_bank();
        let capability_a = inserted(
            registry
                .publish(&capability("cap.binding", 1, "a"))
                .unwrap(),
        );
        let capability_b = inserted(
            registry
                .publish(&capability("cap.binding", 2, "b"))
                .unwrap(),
        );
        let bundle_a = inserted(
            bank.publish_bundle(&bundle("bundle.binding.a", VerificationVerdict::Pass))
                .unwrap(),
        );
        let bundle_b = inserted(
            bank.publish_bundle(&bundle("bundle.binding.b", VerificationVerdict::Fail))
                .unwrap(),
        );
        let capability_a_gen7 =
            CapabilityCurrent::new("cap.binding", 1, &capability_a.digest, 7).unwrap();
        let bundle_a_gen7 = EvidenceCurrent::new(
            key(),
            bundle_a.bundle.bundle_id.clone(),
            &bundle_a.digest,
            EvidenceFreshness::Current,
            7,
        )
        .unwrap();
        let selection_a = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![capability_a_gen7.clone()],
            vec![bundle_a_gen7.clone()],
        )
        .unwrap();
        store.rebuild_projections(&selection_a).unwrap();

        let reset =
            AuthoritativeProjectionSelection::new(ProjectionRebuildIntent::Reset, vec![], vec![])
                .unwrap();
        store.rebuild_projections(&reset).unwrap();
        assert!(registry.load_current("cap.binding").unwrap().is_none());
        assert!(bank.load_current(&key()).unwrap().is_none());

        store.rebuild_projections(&selection_a).unwrap();
        assert_eq!(
            registry.load_current("cap.binding").unwrap().unwrap(),
            capability_a_gen7
        );
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), bundle_a_gen7);
        store.rebuild_projections(&reset).unwrap();

        let capability_b_gen7 =
            CapabilityCurrent::new("cap.binding", 2, &capability_b.digest, 7).unwrap();
        let bundle_b_gen7 = EvidenceCurrent::new(
            key(),
            bundle_b.bundle.bundle_id.clone(),
            &bundle_b.digest,
            EvidenceFreshness::Current,
            7,
        )
        .unwrap();
        for rejected in [
            AuthoritativeProjectionSelection::new(
                ProjectionRebuildIntent::Replace,
                vec![capability_b_gen7],
                vec![],
            )
            .unwrap(),
            AuthoritativeProjectionSelection::new(
                ProjectionRebuildIntent::Replace,
                vec![],
                vec![bundle_b_gen7],
            )
            .unwrap(),
        ] {
            assert!(matches!(
                store.rebuild_projections(&rejected),
                Err(LocalVerificationStoreError::InvalidProjectionSelection(_))
            ));
            assert!(registry.load_current("cap.binding").unwrap().is_none());
            assert!(bank.load_current(&key()).unwrap().is_none());
        }

        let capability_b_gen8 =
            CapabilityCurrent::new("cap.binding", 2, &capability_b.digest, 8).unwrap();
        let bundle_b_gen8 = EvidenceCurrent::new(
            key(),
            bundle_b.bundle.bundle_id.clone(),
            &bundle_b.digest,
            EvidenceFreshness::Current,
            8,
        )
        .unwrap();
        let selection_b = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![capability_b_gen8.clone()],
            vec![bundle_b_gen8.clone()],
        )
        .unwrap();
        store.rebuild_projections(&selection_b).unwrap();

        let capability_only = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![capability_b_gen8.clone()],
            vec![],
        )
        .unwrap();
        store.rebuild_projections(&capability_only).unwrap();
        assert!(bank.load_current(&key()).unwrap().is_none());
        let bundle_only = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![],
            vec![bundle_b_gen8.clone()],
        )
        .unwrap();
        store.rebuild_projections(&bundle_only).unwrap();
        assert!(registry.load_current("cap.binding").unwrap().is_none());
        store.rebuild_projections(&selection_b).unwrap();
        assert_eq!(
            registry.load_current("cap.binding").unwrap().unwrap(),
            capability_b_gen8
        );
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), bundle_b_gen8);

        let connection = Connection::open(store.database_path()).unwrap();
        connection
            .execute(
                "UPDATE capability_generations SET state_digest=?1 WHERE capability_id='cap.binding'",
                [digest('0')],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE bundle_generations SET state_digest=?1 WHERE run_id=?2 AND goal_id=?3 AND task_id=?4",
                params![digest('0'), key().run_id.as_str(), key().goal_id.as_str(), key().task_id.as_str()],
            )
            .unwrap();
        assert!(registry.load_current("cap.binding").is_err());
        assert!(bank.load_current(&key()).is_err());
    }

    #[test]
    fn fingerprint_changes_mark_only_the_projection_stale() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let value = bundle("bundle.fingerprint", VerificationVerdict::Pass);
        let outcome = bank
            .publish_bundle_and_cas(&value, &ProjectionExpectation::Absent)
            .unwrap();
        let current = applied(outcome.projection);
        let mut expected = value.fingerprints.clone();
        expected.command = digest('9');
        let stale = applied(
            bank.mark_stale_if_fingerprints_changed(&key(), &current.token, &expected)
                .unwrap(),
        );
        assert!(matches!(
            stale.freshness,
            EvidenceFreshness::Stale { ref causes } if causes == &[StaleCause::Command].into_iter().collect()
        ));
        assert!(bank.load_bundle(&stale.record_digest).unwrap().is_some());
    }

    #[test]
    fn corrupt_bundle_bytes_digest_canonical_form_and_binding_fail_closed() {
        enum Corruption {
            Bytes,
            Digest,
            Canonical,
            Binding,
        }
        for corruption in [
            Corruption::Bytes,
            Corruption::Digest,
            Corruption::Canonical,
            Corruption::Binding,
        ] {
            let temp = TempDir::new().unwrap();
            let bank = EvidenceBank::try_new(temp.path()).unwrap();
            let value = bundle("bundle.corrupt", VerificationVerdict::Pass);
            let outcome = bank
                .publish_bundle_and_cas(&value, &ProjectionExpectation::Absent)
                .unwrap();
            let record = match outcome.publication {
                PublishOutcome::Inserted(record) => record,
                _ => unreachable!(),
            };
            let connection = Connection::open(bank.database_path()).unwrap();
            connection
                .execute_batch("PRAGMA foreign_keys=OFF;")
                .unwrap();
            match corruption {
                Corruption::Bytes => {
                    connection
                        .execute("UPDATE bundle_records SET canonical_json=X'00'", [])
                        .unwrap();
                }
                Corruption::Digest => {
                    connection
                        .execute("UPDATE bundle_records SET digest=?1", [digest('9')])
                        .unwrap();
                }
                Corruption::Canonical => {
                    let mut bytes = canonical_bundle(&value).unwrap();
                    bytes.push(b' ');
                    let changed_digest = sha256_hex(&bytes);
                    connection
                        .execute(
                            "UPDATE bundle_records SET digest=?1, canonical_json=?2",
                            params![changed_digest, bytes],
                        )
                        .unwrap();
                }
                Corruption::Binding => {
                    connection
                        .execute("UPDATE bundle_records SET goal_id='goal.other'", [])
                        .unwrap();
                }
            }
            assert!(
                bank.load_bundle(&record.digest).is_err() || bank.load_current(&key()).is_err()
            );
            assert!(bank.load_current(&key()).is_err());
        }
    }

    #[test]
    fn atomic_failure_rolls_back_but_cas_conflict_retains_immutable_loser() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let failed = bundle("bundle.injected", VerificationVerdict::Fail);
        assert!(matches!(
            bank.publish_bundle_and_cas_inner(&failed, &ProjectionExpectation::Absent, true),
            Err(LocalVerificationStoreError::InjectedFailure)
        ));
        let failed_digest = sha256_hex(&canonical_bundle(&failed).unwrap());
        assert!(bank.load_bundle(&failed_digest).unwrap().is_none());
        assert!(bank.load_current(&key()).unwrap().is_none());

        let initial = bank
            .publish_bundle_and_cas(
                &bundle("bundle.atomic.initial", VerificationVerdict::Pass),
                &ProjectionExpectation::Absent,
            )
            .unwrap();
        let current = applied(initial.projection);
        assert_eq!(current.token.generation, 1);
        let loser = bundle("bundle.atomic.loser", VerificationVerdict::Fail);
        let conflict = bank
            .publish_bundle_and_cas(
                &loser,
                &ProjectionExpectation::Token(CasToken {
                    generation: current.token.generation,
                    state_digest: digest('0'),
                }),
            )
            .unwrap();
        let loser_record = match conflict.publication {
            PublishOutcome::Inserted(record) => record,
            _ => unreachable!(),
        };
        assert!(matches!(conflict.projection, CasOutcome::Conflict(Some(_))));
        assert!(bank.load_bundle(&loser_record.digest).unwrap().is_some());
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), current);
    }

    #[test]
    fn rebuild_is_exact_transactional_and_never_infers_latest() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        let bank = store.evidence_bank();
        let cap_record = inserted(registry.publish(&capability("cap.v1", 1, "one")).unwrap());
        let newer_unselected = inserted(registry.publish(&capability("cap.v1", 2, "two")).unwrap());
        let bundle_record = inserted(
            bank.publish_bundle(&bundle("bundle.rebuild", VerificationVerdict::Pass))
                .unwrap(),
        );
        let cap_current = CapabilityCurrent::new("cap.v1", 1, &cap_record.digest, 7).unwrap();
        let bundle_current = EvidenceCurrent::new(
            key(),
            bundle_record.bundle.bundle_id.clone(),
            &bundle_record.digest,
            EvidenceFreshness::Current,
            9,
        )
        .unwrap();
        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![cap_current.clone()],
            vec![bundle_current.clone()],
        )
        .unwrap();
        store.rebuild_projections(&selection).unwrap();
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap(),
            cap_current
        );
        assert_ne!(
            registry
                .load_current("cap.v1")
                .unwrap()
                .unwrap()
                .record_digest,
            newer_unselected.digest
        );
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), bundle_current);

        let mut bad_digest = selection.clone();
        bad_digest.selection_set_digest = digest('0');
        assert!(store.rebuild_projections(&bad_digest).is_err());
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap(),
            cap_current
        );

        let mut bad_state_digest = selection.clone();
        bad_state_digest.capabilities[0].token.state_digest = digest('0');
        assert!(matches!(
            store.rebuild_projections(&bad_state_digest),
            Err(LocalVerificationStoreError::InvalidProjectionSelection(_))
        ));
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap(),
            cap_current
        );

        let missing = CapabilityCurrent::new("cap.missing", 1, digest('1'), 10).unwrap();
        let missing_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![missing],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            store.rebuild_projections(&missing_selection),
            Err(LocalVerificationStoreError::MissingRecord { .. })
        ));
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap(),
            cap_current
        );

        let nonmonotonic = CapabilityCurrent::new("cap.v1", 1, &cap_record.digest, 6).unwrap();
        let nonmonotonic_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![nonmonotonic],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            store.rebuild_projections(&nonmonotonic_selection),
            Err(LocalVerificationStoreError::NonMonotonicGeneration { .. })
        ));

        let reused_capability_generation = CapabilityCurrent::new(
            "cap.v1",
            2,
            &newer_unselected.digest,
            cap_current.token.generation,
        )
        .unwrap();
        let reused_capability_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![reused_capability_generation],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            store.rebuild_projections(&reused_capability_selection),
            Err(LocalVerificationStoreError::InvalidProjectionSelection(_))
        ));

        let alternate_bundle = inserted(
            bank.publish_bundle(&bundle(
                "bundle.rebuild.alternate",
                VerificationVerdict::Fail,
            ))
            .unwrap(),
        );
        let reused_bundle_generation = EvidenceCurrent::new(
            key(),
            alternate_bundle.bundle.bundle_id.clone(),
            &alternate_bundle.digest,
            EvidenceFreshness::Current,
            bundle_current.token.generation,
        )
        .unwrap();
        let reused_bundle_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![],
            vec![reused_bundle_generation],
        )
        .unwrap();
        assert!(matches!(
            store.rebuild_projections(&reused_bundle_selection),
            Err(LocalVerificationStoreError::InvalidProjectionSelection(_))
        ));
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap(),
            cap_current
        );
        assert_eq!(bank.load_current(&key()).unwrap().unwrap(), bundle_current);

        assert!(AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![],
            vec![],
        )
        .is_err());
        let duplicate = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![cap_current.clone(), cap_current],
            vec![],
        );
        assert!(duplicate.is_err());

        let cap_a = inserted(registry.publish(&capability("cap.a", 1, "a")).unwrap());
        let cap_z = inserted(registry.publish(&capability("cap.z", 1, "z")).unwrap());
        let unsorted = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![
                CapabilityCurrent::new("cap.z", 1, cap_z.digest, 1).unwrap(),
                CapabilityCurrent::new("cap.a", 1, cap_a.digest, 1).unwrap(),
            ],
            vec![],
        );
        assert!(unsorted.is_err());

        let corrupt_record = inserted(
            registry
                .publish(&capability("cap.corrupt", 1, "corrupt"))
                .unwrap(),
        );
        let corrupt_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new("cap.corrupt", 1, &corrupt_record.digest, 10).unwrap()],
            vec![],
        )
        .unwrap();
        let connection = Connection::open(registry.database_path()).unwrap();
        connection
            .execute(
                "UPDATE capability_records SET canonical_json=X'00' WHERE capability_id='cap.corrupt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.rebuild_projections(&corrupt_selection),
            Err(LocalVerificationStoreError::CorruptRecord { .. })
        ));
        assert_eq!(
            registry.load_current("cap.v1").unwrap().unwrap().revision,
            1
        );
    }

    #[test]
    fn logical_references_never_contain_the_machine_root() {
        let temp = TempDir::new().unwrap();
        let bank = EvidenceBank::try_new(temp.path()).unwrap();
        let record = inserted(
            bank.publish_bundle(&bundle("bundle.reference", VerificationVerdict::Pass))
                .unwrap(),
        );
        assert_eq!(
            record.logical_reference,
            format!("verification-bundles/sha256/{}", record.digest)
        );
        assert!(!record
            .logical_reference
            .contains(&temp.path().display().to_string()));
        assert!(!record.logical_reference.contains('\\'));
    }
}
