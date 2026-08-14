//! Local-only operator operations for the durable verification store.
//!
//! Archives contain closed logical identities only. Health uses a read-only
//! SQLite handle. Recovery requires an exact caller-owned selection and never
//! infers a latest row, generation, pointer, or rollback target.

use super::*;
use rusqlite::OpenFlags;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;

const ARCHIVE_VERSION: &str = "ovca.local-verification-projection-archive.v1";
const ARCHIVE_DIRECTORY: &str = "archives";
const ARCHIVE_IDENTITY_DIRECTORY: &str = "identities";
const ARCHIVE_LOGICAL_PREFIX: &str = "local-verification-archives/sha256/";
const ARCHIVE_MAX_BYTES: u64 = 1_048_576;
const ARCHIVE_ID_MAX_BYTES: usize = 256;
const OPERATOR_MAX_ROWS: usize = 1_024;
const ARCHIVE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projection_archives (
    archive_id TEXT PRIMARY KEY NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    canonical_json BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projection_archive_migration_state (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    legacy_import_complete INTEGER NOT NULL CHECK (legacy_import_complete = 1)
);
"#;

/// The only supported seed policy. Publication is immutable-only: no current
/// pointer or generation allocator row may exist or be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySeedPolicy {
    PublishOnlyNoCurrent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionArchiveManifest {
    pub archive_version: String,
    pub archive_id: String,
    pub selection: AuthoritativeProjectionSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRecord {
    pub manifest: ProjectionArchiveManifest,
    pub record_digest: String,
    pub logical_reference: String,
    pub canonical_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveIdentityMapping {
    archive_id: String,
    record_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalVerificationHealthState {
    Healthy,
    Unhealthy,
    LimitExceeded,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVerificationHealthSection {
    pub state: LocalVerificationHealthState,
    pub checked: u32,
    pub issue_codes: Vec<String>,
}

/// Exactly five closed, bounded sections. No field can carry a filesystem path,
/// URL, environment value, task body, secret, or child stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVerificationHealthReport {
    pub immutable_record_integrity: LocalVerificationHealthSection,
    pub current_projection_integrity: LocalVerificationHealthSection,
    pub capability_dependency_health: LocalVerificationHealthSection,
    pub evidence_binding_health: LocalVerificationHealthSection,
    pub recovery_required: LocalVerificationHealthSection,
}

impl CapabilityRegistry {
    /// Seeds one reviewed immutable definition without selecting it.
    ///
    /// Dependencies are rejected because this single-definition operation cannot
    /// prove an exact dependency closure. A pre-existing current pointer,
    /// generation allocator, or alternate immutable revision fails closed.
    pub fn seed_capability(
        &self,
        definition: &CapabilityDefinition,
        expected_record_digest: &str,
        policy: CapabilitySeedPolicy,
    ) -> LocalVerificationStoreResult<PublishOutcome<CapabilityRecord>> {
        if policy != CapabilitySeedPolicy::PublishOnlyNoCurrent {
            return Err(LocalVerificationStoreError::CapabilitySeedPolicy(
                "unsupported seed policy".to_owned(),
            ));
        }
        validate_digest(expected_record_digest, "expected capability seed digest")?;
        if !definition.dependencies.is_empty() {
            return Err(LocalVerificationStoreError::CapabilitySeedPolicy(
                "single-definition seed requires an empty dependency closure".to_owned(),
            ));
        }
        let canonical = definition.canonical_json_bytes().map_err(|error| {
            LocalVerificationStoreError::InvalidContract {
                contract: "capability_definition",
                detail: error.to_string(),
            }
        })?;
        if sha256_hex(&canonical) != expected_record_digest {
            return Err(LocalVerificationStoreError::BindingMismatch(
                "capability seed expected digest".to_owned(),
            ));
        }

        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin immutable capability seed")?;
        if load_capability_current(&transaction, &definition.capability_id)?.is_some() {
            return Err(LocalVerificationStoreError::CapabilitySeedPolicy(
                "pre-existing current capability is forbidden".to_owned(),
            ));
        }
        if load_capability_generation(&transaction, &definition.capability_id)?.is_some() {
            return Err(LocalVerificationStoreError::CapabilitySeedPolicy(
                "pre-existing capability generation is forbidden".to_owned(),
            ));
        }
        let alternate_revisions: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM capability_records WHERE capability_id=?1 AND revision<>?2",
                params![definition.capability_id, sqlite_u64(definition.revision)?],
                |row| row.get(0),
            )
            .map_err(|source| db("inspect capability seed revisions", source))?;
        if alternate_revisions != 0 {
            return Err(LocalVerificationStoreError::CapabilitySeedPolicy(
                "mixed immutable capability revisions are forbidden".to_owned(),
            ));
        }

        let outcome = publish_capability_tx(&transaction, definition)?;
        let actual = match &outcome {
            PublishOutcome::Inserted(record) | PublishOutcome::ExistingIdentical(record) => {
                &record.digest
            }
        };
        if actual != expected_record_digest {
            return Err(LocalVerificationStoreError::BindingMismatch(
                "published capability seed digest".to_owned(),
            ));
        }
        transaction
            .commit()
            .map_err(|source| db("commit immutable capability seed", source))?;
        Ok(outcome)
    }
}

impl LocalVerificationStore {
    /// Atomically persists a caller-named, content-addressed projection archive.
    ///
    /// The caller-stable archive identity is part of the canonical manifest.
    /// The computed record digest is deliberately not, avoiding a self-reference.
    /// One transactional ownership row prevents an archive identity or content
    /// address from being rebound to different canonical bytes.
    pub fn persist_projection_archive(
        &self,
        archive_id: &str,
        selection: &AuthoritativeProjectionSelection,
    ) -> LocalVerificationStoreResult<ArchiveRecord> {
        self.persist_projection_archive_inner(archive_id, selection, false)
    }

    fn persist_projection_archive_inner(
        &self,
        archive_id: &str,
        selection: &AuthoritativeProjectionSelection,
        inject_failure_after_insert: bool,
    ) -> LocalVerificationStoreResult<ArchiveRecord> {
        validate_archive_id(archive_id)?;
        validate_archive_selection_bounds(selection)?;
        let connection = open_connection(&self.database_path)?;
        validate_selection_records(&connection, selection)?;
        drop(connection);
        ensure_projection_archive_migration(&self.database_path)?;

        let manifest = ProjectionArchiveManifest {
            archive_version: ARCHIVE_VERSION.to_owned(),
            archive_id: archive_id.to_owned(),
            selection: selection.clone(),
        };
        let bytes = canonical_json(&manifest, "projection archive manifest")?;
        if bytes.len() as u64 > ARCHIVE_MAX_BYTES {
            return Err(LocalVerificationStoreError::ArchiveTooLarge);
        }
        let record_digest = sha256_hex(&bytes);
        let logical_reference = format!("{ARCHIVE_LOGICAL_PREFIX}{record_digest}");
        let record = ArchiveRecord {
            manifest,
            record_digest: record_digest.clone(),
            logical_reference,
            canonical_bytes: bytes.len() as u64,
        };

        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin archive publication")?;
        require_complete_projection_archive_state(&transaction)?;
        claim_projection_archive_tx(&transaction, archive_id, &record.record_digest, &bytes)?;
        if inject_failure_after_insert {
            return Err(LocalVerificationStoreError::InjectedFailure);
        }
        transaction
            .commit()
            .map_err(|source| db("commit archive publication", source))?;

        // Re-read through the public strict path so persistence never returns a
        // receipt for an unowned, noncanonical, or raced record.
        self.read_projection_archive(archive_id, &record.record_digest)
    }

    /// Reads one exact caller identity/content-address pair, verifies immutable
    /// ownership and canonical bytes, and revalidates every immutable reference
    /// through a read-only SQLite connection.
    pub fn read_projection_archive(
        &self,
        archive_id: &str,
        expected_record_digest: &str,
    ) -> LocalVerificationStoreResult<ArchiveRecord> {
        validate_archive_id(archive_id)?;
        validate_digest(expected_record_digest, "expected archive record digest")?;
        ensure_projection_archive_migration(&self.database_path)?;
        let connection = open_read_only_connection(&self.database_path)?;
        require_complete_projection_archive_state(&connection)?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT canonical_json FROM projection_archives WHERE archive_id=?1 AND record_digest=?2",
                params![archive_id, expected_record_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| db("read exact projection archive", source))?;
        let bytes = bytes.ok_or_else(|| {
            LocalVerificationStoreError::InvalidArchive(
                "archive identity/content-address pair is not owned".to_owned(),
            )
        })?;
        let manifest = decode_archive_manifest(&bytes, expected_record_digest)?;
        if manifest.archive_version != ARCHIVE_VERSION || manifest.archive_id != archive_id {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive manifest identity mismatch".to_owned(),
            ));
        }
        validate_archive_selection_bounds(&manifest.selection)?;
        validate_selection_records(&connection, &manifest.selection)?;
        let canonical_bytes = bytes.len() as u64;
        Ok(ArchiveRecord {
            manifest,
            record_digest: expected_record_digest.to_owned(),
            logical_reference: format!("{ARCHIVE_LOGICAL_PREFIX}{expected_record_digest}"),
            canonical_bytes,
        })
    }

    /// Rebuilds current projections only from the exact archive and exact
    /// caller-supplied selection. Every caller generation must be strictly newer
    /// than its durable allocator, including legitimate rollback to older bytes.
    pub fn recover_projections_from_archive(
        &self,
        archive_id: &str,
        expected_record_digest: &str,
        exact_selection: &AuthoritativeProjectionSelection,
    ) -> LocalVerificationStoreResult<()> {
        self.recover_projections_from_archive_inner(
            archive_id,
            expected_record_digest,
            exact_selection,
            false,
        )
    }

    fn recover_projections_from_archive_inner(
        &self,
        archive_id: &str,
        expected_record_digest: &str,
        exact_selection: &AuthoritativeProjectionSelection,
        inject_failure: bool,
    ) -> LocalVerificationStoreResult<()> {
        let archive = self.read_projection_archive(archive_id, expected_record_digest)?;
        if archive.manifest.selection != *exact_selection {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "caller selection differs from archived selection".to_owned(),
            ));
        }
        let mut connection = open_connection(&self.database_path)?;
        let transaction = begin_immediate(&mut connection, "begin archive recovery")?;
        validate_selection_records(&transaction, exact_selection)?;
        match exact_selection.intent {
            ProjectionRebuildIntent::Genesis => {
                require_pristine_genesis(&transaction)?;
                return transaction
                    .commit()
                    .map_err(|source| db("commit pristine genesis recovery", source));
            }
            ProjectionRebuildIntent::Reset => {
                return Err(LocalVerificationStoreError::InvalidArchive(
                    "reset archives are not recovery authority".to_owned(),
                ));
            }
            ProjectionRebuildIntent::Replace => {
                require_complete_allocator_selection(&transaction, exact_selection)?;
            }
        }
        for current in &exact_selection.capabilities {
            require_fresh_capability_generation(&transaction, current)?;
        }
        for current in &exact_selection.bundles {
            require_fresh_bundle_generation(&transaction, current)?;
        }

        transaction
            .execute("DELETE FROM capability_current", [])
            .map_err(|source| db("clear capability projection for recovery", source))?;
        transaction
            .execute("DELETE FROM bundle_current", [])
            .map_err(|source| db("clear bundle projection for recovery", source))?;
        if inject_failure {
            return Err(LocalVerificationStoreError::InjectedFailure);
        }
        for current in &exact_selection.capabilities {
            write_capability_current(&transaction, current)?;
            persist_capability_generation(&transaction, current)?;
        }
        for current in &exact_selection.bundles {
            write_bundle_current(&transaction, current)?;
            persist_bundle_generation(&transaction, current)?;
        }
        transaction
            .commit()
            .map_err(|source| db("commit archive recovery", source))
    }

    /// Produces a deterministic five-section report using read-only SQL only.
    pub fn local_verification_health(
        &self,
    ) -> LocalVerificationStoreResult<LocalVerificationHealthReport> {
        let connection = open_read_only_connection(&self.database_path)?;
        let capability_record_count = query_count(&connection, "capability_records")?;
        let bundle_record_count = query_count(&connection, "bundle_records")?;
        let capability_current_count = query_count(&connection, "capability_current")?;
        let bundle_current_count = query_count(&connection, "bundle_current")?;

        let immutable_overflow = capability_record_count
            .checked_add(bundle_record_count)
            .is_none_or(|count| count > OPERATOR_MAX_ROWS);
        let current_overflow = capability_current_count
            .checked_add(bundle_current_count)
            .is_none_or(|count| count > OPERATOR_MAX_ROWS);

        let mut immutable_issues = BTreeSet::new();
        let mut current_issues = BTreeSet::new();
        let mut dependency_issues = BTreeSet::new();
        let mut evidence_issues = BTreeSet::new();
        let mut capability_records = BTreeMap::new();
        let mut current_capabilities = BTreeMap::new();

        if immutable_overflow {
            immutable_issues.insert("record_limit_exceeded".to_owned());
        } else {
            for (capability_id, revision) in capability_record_keys(&connection)? {
                match load_capability(&connection, &capability_id, revision) {
                    Ok(Some(record)) => {
                        capability_records.insert((capability_id, revision), record);
                    }
                    _ => {
                        immutable_issues.insert("capability_record_invalid".to_owned());
                    }
                }
            }
            for digest in bundle_record_digests(&connection)? {
                if !matches!(load_bundle_by_digest(&connection, &digest), Ok(Some(_))) {
                    immutable_issues.insert("bundle_record_invalid".to_owned());
                }
            }
        }

        if current_overflow {
            current_issues.insert("projection_limit_exceeded".to_owned());
            dependency_issues.insert("projection_limit_exceeded".to_owned());
            evidence_issues.insert("projection_limit_exceeded".to_owned());
        } else {
            for capability_id in current_capability_ids(&connection)? {
                match load_capability_current(&connection, &capability_id) {
                    Ok(Some(current))
                        if validate_capability_selection(&connection, &current).is_ok()
                            && validate_allocator_at_least_capability(&connection, &current)
                                .is_ok() =>
                    {
                        current_capabilities.insert(capability_id, current);
                    }
                    _ => {
                        current_issues.insert("capability_projection_invalid".to_owned());
                    }
                }
            }
            for key in current_bundle_keys(&connection)? {
                match load_bundle_current(&connection, &key) {
                    Ok(Some(current))
                        if validate_bundle_selection(&connection, &current).is_ok()
                            && validate_allocator_at_least_bundle(&connection, &current)
                                .is_ok() =>
                    {
                        let record = load_bundle_by_digest(&connection, &current.record_digest)?
                            .ok_or_else(|| LocalVerificationStoreError::MissingRecord {
                                kind: "bundle",
                                identity: current.record_digest.clone(),
                            })?;
                        match exact_bundle_capability_fingerprints(
                            &record.bundle.capability_ids,
                            &current_capabilities,
                            &capability_records,
                        ) {
                            Ok((capabilities, commands, policy))
                                if record.bundle.fingerprints.capability_set == capabilities
                                    && record.bundle.fingerprints.command == commands
                                    && record.bundle.fingerprints.policy == policy => {}
                            _ => {
                                evidence_issues.insert("bundle_capability_set_mismatch".to_owned());
                            }
                        }
                    }
                    _ => {
                        current_issues.insert("bundle_projection_invalid".to_owned());
                        evidence_issues.insert("bundle_binding_invalid".to_owned());
                    }
                }
            }
            for current in current_capabilities.values() {
                let Some(record) =
                    capability_records.get(&(current.capability_id.clone(), current.revision))
                else {
                    dependency_issues.insert("current_capability_record_missing".to_owned());
                    continue;
                };
                if record
                    .definition
                    .dependencies
                    .iter()
                    .any(|id| !current_capabilities.contains_key(id))
                {
                    dependency_issues.insert("capability_dependency_not_current".to_owned());
                }
            }
        }

        let immutable = health_section(
            immutable_overflow,
            capability_record_count.saturating_add(bundle_record_count),
            immutable_issues,
        );
        let current = health_section(
            current_overflow,
            capability_current_count.saturating_add(bundle_current_count),
            current_issues,
        );
        let dependencies = health_section(
            current_overflow,
            current_capabilities.len(),
            dependency_issues,
        );
        let evidence = health_section(current_overflow, bundle_current_count, evidence_issues);
        let recovery_is_required = [
            &immutable.state,
            &current.state,
            &dependencies.state,
            &evidence.state,
        ]
        .iter()
        .any(|state| **state != LocalVerificationHealthState::Healthy);
        let recovery = LocalVerificationHealthSection {
            state: if recovery_is_required {
                LocalVerificationHealthState::RecoveryRequired
            } else {
                LocalVerificationHealthState::Healthy
            },
            checked: 0,
            issue_codes: if recovery_is_required {
                vec!["recovery_required".to_owned()]
            } else {
                Vec::new()
            },
        };
        Ok(LocalVerificationHealthReport {
            immutable_record_integrity: immutable,
            current_projection_integrity: current,
            capability_dependency_health: dependencies,
            evidence_binding_health: evidence,
            recovery_required: recovery,
        })
    }
}

fn validate_archive_selection_bounds(
    selection: &AuthoritativeProjectionSelection,
) -> LocalVerificationStoreResult<()> {
    selection.validate()?;
    if selection
        .capabilities
        .len()
        .checked_add(selection.bundles.len())
        .is_none_or(|count| count > OPERATOR_MAX_ROWS)
    {
        return Err(LocalVerificationStoreError::ArchiveTooLarge);
    }
    Ok(())
}

fn validate_selection_records(
    connection: &Connection,
    selection: &AuthoritativeProjectionSelection,
) -> LocalVerificationStoreResult<()> {
    selection.validate()?;
    let selected_ids = selection
        .capabilities
        .iter()
        .map(|current| current.capability_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut selected_currents = BTreeMap::new();
    let mut selected_records = BTreeMap::new();
    for current in &selection.capabilities {
        validate_capability_selection(connection, current)?;
        let record = load_capability(connection, &current.capability_id, current.revision)?
            .ok_or_else(|| LocalVerificationStoreError::MissingRecord {
                kind: "capability",
                identity: format!("{}@{}", current.capability_id, current.revision),
            })?;
        if record
            .definition
            .dependencies
            .iter()
            .any(|dependency| !selected_ids.contains(dependency.as_str()))
        {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                format!(
                    "capability {} has an incomplete selected dependency closure",
                    current.capability_id
                ),
            ));
        }
        selected_currents.insert(current.capability_id.clone(), current.clone());
        selected_records.insert((current.capability_id.clone(), current.revision), record);
    }
    for current in &selection.bundles {
        validate_bundle_selection(connection, current)?;
        let record =
            load_bundle_by_digest(connection, &current.record_digest)?.ok_or_else(|| {
                LocalVerificationStoreError::MissingRecord {
                    kind: "bundle",
                    identity: current.record_digest.clone(),
                }
            })?;
        let (expected_capability_set, expected_command_set, expected_policy) =
            exact_bundle_capability_fingerprints(
                &record.bundle.capability_ids,
                &selected_currents,
                &selected_records,
            )?;
        if record.bundle.fingerprints.capability_set != expected_capability_set
            || record.bundle.fingerprints.command != expected_command_set
            || record.bundle.fingerprints.policy != expected_policy
        {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                format!(
                    "bundle {} differs from the exact selected capability identities or fingerprints",
                    current.bundle_id
                ),
            ));
        }
    }
    Ok(())
}

fn exact_bundle_capability_fingerprints(
    capability_ids: &[String],
    selected_currents: &BTreeMap<String, CapabilityCurrent>,
    selected_records: &BTreeMap<(String, u64), CapabilityRecord>,
) -> LocalVerificationStoreResult<(String, String, String)> {
    let capability_id_set = capability_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut selected_capabilities = Vec::with_capacity(capability_ids.len());
    let mut definitions = Vec::with_capacity(capability_ids.len());
    for capability_id in capability_ids {
        let current = selected_currents.get(capability_id).ok_or_else(|| {
            LocalVerificationStoreError::InvalidProjectionSelection(
                "bundle capability is not present in the exact selected projection".to_owned(),
            )
        })?;
        let record = selected_records
            .get(&(capability_id.clone(), current.revision))
            .ok_or_else(|| LocalVerificationStoreError::MissingRecord {
                kind: "capability",
                identity: format!("{}@{}", capability_id, current.revision),
            })?;
        if record
            .definition
            .dependencies
            .iter()
            .any(|dependency| !capability_id_set.contains(dependency.as_str()))
        {
            return Err(LocalVerificationStoreError::InvalidProjectionSelection(
                "bundle capability set has an incomplete dependency closure".to_owned(),
            ));
        }
        selected_capabilities.push(SelectedCapability {
            capability_id: capability_id.clone(),
            revision: current.revision,
            record_digest: current.record_digest.clone(),
        });
        definitions.push(record.definition.clone());
    }
    let capability_set = verification_selected_capability_set_digest(&selected_capabilities)
        .map_err(|error| LocalVerificationStoreError::InvalidContract {
            contract: "bundle selected capability set",
            detail: error.to_string(),
        })?;
    let command_set = verification_command_set_digest(&definitions).map_err(|error| {
        LocalVerificationStoreError::InvalidContract {
            contract: "bundle selected capability commands",
            detail: error.to_string(),
        }
    })?;
    let policy = verification_policy_digest(&definitions).map_err(|error| {
        LocalVerificationStoreError::InvalidContract {
            contract: "bundle selected capability policy",
            detail: error.to_string(),
        }
    })?;
    Ok((capability_set, command_set, policy))
}

fn require_fresh_capability_generation(
    connection: &Connection,
    current: &CapabilityCurrent,
) -> LocalVerificationStoreResult<()> {
    let durable = load_capability_generation(connection, &current.capability_id)?;
    if durable.is_none() && capability_current_key_exists(connection, &current.capability_id)? {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "existing capability projection is missing its durable allocator".to_owned(),
        ));
    }
    let durable_generation = durable.as_ref().map_or(0, |value| value.generation);
    let valid = durable.as_ref().map_or_else(
        || current.token.generation == 1,
        |value| current.token.generation > value.generation,
    );
    if !valid {
        return Err(
            LocalVerificationStoreError::RecoveryRequiresFreshGeneration {
                key: format!("capability:{}", current.capability_id),
                selected: current.token.generation,
                durable: durable_generation,
            },
        );
    }
    Ok(())
}

fn require_fresh_bundle_generation(
    connection: &Connection,
    current: &EvidenceCurrent,
) -> LocalVerificationStoreResult<()> {
    let durable = load_bundle_generation(connection, &current.key)?;
    if durable.is_none() && bundle_current_key_exists(connection, &current.key)? {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "existing bundle projection is missing its durable allocator".to_owned(),
        ));
    }
    let durable_generation = durable.as_ref().map_or(0, |value| value.generation);
    let valid = durable.as_ref().map_or_else(
        || current.token.generation == 1,
        |value| current.token.generation > value.generation,
    );
    if !valid {
        return Err(
            LocalVerificationStoreError::RecoveryRequiresFreshGeneration {
                key: format!("bundle:{}", evidence_key_label(&current.key)),
                selected: current.token.generation,
                durable: durable_generation,
            },
        );
    }
    Ok(())
}

fn capability_current_key_exists(
    connection: &Connection,
    capability_id: &str,
) -> LocalVerificationStoreResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM capability_current WHERE capability_id=?1 LIMIT 1",
            [capability_id],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|source| db("inspect capability recovery key", source))
}

fn bundle_current_key_exists(
    connection: &Connection,
    key: &EvidenceKey,
) -> LocalVerificationStoreResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM bundle_current WHERE run_id=?1 AND goal_id=?2 AND task_id=?3 LIMIT 1",
            params![
                key.run_id.as_str(),
                key.goal_id.as_str(),
                key.task_id.as_str()
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|source| db("inspect bundle recovery key", source))
}

fn require_pristine_genesis(connection: &Connection) -> LocalVerificationStoreResult<()> {
    for table in [
        "capability_records",
        "bundle_records",
        "capability_current",
        "bundle_current",
        "capability_generations",
        "bundle_generations",
    ] {
        if query_count(connection, table)? != 0 {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "genesis recovery requires pristine empty projections and allocators".to_owned(),
            ));
        }
    }
    Ok(())
}

fn require_complete_allocator_selection(
    connection: &Connection,
    selection: &AuthoritativeProjectionSelection,
) -> LocalVerificationStoreResult<()> {
    let capability_allocator_count = query_count(connection, "capability_generations")?;
    let bundle_allocator_count = query_count(connection, "bundle_generations")?;
    if capability_allocator_count
        .checked_add(bundle_allocator_count)
        .is_none_or(|count| count > OPERATOR_MAX_ROWS)
    {
        return Err(LocalVerificationStoreError::ArchiveTooLarge);
    }

    let selected_capabilities = selection
        .capabilities
        .iter()
        .map(|value| value.capability_id.as_str())
        .collect::<BTreeSet<_>>();
    let selected_bundles = selection
        .bundles
        .iter()
        .map(|value| &value.key)
        .collect::<BTreeSet<_>>();

    for capability_id in capability_generation_ids(connection)?
        .into_iter()
        .chain(current_capability_ids(connection)?)
    {
        if !selected_capabilities.contains(capability_id.as_str()) {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "replace recovery omits a durable capability key".to_owned(),
            ));
        }
    }
    for key in bundle_generation_keys(connection)?
        .into_iter()
        .chain(current_bundle_keys(connection)?)
    {
        if !selected_bundles.contains(&key) {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "replace recovery omits a durable bundle key".to_owned(),
            ));
        }
    }
    Ok(())
}

fn capability_generation_ids(connection: &Connection) -> LocalVerificationStoreResult<Vec<String>> {
    query_strings(
        connection,
        "SELECT capability_id FROM capability_generations ORDER BY capability_id",
        "query capability generation identities",
    )
}

fn bundle_generation_keys(
    connection: &Connection,
) -> LocalVerificationStoreResult<Vec<EvidenceKey>> {
    let mut statement = connection
        .prepare(
            "SELECT run_id, goal_id, task_id FROM bundle_generations ORDER BY run_id, goal_id, task_id",
        )
        .map_err(|source| db("prepare bundle generation identities", source))?;
    let rows = statement
        .query_map([], |row| {
            Ok(EvidenceKey {
                run_id: RunId::from(row.get::<_, String>(0)?),
                goal_id: GoalId::from(row.get::<_, String>(1)?),
                task_id: TaskId::from(row.get::<_, String>(2)?),
            })
        })
        .map_err(|source| db("query bundle generation identities", source))?;
    rows.map(|row| row.map_err(|source| db("read bundle generation identity", source)))
        .collect()
}

fn archive_directory(database_path: &Path) -> LocalVerificationStoreResult<PathBuf> {
    database_path
        .parent()
        .map(|parent| parent.join(ARCHIVE_DIRECTORY))
        .ok_or_else(|| {
            LocalVerificationStoreError::InvalidArchive(
                "database has no local-verification parent".to_owned(),
            )
        })
}

/// Initializes the single transactional archive authority and performs at most
/// one bounded import of the legacy two-file archive layout. Once the marker is
/// committed, filesystem archives are never consulted again.
fn ensure_projection_archive_migration(database_path: &Path) -> LocalVerificationStoreResult<()> {
    if database_path.is_file() {
        let connection = open_read_only_connection(database_path)?;
        match projection_archive_migration_state(&connection)? {
            ProjectionArchiveMigrationState::Complete => return Ok(()),
            ProjectionArchiveMigrationState::Pristine => {}
        }
    }
    let mut connection = open_connection(database_path)?;
    let transaction = begin_immediate(&mut connection, "begin archive legacy migration")?;
    match projection_archive_migration_state(&transaction)? {
        ProjectionArchiveMigrationState::Complete => {
            return transaction
                .commit()
                .map_err(|source| db("commit concurrent archive migration observation", source));
        }
        ProjectionArchiveMigrationState::Pristine => {}
    }
    transaction
        .execute_batch(ARCHIVE_SCHEMA)
        .map_err(|source| db("initialize archive schema extension", source))?;
    let directory = archive_directory(database_path)?;
    for mapping in scan_archive_ownership(&directory)? {
        let bytes = read_archive_bytes(&directory, &mapping.record_digest)?;
        let manifest = decode_archive_manifest(&bytes, &mapping.record_digest)?;
        if manifest.archive_version != ARCHIVE_VERSION || manifest.archive_id != mapping.archive_id
        {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "legacy archive identity mismatch".to_owned(),
            ));
        }
        validate_archive_selection_bounds(&manifest.selection)?;
        validate_selection_records(&transaction, &manifest.selection)?;
        claim_projection_archive_tx(
            &transaction,
            &mapping.archive_id,
            &mapping.record_digest,
            &bytes,
        )?;
    }
    transaction
        .execute(
            "INSERT INTO projection_archive_migration_state (singleton, legacy_import_complete) VALUES (1, 1)",
            [],
        )
        .map_err(|source| db("record archive migration completion", source))?;
    transaction
        .commit()
        .map_err(|source| db("commit archive legacy migration", source))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionArchiveMigrationState {
    Pristine,
    Complete,
}

fn projection_archive_migration_state(
    connection: &Connection,
) -> LocalVerificationStoreResult<ProjectionArchiveMigrationState> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('projection_archives', 'projection_archive_migration_state') ORDER BY name",
        )
        .map_err(|source| db("prepare archive schema state inspection", source))?;
    let table_names: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .map_err(|source| db("inspect archive schema state", source))?
        .map(|row| row.map_err(|source| db("read archive schema state", source)))
        .collect::<LocalVerificationStoreResult<_>>()?;
    drop(statement);

    if table_names.is_empty() {
        return Ok(ProjectionArchiveMigrationState::Pristine);
    }
    if table_names
        != [
            "projection_archive_migration_state".to_owned(),
            "projection_archives".to_owned(),
        ]
    {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive schema extension is partial".to_owned(),
        ));
    }
    validate_projection_archive_table_schema(connection)?;
    validate_projection_archive_marker_schema(connection)?;

    let mut statement = connection
        .prepare(
            "SELECT singleton, legacy_import_complete FROM projection_archive_migration_state ORDER BY singleton",
        )
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker schema is invalid".to_owned(),
            )
        })?;
    let marker_rows: Vec<(i64, i64)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker state is invalid".to_owned(),
            )
        })?
        .collect::<Result<_, _>>()
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker state is invalid".to_owned(),
            )
        })?;
    if marker_rows != [(1, 1)] {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive migration marker must be exactly one valid singleton".to_owned(),
        ));
    }
    Ok(ProjectionArchiveMigrationState::Complete)
}

fn validate_projection_archive_table_schema(
    connection: &Connection,
) -> LocalVerificationStoreResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info('projection_archives')")
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive ownership table schema is invalid".to_owned(),
            )
        })?;
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive ownership table schema is invalid".to_owned(),
            )
        })?
        .collect::<Result<_, _>>()
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive ownership table schema is invalid".to_owned(),
            )
        })?;
    let expected = [
        (0, "archive_id", "TEXT", 1, 1),
        (1, "record_digest", "TEXT", 1, 0),
        (2, "canonical_json", "BLOB", 1, 0),
    ];
    if columns.len() != expected.len()
        || !columns.iter().zip(expected).all(
            |((cid, name, data_type, not_null, default_value, primary_key), expected)| {
                *cid == expected.0
                    && name == expected.1
                    && data_type.eq_ignore_ascii_case(expected.2)
                    && *not_null == expected.3
                    && default_value.is_none()
                    && *primary_key == expected.4
            },
        )
    {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive ownership table does not have the frozen column shape".to_owned(),
        ));
    }

    let digest_unique_indexes: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT il.name
                 FROM pragma_index_list('projection_archives') AS il
                 JOIN pragma_index_info(il.name) AS ii
                 WHERE il.[unique] = 1 AND il.partial = 0
                 GROUP BY il.name
                 HAVING COUNT(*) = 1 AND MIN(ii.name) = 'record_digest' AND MAX(ii.name) = 'record_digest'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive record digest uniqueness schema is invalid".to_owned(),
            )
        })?;
    if digest_unique_indexes != 1 {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive record digest must have exactly one non-partial unique owner index".to_owned(),
        ));
    }
    Ok(())
}

fn validate_projection_archive_marker_schema(
    connection: &Connection,
) -> LocalVerificationStoreResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info('projection_archive_migration_state')")
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker schema is invalid".to_owned(),
            )
        })?;
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker schema is invalid".to_owned(),
            )
        })?
        .collect::<Result<_, _>>()
        .map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive migration marker schema is invalid".to_owned(),
            )
        })?;
    let expected = [
        (0, "singleton", "INTEGER", 1, 1),
        (1, "legacy_import_complete", "INTEGER", 1, 0),
    ];
    if columns.len() != expected.len()
        || !columns.iter().zip(expected).all(
            |((cid, name, data_type, not_null, default_value, primary_key), expected)| {
                *cid == expected.0
                    && name == expected.1
                    && data_type.eq_ignore_ascii_case(expected.2)
                    && *not_null == expected.3
                    && default_value.is_none()
                    && *primary_key == expected.4
            },
        )
    {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive migration marker does not have the frozen column shape".to_owned(),
        ));
    }
    Ok(())
}

fn require_complete_projection_archive_state(
    connection: &Connection,
) -> LocalVerificationStoreResult<()> {
    if projection_archive_migration_state(connection)? != ProjectionArchiveMigrationState::Complete
    {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive schema extension is not complete".to_owned(),
        ));
    }
    Ok(())
}

fn claim_projection_archive_tx(
    transaction: &Transaction<'_>,
    archive_id: &str,
    record_digest: &str,
    canonical_bytes: &[u8],
) -> LocalVerificationStoreResult<bool> {
    let existing_by_id: Option<(String, Vec<u8>)> = transaction
        .query_row(
            "SELECT record_digest, canonical_json FROM projection_archives WHERE archive_id=?1",
            [archive_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| db("read archive identity ownership", source))?;
    if let Some((owned_digest, owned_bytes)) = existing_by_id {
        if owned_digest == record_digest && owned_bytes == canonical_bytes {
            return Ok(false);
        }
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive identity is already owned by different canonical bytes".to_owned(),
        ));
    }

    let existing_digest_owner: Option<String> = transaction
        .query_row(
            "SELECT archive_id FROM projection_archives WHERE record_digest=?1",
            [record_digest],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| db("read archive content-address ownership", source))?;
    if existing_digest_owner.is_some() {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive content address is already owned by a different identity".to_owned(),
        ));
    }

    transaction
        .execute(
            "INSERT INTO projection_archives (archive_id, record_digest, canonical_json) VALUES (?1, ?2, ?3)",
            params![archive_id, record_digest, canonical_bytes],
        )
        .map_err(|source| db("insert projection archive", source))?;
    Ok(true)
}

fn validate_archive_id(archive_id: &str) -> LocalVerificationStoreResult<()> {
    if archive_id.is_empty()
        || archive_id.len() > ARCHIVE_ID_MAX_BYTES
        || !archive_id.is_ascii()
        || !archive_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !archive_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive identity must be a bounded stable ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

fn archive_identity_path(directory: &Path, archive_id: &str) -> PathBuf {
    directory.join(format!("{}.json", sha256_hex(archive_id.as_bytes())))
}

fn scan_archive_ownership(
    directory: &Path,
) -> LocalVerificationStoreResult<Vec<ArchiveIdentityMapping>> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(LocalVerificationStoreError::ArchiveIo {
                operation: "inspect archive directory",
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive directory is not an ordinary directory".to_owned(),
        ));
    }

    let mut record_mappings = Vec::new();
    let mut archive_entries = 0_usize;
    for entry in
        fs::read_dir(directory).map_err(|source| LocalVerificationStoreError::ArchiveIo {
            operation: "scan archive records",
            source,
        })?
    {
        let entry = entry.map_err(|source| LocalVerificationStoreError::ArchiveIo {
            operation: "read archive record entry",
            source,
        })?;
        archive_entries = archive_entries
            .checked_add(1)
            .ok_or(LocalVerificationStoreError::ArchiveTooLarge)?;
        if archive_entries > OPERATOR_MAX_ROWS + 1 {
            return Err(LocalVerificationStoreError::ArchiveTooLarge);
        }
        if entry.file_name() == ARCHIVE_IDENTITY_DIRECTORY {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let record_count = record_mappings
            .len()
            .checked_add(1)
            .ok_or(LocalVerificationStoreError::ArchiveTooLarge)?;
        if record_count > OPERATOR_MAX_ROWS {
            return Err(LocalVerificationStoreError::ArchiveTooLarge);
        }
        let digest = name.strip_suffix(".json").ok_or_else(|| {
            LocalVerificationStoreError::InvalidArchive(
                "archive directory contains an invalid record name".to_owned(),
            )
        })?;
        validate_digest(digest, "archive record file digest")?;
        let entry_metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
            LocalVerificationStoreError::ArchiveIo {
                operation: "inspect archive record entry",
                source,
            }
        })?;
        if entry_metadata.file_type().is_symlink() || !entry_metadata.is_file() {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive record is not an ordinary file".to_owned(),
            ));
        }
        let bytes = read_archive_bytes(directory, digest)?;
        let manifest = decode_archive_manifest(&bytes, digest)?;
        validate_archive_id(&manifest.archive_id)?;
        if manifest.archive_version != ARCHIVE_VERSION {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive record version mismatch".to_owned(),
            ));
        }
        let mapping = ArchiveIdentityMapping {
            archive_id: manifest.archive_id,
            record_digest: digest.to_owned(),
        };
        if record_mappings
            .iter()
            .any(|prior: &ArchiveIdentityMapping| {
                prior.archive_id == mapping.archive_id
                    || prior.record_digest == mapping.record_digest
            })
        {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive record ownership is ambiguous".to_owned(),
            ));
        }
        record_mappings.push(mapping);
    }

    let identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
    let identity_metadata = match fs::symlink_metadata(&identity_directory) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            if record_mappings.is_empty() {
                return Ok(Vec::new());
            }
            return Err(LocalVerificationStoreError::InvalidArchive(
                "legacy archive records have no identity mapping directory".to_owned(),
            ));
        }
        Err(source) => {
            return Err(LocalVerificationStoreError::ArchiveIo {
                operation: "inspect archive identities",
                source,
            });
        }
    };
    if identity_metadata.file_type().is_symlink() || !identity_metadata.is_dir() {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive identity directory is not an ordinary directory".to_owned(),
        ));
    }

    let mut identity_mappings = Vec::new();
    let mut identity_entries = 0_usize;
    for entry in fs::read_dir(&identity_directory).map_err(|source| {
        LocalVerificationStoreError::ArchiveIo {
            operation: "scan archive identities",
            source,
        }
    })? {
        let entry = entry.map_err(|source| LocalVerificationStoreError::ArchiveIo {
            operation: "read archive identity entry",
            source,
        })?;
        identity_entries = identity_entries
            .checked_add(1)
            .ok_or(LocalVerificationStoreError::ArchiveTooLarge)?;
        if identity_entries > OPERATOR_MAX_ROWS {
            return Err(LocalVerificationStoreError::ArchiveTooLarge);
        }
        if identity_mappings.len() >= OPERATOR_MAX_ROWS {
            return Err(LocalVerificationStoreError::ArchiveTooLarge);
        }
        let bytes = read_bounded_file(&entry.path())?;
        std::str::from_utf8(&bytes).map_err(|_| {
            LocalVerificationStoreError::InvalidArchive(
                "archive identity mapping is not strict UTF-8".to_owned(),
            )
        })?;
        let mapping: ArchiveIdentityMapping = serde_json::from_slice(&bytes).map_err(|source| {
            LocalVerificationStoreError::Deserialize {
                kind: "archive identity mapping",
                source,
            }
        })?;
        if canonical_json(&mapping, "archive identity mapping")? != bytes {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive identity mapping is not canonical".to_owned(),
            ));
        }
        validate_archive_id(&mapping.archive_id)?;
        validate_digest(&mapping.record_digest, "archive mapping record digest")?;
        if entry.path() != archive_identity_path(&identity_directory, &mapping.archive_id) {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive identity mapping filename mismatch".to_owned(),
            ));
        }
        if identity_mappings
            .iter()
            .any(|prior: &ArchiveIdentityMapping| {
                prior.archive_id == mapping.archive_id
                    || prior.record_digest == mapping.record_digest
            })
        {
            return Err(LocalVerificationStoreError::InvalidArchive(
                "archive ownership mapping is ambiguous".to_owned(),
            ));
        }
        identity_mappings.push(mapping);
    }
    record_mappings.sort_by(|left, right| {
        (&left.archive_id, &left.record_digest).cmp(&(&right.archive_id, &right.record_digest))
    });
    identity_mappings.sort_by(|left, right| {
        (&left.archive_id, &left.record_digest).cmp(&(&right.archive_id, &right.record_digest))
    });
    if record_mappings != identity_mappings {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "legacy archive records and identity mappings are not an exact bijection".to_owned(),
        ));
    }
    Ok(record_mappings)
}

fn read_archive_bytes(
    directory: &Path,
    record_digest: &str,
) -> LocalVerificationStoreResult<Vec<u8>> {
    let path = directory.join(format!("{record_digest}.json"));
    read_bounded_file(&path)
}

fn decode_archive_manifest(
    bytes: &[u8],
    record_digest: &str,
) -> LocalVerificationStoreResult<ProjectionArchiveManifest> {
    if bytes.len() as u64 > ARCHIVE_MAX_BYTES {
        return Err(LocalVerificationStoreError::ArchiveTooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| {
        LocalVerificationStoreError::InvalidArchive("archive is not strict UTF-8".to_owned())
    })?;
    if sha256_hex(bytes) != record_digest {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive record digest mismatch".to_owned(),
        ));
    }
    let manifest: ProjectionArchiveManifest = serde_json::from_slice(bytes).map_err(|source| {
        LocalVerificationStoreError::Deserialize {
            kind: "projection archive manifest",
            source,
        }
    })?;
    if canonical_json(&manifest, "projection archive manifest")? != bytes {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive manifest bytes are not canonical".to_owned(),
        ));
    }
    Ok(manifest)
}

fn read_bounded_file(path: &Path) -> LocalVerificationStoreResult<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| LocalVerificationStoreError::ArchiveIo {
            operation: "inspect archive file",
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LocalVerificationStoreError::InvalidArchive(
            "archive path is not an ordinary file".to_owned(),
        ));
    }
    let file = File::open(path).map_err(|source| LocalVerificationStoreError::ArchiveIo {
        operation: "open archive",
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(ARCHIVE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| LocalVerificationStoreError::ArchiveIo {
            operation: "read archive",
            source,
        })?;
    if bytes.len() as u64 > ARCHIVE_MAX_BYTES {
        return Err(LocalVerificationStoreError::ArchiveTooLarge);
    }
    Ok(bytes)
}

fn open_read_only_connection(path: &Path) -> LocalVerificationStoreResult<Connection> {
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|source| {
            LocalVerificationStoreError::OpenDatabase {
                path: path.to_path_buf(),
                source,
            }
        })?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(LocalVerificationStoreError::ConfigureDatabase)?;
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

fn query_count(
    connection: &Connection,
    table: &'static str,
) -> LocalVerificationStoreResult<usize> {
    let sql = match table {
        "capability_records" => "SELECT COUNT(*) FROM capability_records",
        "bundle_records" => "SELECT COUNT(*) FROM bundle_records",
        "capability_current" => "SELECT COUNT(*) FROM capability_current",
        "bundle_current" => "SELECT COUNT(*) FROM bundle_current",
        "capability_generations" => "SELECT COUNT(*) FROM capability_generations",
        "bundle_generations" => "SELECT COUNT(*) FROM bundle_generations",
        _ => unreachable!("closed local-verification table set"),
    };
    let count: i64 = connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(|source| db("count local-verification rows", source))?;
    usize::try_from(count).map_err(|_| {
        LocalVerificationStoreError::InvalidProjectionSelection(
            "negative or unrepresentable health row count".to_owned(),
        )
    })
}

fn capability_record_keys(
    connection: &Connection,
) -> LocalVerificationStoreResult<Vec<(String, u64)>> {
    let mut statement = connection
        .prepare("SELECT capability_id, revision FROM capability_records ORDER BY capability_id, revision")
        .map_err(|source| db("prepare capability health records", source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|source| db("query capability health records", source))?;
    rows.map(|row| {
        let (id, revision) = row.map_err(|source| db("read capability health record", source))?;
        Ok((id, stored_u64(revision, "capability revision")?))
    })
    .collect()
}

fn bundle_record_digests(connection: &Connection) -> LocalVerificationStoreResult<Vec<String>> {
    query_strings(
        connection,
        "SELECT digest FROM bundle_records ORDER BY digest",
        "bundle health records",
    )
}

fn current_capability_ids(connection: &Connection) -> LocalVerificationStoreResult<Vec<String>> {
    query_strings(
        connection,
        "SELECT capability_id FROM capability_current ORDER BY capability_id",
        "capability health projections",
    )
}

fn current_bundle_keys(connection: &Connection) -> LocalVerificationStoreResult<Vec<EvidenceKey>> {
    let mut statement = connection
        .prepare(
            "SELECT run_id, goal_id, task_id FROM bundle_current ORDER BY run_id, goal_id, task_id",
        )
        .map_err(|source| db("prepare bundle health projections", source))?;
    let rows = statement
        .query_map([], |row| {
            Ok(EvidenceKey {
                run_id: RunId::from(row.get::<_, String>(0)?),
                goal_id: GoalId::from(row.get::<_, String>(1)?),
                task_id: TaskId::from(row.get::<_, String>(2)?),
            })
        })
        .map_err(|source| db("query bundle health projections", source))?;
    rows.map(|row| row.map_err(|source| db("read bundle health projection", source)))
        .collect()
}

fn query_strings(
    connection: &Connection,
    sql: &'static str,
    operation: &'static str,
) -> LocalVerificationStoreResult<Vec<String>> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|source| db(operation, source))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| db(operation, source))?;
    rows.map(|row| row.map_err(|source| db(operation, source)))
        .collect()
}

fn health_section(
    overflow: bool,
    checked: usize,
    issues: BTreeSet<String>,
) -> LocalVerificationHealthSection {
    LocalVerificationHealthSection {
        state: if overflow {
            LocalVerificationHealthState::LimitExceeded
        } else if issues.is_empty() {
            LocalVerificationHealthState::Healthy
        } else {
            LocalVerificationHealthState::Unhealthy
        },
        checked: u32::try_from(checked).unwrap_or(u32::MAX),
        issue_codes: issues.into_iter().collect(),
    }
}

fn stored_u64(value: i64, field: &str) -> LocalVerificationStoreResult<u64> {
    u64::try_from(value).map_err(|_| {
        LocalVerificationStoreError::InvalidProjectionSelection(format!("{field} is negative"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovca_types::{
        DeniedAccess, DigestAlgorithm, LocalMachinePolicy, ShellPolicy, VerificationCommand,
        WorkingDirectory, LOCAL_VERIFICATION_CONTRACT_VERSION,
    };
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn capability() -> CapabilityDefinition {
        CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "cap.v5.seed".to_owned(),
            revision: 1,
            criterion_ids: vec![],
            dependencies: vec![],
            changed_path_selectors: vec![],
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
                allowed_executable_ids: BTreeSet::from(["test-runner".to_owned()]),
                allowed_environment_names: BTreeSet::new(),
            },
            commands: vec![VerificationCommand {
                command_id: "command.v5.seed".to_owned(),
                executable_id: "test-runner".to_owned(),
                argv: vec!["probe".to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: BTreeSet::new(),
            }],
        }
    }

    fn setup() -> (TempDir, LocalVerificationStore, CapabilityRecord) {
        let root = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(root.path()).unwrap();
        let definition = capability();
        let digest = sha256_hex(&definition.canonical_json_bytes().unwrap());
        let record = match store
            .capability_registry()
            .seed_capability(
                &definition,
                &digest,
                CapabilitySeedPolicy::PublishOnlyNoCurrent,
            )
            .unwrap()
        {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => panic!("first seed must insert"),
        };
        (root, store, record)
    }

    fn applied<T: std::fmt::Debug>(outcome: CasOutcome<T>) -> T {
        match outcome {
            CasOutcome::Applied(value) => value,
            other => panic!("expected applied CAS, got {other:?}"),
        }
    }

    type RawCapabilityProjection = (String, i64, String, i64, String);
    type RawCapabilityAllocator = (String, i64, String);

    fn raw_capability_state(
        connection: &Connection,
    ) -> (Vec<RawCapabilityProjection>, Vec<RawCapabilityAllocator>) {
        let projections = {
            let mut statement = connection
                .prepare(
                    "SELECT capability_id, revision, record_digest, generation, state_digest FROM capability_current ORDER BY capability_id",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let allocators = {
            let mut statement = connection
                .prepare(
                    "SELECT capability_id, max_generation, state_digest FROM capability_generations ORDER BY capability_id",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        (projections, allocators)
    }

    fn raw_archive_rows(connection: &Connection) -> Vec<(String, String, Vec<u8>)> {
        let mut statement = connection
            .prepare(
                "SELECT archive_id, record_digest, canonical_json FROM projection_archives ORDER BY archive_id",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn archive_schema_snapshot(connection: &Connection) -> Vec<(String, String)> {
        let mut statement = connection
            .prepare(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name IN ('projection_archives', 'projection_archive_migration_state') ORDER BY name",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn archive_row_count_if_present(connection: &Connection) -> Option<i64> {
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='projection_archives'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (exists == 1).then(|| {
            connection
                .query_row("SELECT COUNT(*) FROM projection_archives", [], |row| {
                    row.get(0)
                })
                .unwrap()
        })
    }

    fn legacy_tree_snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut snapshot = BTreeMap::new();
        if !directory.exists() {
            return snapshot;
        }
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                snapshot.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            } else if entry.file_name() == ARCHIVE_IDENTITY_DIRECTORY {
                for identity in fs::read_dir(entry.path()).unwrap() {
                    let identity = identity.unwrap();
                    snapshot.insert(
                        format!(
                            "{ARCHIVE_IDENTITY_DIRECTORY}/{}",
                            identity.file_name().to_string_lossy()
                        ),
                        fs::read(identity.path()).unwrap(),
                    );
                }
            }
        }
        snapshot
    }

    fn legacy_manifest(
        record: &CapabilityRecord,
        archive_id: &str,
        generation: u64,
    ) -> (ProjectionArchiveManifest, Vec<u8>, String) {
        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                record.definition.capability_id.clone(),
                record.definition.revision,
                record.digest.clone(),
                generation,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        let manifest = ProjectionArchiveManifest {
            archive_version: ARCHIVE_VERSION.to_owned(),
            archive_id: archive_id.to_owned(),
            selection,
        };
        let bytes = canonical_json(&manifest, "projection archive manifest").unwrap();
        let digest = sha256_hex(&bytes);
        (manifest, bytes, digest)
    }

    fn write_legacy_record(directory: &Path, digest: &str, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(directory).unwrap();
        let path = directory.join(format!("{digest}.json"));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn write_legacy_mapping(directory: &Path, archive_id: &str, record_digest: &str) -> PathBuf {
        let identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
        fs::create_dir_all(&identity_directory).unwrap();
        let path = archive_identity_path(&identity_directory, archive_id);
        fs::write(
            &path,
            canonical_json(
                &ArchiveIdentityMapping {
                    archive_id: archive_id.to_owned(),
                    record_digest: record_digest.to_owned(),
                },
                "archive identity mapping",
            )
            .unwrap(),
        )
        .unwrap();
        path
    }

    #[cfg(windows)]
    fn create_test_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(unix)]
    fn create_test_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[test]
    fn publish_only_seed_is_idempotent_and_never_selects_current() {
        let (_root, store, record) = setup();
        let outcome = store
            .capability_registry()
            .seed_capability(
                &record.definition,
                &record.digest,
                CapabilitySeedPolicy::PublishOnlyNoCurrent,
            )
            .unwrap();
        assert!(matches!(outcome, PublishOutcome::ExistingIdentical(_)));
        assert!(store
            .capability_registry()
            .load_current(&record.definition.capability_id)
            .unwrap()
            .is_none());
        let connection = open_read_only_connection(store.database_path()).unwrap();
        assert!(
            load_capability_generation(&connection, &record.definition.capability_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn seed_rejects_dependency_or_preexisting_current_without_partial_publication() {
        let root = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(root.path()).unwrap();
        let mut incomplete = capability();
        incomplete.capability_id = "cap.v5.incomplete".to_owned();
        incomplete.dependencies = vec!["cap.v5.missing".to_owned()];
        let digest = sha256_hex(&incomplete.canonical_json_bytes().unwrap());
        assert!(matches!(
            store.capability_registry().seed_capability(
                &incomplete,
                &digest,
                CapabilitySeedPolicy::PublishOnlyNoCurrent
            ),
            Err(LocalVerificationStoreError::CapabilitySeedPolicy(_))
        ));
        assert!(store
            .capability_registry()
            .load(&incomplete.capability_id, incomplete.revision)
            .unwrap()
            .is_none());

        let definition = capability();
        let registry = store.capability_registry();
        let record = match registry.publish(&definition).unwrap() {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => unreachable!(),
        };
        assert!(matches!(
            registry
                .compare_and_swap_current(
                    &definition.capability_id,
                    definition.revision,
                    &record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
            CasOutcome::Applied(_)
        ));
        assert!(matches!(
            registry.seed_capability(
                &definition,
                &record.digest,
                CapabilitySeedPolicy::PublishOnlyNoCurrent
            ),
            Err(LocalVerificationStoreError::CapabilitySeedPolicy(_))
        ));
    }

    #[test]
    fn archive_is_idempotent_read_only_and_recovery_requires_fresh_generation() {
        let (_root, store, record) = setup();
        let registry = store.capability_registry();
        let initial = match registry
            .compare_and_swap_current(
                &record.definition.capability_id,
                record.definition.revision,
                &record.digest,
                &ProjectionExpectation::Absent,
            )
            .unwrap()
        {
            CasOutcome::Applied(value) => value,
            other => panic!("unexpected CAS {other:?}"),
        };
        let stale = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![initial.clone()],
            vec![],
        )
        .unwrap();
        let stale_receipt = store
            .persist_projection_archive("archive.v5.stale", &stale)
            .unwrap();
        assert!(matches!(
            store.recover_projections_from_archive(
                &stale_receipt.manifest.archive_id,
                &stale_receipt.record_digest,
                &stale
            ),
            Err(LocalVerificationStoreError::RecoveryRequiresFreshGeneration { .. })
        ));

        let fresh_current = CapabilityCurrent::new(
            initial.capability_id,
            initial.revision,
            initial.record_digest,
            initial.token.generation + 1,
        )
        .unwrap();
        let fresh = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![fresh_current.clone()],
            vec![],
        )
        .unwrap();
        let receipt = store
            .persist_projection_archive("archive.v5.fresh", &fresh)
            .unwrap();
        assert_eq!(
            receipt,
            store
                .persist_projection_archive("archive.v5.fresh", &fresh)
                .unwrap()
        );
        assert_eq!(
            store
                .read_projection_archive(&receipt.manifest.archive_id, &receipt.record_digest)
                .unwrap()
                .manifest
                .selection,
            fresh
        );
        store
            .recover_projections_from_archive(
                &receipt.manifest.archive_id,
                &receipt.record_digest,
                &fresh,
            )
            .unwrap();
        assert_eq!(
            registry
                .load_current(&record.definition.capability_id)
                .unwrap()
                .unwrap(),
            fresh_current
        );
    }

    #[test]
    fn archive_identity_manifest_and_reopen_are_strict_and_immutable() {
        let (_root, store, record) = setup();
        let current = applied(
            store
                .capability_registry()
                .compare_and_swap_current(
                    &record.definition.capability_id,
                    record.definition.revision,
                    &record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );
        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![current.clone()],
            vec![],
        )
        .unwrap();
        let archive = store
            .persist_projection_archive("archive.v5.identity", &selection)
            .unwrap();
        assert_eq!(
            archive.logical_reference,
            format!("{ARCHIVE_LOGICAL_PREFIX}{}", archive.record_digest)
        );
        let manifest = serde_json::to_value(&archive.manifest).unwrap();
        assert_eq!(manifest.as_object().unwrap().len(), 3);
        assert!(manifest.get("record_digest").is_none());
        assert!(manifest.get("payload_digest").is_none());

        let rebound = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                current.capability_id,
                current.revision,
                current.record_digest,
                current.token.generation + 1,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            store.persist_projection_archive("archive.v5.identity", &rebound),
            Err(LocalVerificationStoreError::InvalidArchive(_))
        ));
        for rejected in [
            "C:drive",
            "scheme:value",
            "../escape",
            "slash/value",
            r"back\value",
            "control\nvalue",
        ] {
            assert!(matches!(
                store.persist_projection_archive(rejected, &selection),
                Err(LocalVerificationStoreError::InvalidArchive(_))
            ));
        }
        let oversized_archive_id = "a".repeat(ARCHIVE_ID_MAX_BYTES + 1);
        assert!(matches!(
            store.persist_projection_archive(&oversized_archive_id, &selection),
            Err(LocalVerificationStoreError::InvalidArchive(_))
        ));

        let directory = archive_directory(store.database_path()).unwrap();
        assert!(!directory.exists());
        assert_eq!(
            store
                .persist_projection_archive("archive.v5.identity", &selection)
                .unwrap(),
            archive
        );
        let reopened = LocalVerificationStore::try_new(
            store.database_path().parent().unwrap().parent().unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .read_projection_archive(&archive.manifest.archive_id, &archive.record_digest)
                .unwrap(),
            archive
        );

        // Once the compatible archive migration is marked complete, legacy
        // files are non-authoritative derived data and cannot poison readback.
        let legacy_identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
        fs::create_dir_all(&legacy_identity_directory).unwrap();
        let ignored_mapping = ArchiveIdentityMapping {
            archive_id: "archive.v5.other".to_owned(),
            record_digest: archive.record_digest.clone(),
        };
        fs::write(
            archive_identity_path(&legacy_identity_directory, &ignored_mapping.archive_id),
            canonical_json(&ignored_mapping, "archive identity mapping").unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .read_projection_archive(&archive.manifest.archive_id, &archive.record_digest)
                .unwrap(),
            archive
        );

        let connection = open_connection(reopened.database_path()).unwrap();
        connection
            .execute(
                "UPDATE projection_archives SET canonical_json=?1 WHERE archive_id=?2",
                params![b"{}".as_slice(), archive.manifest.archive_id],
            )
            .unwrap();
        assert!(matches!(
            reopened.read_projection_archive(&archive.manifest.archive_id, &archive.record_digest),
            Err(LocalVerificationStoreError::InvalidArchive(_))
        ));
    }

    #[test]
    fn archive_publication_is_atomic_and_has_no_projection_or_filesystem_side_effects() {
        let (root, store, record) = setup();
        let invalid_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new("cap.v5.missing", 1, "0".repeat(64), 1).unwrap()],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            store.persist_projection_archive("archive.v5.invalid", &invalid_selection),
            Err(LocalVerificationStoreError::MissingRecord { .. })
        ));
        let connection = open_read_only_connection(store.database_path()).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projection_archives', 'projection_archive_migration_state')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);

        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                record.definition.capability_id,
                record.definition.revision,
                record.digest,
                1,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        ensure_projection_archive_migration(store.database_path()).unwrap();
        let connection = open_connection(store.database_path()).unwrap();
        let prior_projection = raw_capability_state(&connection);
        let prior_archives = raw_archive_rows(&connection);
        drop(connection);

        assert!(matches!(
            store.persist_projection_archive_inner("archive.v5.rollback", &selection, true),
            Err(LocalVerificationStoreError::InjectedFailure)
        ));
        let reopened = LocalVerificationStore::try_new(root.path()).unwrap();
        let connection = open_connection(reopened.database_path()).unwrap();
        assert_eq!(raw_capability_state(&connection), prior_projection);
        assert_eq!(raw_archive_rows(&connection), prior_archives);
        assert!(!archive_directory(reopened.database_path())
            .unwrap()
            .exists());
        let digest = sha256_hex(
            &canonical_json(
                &ProjectionArchiveManifest {
                    archive_version: ARCHIVE_VERSION.to_owned(),
                    archive_id: "archive.v5.rollback".to_owned(),
                    selection,
                },
                "projection archive manifest",
            )
            .unwrap(),
        );
        assert!(matches!(
            reopened.read_projection_archive("archive.v5.rollback", &digest),
            Err(LocalVerificationStoreError::InvalidArchive(_))
        ));
    }

    #[test]
    fn archive_publication_serializes_conflicts_and_identical_repeats() {
        let (_root, store, record) = setup();
        let selection_one = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                record.definition.capability_id.clone(),
                record.definition.revision,
                record.digest.clone(),
                1,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        let selection_two = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                record.definition.capability_id,
                record.definition.revision,
                record.digest,
                2,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        let prior_projection =
            raw_capability_state(&open_connection(store.database_path()).unwrap());

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [selection_one.clone(), selection_two]
            .into_iter()
            .map(|selection| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.persist_projection_archive("archive.v5.concurrent-id", &selection)
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(LocalVerificationStoreError::InvalidArchive(_))
                ))
                .count(),
            1
        );

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let selection = selection_one.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.persist_projection_archive("archive.v5.concurrent-identical", &selection)
                })
            })
            .collect();
        let identical: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert_eq!(identical[0], identical[1]);

        // Test the UNIQUE content-address owner directly because archive_id is
        // part of canonical bytes, so a real SHA-256 collision is unavailable.
        let forced_digest = sha256_hex(b"test-only forced archive digest");
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [
            ("archive.v5.collision-a", b"collision-a".to_vec()),
            ("archive.v5.collision-b", b"collision-b".to_vec()),
        ]
        .into_iter()
        .map(|(archive_id, bytes)| {
            let store = store.clone();
            let digest = forced_digest.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || -> LocalVerificationStoreResult<bool> {
                barrier.wait();
                let mut connection = open_connection(store.database_path())?;
                let transaction =
                    begin_immediate(&mut connection, "test archive digest ownership race")?;
                let inserted =
                    claim_projection_archive_tx(&transaction, archive_id, &digest, &bytes)?;
                transaction
                    .commit()
                    .map_err(|source| db("commit archive digest ownership race", source))?;
                Ok(inserted)
            })
        })
        .collect();
        let collision_results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            collision_results
                .iter()
                .filter(|result| result.is_ok())
                .count(),
            1
        );
        assert_eq!(
            collision_results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(LocalVerificationStoreError::InvalidArchive(_))
                ))
                .count(),
            1
        );
        assert_eq!(
            raw_capability_state(&open_connection(store.database_path()).unwrap()),
            prior_projection
        );
        assert!(!archive_directory(store.database_path()).unwrap().exists());
    }

    #[test]
    fn legacy_archive_import_is_transactional_idempotent_and_then_non_authoritative() {
        let root = TempDir::new().unwrap();
        let registry = CapabilityRegistry::try_new(root.path()).unwrap();
        let definition = capability();
        let record = match registry.publish(&definition).unwrap() {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => unreachable!(),
        };
        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![CapabilityCurrent::new(
                definition.capability_id,
                definition.revision,
                record.digest,
                1,
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        let manifest = ProjectionArchiveManifest {
            archive_version: ARCHIVE_VERSION.to_owned(),
            archive_id: "archive.v5.legacy".to_owned(),
            selection,
        };
        let bytes = canonical_json(&manifest, "projection archive manifest").unwrap();
        let digest = sha256_hex(&bytes);

        let connection = open_connection(registry.database_path()).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projection_archives', 'projection_archive_migration_state')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);
        let directory = archive_directory(registry.database_path()).unwrap();
        let identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
        fs::create_dir_all(&identity_directory).unwrap();
        let record_path = directory.join(format!("{digest}.json"));
        let identity_path = archive_identity_path(&identity_directory, &manifest.archive_id);
        fs::write(&record_path, &bytes).unwrap();
        fs::write(
            &identity_path,
            canonical_json(
                &ArchiveIdentityMapping {
                    archive_id: manifest.archive_id.clone(),
                    record_digest: digest.clone(),
                },
                "archive identity mapping",
            )
            .unwrap(),
        )
        .unwrap();

        let store = LocalVerificationStore::try_new(root.path()).unwrap();
        assert_eq!(
            open_read_only_connection(store.database_path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projection_archives', 'projection_archive_migration_state')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let imported = store
            .read_projection_archive(&manifest.archive_id, &digest)
            .unwrap();
        assert_eq!(imported.manifest, manifest);
        let connection = open_connection(store.database_path()).unwrap();
        assert_eq!(raw_archive_rows(&connection).len(), 1);
        assert_eq!(
            connection
                .query_row(
                    "SELECT legacy_import_complete FROM projection_archive_migration_state WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT schema_version FROM local_verification_metadata WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            i64::from(LOCAL_VERIFICATION_STORAGE_SCHEMA_VERSION)
        );
        drop(connection);

        fs::write(&record_path, b"corrupt legacy bytes").unwrap();
        fs::write(&identity_path, b"corrupt legacy mapping").unwrap();
        let database_bytes_before = fs::read(store.database_path()).unwrap();
        let reopened = LocalVerificationStore::try_new(root.path()).unwrap();
        assert_eq!(
            reopened
                .read_projection_archive(&manifest.archive_id, &digest)
                .unwrap(),
            imported
        );
        assert_eq!(
            fs::read(reopened.database_path()).unwrap(),
            database_bytes_before
        );
        assert_eq!(
            raw_archive_rows(&open_connection(reopened.database_path()).unwrap()).len(),
            1
        );
    }

    #[test]
    fn legacy_archive_import_requires_an_exact_bijection_and_rolls_back_every_case() {
        for case in [
            "record_only",
            "mapping_only",
            "mismatch",
            "unknown_record_entry",
            "unknown_identity_entry",
            "corrupt_mapping_bytes",
            "identity_symlink",
            "duplicate_record_identity",
            "duplicate_mapping_digest",
        ] {
            let root = TempDir::new().unwrap();
            let registry = CapabilityRegistry::try_new(root.path()).unwrap();
            let definition = capability();
            let record = match registry.publish(&definition).unwrap() {
                PublishOutcome::Inserted(record) => record,
                PublishOutcome::ExistingIdentical(_) => unreachable!(),
            };
            let (manifest, bytes, digest) = legacy_manifest(&record, "archive.v5.bijection", 1);
            let directory = archive_directory(registry.database_path()).unwrap();
            match case {
                "record_only" => {
                    write_legacy_record(&directory, &digest, &bytes);
                }
                "mapping_only" => {
                    write_legacy_mapping(&directory, &manifest.archive_id, &digest);
                }
                "mismatch" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    write_legacy_mapping(&directory, &manifest.archive_id, &"0".repeat(64));
                }
                "unknown_record_entry" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    write_legacy_mapping(&directory, &manifest.archive_id, &digest);
                    fs::write(directory.join("unknown.entry"), b"unknown").unwrap();
                }
                "unknown_identity_entry" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    write_legacy_mapping(&directory, &manifest.archive_id, &digest);
                    fs::write(
                        directory
                            .join(ARCHIVE_IDENTITY_DIRECTORY)
                            .join("unknown.entry"),
                        b"unknown",
                    )
                    .unwrap();
                }
                "corrupt_mapping_bytes" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    let identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
                    fs::create_dir_all(&identity_directory).unwrap();
                    fs::write(
                        archive_identity_path(&identity_directory, &manifest.archive_id),
                        [0xff, 0xfe],
                    )
                    .unwrap();
                }
                "identity_symlink" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    let identity_directory = directory.join(ARCHIVE_IDENTITY_DIRECTORY);
                    fs::create_dir_all(&identity_directory).unwrap();
                    let target = root.path().join("legacy-mapping-target.json");
                    fs::write(
                        &target,
                        canonical_json(
                            &ArchiveIdentityMapping {
                                archive_id: manifest.archive_id.clone(),
                                record_digest: digest.clone(),
                            },
                            "archive identity mapping",
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    create_test_file_symlink(
                        &target,
                        &archive_identity_path(&identity_directory, &manifest.archive_id),
                    )
                    .unwrap();
                }
                "duplicate_record_identity" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    write_legacy_mapping(&directory, &manifest.archive_id, &digest);
                    let (_, alternate_bytes, alternate_digest) =
                        legacy_manifest(&record, &manifest.archive_id, 2);
                    write_legacy_record(&directory, &alternate_digest, &alternate_bytes);
                }
                "duplicate_mapping_digest" => {
                    write_legacy_record(&directory, &digest, &bytes);
                    write_legacy_mapping(&directory, &manifest.archive_id, &digest);
                    write_legacy_mapping(&directory, "archive.v5.bijection-other", &digest);
                }
                _ => unreachable!(),
            }

            let database_bytes_before = fs::read(registry.database_path()).unwrap();
            let legacy_bytes_before = legacy_tree_snapshot(&directory);
            let connection = open_read_only_connection(registry.database_path()).unwrap();
            let capability_state_before = raw_capability_state(&connection);
            let archive_schema_before = archive_schema_snapshot(&connection);
            drop(connection);
            assert!(archive_schema_before.is_empty());

            let store = LocalVerificationStore::try_new(root.path()).unwrap();
            let error = store
                .read_projection_archive(&manifest.archive_id, &digest)
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    LocalVerificationStoreError::InvalidArchive(_)
                        | LocalVerificationStoreError::Deserialize { .. }
                ),
                "unexpected {case} migration error: {error:?}"
            );
            assert_eq!(
                fs::read(store.database_path()).unwrap(),
                database_bytes_before
            );
            assert_eq!(legacy_tree_snapshot(&directory), legacy_bytes_before);
            let connection = open_read_only_connection(store.database_path()).unwrap();
            assert!(archive_schema_snapshot(&connection).is_empty());
            assert_eq!(archive_row_count_if_present(&connection), None);
            assert_eq!(raw_capability_state(&connection), capability_state_before);
        }
    }

    #[test]
    fn archive_migration_state_rejects_partial_or_invalid_internal_state_without_rescan() {
        for case in [
            "archive_table_only",
            "marker_table_only",
            "both_without_marker",
            "malformed_archive_table",
            "malformed_marker_schema",
            "malformed_marker",
            "extra_marker",
        ] {
            let root = TempDir::new().unwrap();
            let registry = CapabilityRegistry::try_new(root.path()).unwrap();
            let definition = capability();
            let record = match registry.publish(&definition).unwrap() {
                PublishOutcome::Inserted(record) => record,
                PublishOutcome::ExistingIdentical(_) => unreachable!(),
            };
            let (manifest, bytes, digest) = legacy_manifest(&record, "archive.v5.state-machine", 1);
            let directory = archive_directory(registry.database_path()).unwrap();
            write_legacy_record(&directory, &digest, &bytes);
            write_legacy_mapping(&directory, &manifest.archive_id, &digest);

            let connection = open_connection(registry.database_path()).unwrap();
            match case {
                "archive_table_only" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archives (archive_id TEXT PRIMARY KEY NOT NULL, record_digest TEXT NOT NULL UNIQUE, canonical_json BLOB NOT NULL);",
                    )
                    .unwrap(),
                "marker_table_only" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archive_migration_state (singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1), legacy_import_complete INTEGER NOT NULL CHECK (legacy_import_complete = 1));",
                    )
                    .unwrap(),
                "both_without_marker" => connection.execute_batch(ARCHIVE_SCHEMA).unwrap(),
                "malformed_archive_table" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archives (archive_id TEXT PRIMARY KEY NOT NULL, record_digest TEXT NOT NULL, canonical_json TEXT NOT NULL);
                         CREATE TABLE projection_archive_migration_state (singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1), legacy_import_complete INTEGER NOT NULL CHECK (legacy_import_complete = 1));
                         INSERT INTO projection_archive_migration_state VALUES (1, 1);",
                    )
                    .unwrap(),
                "malformed_marker_schema" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archives (archive_id TEXT PRIMARY KEY NOT NULL, record_digest TEXT NOT NULL UNIQUE, canonical_json BLOB NOT NULL);
                         CREATE TABLE projection_archive_migration_state (singleton TEXT, legacy_import_complete TEXT);
                         INSERT INTO projection_archive_migration_state VALUES ('1', '1');",
                    )
                    .unwrap(),
                "malformed_marker" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archives (archive_id TEXT PRIMARY KEY NOT NULL, record_digest TEXT NOT NULL UNIQUE, canonical_json BLOB NOT NULL);
                         CREATE TABLE projection_archive_migration_state (singleton INTEGER PRIMARY KEY NOT NULL, legacy_import_complete INTEGER NOT NULL);
                         INSERT INTO projection_archive_migration_state VALUES (1, 0);",
                    )
                    .unwrap(),
                "extra_marker" => connection
                    .execute_batch(
                        "CREATE TABLE projection_archives (archive_id TEXT PRIMARY KEY NOT NULL, record_digest TEXT NOT NULL UNIQUE, canonical_json BLOB NOT NULL);
                         CREATE TABLE projection_archive_migration_state (singleton INTEGER PRIMARY KEY NOT NULL, legacy_import_complete INTEGER NOT NULL);
                         INSERT INTO projection_archive_migration_state VALUES (1, 1), (2, 1);",
                    )
                    .unwrap(),
                _ => unreachable!(),
            }
            let schema_before = archive_schema_snapshot(&connection);
            let archive_rows_before = archive_row_count_if_present(&connection);
            let capability_state_before = raw_capability_state(&connection);
            drop(connection);
            let database_bytes_before = fs::read(registry.database_path()).unwrap();
            let legacy_bytes_before = legacy_tree_snapshot(&directory);

            let store = LocalVerificationStore::try_new(root.path()).unwrap();
            assert!(matches!(
                store.read_projection_archive(&manifest.archive_id, &digest),
                Err(LocalVerificationStoreError::InvalidArchive(_))
            ));
            assert_eq!(
                fs::read(store.database_path()).unwrap(),
                database_bytes_before
            );
            assert_eq!(legacy_tree_snapshot(&directory), legacy_bytes_before);
            let connection = open_read_only_connection(store.database_path()).unwrap();
            assert_eq!(archive_schema_snapshot(&connection), schema_before);
            assert_eq!(
                archive_row_count_if_present(&connection),
                archive_rows_before
            );
            assert_eq!(raw_capability_state(&connection), capability_state_before);
        }
    }

    #[test]
    fn deleted_marker_never_reimports_postmarker_legacy_files() {
        let root = TempDir::new().unwrap();
        let registry = CapabilityRegistry::try_new(root.path()).unwrap();
        let definition = capability();
        let record = match registry.publish(&definition).unwrap() {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => unreachable!(),
        };
        let (first_manifest, first_bytes, first_digest) =
            legacy_manifest(&record, "archive.v5.marker-first", 1);
        let directory = archive_directory(registry.database_path()).unwrap();
        write_legacy_record(&directory, &first_digest, &first_bytes);
        write_legacy_mapping(&directory, &first_manifest.archive_id, &first_digest);

        let store = LocalVerificationStore::try_new(root.path()).unwrap();
        store
            .read_projection_archive(&first_manifest.archive_id, &first_digest)
            .unwrap();
        let connection = open_connection(store.database_path()).unwrap();
        connection
            .execute("DELETE FROM projection_archive_migration_state", [])
            .unwrap();
        let archive_rows_before = raw_archive_rows(&connection);
        let capability_state_before = raw_capability_state(&connection);
        drop(connection);

        let (second_manifest, second_bytes, second_digest) =
            legacy_manifest(&record, "archive.v5.marker-second", 2);
        write_legacy_record(&directory, &second_digest, &second_bytes);
        write_legacy_mapping(&directory, &second_manifest.archive_id, &second_digest);
        let database_bytes_before = fs::read(store.database_path()).unwrap();
        let legacy_bytes_before = legacy_tree_snapshot(&directory);

        assert!(matches!(
            store.read_projection_archive(&second_manifest.archive_id, &second_digest),
            Err(LocalVerificationStoreError::InvalidArchive(_))
        ));
        assert_eq!(
            fs::read(store.database_path()).unwrap(),
            database_bytes_before
        );
        assert_eq!(legacy_tree_snapshot(&directory), legacy_bytes_before);
        let connection = open_read_only_connection(store.database_path()).unwrap();
        assert_eq!(raw_archive_rows(&connection), archive_rows_before);
        assert_eq!(raw_capability_state(&connection), capability_state_before);
        let marker_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM projection_archive_migration_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker_count, 0);
    }

    #[test]
    fn recovery_rejects_reset_genesis_and_omitted_allocator_keys_without_mutation() {
        let (_root, store, first_record) = setup();
        let registry = store.capability_registry();
        let first = applied(
            registry
                .compare_and_swap_current(
                    &first_record.definition.capability_id,
                    first_record.definition.revision,
                    &first_record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );
        let mut second_definition = capability();
        second_definition.capability_id = "cap.v5.second".to_owned();
        second_definition.commands[0].command_id = "command.v5.second".to_owned();
        let second_record = match registry.publish(&second_definition).unwrap() {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => unreachable!(),
        };
        let second = applied(
            registry
                .compare_and_swap_current(
                    &second_definition.capability_id,
                    second_definition.revision,
                    &second_record.digest,
                    &ProjectionExpectation::Absent,
                )
                .unwrap(),
        );

        for (archive_id, intent) in [
            ("archive.v5.reset", ProjectionRebuildIntent::Reset),
            ("archive.v5.genesis", ProjectionRebuildIntent::Genesis),
        ] {
            let empty = AuthoritativeProjectionSelection::new(intent, vec![], vec![]).unwrap();
            let archive = store
                .persist_projection_archive(archive_id, &empty)
                .unwrap();
            assert!(store
                .recover_projections_from_archive(archive_id, &archive.record_digest, &empty,)
                .is_err());
            assert_eq!(
                registry
                    .load_current(&first_record.definition.capability_id)
                    .unwrap()
                    .unwrap(),
                first
            );
            assert_eq!(
                registry
                    .load_current(&second_definition.capability_id)
                    .unwrap()
                    .unwrap(),
                second
            );
        }

        let omitted = CapabilityCurrent::new(
            first.capability_id.clone(),
            first.revision,
            first.record_digest.clone(),
            first.token.generation + 1,
        )
        .unwrap();
        let omitted_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![omitted],
            vec![],
        )
        .unwrap();
        let omitted_archive = store
            .persist_projection_archive("archive.v5.omitted-capability", &omitted_selection)
            .unwrap();
        assert!(store
            .recover_projections_from_archive(
                &omitted_archive.manifest.archive_id,
                &omitted_archive.record_digest,
                &omitted_selection,
            )
            .is_err());
        assert_eq!(
            registry
                .load_current(&second_definition.capability_id)
                .unwrap()
                .unwrap(),
            second
        );

        let connection = open_connection(store.database_path()).unwrap();
        connection
            .execute(
                "DELETE FROM capability_generations WHERE capability_id=?1",
                [&second_definition.capability_id],
            )
            .unwrap();
        let mut corrupt_allocator_selection = vec![
            CapabilityCurrent::new(
                first.capability_id.clone(),
                first.revision,
                first.record_digest.clone(),
                first.token.generation + 1,
            )
            .unwrap(),
            CapabilityCurrent::new(
                second.capability_id.clone(),
                second.revision,
                second.record_digest.clone(),
                1,
            )
            .unwrap(),
        ];
        corrupt_allocator_selection
            .sort_by(|left, right| left.capability_id.cmp(&right.capability_id));
        let corrupt_allocator_selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            corrupt_allocator_selection,
            vec![],
        )
        .unwrap();
        let corrupt_allocator_archive = store
            .persist_projection_archive(
                "archive.v5.missing-allocator",
                &corrupt_allocator_selection,
            )
            .unwrap();
        let archive_rows_before = raw_archive_rows(&connection);
        let durable_state_before = raw_capability_state(&connection);
        let missing_allocator_error = store
            .recover_projections_from_archive(
                &corrupt_allocator_archive.manifest.archive_id,
                &corrupt_allocator_archive.record_digest,
                &corrupt_allocator_selection,
            )
            .unwrap_err();
        assert_eq!(raw_capability_state(&connection), durable_state_before);
        assert_eq!(raw_archive_rows(&connection), archive_rows_before);
        assert!(
            matches!(
                missing_allocator_error,
                LocalVerificationStoreError::InvalidArchive(_)
            ),
            "unexpected missing-allocator error: {missing_allocator_error:?}"
        );

        let pristine_root = TempDir::new().unwrap();
        let pristine = LocalVerificationStore::try_new(pristine_root.path()).unwrap();
        drop(open_connection(pristine.database_path()).unwrap());
        let genesis =
            AuthoritativeProjectionSelection::new(ProjectionRebuildIntent::Genesis, vec![], vec![])
                .unwrap();
        let genesis_archive = pristine
            .persist_projection_archive("archive.v5.pristine-genesis", &genesis)
            .unwrap();
        pristine
            .recover_projections_from_archive(
                &genesis_archive.manifest.archive_id,
                &genesis_archive.record_digest,
                &genesis,
            )
            .unwrap();
    }

    #[test]
    fn injected_recovery_failure_preserves_prior_current() {
        let (_root, store, record) = setup();
        let registry = store.capability_registry();
        let initial = match registry
            .compare_and_swap_current(
                &record.definition.capability_id,
                record.definition.revision,
                &record.digest,
                &ProjectionExpectation::Absent,
            )
            .unwrap()
        {
            CasOutcome::Applied(value) => value,
            other => panic!("unexpected CAS {other:?}"),
        };
        let replacement = CapabilityCurrent::new(
            initial.capability_id.clone(),
            initial.revision,
            initial.record_digest.clone(),
            initial.token.generation + 1,
        )
        .unwrap();
        let selection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![replacement],
            vec![],
        )
        .unwrap();
        let receipt = store
            .persist_projection_archive("archive.v5.injected", &selection)
            .unwrap();
        assert!(matches!(
            store.recover_projections_from_archive_inner(
                &receipt.manifest.archive_id,
                &receipt.record_digest,
                &selection,
                true
            ),
            Err(LocalVerificationStoreError::InjectedFailure)
        ));
        assert_eq!(
            registry
                .load_current(&record.definition.capability_id)
                .unwrap()
                .unwrap(),
            initial
        );
    }

    #[test]
    fn health_has_exactly_five_closed_sections_and_no_machine_data() {
        let (root, store, _record) = setup();
        let report = store.local_verification_health().unwrap();
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains(&root.path().to_string_lossy().to_string()));
        assert_eq!(
            report.immutable_record_integrity.state,
            LocalVerificationHealthState::Healthy
        );
    }

    #[test]
    fn bundle_fingerprints_bind_only_the_bundle_selected_capability_subset() {
        let (_root, store, first_record) = setup();
        let mut unrelated = capability();
        unrelated.capability_id = "cap.v5.unrelated".to_owned();
        unrelated.commands[0].command_id = "command.v5.unrelated".to_owned();
        let unrelated_record = match store.capability_registry().publish(&unrelated).unwrap() {
            PublishOutcome::Inserted(record) => record,
            PublishOutcome::ExistingIdentical(_) => unreachable!(),
        };
        let first_current = CapabilityCurrent::new(
            first_record.definition.capability_id.clone(),
            first_record.definition.revision,
            first_record.digest.clone(),
            1,
        )
        .unwrap();
        let unrelated_current = CapabilityCurrent::new(
            unrelated_record.definition.capability_id.clone(),
            unrelated_record.definition.revision,
            unrelated_record.digest.clone(),
            1,
        )
        .unwrap();
        let currents = BTreeMap::from([
            (first_current.capability_id.clone(), first_current.clone()),
            (unrelated_current.capability_id.clone(), unrelated_current),
        ]);
        let records = BTreeMap::from([
            (
                (
                    first_record.definition.capability_id.clone(),
                    first_record.definition.revision,
                ),
                first_record.clone(),
            ),
            (
                (
                    unrelated_record.definition.capability_id.clone(),
                    unrelated_record.definition.revision,
                ),
                unrelated_record,
            ),
        ]);
        let actual = exact_bundle_capability_fingerprints(
            std::slice::from_ref(&first_current.capability_id),
            &currents,
            &records,
        )
        .unwrap();
        let expected_selection = vec![SelectedCapability {
            capability_id: first_current.capability_id,
            revision: first_current.revision,
            record_digest: first_current.record_digest,
        }];
        assert_eq!(
            actual,
            (
                verification_selected_capability_set_digest(&expected_selection).unwrap(),
                verification_command_set_digest(std::slice::from_ref(&first_record.definition))
                    .unwrap(),
                verification_policy_digest(std::slice::from_ref(&first_record.definition)).unwrap(),
            )
        );
    }

    #[test]
    fn health_limit_overflow_is_never_reported_healthy() {
        let root = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(root.path()).unwrap();
        let mut connection = open_connection(store.database_path()).unwrap();
        let transaction = begin_immediate(&mut connection, "seed health limit fixture").unwrap();
        for index in 0..=OPERATOR_MAX_ROWS {
            let mut definition = capability();
            definition.capability_id = format!("cap.v5.limit.{index:04}");
            let canonical = definition.canonical_json_bytes().unwrap();
            let digest = sha256_hex(&canonical);
            transaction
                .execute(
                    "INSERT INTO capability_records (capability_id, revision, digest, canonical_json) VALUES (?1, ?2, ?3, ?4)",
                    params![definition.capability_id, 1_i64, digest, canonical],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        let report = store.local_verification_health().unwrap();
        assert_eq!(
            report.immutable_record_integrity.state,
            LocalVerificationHealthState::LimitExceeded
        );
        assert_eq!(
            report.recovery_required.state,
            LocalVerificationHealthState::RecoveryRequired
        );
    }
}
