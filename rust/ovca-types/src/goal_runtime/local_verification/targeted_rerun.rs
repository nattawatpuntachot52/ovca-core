//! Pure deterministic targeted-rerun selection and failure-classification rules.
//!
//! This module accepts only caller-provided logical paths and immutable Registry
//! facts. It performs no I/O, does not inspect Git or the host, and never grants
//! completion authority.

use super::{
    invalid, validate_digest, validate_logical_path, validate_stable_id, CapabilityDefinition,
    FailureConfirmation, LocalVerificationResult, PathSelectorKind, VerificationFailure,
    VerificationFailureCategory, LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use crate::{ContractVersion, GoalId, RunId, TaskId, WorkerId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangedPathKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPathEntry {
    pub kind: ChangedPathKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPathManifest {
    pub entries: Vec<ChangedPathEntry>,
}

impl ChangedPathManifest {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        let mut prior: Option<(&str, ChangedPathKind, &str)> = None;
        let mut affected_paths = BTreeSet::new();
        for entry in &self.entries {
            validate_logical_path(&entry.path)?;
            match (entry.kind, &entry.previous_path) {
                (ChangedPathKind::Renamed, Some(previous_path)) => {
                    validate_logical_path(previous_path)?;
                    if previous_path == &entry.path {
                        return Err(invalid(
                            "invalid_changed_path_manifest",
                            "rename source and destination must differ",
                        ));
                    }
                }
                (ChangedPathKind::Renamed, None) => {
                    return Err(invalid(
                        "invalid_changed_path_manifest",
                        "rename entries require previous_path",
                    ));
                }
                (_, Some(_)) => {
                    return Err(invalid(
                        "invalid_changed_path_manifest",
                        "previous_path is valid only for rename entries",
                    ));
                }
                (_, None) => {}
            }

            let key = (
                entry.path.as_str(),
                entry.kind,
                entry.previous_path.as_deref().unwrap_or(""),
            );
            if prior.is_some_and(|value| value >= key) {
                return Err(invalid(
                    "invalid_changed_path_manifest",
                    "changed paths must be strictly sorted and unique",
                ));
            }
            prior = Some(key);

            if !affected_paths.insert(entry.path.as_str()) {
                return Err(invalid(
                    "invalid_changed_path_manifest",
                    format!("duplicate affected path {}", entry.path),
                ));
            }
            if let Some(previous_path) = &entry.previous_path {
                if !affected_paths.insert(previous_path.as_str()) {
                    return Err(invalid(
                        "invalid_changed_path_manifest",
                        format!("duplicate affected path {previous_path}"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))
    }

    fn logical_paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().flat_map(|entry| {
            std::iter::once(entry.path.as_str()).chain(entry.previous_path.as_deref())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownPathPolicy {
    FullSafe,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRegistryRow {
    pub definition: CapabilityDefinition,
    pub record_digest: String,
    pub generation: u64,
    pub state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRegistrySnapshot {
    pub capabilities: Vec<CapabilityRegistryRow>,
    pub registry_snapshot_digest: String,
}

#[derive(Serialize)]
struct CapabilityStateDigest<'a> {
    capability_id: &'a str,
    revision: u64,
    record_digest: &'a str,
    generation: u64,
}

#[derive(Serialize)]
struct RegistryIdentity<'a> {
    capability_id: &'a str,
    revision: u64,
    record_digest: &'a str,
    generation: u64,
    state_digest: &'a str,
}

#[derive(Serialize)]
struct RegistryDigestPayload<'a> {
    capabilities: Vec<RegistryIdentity<'a>>,
}

impl CapabilityRegistrySnapshot {
    pub fn new(capabilities: Vec<CapabilityRegistryRow>) -> LocalVerificationResult<Self> {
        let registry_snapshot_digest = registry_snapshot_digest(&capabilities)?;
        let value = Self {
            capabilities,
            registry_snapshot_digest,
        };
        value.validate_rows()?;
        Ok(value)
    }

    pub fn validate(&self) -> LocalVerificationResult<()> {
        self.validate_rows()?;
        validate_digest(&self.registry_snapshot_digest, "registry_snapshot_digest")?;
        if registry_snapshot_digest(&self.capabilities)? != self.registry_snapshot_digest {
            return Err(invalid(
                "inconsistent_registry_snapshot",
                "registry snapshot digest mismatch",
            ));
        }
        Ok(())
    }

    fn validate_rows(&self) -> LocalVerificationResult<()> {
        let mut prior_id: Option<&str> = None;
        for row in &self.capabilities {
            row.definition.validate()?;
            if prior_id.is_some_and(|prior| prior >= row.definition.capability_id.as_str()) {
                return Err(invalid(
                    "duplicate_or_noncanonical_current_identity",
                    "current capabilities must be strictly sorted by capability_id",
                ));
            }
            prior_id = Some(row.definition.capability_id.as_str());
            validate_digest(&row.record_digest, "capability_record_digest")?;
            validate_digest(&row.state_digest, "capability_state_digest")?;
            if row.generation == 0 {
                return Err(invalid(
                    "invalid_capability_generation",
                    "current capability generation must be greater than zero",
                ));
            }
            let canonical = row.definition.canonical_json_bytes()?;
            if sha256_hex(&canonical) != row.record_digest {
                return Err(invalid(
                    "inconsistent_registry_snapshot",
                    format!(
                        "record digest mismatch for {}",
                        row.definition.capability_id
                    ),
                ));
            }
            let state = serde_json::to_vec(&CapabilityStateDigest {
                capability_id: &row.definition.capability_id,
                revision: row.definition.revision,
                record_digest: &row.record_digest,
                generation: row.generation,
            })
            .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
            if sha256_hex(&state) != row.state_digest {
                return Err(invalid(
                    "inconsistent_registry_snapshot",
                    format!("state digest mismatch for {}", row.definition.capability_id),
                ));
            }
        }
        Ok(())
    }
}

pub fn registry_snapshot_digest(
    capabilities: &[CapabilityRegistryRow],
) -> LocalVerificationResult<String> {
    let payload = RegistryDigestPayload {
        capabilities: capabilities
            .iter()
            .map(|row| RegistryIdentity {
                capability_id: &row.definition.capability_id,
                revision: row.definition.revision,
                record_digest: &row.record_digest,
                generation: row.generation,
                state_digest: &row.state_digest,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetedRerunRequest {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub source_fingerprint: String,
    pub policy_digest: String,
    pub changed_paths: ChangedPathManifest,
    pub unknown_path_policy: UnknownPathPolicy,
}

impl TargetedRerunRequest {
    fn validate(&self) -> LocalVerificationResult<()> {
        if self.contract_version != LOCAL_VERIFICATION_CONTRACT_VERSION {
            return Err(invalid(
                "unsupported_contract_version",
                "targeted rerun request must use the local verification contract version",
            ));
        }
        validate_stable_id(self.run_id.as_str(), "run_id")?;
        validate_stable_id(self.goal_id.as_str(), "goal_id")?;
        validate_stable_id(self.task_id.as_str(), "task_id")?;
        validate_digest(&self.source_fingerprint, "source_fingerprint")?;
        validate_digest(&self.policy_digest, "policy_digest")?;
        self.changed_paths.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetedRerunMode {
    Targeted,
    FullSafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedCapability {
    pub capability_id: String,
    pub revision: u64,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetedRerunSelection {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub source_fingerprint: String,
    pub policy_digest: String,
    pub unknown_path_policy: UnknownPathPolicy,
    pub registry_snapshot_digest: String,
    pub changed_path_manifest: ChangedPathManifest,
    pub changed_path_manifest_digest: String,
    pub mode: TargetedRerunMode,
    pub unknown_paths: Vec<String>,
    pub capabilities: Vec<SelectedCapability>,
    pub selection_digest: String,
}

#[derive(Serialize)]
struct SelectionDigestPayload<'a> {
    contract_version: ContractVersion,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    source_fingerprint: &'a str,
    policy_digest: &'a str,
    unknown_path_policy: UnknownPathPolicy,
    registry_snapshot_digest: &'a str,
    changed_path_manifest: &'a ChangedPathManifest,
    changed_path_manifest_digest: &'a str,
    mode: TargetedRerunMode,
    unknown_paths: &'a [String],
    capabilities: &'a [SelectedCapability],
}

impl TargetedRerunSelection {
    fn new(
        request: &TargetedRerunRequest,
        snapshot: &CapabilityRegistrySnapshot,
        mode: TargetedRerunMode,
        unknown_paths: Vec<String>,
        capabilities: Vec<SelectedCapability>,
    ) -> LocalVerificationResult<Self> {
        let changed_path_manifest_digest =
            sha256_hex(&request.changed_paths.canonical_json_bytes()?);
        let mut value = Self {
            contract_version: request.contract_version,
            run_id: request.run_id.clone(),
            goal_id: request.goal_id.clone(),
            task_id: request.task_id.clone(),
            source_fingerprint: request.source_fingerprint.clone(),
            policy_digest: request.policy_digest.clone(),
            unknown_path_policy: request.unknown_path_policy,
            registry_snapshot_digest: snapshot.registry_snapshot_digest.clone(),
            changed_path_manifest: request.changed_paths.clone(),
            changed_path_manifest_digest,
            mode,
            unknown_paths,
            capabilities,
            selection_digest: String::new(),
        };
        value.selection_digest = value.expected_selection_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn expected_selection_digest(&self) -> LocalVerificationResult<String> {
        let bytes = serde_json::to_vec(&SelectionDigestPayload {
            contract_version: self.contract_version,
            run_id: &self.run_id,
            goal_id: &self.goal_id,
            task_id: &self.task_id,
            source_fingerprint: &self.source_fingerprint,
            policy_digest: &self.policy_digest,
            unknown_path_policy: self.unknown_path_policy,
            registry_snapshot_digest: &self.registry_snapshot_digest,
            changed_path_manifest: &self.changed_path_manifest,
            changed_path_manifest_digest: &self.changed_path_manifest_digest,
            mode: self.mode,
            unknown_paths: &self.unknown_paths,
            capabilities: &self.capabilities,
        })
        .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    pub fn validate(&self) -> LocalVerificationResult<()> {
        if self.contract_version != LOCAL_VERIFICATION_CONTRACT_VERSION {
            return Err(invalid(
                "unsupported_contract_version",
                "targeted rerun selection must use the local verification contract version",
            ));
        }
        validate_stable_id(self.run_id.as_str(), "run_id")?;
        validate_stable_id(self.goal_id.as_str(), "goal_id")?;
        validate_stable_id(self.task_id.as_str(), "task_id")?;
        validate_digest(&self.source_fingerprint, "source_fingerprint")?;
        validate_digest(&self.policy_digest, "policy_digest")?;
        validate_digest(&self.registry_snapshot_digest, "registry_snapshot_digest")?;
        self.changed_path_manifest.validate()?;
        validate_digest(
            &self.changed_path_manifest_digest,
            "changed_path_manifest_digest",
        )?;
        if sha256_hex(&self.changed_path_manifest.canonical_json_bytes()?)
            != self.changed_path_manifest_digest
        {
            return Err(invalid(
                "changed_path_manifest_digest_mismatch",
                "changed path manifest digest mismatch",
            ));
        }

        let manifest_paths: BTreeSet<&str> = self.changed_path_manifest.logical_paths().collect();
        let mut prior_unknown: Option<&str> = None;
        for path in &self.unknown_paths {
            validate_logical_path(path)?;
            if prior_unknown.is_some_and(|prior| prior >= path.as_str()) {
                return Err(invalid(
                    "noncanonical_unknown_paths",
                    "unknown paths must be strictly sorted and unique",
                ));
            }
            if !manifest_paths.contains(path.as_str()) {
                return Err(invalid("unknown_path_not_in_manifest", path.clone()));
            }
            prior_unknown = Some(path);
        }

        if self.capabilities.is_empty() {
            return Err(invalid(
                "empty_targeted_rerun_selection",
                "selected capabilities must not be empty",
            ));
        }
        let mut prior_capability: Option<&str> = None;
        for capability in &self.capabilities {
            validate_stable_id(&capability.capability_id, "capability_id")?;
            if prior_capability.is_some_and(|prior| prior >= capability.capability_id.as_str()) {
                return Err(invalid(
                    "noncanonical_selected_capabilities",
                    "selected capabilities must be strictly sorted and unique",
                ));
            }
            if capability.revision == 0 {
                return Err(invalid(
                    "invalid_capability_revision",
                    capability.capability_id.clone(),
                ));
            }
            validate_digest(&capability.record_digest, "capability_record_digest")?;
            prior_capability = Some(&capability.capability_id);
        }

        match self.mode {
            TargetedRerunMode::Targeted if !self.unknown_paths.is_empty() => {
                return Err(invalid(
                    "targeted_mode_has_unknown_paths",
                    "targeted mode requires an empty unknown path set",
                ));
            }
            TargetedRerunMode::FullSafe
                if self.unknown_path_policy != UnknownPathPolicy::FullSafe =>
            {
                return Err(invalid(
                    "full_safe_mode_requires_policy",
                    "full-safe mode requires the full-safe unknown path policy",
                ));
            }
            TargetedRerunMode::FullSafe if self.unknown_paths.is_empty() => {
                return Err(invalid(
                    "full_safe_mode_requires_unknown_paths",
                    "full-safe mode requires a nonempty unknown path set",
                ));
            }
            _ => {}
        }

        validate_digest(&self.selection_digest, "selection_digest")?;
        if self.expected_selection_digest()? != self.selection_digest {
            return Err(invalid(
                "selection_digest_mismatch",
                "targeted rerun selection digest mismatch",
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        request: &TargetedRerunRequest,
        snapshot: &CapabilityRegistrySnapshot,
    ) -> LocalVerificationResult<()> {
        self.validate()?;
        request.validate()?;
        snapshot.validate()?;
        match select_targeted_rerun(request, snapshot) {
            TargetedRerunOutcome::Selected { selection } if selection.as_ref() == self => Ok(()),
            _ => Err(invalid(
                "selection_context_mismatch",
                "selection is not the exact deterministic result for the supplied request and registry snapshot",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoApplicableCapabilityReason {
    #[serde(rename = "ZERO_CHANGED_PATHS")]
    ZeroChangedPaths,
    #[serde(rename = "NO_DIRECT_MATCH")]
    NoDirectMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetedRerunBlockCode {
    #[serde(rename = "BLOCKED_INVALID_REQUEST")]
    InvalidRequest,
    #[serde(rename = "BLOCKED_INVALID_MANIFEST")]
    InvalidManifest,
    #[serde(rename = "BLOCKED_INCONSISTENT_REGISTRY")]
    InconsistentRegistry,
    #[serde(rename = "BLOCKED_DUPLICATE_CURRENT_IDENTITY")]
    DuplicateCurrentIdentity,
    #[serde(rename = "BLOCKED_MISSING_DEPENDENCY")]
    MissingDependency,
    #[serde(rename = "BLOCKED_DEPENDENCY_CYCLE")]
    DependencyCycle,
    #[serde(rename = "BLOCKED_UNKNOWN_PATH")]
    UnknownPath,
    #[serde(rename = "BLOCKED_EMPTY_REGISTRY")]
    EmptyRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetedRerunOutcome {
    Selected {
        selection: Box<TargetedRerunSelection>,
    },
    #[serde(rename = "NO_APPLICABLE_CAPABILITY")]
    NoApplicableCapability {
        reason: NoApplicableCapabilityReason,
    },
    Blocked {
        code: TargetedRerunBlockCode,
        detail: String,
    },
}

pub fn select_targeted_rerun(
    request: &TargetedRerunRequest,
    snapshot: &CapabilityRegistrySnapshot,
) -> TargetedRerunOutcome {
    if let Err(error) = request.validate() {
        let code = if error.code == "invalid_changed_path_manifest"
            || error.code == "unsafe_logical_path"
        {
            TargetedRerunBlockCode::InvalidManifest
        } else {
            TargetedRerunBlockCode::InvalidRequest
        };
        return blocked(code, error.to_string());
    }
    if let Err(error) = snapshot.validate() {
        let code = if error.code == "duplicate_or_noncanonical_current_identity" {
            TargetedRerunBlockCode::DuplicateCurrentIdentity
        } else {
            TargetedRerunBlockCode::InconsistentRegistry
        };
        return blocked(code, error.to_string());
    }
    if let Err((code, detail)) = validate_dependency_graph(&snapshot.capabilities) {
        return blocked(code, detail);
    }
    if request.changed_paths.entries.is_empty() {
        return TargetedRerunOutcome::NoApplicableCapability {
            reason: NoApplicableCapabilityReason::ZeroChangedPaths,
        };
    }
    if snapshot.capabilities.is_empty() {
        return match request.unknown_path_policy {
            UnknownPathPolicy::FullSafe => blocked(
                TargetedRerunBlockCode::EmptyRegistry,
                "full-safe selection cannot run an empty registry",
            ),
            UnknownPathPolicy::Blocked => blocked(
                TargetedRerunBlockCode::UnknownPath,
                "no current capability recognizes the changed paths",
            ),
        };
    }

    let by_id: BTreeMap<&str, &CapabilityRegistryRow> = snapshot
        .capabilities
        .iter()
        .map(|row| (row.definition.capability_id.as_str(), row))
        .collect();
    let mut direct = BTreeSet::new();
    let mut unknown_paths = BTreeSet::new();
    for path in request.changed_paths.logical_paths() {
        let matches: Vec<&str> = snapshot
            .capabilities
            .iter()
            .filter(|row| {
                row.definition
                    .changed_path_selectors
                    .iter()
                    .any(|selector| selector_matches(selector.kind, &selector.path, path))
            })
            .map(|row| row.definition.capability_id.as_str())
            .collect();
        if matches.is_empty() {
            unknown_paths.insert(path.to_owned());
        } else {
            direct.extend(matches);
        }
    }

    let unknown_paths: Vec<String> = unknown_paths.into_iter().collect();
    let (mode, selected_ids) = if unknown_paths.is_empty() {
        if direct.is_empty() {
            return TargetedRerunOutcome::NoApplicableCapability {
                reason: NoApplicableCapabilityReason::NoDirectMatch,
            };
        }
        let selected = match selection_closure(&direct, &by_id) {
            Ok(selected) => selected,
            Err(detail) => {
                return blocked(TargetedRerunBlockCode::InconsistentRegistry, detail);
            }
        };
        (TargetedRerunMode::Targeted, selected)
    } else {
        match request.unknown_path_policy {
            UnknownPathPolicy::Blocked => {
                return blocked(
                    TargetedRerunBlockCode::UnknownPath,
                    format!("unrecognized changed paths: {}", unknown_paths.join(",")),
                );
            }
            UnknownPathPolicy::FullSafe => (
                TargetedRerunMode::FullSafe,
                by_id.keys().map(|id| (*id).to_owned()).collect(),
            ),
        }
    };

    let mut capabilities = Vec::with_capacity(selected_ids.len());
    for capability_id in selected_ids {
        let Some(row) = by_id.get(capability_id.as_str()) else {
            return blocked(
                TargetedRerunBlockCode::InconsistentRegistry,
                format!("closure references missing capability {capability_id}"),
            );
        };
        capabilities.push(SelectedCapability {
            capability_id,
            revision: row.definition.revision,
            record_digest: row.record_digest.clone(),
        });
    }
    match TargetedRerunSelection::new(request, snapshot, mode, unknown_paths, capabilities) {
        Ok(selection) => TargetedRerunOutcome::Selected {
            selection: Box::new(selection),
        },
        Err(error) => blocked(
            TargetedRerunBlockCode::InconsistentRegistry,
            error.to_string(),
        ),
    }
}

fn blocked(code: TargetedRerunBlockCode, detail: impl Into<String>) -> TargetedRerunOutcome {
    TargetedRerunOutcome::Blocked {
        code,
        detail: detail.into(),
    }
}

fn selector_matches(kind: PathSelectorKind, selector: &str, path: &str) -> bool {
    match kind {
        PathSelectorKind::Exact => path == selector,
        PathSelectorKind::Prefix => {
            path == selector
                || path
                    .strip_prefix(selector)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
    }
}

fn validate_dependency_graph(
    rows: &[CapabilityRegistryRow],
) -> Result<(), (TargetedRerunBlockCode, String)> {
    let ids: BTreeSet<&str> = rows
        .iter()
        .map(|row| row.definition.capability_id.as_str())
        .collect();
    for row in rows {
        for dependency in &row.definition.dependencies {
            if !ids.contains(dependency.as_str()) {
                return Err((
                    TargetedRerunBlockCode::MissingDependency,
                    format!(
                        "{} depends on missing {}",
                        row.definition.capability_id, dependency
                    ),
                ));
            }
        }
    }

    let dependencies: BTreeMap<&str, &[String]> = rows
        .iter()
        .map(|row| {
            (
                row.definition.capability_id.as_str(),
                row.definition.dependencies.as_slice(),
            )
        })
        .collect();
    let mut state: BTreeMap<&str, u8> = ids.iter().map(|id| (*id, 0)).collect();
    for id in &ids {
        if visit_dependency(id, &dependencies, &mut state) {
            return Err((
                TargetedRerunBlockCode::DependencyCycle,
                format!("dependency cycle includes {id}"),
            ));
        }
    }
    Ok(())
}

fn visit_dependency<'a>(
    id: &'a str,
    dependencies: &BTreeMap<&'a str, &'a [String]>,
    state: &mut BTreeMap<&'a str, u8>,
) -> bool {
    match state.get(id).copied().unwrap_or_default() {
        1 => return true,
        2 => return false,
        _ => {}
    }
    state.insert(id, 1);
    for dependency in dependencies.get(id).copied().unwrap_or_default() {
        if visit_dependency(dependency, dependencies, state) {
            return true;
        }
    }
    state.insert(id, 2);
    false
}

fn selection_closure(
    direct: &BTreeSet<&str>,
    by_id: &BTreeMap<&str, &CapabilityRegistryRow>,
) -> Result<BTreeSet<String>, String> {
    let mut impacted: BTreeSet<String> = direct.iter().map(|id| (*id).to_owned()).collect();
    loop {
        let before = impacted.len();
        for (candidate_id, row) in by_id {
            if row
                .definition
                .dependencies
                .iter()
                .any(|dependency| impacted.contains(dependency))
            {
                impacted.insert((*candidate_id).to_owned());
            }
        }
        if impacted.len() == before {
            break;
        }
    }

    let mut selected = impacted.clone();
    let mut pending: Vec<String> = impacted.into_iter().collect();
    while let Some(capability_id) = pending.pop() {
        let Some(row) = by_id.get(capability_id.as_str()) else {
            return Err(format!(
                "closure references missing capability {capability_id}"
            ));
        };
        for dependency in &row.definition.dependencies {
            if selected.insert(dependency.clone()) {
                pending.push(dependency.clone());
            }
        }
    }
    Ok(selected)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifiedVerificationFailure {
    pub failure: VerificationFailure,
    pub classifier_actor: WorkerId,
}

impl ClassifiedVerificationFailure {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        self.failure.validate()?;
        if self.failure.recorded_at.timestamp_subsec_nanos() % 1_000 != 0 {
            return Err(invalid(
                "recorded_at_exceeds_microsecond_precision",
                self.failure.failure_id.clone(),
            ));
        }
        validate_stable_id(self.classifier_actor.as_str(), "classifier_actor")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureOwnerBinding {
    ImplementationActor,
    VerifierActor,
    CapabilityOwner,
    TestOwner,
    Coordinator,
    ConfirmationOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureRouteDirective {
    Retry,
    AwaitingConfirmation,
    EscalateToOwner,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureOwnerBindings {
    pub implementation_actor: Option<WorkerId>,
    pub verifier_actor: Option<WorkerId>,
    pub capability_owner: Option<WorkerId>,
    pub test_owner: Option<WorkerId>,
    pub coordinator: Option<WorkerId>,
    pub confirmation_owner: Option<WorkerId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationFailureRoute {
    pub directive: FailureRouteDirective,
    pub category: VerificationFailureCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_binding: Option<FailureOwnerBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_owner: Option<WorkerId>,
    pub reason: String,
}

pub const fn failure_owner_binding(category: VerificationFailureCategory) -> FailureOwnerBinding {
    match category {
        VerificationFailureCategory::ProductBug => FailureOwnerBinding::CapabilityOwner,
        VerificationFailureCategory::TestFragility => FailureOwnerBinding::TestOwner,
        VerificationFailureCategory::SourceDrift => FailureOwnerBinding::ImplementationActor,
        VerificationFailureCategory::PolicyBlock
        | VerificationFailureCategory::ContractViolation => FailureOwnerBinding::VerifierActor,
        VerificationFailureCategory::Timeout
        | VerificationFailureCategory::Environment
        | VerificationFailureCategory::Infrastructure
        | VerificationFailureCategory::TestFailedUnclassified => FailureOwnerBinding::Coordinator,
    }
}

pub fn route_classified_verification_failure(
    failure: &ClassifiedVerificationFailure,
    prior_failure: Option<&ClassifiedVerificationFailure>,
    bindings: &FailureOwnerBindings,
    retry_permitted: bool,
) -> VerificationFailureRoute {
    let blocked = |owner_binding, reason: String| VerificationFailureRoute {
        directive: FailureRouteDirective::Blocked,
        category: failure.failure.category,
        owner_binding,
        target_owner: None,
        reason,
    };

    let classifications = prior_failure
        .into_iter()
        .chain(std::iter::once(failure))
        .cloned()
        .collect::<Vec<_>>();
    if let Err(error) = validate_failure_classifications(&classifications) {
        return blocked(None, error.to_string());
    }

    for (binding, actor) in [
        (
            FailureOwnerBinding::ImplementationActor,
            bindings.implementation_actor.as_ref(),
        ),
        (
            FailureOwnerBinding::VerifierActor,
            bindings.verifier_actor.as_ref(),
        ),
    ] {
        let Some(actor) = actor else {
            return blocked(
                Some(binding),
                format!(
                    "missing required {} binding",
                    failure_owner_binding_name(binding)
                ),
            );
        };
        if let Err(error) = validate_stable_id(actor.as_str(), failure_owner_binding_name(binding))
        {
            return blocked(Some(binding), error.to_string());
        }
    }
    if bindings.implementation_actor == bindings.verifier_actor {
        return blocked(
            None,
            "implementation_actor and verifier_actor must differ".to_owned(),
        );
    }

    let (directive, owner_binding) = if failure.failure.confirmation
        == FailureConfirmation::Provisional
        && matches!(
            failure.failure.category,
            VerificationFailureCategory::ProductBug | VerificationFailureCategory::TestFragility
        ) {
        (
            FailureRouteDirective::AwaitingConfirmation,
            FailureOwnerBinding::ConfirmationOwner,
        )
    } else {
        (
            if retry_permitted {
                FailureRouteDirective::Retry
            } else {
                FailureRouteDirective::EscalateToOwner
            },
            failure_owner_binding(failure.failure.category),
        )
    };

    let target_owner = match owner_binding {
        FailureOwnerBinding::ImplementationActor => bindings.implementation_actor.as_ref(),
        FailureOwnerBinding::VerifierActor => bindings.verifier_actor.as_ref(),
        FailureOwnerBinding::CapabilityOwner => bindings.capability_owner.as_ref(),
        FailureOwnerBinding::TestOwner => bindings.test_owner.as_ref(),
        FailureOwnerBinding::Coordinator => bindings.coordinator.as_ref(),
        FailureOwnerBinding::ConfirmationOwner => bindings.confirmation_owner.as_ref(),
    };
    let Some(target_owner) = target_owner else {
        return blocked(
            Some(owner_binding),
            format!(
                "missing required {} binding",
                failure_owner_binding_name(owner_binding)
            ),
        );
    };
    if let Err(error) = validate_stable_id(
        target_owner.as_str(),
        failure_owner_binding_name(owner_binding),
    ) {
        return blocked(Some(owner_binding), error.to_string());
    }
    if directive == FailureRouteDirective::AwaitingConfirmation
        && target_owner == &failure.classifier_actor
    {
        return blocked(
            Some(owner_binding),
            "confirmation_owner must differ from classifier_actor".to_owned(),
        );
    }

    VerificationFailureRoute {
        directive,
        category: failure.failure.category,
        owner_binding: Some(owner_binding),
        target_owner: Some(target_owner.clone()),
        reason: match directive {
            FailureRouteDirective::Retry => "existing revision state permits retry",
            FailureRouteDirective::AwaitingConfirmation => {
                "sensitive provisional failure requires independent confirmation"
            }
            FailureRouteDirective::EscalateToOwner => {
                "existing revision state exhausted its attempt budget"
            }
            FailureRouteDirective::Blocked => "failure route is blocked",
        }
        .to_owned(),
    }
}

const fn failure_owner_binding_name(binding: FailureOwnerBinding) -> &'static str {
    match binding {
        FailureOwnerBinding::ImplementationActor => "implementation_actor",
        FailureOwnerBinding::VerifierActor => "verifier_actor",
        FailureOwnerBinding::CapabilityOwner => "capability_owner",
        FailureOwnerBinding::TestOwner => "test_owner",
        FailureOwnerBinding::Coordinator => "coordinator",
        FailureOwnerBinding::ConfirmationOwner => "confirmation_owner",
    }
}

pub fn validate_failure_classifications(
    classifications: &[ClassifiedVerificationFailure],
) -> LocalVerificationResult<()> {
    let mut by_id = BTreeMap::new();
    for classification in classifications {
        classification.validate()?;
        if by_id
            .insert(classification.failure.failure_id.as_str(), classification)
            .is_some()
        {
            return Err(invalid(
                "duplicate_failure_classification",
                classification.failure.failure_id.clone(),
            ));
        }
    }

    for classification in classifications {
        let failure = &classification.failure;
        if failure.confirmation != FailureConfirmation::Confirmed
            || !matches!(
                failure.category,
                VerificationFailureCategory::ProductBug
                    | VerificationFailureCategory::TestFragility
            )
        {
            continue;
        }
        let Some(superseded_id) = failure.supersedes_failure_id.as_deref() else {
            return Err(invalid(
                "missing_provisional_failure",
                failure.failure_id.clone(),
            ));
        };
        let Some(prior) = by_id.get(superseded_id).copied() else {
            return Err(invalid(
                "missing_provisional_failure",
                superseded_id.to_owned(),
            ));
        };
        if prior.failure.confirmation != FailureConfirmation::Provisional
            || prior.failure.category != failure.category
            || prior.failure.criterion_id != failure.criterion_id
        {
            return Err(invalid(
                "mismatched_provisional_failure",
                superseded_id.to_owned(),
            ));
        }
        if prior.failure.recorded_at > failure.recorded_at {
            return Err(invalid(
                "noncausal_failure_confirmation",
                failure.failure_id.clone(),
            ));
        }
        if prior.classifier_actor == classification.classifier_actor {
            return Err(invalid(
                "classifier_not_independent",
                failure.failure_id.clone(),
            ));
        }
    }
    Ok(())
}

// Dependency-free SHA-256 keeps ovca-types pure and avoids changing Cargo scope.
fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut hash = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut schedule = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    hash.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeniedAccess, DigestAlgorithm, LocalMachinePolicy, ShellPolicy, VerificationCommand,
        WorkingDirectory,
    };
    use chrono::{TimeZone, Timelike, Utc};

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn capability(
        id: &str,
        dependencies: &[&str],
        selectors: Vec<(PathSelectorKind, &str)>,
    ) -> CapabilityDefinition {
        CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: id.to_owned(),
            revision: 1,
            criterion_ids: vec![],
            dependencies: dependencies
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            changed_path_selectors: selectors
                .into_iter()
                .map(|(kind, path)| crate::ChangedPathSelector {
                    kind,
                    path: path.to_owned(),
                })
                .collect(),
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
                allowed_executable_ids: BTreeSet::from(["cargo".to_owned()]),
                allowed_environment_names: BTreeSet::new(),
            },
            commands: vec![VerificationCommand {
                command_id: format!("verify-{id}"),
                executable_id: "cargo".to_owned(),
                argv: vec!["test".to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: BTreeSet::new(),
            }],
        }
    }

    fn row(definition: CapabilityDefinition, generation: u64) -> CapabilityRegistryRow {
        let record_digest = sha256_hex(&definition.canonical_json_bytes().unwrap());
        let state_digest = sha256_hex(
            &serde_json::to_vec(&CapabilityStateDigest {
                capability_id: &definition.capability_id,
                revision: definition.revision,
                record_digest: &record_digest,
                generation,
            })
            .unwrap(),
        );
        CapabilityRegistryRow {
            definition,
            record_digest,
            generation,
            state_digest,
        }
    }

    fn graph() -> CapabilityRegistrySnapshot {
        CapabilityRegistrySnapshot::new(vec![
            row(
                capability(
                    "api",
                    &["core"],
                    vec![(PathSelectorKind::Prefix, "src/api")],
                ),
                3,
            ),
            row(
                capability("core", &[], vec![(PathSelectorKind::Exact, "src/core.rs")]),
                2,
            ),
            row(
                capability(
                    "e2e",
                    &["api"],
                    vec![(PathSelectorKind::Prefix, "tests/e2e")],
                ),
                4,
            ),
        ])
        .unwrap()
    }

    fn request(entries: Vec<ChangedPathEntry>, policy: UnknownPathPolicy) -> TargetedRerunRequest {
        TargetedRerunRequest {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            run_id: RunId::from("run.v2"),
            goal_id: GoalId::from("goal.v2"),
            task_id: TaskId::from("task.v2"),
            source_fingerprint: digest('a'),
            policy_digest: digest('b'),
            changed_paths: ChangedPathManifest { entries },
            unknown_path_policy: policy,
        }
    }

    fn changed(path: &str) -> ChangedPathEntry {
        ChangedPathEntry {
            kind: ChangedPathKind::Modified,
            path: path.to_owned(),
            previous_path: None,
        }
    }

    fn selected(outcome: TargetedRerunOutcome) -> TargetedRerunSelection {
        match outcome {
            TargetedRerunOutcome::Selected { selection } => *selection,
            other => panic!("expected selection, got {other:?}"),
        }
    }

    fn externalized(selection: &TargetedRerunSelection) -> TargetedRerunSelection {
        serde_json::from_slice(&serde_json::to_vec(selection).unwrap()).unwrap()
    }

    fn rehash(selection: &mut TargetedRerunSelection) {
        selection.selection_digest = selection.expected_selection_digest().unwrap();
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exact_and_prefix_use_only_the_declared_boundary() {
        assert!(selector_matches(
            PathSelectorKind::Exact,
            "src/core.rs",
            "src/core.rs"
        ));
        assert!(!selector_matches(
            PathSelectorKind::Exact,
            "src/core.rs",
            "src/core.rs.bak"
        ));
        assert!(selector_matches(
            PathSelectorKind::Prefix,
            "src/api",
            "src/api/client.rs"
        ));
        assert!(!selector_matches(
            PathSelectorKind::Prefix,
            "src/api",
            "src/apiary/client.rs"
        ));
    }

    #[test]
    fn selection_is_byte_deterministic_and_has_reverse_then_forward_closure() {
        let request = request(
            vec![changed("src/api/client.rs")],
            UnknownPathPolicy::Blocked,
        );
        let first = selected(select_targeted_rerun(&request, &graph()));
        let second = selected(select_targeted_rerun(&request, &graph()));
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert_eq!(
            first
                .capabilities
                .iter()
                .map(|value| value.capability_id.as_str())
                .collect::<Vec<_>>(),
            ["api", "core", "e2e"]
        );
        first.validate().unwrap();
    }

    #[test]
    fn rename_binds_both_logical_paths() {
        let selection = selected(select_targeted_rerun(
            &request(
                vec![ChangedPathEntry {
                    kind: ChangedPathKind::Renamed,
                    path: "src/api/new.rs".to_owned(),
                    previous_path: Some("src/api/old.rs".to_owned()),
                }],
                UnknownPathPolicy::Blocked,
            ),
            &graph(),
        ));
        assert_eq!(selection.mode, TargetedRerunMode::Targeted);
        assert!(selection.unknown_paths.is_empty());

        let deleted = selected(select_targeted_rerun(
            &request(
                vec![ChangedPathEntry {
                    kind: ChangedPathKind::Deleted,
                    path: "src/api/removed.rs".to_owned(),
                    previous_path: None,
                }],
                UnknownPathPolicy::Blocked,
            ),
            &graph(),
        ));
        assert_eq!(deleted.mode, TargetedRerunMode::Targeted);
    }

    #[test]
    fn unknown_paths_are_full_safe_or_blocked_and_never_ignored() {
        let full_safe = selected(select_targeted_rerun(
            &request(vec![changed("docs/new.md")], UnknownPathPolicy::FullSafe),
            &graph(),
        ));
        assert_eq!(full_safe.mode, TargetedRerunMode::FullSafe);
        assert_eq!(full_safe.capabilities.len(), 3);
        assert_eq!(full_safe.unknown_paths, ["docs/new.md"]);

        assert!(matches!(
            select_targeted_rerun(
                &request(vec![changed("docs/new.md")], UnknownPathPolicy::Blocked),
                &graph()
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::UnknownPath,
                ..
            }
        ));
    }

    #[test]
    fn no_selector_match_cannot_become_an_empty_pass() {
        let blocked = select_targeted_rerun(
            &request(vec![changed("unmapped/new.rs")], UnknownPathPolicy::Blocked),
            &graph(),
        );
        assert!(matches!(
            blocked,
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::UnknownPath,
                ..
            }
        ));
        assert!(!serde_json::to_string(&blocked)
            .unwrap()
            .contains("\"status\":\"pass\""));
    }

    #[test]
    fn empty_full_safe_registry_and_zero_paths_are_closed() {
        let empty = CapabilityRegistrySnapshot::new(vec![]).unwrap();
        let empty_outcome = select_targeted_rerun(
            &request(vec![changed("src/x.rs")], UnknownPathPolicy::FullSafe),
            &empty,
        );
        assert!(matches!(
            &empty_outcome,
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::EmptyRegistry,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_value(&empty_outcome).unwrap()["code"],
            "BLOCKED_EMPTY_REGISTRY"
        );

        let no_applicable =
            select_targeted_rerun(&request(vec![], UnknownPathPolicy::Blocked), &graph());
        assert!(matches!(
            &no_applicable,
            TargetedRerunOutcome::NoApplicableCapability {
                reason: NoApplicableCapabilityReason::ZeroChangedPaths
            }
        ));
        assert_eq!(
            serde_json::to_value(&no_applicable).unwrap()["status"],
            "NO_APPLICABLE_CAPABILITY"
        );
    }

    #[test]
    fn invalid_manifest_is_blocked() {
        assert!(matches!(
            select_targeted_rerun(
                &request(
                    vec![changed("src/core.rs"), changed("src/core.rs")],
                    UnknownPathPolicy::Blocked
                ),
                &graph()
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::InvalidManifest,
                ..
            }
        ));
    }

    #[test]
    fn missing_dependency_and_cycle_are_blocked() {
        let missing = CapabilityRegistrySnapshot::new(vec![row(
            capability(
                "api",
                &["missing"],
                vec![(PathSelectorKind::Prefix, "src/api")],
            ),
            1,
        )])
        .unwrap();
        assert!(matches!(
            select_targeted_rerun(
                &request(vec![changed("src/api/x.rs")], UnknownPathPolicy::Blocked),
                &missing
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::MissingDependency,
                ..
            }
        ));

        let cycle = CapabilityRegistrySnapshot::new(vec![
            row(
                capability("a", &["b"], vec![(PathSelectorKind::Prefix, "src/a")]),
                1,
            ),
            row(
                capability("b", &["a"], vec![(PathSelectorKind::Prefix, "src/b")]),
                1,
            ),
        ])
        .unwrap();
        assert!(matches!(
            select_targeted_rerun(
                &request(vec![changed("src/a/x.rs")], UnknownPathPolicy::Blocked),
                &cycle
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::DependencyCycle,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_identity_and_snapshot_tampering_are_blocked() {
        let valid = graph();
        let duplicate = CapabilityRegistrySnapshot {
            capabilities: vec![valid.capabilities[0].clone(), valid.capabilities[0].clone()],
            registry_snapshot_digest: digest('c'),
        };
        assert!(matches!(
            select_targeted_rerun(
                &request(vec![changed("src/api/x.rs")], UnknownPathPolicy::Blocked),
                &duplicate
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::DuplicateCurrentIdentity,
                ..
            }
        ));

        let mut tampered = graph();
        tampered.registry_snapshot_digest = digest('d');
        assert!(matches!(
            select_targeted_rerun(
                &request(vec![changed("src/api/x.rs")], UnknownPathPolicy::Blocked),
                &tampered
            ),
            TargetedRerunOutcome::Blocked {
                code: TargetedRerunBlockCode::InconsistentRegistry,
                ..
            }
        ));
    }

    #[test]
    fn selection_binds_every_required_identity_and_fingerprint() {
        let request = request(vec![changed("src/core.rs")], UnknownPathPolicy::Blocked);
        let snapshot = graph();
        let selection = selected(select_targeted_rerun(&request, &snapshot));
        assert_eq!(selection.run_id, request.run_id);
        assert_eq!(selection.goal_id, request.goal_id);
        assert_eq!(selection.task_id, request.task_id);
        assert_eq!(selection.source_fingerprint, request.source_fingerprint);
        assert_eq!(selection.policy_digest, request.policy_digest);
        assert_eq!(selection.unknown_path_policy, request.unknown_path_policy);
        assert_eq!(
            selection.registry_snapshot_digest,
            snapshot.registry_snapshot_digest
        );
        assert_eq!(selection.changed_path_manifest, request.changed_paths);
        assert!(selection
            .capabilities
            .iter()
            .all(|value| value.revision == 1 && value.record_digest.len() == 64));
    }

    #[test]
    fn externally_deserialized_rehashed_selection_rejects_invalid_identity_and_digests() {
        let valid = selected(select_targeted_rerun(
            &request(vec![changed("src/core.rs")], UnknownPathPolicy::Blocked),
            &graph(),
        ));

        let mut wrong_version = externalized(&valid);
        wrong_version.contract_version = ContractVersion(2);
        rehash(&mut wrong_version);
        assert_eq!(
            wrong_version.validate().unwrap_err().code,
            "unsupported_contract_version"
        );

        let mut invalid_id = externalized(&valid);
        invalid_id.run_id = RunId::from("bad run id");
        rehash(&mut invalid_id);
        assert_eq!(invalid_id.validate().unwrap_err().code, "invalid_stable_id");

        for mutate in [
            |value: &mut TargetedRerunSelection| value.source_fingerprint = "bad".to_owned(),
            |value: &mut TargetedRerunSelection| value.policy_digest = "bad".to_owned(),
            |value: &mut TargetedRerunSelection| value.registry_snapshot_digest = "bad".to_owned(),
        ] {
            let mut invalid = externalized(&valid);
            mutate(&mut invalid);
            rehash(&mut invalid);
            assert_eq!(
                invalid.validate().unwrap_err().code,
                "invalid_sha256_digest"
            );
        }
    }

    #[test]
    fn externally_deserialized_rehashed_selection_rejects_manifest_and_mode_drift() {
        let valid = selected(select_targeted_rerun(
            &request(vec![changed("src/core.rs")], UnknownPathPolicy::Blocked),
            &graph(),
        ));

        let mut bad_manifest = externalized(&valid);
        bad_manifest.changed_path_manifest.entries[0].previous_path = Some("src/old.rs".to_owned());
        rehash(&mut bad_manifest);
        assert_eq!(
            bad_manifest.validate().unwrap_err().code,
            "invalid_changed_path_manifest"
        );

        let mut manifest_digest_drift = externalized(&valid);
        manifest_digest_drift.changed_path_manifest.entries[0].path = "src/api/x.rs".to_owned();
        rehash(&mut manifest_digest_drift);
        assert_eq!(
            manifest_digest_drift.validate().unwrap_err().code,
            "changed_path_manifest_digest_mismatch"
        );

        let mut targeted_unknown = externalized(&valid);
        targeted_unknown.unknown_paths = vec!["src/core.rs".to_owned()];
        rehash(&mut targeted_unknown);
        assert_eq!(
            targeted_unknown.validate().unwrap_err().code,
            "targeted_mode_has_unknown_paths"
        );

        let full_safe = selected(select_targeted_rerun(
            &request(vec![changed("docs/new.md")], UnknownPathPolicy::FullSafe),
            &graph(),
        ));
        let mut wrong_policy = externalized(&full_safe);
        wrong_policy.unknown_path_policy = UnknownPathPolicy::Blocked;
        rehash(&mut wrong_policy);
        assert_eq!(
            wrong_policy.validate().unwrap_err().code,
            "full_safe_mode_requires_policy"
        );

        let mut empty_unknown = externalized(&full_safe);
        empty_unknown.unknown_paths.clear();
        rehash(&mut empty_unknown);
        assert_eq!(
            empty_unknown.validate().unwrap_err().code,
            "full_safe_mode_requires_unknown_paths"
        );
    }

    #[test]
    fn externally_deserialized_rehashed_selection_rejects_noncanonical_members() {
        let valid = selected(select_targeted_rerun(
            &request(vec![changed("src/core.rs")], UnknownPathPolicy::Blocked),
            &graph(),
        ));

        let mut empty = externalized(&valid);
        empty.capabilities.clear();
        rehash(&mut empty);
        assert_eq!(
            empty.validate().unwrap_err().code,
            "empty_targeted_rerun_selection"
        );

        let mut duplicate = externalized(&valid);
        duplicate
            .capabilities
            .insert(1, duplicate.capabilities[0].clone());
        rehash(&mut duplicate);
        assert_eq!(
            duplicate.validate().unwrap_err().code,
            "noncanonical_selected_capabilities"
        );

        let mut bad_revision = externalized(&valid);
        bad_revision.capabilities[0].revision = 0;
        rehash(&mut bad_revision);
        assert_eq!(
            bad_revision.validate().unwrap_err().code,
            "invalid_capability_revision"
        );

        let mut bad_record_digest = externalized(&valid);
        bad_record_digest.capabilities[0].record_digest = "bad".to_owned();
        rehash(&mut bad_record_digest);
        assert_eq!(
            bad_record_digest.validate().unwrap_err().code,
            "invalid_sha256_digest"
        );

        let full_safe = selected(select_targeted_rerun(
            &request(vec![changed("docs/new.md")], UnknownPathPolicy::FullSafe),
            &graph(),
        ));
        let mut duplicate_unknown = externalized(&full_safe);
        duplicate_unknown
            .unknown_paths
            .push("docs/new.md".to_owned());
        rehash(&mut duplicate_unknown);
        assert_eq!(
            duplicate_unknown.validate().unwrap_err().code,
            "noncanonical_unknown_paths"
        );

        let mut foreign_unknown = externalized(&full_safe);
        foreign_unknown.unknown_paths = vec!["docs/other.md".to_owned()];
        rehash(&mut foreign_unknown);
        assert_eq!(
            foreign_unknown.validate().unwrap_err().code,
            "unknown_path_not_in_manifest"
        );
    }

    #[test]
    fn selection_validate_against_requires_exact_request_and_registry_result() {
        let request = request(
            vec![changed("src/api/client.rs")],
            UnknownPathPolicy::Blocked,
        );
        let snapshot = graph();
        let selection = selected(select_targeted_rerun(&request, &snapshot));
        selection.validate_against(&request, &snapshot).unwrap();

        let mut omitted_capability = externalized(&selection);
        omitted_capability.capabilities.pop();
        rehash(&mut omitted_capability);
        omitted_capability.validate().unwrap();
        assert_eq!(
            omitted_capability
                .validate_against(&request, &snapshot)
                .unwrap_err()
                .code,
            "selection_context_mismatch"
        );

        let mut different_request = request.clone();
        different_request.source_fingerprint = digest('f');
        assert_eq!(
            selection
                .validate_against(&different_request, &snapshot)
                .unwrap_err()
                .code,
            "selection_context_mismatch"
        );
    }

    fn classified(
        id: &str,
        category: VerificationFailureCategory,
        confirmation: FailureConfirmation,
        supersedes: Option<&str>,
        actor: &str,
        second: u32,
    ) -> ClassifiedVerificationFailure {
        ClassifiedVerificationFailure {
            failure: VerificationFailure {
                contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
                failure_id: id.to_owned(),
                category,
                confirmation,
                supersedes_failure_id: supersedes.map(str::to_owned),
                criterion_id: Some("criterion.v2".to_owned()),
                summary: "classification".to_owned(),
                recorded_at: Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, second).unwrap(),
            },
            classifier_actor: WorkerId::from(actor),
        }
    }

    fn owner_bindings() -> FailureOwnerBindings {
        FailureOwnerBindings {
            implementation_actor: Some(WorkerId::from("engineer.implementation")),
            verifier_actor: Some(WorkerId::from("reviewer.verifier")),
            capability_owner: Some(WorkerId::from("engineer.capability")),
            test_owner: Some(WorkerId::from("auditor.tests")),
            coordinator: Some(WorkerId::from("coordinator.coordinator")),
            confirmation_owner: Some(WorkerId::from("auditor.confirmation")),
        }
    }

    #[test]
    fn sensitive_confirmation_requires_matching_provisional_and_independent_actor() {
        for category in [
            VerificationFailureCategory::ProductBug,
            VerificationFailureCategory::TestFragility,
        ] {
            let provisional = classified(
                "failure.provisional",
                category,
                FailureConfirmation::Provisional,
                None,
                "reviewer.first",
                1,
            );
            let confirmed = classified(
                "failure.confirmed",
                category,
                FailureConfirmation::Confirmed,
                Some("failure.provisional"),
                "auditor.second",
                2,
            );
            validate_failure_classifications(&[provisional.clone(), confirmed]).unwrap();

            let same_actor = classified(
                "failure.confirmed",
                category,
                FailureConfirmation::Confirmed,
                Some("failure.provisional"),
                "reviewer.first",
                2,
            );
            assert_eq!(
                validate_failure_classifications(&[provisional.clone(), same_actor])
                    .unwrap_err()
                    .code,
                "classifier_not_independent"
            );

            let missing = classified(
                "failure.confirmed",
                category,
                FailureConfirmation::Confirmed,
                Some("failure.unknown"),
                "auditor.second",
                2,
            );
            assert_eq!(
                validate_failure_classifications(&[provisional, missing])
                    .unwrap_err()
                    .code,
                "missing_provisional_failure"
            );
        }
    }

    #[test]
    fn failure_owner_mapping_is_exhaustive_and_wire_stable() {
        for (category, expected) in [
            (
                VerificationFailureCategory::ProductBug,
                FailureOwnerBinding::CapabilityOwner,
            ),
            (
                VerificationFailureCategory::TestFragility,
                FailureOwnerBinding::TestOwner,
            ),
            (
                VerificationFailureCategory::SourceDrift,
                FailureOwnerBinding::ImplementationActor,
            ),
            (
                VerificationFailureCategory::PolicyBlock,
                FailureOwnerBinding::VerifierActor,
            ),
            (
                VerificationFailureCategory::ContractViolation,
                FailureOwnerBinding::VerifierActor,
            ),
            (
                VerificationFailureCategory::Timeout,
                FailureOwnerBinding::Coordinator,
            ),
            (
                VerificationFailureCategory::Environment,
                FailureOwnerBinding::Coordinator,
            ),
            (
                VerificationFailureCategory::Infrastructure,
                FailureOwnerBinding::Coordinator,
            ),
            (
                VerificationFailureCategory::TestFailedUnclassified,
                FailureOwnerBinding::Coordinator,
            ),
        ] {
            assert_eq!(failure_owner_binding(category), expected);
        }
        assert_eq!(
            serde_json::to_string(&FailureRouteDirective::AwaitingConfirmation).unwrap(),
            "\"awaiting_confirmation\""
        );
        assert_eq!(
            serde_json::to_string(&FailureOwnerBinding::ConfirmationOwner).unwrap(),
            "\"confirmation_owner\""
        );
    }

    #[test]
    fn sensitive_provisional_awaits_explicit_confirmation_owner() {
        let provisional = classified(
            "failure.provisional",
            VerificationFailureCategory::ProductBug,
            FailureConfirmation::Provisional,
            None,
            "reviewer.first",
            1,
        );
        let route =
            route_classified_verification_failure(&provisional, None, &owner_bindings(), true);
        assert_eq!(route.directive, FailureRouteDirective::AwaitingConfirmation);
        assert_eq!(
            route.owner_binding,
            Some(FailureOwnerBinding::ConfirmationOwner)
        );
        assert_eq!(
            route.target_owner,
            Some(WorkerId::from("auditor.confirmation"))
        );

        let mut missing = owner_bindings();
        missing.confirmation_owner = None;
        let blocked = route_classified_verification_failure(&provisional, None, &missing, true);
        assert_eq!(blocked.directive, FailureRouteDirective::Blocked);
        assert_eq!(
            blocked.owner_binding,
            Some(FailureOwnerBinding::ConfirmationOwner)
        );

        let mut same_actor = owner_bindings();
        same_actor.confirmation_owner = Some(WorkerId::from("reviewer.first"));
        let blocked = route_classified_verification_failure(&provisional, None, &same_actor, true);
        assert_eq!(blocked.directive, FailureRouteDirective::Blocked);
        assert_eq!(
            blocked.owner_binding,
            Some(FailureOwnerBinding::ConfirmationOwner)
        );
        assert!(blocked.reason.contains("differ"));
    }

    #[test]
    fn classified_failure_timestamps_preserve_v0_and_enforce_v2_wire_precision() {
        let base = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        for (nanoseconds, expected) in [
            (0, "2026-08-10T00:00:00Z"),
            (123_000_000, "2026-08-10T00:00:00.123Z"),
            (123_456_000, "2026-08-10T00:00:00.123456Z"),
        ] {
            let mut classification = classified(
                "failure.timestamp",
                VerificationFailureCategory::Timeout,
                FailureConfirmation::Confirmed,
                None,
                "reviewer.first",
                1,
            );
            classification.failure.recorded_at = base.with_nanosecond(nanoseconds).unwrap();
            classification.failure.validate().unwrap();
            classification.validate().unwrap();
            assert_eq!(
                serde_json::to_value(&classification.failure).unwrap()["recorded_at"],
                expected
            );
            assert_eq!(
                route_classified_verification_failure(
                    &classification,
                    None,
                    &owner_bindings(),
                    true,
                )
                .directive,
                FailureRouteDirective::Retry
            );
        }

        let mut nanosecond_classification = classified(
            "failure.timestamp",
            VerificationFailureCategory::Timeout,
            FailureConfirmation::Confirmed,
            None,
            "reviewer.first",
            1,
        );
        nanosecond_classification.failure.recorded_at = base.with_nanosecond(123_456_789).unwrap();
        nanosecond_classification.failure.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&nanosecond_classification.failure).unwrap()["recorded_at"],
            "2026-08-10T00:00:00.123456789Z"
        );
        assert_eq!(
            nanosecond_classification.validate().unwrap_err().code,
            "recorded_at_exceeds_microsecond_precision"
        );
        let blocked = route_classified_verification_failure(
            &nanosecond_classification,
            None,
            &owner_bindings(),
            true,
        );
        assert_eq!(blocked.directive, FailureRouteDirective::Blocked);
        assert!(blocked
            .reason
            .contains("recorded_at_exceeds_microsecond_precision"));
    }

    #[test]
    fn confirmed_sensitive_route_requires_chain_and_never_guesses_owner() {
        let provisional = classified(
            "failure.provisional",
            VerificationFailureCategory::TestFragility,
            FailureConfirmation::Provisional,
            None,
            "reviewer.first",
            1,
        );
        let confirmed = classified(
            "failure.confirmed",
            VerificationFailureCategory::TestFragility,
            FailureConfirmation::Confirmed,
            Some("failure.provisional"),
            "auditor.second",
            2,
        );
        let route = route_classified_verification_failure(
            &confirmed,
            Some(&provisional),
            &owner_bindings(),
            true,
        );
        assert_eq!(route.directive, FailureRouteDirective::Retry);
        assert_eq!(route.owner_binding, Some(FailureOwnerBinding::TestOwner));

        let mut missing = owner_bindings();
        missing.test_owner = None;
        let blocked =
            route_classified_verification_failure(&confirmed, Some(&provisional), &missing, true);
        assert_eq!(blocked.directive, FailureRouteDirective::Blocked);
        assert_eq!(blocked.owner_binding, Some(FailureOwnerBinding::TestOwner));

        let invalid_chain =
            route_classified_verification_failure(&confirmed, None, &owner_bindings(), true);
        assert_eq!(invalid_chain.directive, FailureRouteDirective::Blocked);
    }
}
