//! Pure local-verification contracts and deterministic bridge mapping.
//!
//! This module performs validation and serialization only. It does not read or
//! write evidence, execute commands, inspect a current pointer, or change runtime
//! completion behavior.

pub mod operations;
pub mod targeted_rerun;
pub use operations::*;
pub use targeted_rerun::*;

use super::{
    CompletionEvidence, ContractVersion, CriterionKind, EvidenceId, EvidenceKind, EvidenceRef,
    GoalContract, GoalId, IntegrityMetadata, Role, RunId, TaskId, WorkerId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

pub const LOCAL_VERIFICATION_CONTRACT_VERSION: ContractVersion = ContractVersion(1);

pub type LocalVerificationResult<T> = Result<T, LocalVerificationError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalVerificationError {
    pub code: &'static str,
    pub detail: String,
}

impl LocalVerificationError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for LocalVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for LocalVerificationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralAcceptanceContract {
    pub contract_version: ContractVersion,
    pub contract_id: String,
    pub binding: BehaviorBinding,
    pub criteria: Vec<BehaviorCriterion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BehaviorBinding {
    Bound { goal_id: GoalId, task_id: TaskId },
    Unbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorKind {
    Acceptance,
    Verification,
    DefinitionOfDone,
}

impl From<BehaviorKind> for CriterionKind {
    fn from(value: BehaviorKind) -> Self {
        match value {
            BehaviorKind::Acceptance => Self::Acceptance,
            BehaviorKind::Verification => Self::Verification,
            BehaviorKind::DefinitionOfDone => Self::DefinitionOfDone,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorCriterion {
    pub criterion_id: String,
    pub order: u32,
    pub kind: BehaviorKind,
    pub text: String,
    pub required: bool,
    #[serde(default)]
    pub capability_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDefinition {
    pub contract_version: ContractVersion,
    pub capability_id: String,
    pub revision: u64,
    #[serde(default)]
    pub criterion_ids: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub changed_path_selectors: Vec<ChangedPathSelector>,
    pub policy: LocalMachinePolicy,
    pub commands: Vec<VerificationCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSelectorKind {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPathSelector {
    pub kind: PathSelectorKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedAccess {
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellPolicy {
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMachinePolicy {
    pub local_only: bool,
    pub network: DeniedAccess,
    pub provider: DeniedAccess,
    pub telemetry: DeniedAccess,
    pub egress: DeniedAccess,
    pub external_evidence: DeniedAccess,
    pub external_storage: DeniedAccess,
    pub raw_shell: ShellPolicy,
    pub inherit_environment: bool,
    pub fingerprint_algorithm: DigestAlgorithm,
    #[serde(default)]
    pub allowed_executable_ids: BTreeSet<String>,
    #[serde(default)]
    pub allowed_environment_names: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A declarative command whose `argv` entries are opaque exact tokens.
///
/// A verifier must pass these tokens unchanged to direct argv execution. It must
/// not percent-decode, URI-decode, shell-expand, environment-expand, or
/// interpolate them. Percent-encoded literals are not interpreted by V0.
pub struct VerificationCommand {
    pub command_id: String,
    pub executable_id: String,
    pub argv: Vec<String>,
    pub cwd: WorkingDirectory,
    #[serde(default)]
    pub environment_names: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkingDirectory {
    SnapshotRoot,
    Relative { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailureCategory {
    Timeout,
    PolicyBlock,
    ContractViolation,
    SourceDrift,
    Environment,
    Infrastructure,
    TestFailedUnclassified,
    ProductBug,
    TestFragility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureConfirmation {
    Provisional,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationFailure {
    pub contract_version: ContractVersion,
    pub failure_id: String,
    pub category: VerificationFailureCategory,
    pub confirmation: FailureConfirmation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_failure_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criterion_id: Option<String>,
    pub summary: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Pass,
    Fail,
    Blocked,
    Timeout,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriterionResultVerdict {
    Pass,
    Fail,
    Blocked,
    Timeout,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriterionResult {
    pub criterion_id: String,
    pub order: u32,
    pub kind: BehaviorKind,
    pub text: String,
    pub verdict: CriterionResultVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationFingerprints {
    pub source_pre: String,
    pub source_post: String,
    pub behavior_contract: String,
    pub capability_set: String,
    pub command: String,
    pub policy: String,
    pub environment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBundle {
    pub contract_version: ContractVersion,
    pub bundle_id: String,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub behavior_contract_id: String,
    pub capability_ids: Vec<String>,
    pub implementation_actor: WorkerId,
    pub verifier_actor: WorkerId,
    pub fingerprints: VerificationFingerprints,
    pub criterion_results: Vec<CriterionResult>,
    #[serde(default)]
    pub failures: Vec<VerificationFailure>,
    pub verdict: VerificationVerdict,
    pub created_at: DateTime<Utc>,
}

/// Canonical, output-free identity for one attempted verification command.
///
/// Raw process output and machine paths are deliberately absent. Stream hashes
/// are computed by the local verifier from the retained raw byte prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationTranscriptCommandIdentity {
    pub sequence: u32,
    pub command_digest: String,
    pub executable_digest: String,
    pub termination: VerificationTermination,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationTermination {
    Completed,
    Timeout,
    OutputLimit,
    Invalid,
}

/// Typed in-memory transcript identity used by the all-verdict validator.
/// The wire payload version is supplied by the canonical serializer rather
/// than by an untrusted caller.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerificationTranscriptIdentity {
    pub commands: Vec<VerificationTranscriptCommandIdentity>,
}

/// Caller-provided assertions about bundle integrity and currentness.
///
/// This value is not authoritative freshness evidence and cannot open completion
/// directly. V4c must reread the Evidence Bank CAS pointer and independently
/// revalidate checksums, bindings, and every expected fingerprint before enforcing
/// completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentBundleProof {
    pub contract_version: ContractVersion,
    pub bundle_digest: String,
    pub checksum_verified: bool,
    pub integrity_verified: bool,
    pub current_pointer_verified: bool,
    pub current_pointer_digest: String,
    pub expected_run_id: RunId,
    pub expected_goal_id: GoalId,
    pub expected_task_id: TaskId,
    pub expected_behavior_contract_digest: String,
    pub expected_capability_set_digest: String,
    pub expected_command_digest: String,
    pub expected_policy_digest: String,
    pub expected_source_digest: String,
    pub expected_environment_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeCriterionSatisfaction {
    pub criterion_id: String,
    pub kind: BehaviorKind,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedTaskEvidence {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub evidence_ref: EvidenceRef,
    pub satisfactions: Vec<AuthoritativeCriterionSatisfaction>,
}

fn invalid(code: &'static str, detail: impl Into<String>) -> LocalVerificationError {
    LocalVerificationError::new(code, detail)
}

fn validate_version(version: ContractVersion, contract: &str) -> LocalVerificationResult<()> {
    if version != LOCAL_VERIFICATION_CONTRACT_VERSION {
        return Err(invalid(
            "unsupported_contract_version",
            format!(
                "{contract} expected {}, got {}",
                LOCAL_VERIFICATION_CONTRACT_VERSION, version
            ),
        ));
    }
    Ok(())
}

fn validate_stable_id(value: &str, field: &str) -> LocalVerificationResult<()> {
    if value.is_empty()
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(invalid(
            "invalid_stable_id",
            format!("{field} must be a non-blank stable ASCII identifier"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> LocalVerificationResult<()> {
    if value.trim().is_empty() {
        return Err(invalid("blank_text", format!("{field} must not be blank")));
    }
    if value.contains('\0') {
        return Err(invalid(
            "invalid_text",
            format!("{field} must not contain NUL"),
        ));
    }
    Ok(())
}

fn validate_sorted_unique_ids(values: &[String], field: &str) -> LocalVerificationResult<()> {
    for value in values {
        validate_stable_id(value, field)?;
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(invalid(
                "noncanonical_or_duplicate_id",
                format!("{field} must be strictly sorted and unique"),
            ));
        }
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> LocalVerificationResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(
            "invalid_sha256_digest",
            format!("{field} must be lowercase 64-hex SHA-256"),
        ));
    }
    Ok(())
}

pub fn validate_logical_path(value: &str) -> LocalVerificationResult<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character <= '\u{001f}' || character == '\u{007f}')
        || value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains(':')
    {
        return Err(invalid(
            "unsafe_logical_path",
            "path must be relative and cannot contain a drive, URI, UNC, or backslash",
        ));
    }
    for segment in value.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(invalid(
                "unsafe_logical_path",
                "path contains an empty, dot, or parent segment",
            ));
        }
    }
    Ok(())
}

fn validate_executable_id(value: &str, field: &str) -> LocalVerificationResult<()> {
    validate_stable_id(value, field)?;
    if value != value.to_ascii_lowercase() {
        return Err(invalid(
            "noncanonical_executable_id",
            format!("{field} must be lowercase"),
        ));
    }
    if is_forbidden_verification_shell(value) {
        return Err(invalid(
            "raw_shell_forbidden",
            format!("{value} cannot be used as an executable ID"),
        ));
    }
    Ok(())
}

fn validate_argv_token(value: &str) -> LocalVerificationResult<()> {
    if value
        .chars()
        .any(|character| character <= '\u{001f}' || character == '\u{007f}')
        || value.contains('\\')
    {
        return Err(invalid(
            "invalid_argv",
            "argv entries cannot contain backslashes, C0 controls, or DEL",
        ));
    }
    let unsafe_suffix = value
        .match_indices('=')
        .any(|(index, _)| argv_reference_is_unsafe(&value[index + 1..]));
    if argv_reference_is_unsafe(value) || unsafe_suffix {
        return Err(invalid(
            "unsafe_argv_reference",
            "argv cannot contain absolute, drive/scheme-like, UNC, URL, or external references",
        ));
    }
    Ok(())
}

fn argv_reference_is_unsafe(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    let drive_absolute_anywhere = bytes
        .windows(3)
        .any(|window| window[0].is_ascii_alphabetic() && window[1] == b':' && window[2] == b'/');
    let drive_or_scheme_like_single_colon_anywhere =
        bytes.iter().enumerate().any(|(index, byte)| {
            byte.is_ascii_alphabetic()
                && bytes.get(index + 1) == Some(&b':')
                && !matches!(bytes.get(index + 2), Some(b':' | b'/'))
        });
    let scheme_at_boundary = bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, byte)| {
                if *byte == b':' {
                    Some(bytes.get(index + 1) != Some(&b':'))
                } else if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
                    None
                } else {
                    Some(false)
                }
            })
            .unwrap_or(false);
    candidate.starts_with('/')
        || drive_absolute_anywhere
        || drive_or_scheme_like_single_colon_anywhere
        || scheme_at_boundary
        || candidate.contains("://")
}

fn validate_environment_name(value: &str) -> LocalVerificationResult<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(invalid(
            "invalid_environment_name",
            "environment name is blank",
        ));
    };
    if !(first.is_ascii_uppercase() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(invalid(
            "invalid_environment_name",
            format!("{value} is not an uppercase environment-name token"),
        ));
    }
    Ok(())
}

fn validate_canonical_json<T: Serialize>(
    value: &T,
    validate: impl FnOnce() -> LocalVerificationResult<()>,
) -> LocalVerificationResult<Vec<u8>> {
    validate()?;
    serde_json::to_vec(value)
        .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))
}

impl BehavioralAcceptanceContract {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        validate_version(self.contract_version, "behavioral_acceptance_contract")?;
        validate_stable_id(&self.contract_id, "contract_id")?;
        match &self.binding {
            BehaviorBinding::Bound { goal_id, task_id } => {
                validate_stable_id(goal_id.as_str(), "goal_id")?;
                validate_stable_id(task_id.as_str(), "task_id")?;
            }
            BehaviorBinding::Unbound => {}
        }
        if self.criteria.is_empty() {
            return Err(invalid(
                "empty_behavior_criteria",
                "at least one criterion is required",
            ));
        }
        let mut ids = BTreeSet::new();
        for (index, criterion) in self.criteria.iter().enumerate() {
            validate_stable_id(&criterion.criterion_id, "criterion_id")?;
            if !ids.insert(criterion.criterion_id.as_str()) {
                return Err(invalid(
                    "duplicate_criterion_id",
                    criterion.criterion_id.clone(),
                ));
            }
            if criterion.order != index as u32 {
                return Err(invalid(
                    "noncanonical_criterion_order",
                    "criterion order must be contiguous and match declaration order",
                ));
            }
            validate_text(&criterion.text, "criterion.text")?;
            validate_sorted_unique_ids(&criterion.capability_ids, "capability_ids")?;
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        validate_canonical_json(self, || self.validate())
    }

    fn bound_ids(&self) -> LocalVerificationResult<(&GoalId, &TaskId)> {
        match &self.binding {
            BehaviorBinding::Bound { goal_id, task_id } => Ok((goal_id, task_id)),
            BehaviorBinding::Unbound => Err(invalid(
                "unbound_behavior_contract",
                "unbound behavior is not admissible as completion evidence",
            )),
        }
    }
}

impl LocalMachinePolicy {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        if !self.local_only {
            return Err(invalid("unsafe_machine_policy", "local_only must be true"));
        }
        if self.inherit_environment {
            return Err(invalid(
                "unsafe_machine_policy",
                "environment inheritance is forbidden",
            ));
        }
        if self.allowed_executable_ids.is_empty() {
            return Err(invalid(
                "empty_executable_allowlist",
                "at least one logical executable ID is required",
            ));
        }
        for executable in &self.allowed_executable_ids {
            validate_executable_id(executable, "allowed_executable_ids")?;
        }
        for name in &self.allowed_environment_names {
            validate_environment_name(name)?;
        }
        Ok(())
    }
}

/// Return whether a verification executable name is one of the frozen shell
/// entry points forbidden by the local no-shell contract.
pub fn is_forbidden_verification_shell(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "sh" | "sh.exe"
            | "bash"
            | "bash.exe"
            | "zsh"
            | "zsh.exe"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

impl VerificationCommand {
    fn validate(&self, policy: &LocalMachinePolicy) -> LocalVerificationResult<()> {
        validate_stable_id(&self.command_id, "command_id")?;
        validate_executable_id(&self.executable_id, "executable_id")?;
        if !policy.allowed_executable_ids.contains(&self.executable_id) {
            return Err(invalid(
                "executable_not_allowlisted",
                self.executable_id.clone(),
            ));
        }
        if let WorkingDirectory::Relative { path } = &self.cwd {
            validate_logical_path(path)?;
        }
        for argument in &self.argv {
            validate_argv_token(argument)?;
        }
        for name in &self.environment_names {
            validate_environment_name(name)?;
            if !policy.allowed_environment_names.contains(name) {
                return Err(invalid("environment_not_allowlisted", name.clone()));
            }
        }
        Ok(())
    }
}

impl CapabilityDefinition {
    /// Validate the intrinsic capability fields that are independent of the
    /// nested command array. V3 uses this phase to preserve the frozen typed
    /// structural-rejection partition without parsing error text.
    pub fn validate_non_command_fields(&self) -> LocalVerificationResult<()> {
        validate_version(self.contract_version, "capability_definition")?;
        validate_stable_id(&self.capability_id, "capability_id")?;
        if self.revision == 0 {
            return Err(invalid(
                "invalid_capability_revision",
                "revision must be greater than zero",
            ));
        }
        validate_sorted_unique_ids(&self.criterion_ids, "criterion_ids")?;
        validate_sorted_unique_ids(&self.dependencies, "dependencies")?;
        if self.dependencies.iter().any(|id| id == &self.capability_id) {
            return Err(invalid(
                "self_capability_dependency",
                self.capability_id.clone(),
            ));
        }
        self.policy.validate()?;
        let mut prior_selector: Option<(PathSelectorKind, &str)> = None;
        for selector in &self.changed_path_selectors {
            validate_logical_path(&selector.path)?;
            let key = (selector.kind, selector.path.as_str());
            if prior_selector.is_some_and(|prior| prior >= key) {
                return Err(invalid(
                    "noncanonical_path_selectors",
                    "changed path selectors must be strictly sorted and unique",
                ));
            }
            prior_selector = Some(key);
        }
        Ok(())
    }

    /// Validate only the command-array shape and nested command fields.
    pub fn validate_commands(&self) -> LocalVerificationResult<()> {
        if self.commands.is_empty() {
            return Err(invalid(
                "empty_verification_commands",
                "at least one command is required",
            ));
        }
        let mut prior_command: Option<&str> = None;
        for command in &self.commands {
            command.validate(&self.policy)?;
            if prior_command.is_some_and(|prior| prior >= command.command_id.as_str()) {
                return Err(invalid(
                    "noncanonical_or_duplicate_command",
                    "commands must be strictly sorted by command_id",
                ));
            }
            prior_command = Some(command.command_id.as_str());
        }
        Ok(())
    }

    pub fn validate(&self) -> LocalVerificationResult<()> {
        self.validate_non_command_fields()?;
        self.validate_commands()
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        validate_canonical_json(self, || self.validate())
    }
}

impl VerificationFailure {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        validate_version(self.contract_version, "verification_failure")?;
        validate_stable_id(&self.failure_id, "failure_id")?;
        validate_text(&self.summary, "summary")?;
        if let Some(criterion_id) = &self.criterion_id {
            validate_stable_id(criterion_id, "criterion_id")?;
        }
        if let Some(supersedes) = &self.supersedes_failure_id {
            validate_stable_id(supersedes, "supersedes_failure_id")?;
            if supersedes == &self.failure_id {
                return Err(invalid("self_superseding_failure", self.failure_id.clone()));
            }
        }
        if matches!(
            self.category,
            VerificationFailureCategory::ProductBug | VerificationFailureCategory::TestFragility
        ) {
            match self.confirmation {
                FailureConfirmation::Provisional if self.supersedes_failure_id.is_some() => {
                    return Err(invalid(
                        "provisional_failure_cannot_supersede",
                        self.failure_id.clone(),
                    ));
                }
                FailureConfirmation::Confirmed if self.supersedes_failure_id.is_none() => {
                    return Err(invalid(
                        "confirmed_failure_requires_superseded_record",
                        self.failure_id.clone(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        validate_canonical_json(self, || self.validate())
    }
}

impl VerificationFingerprints {
    fn validate(&self) -> LocalVerificationResult<()> {
        validate_digest(&self.source_pre, "source_pre")?;
        validate_digest(&self.source_post, "source_post")?;
        validate_digest(&self.behavior_contract, "behavior_contract")?;
        validate_digest(&self.capability_set, "capability_set")?;
        validate_digest(&self.command, "command")?;
        validate_digest(&self.policy, "policy")?;
        validate_digest(&self.environment, "environment")?;
        Ok(())
    }
}

fn failure_matches_verdict(
    category: VerificationFailureCategory,
    verdict: VerificationVerdict,
) -> bool {
    match verdict {
        VerificationVerdict::Pass => false,
        VerificationVerdict::Timeout => category == VerificationFailureCategory::Timeout,
        VerificationVerdict::Blocked => matches!(
            category,
            VerificationFailureCategory::PolicyBlock
                | VerificationFailureCategory::Environment
                | VerificationFailureCategory::Infrastructure
        ),
        VerificationVerdict::Invalid => matches!(
            category,
            VerificationFailureCategory::ContractViolation
                | VerificationFailureCategory::SourceDrift
        ),
        VerificationVerdict::Fail => matches!(
            category,
            VerificationFailureCategory::TestFailedUnclassified
                | VerificationFailureCategory::ProductBug
                | VerificationFailureCategory::TestFragility
                | VerificationFailureCategory::Environment
                | VerificationFailureCategory::Infrastructure
        ),
    }
}

impl VerificationBundle {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        validate_version(self.contract_version, "verification_bundle")?;
        validate_stable_id(&self.bundle_id, "bundle_id")?;
        validate_stable_id(self.run_id.as_str(), "run_id")?;
        validate_stable_id(self.goal_id.as_str(), "goal_id")?;
        validate_stable_id(self.task_id.as_str(), "task_id")?;
        validate_stable_id(&self.behavior_contract_id, "behavior_contract_id")?;
        validate_sorted_unique_ids(&self.capability_ids, "capability_ids")?;
        validate_stable_id(self.implementation_actor.as_str(), "implementation_actor")?;
        validate_stable_id(self.verifier_actor.as_str(), "verifier_actor")?;
        if self.implementation_actor == self.verifier_actor {
            return Err(invalid(
                "verifier_not_independent",
                "implementation and verifier actors must differ",
            ));
        }
        self.fingerprints.validate()?;
        let mut result_ids = BTreeSet::new();
        for (index, result) in self.criterion_results.iter().enumerate() {
            validate_stable_id(&result.criterion_id, "criterion_result.criterion_id")?;
            validate_text(&result.text, "criterion_result.text")?;
            if !result_ids.insert(result.criterion_id.as_str()) {
                return Err(invalid(
                    "duplicate_criterion_result",
                    result.criterion_id.clone(),
                ));
            }
            if result.order != index as u32 {
                return Err(invalid(
                    "noncanonical_result_order",
                    "criterion result order must be contiguous",
                ));
            }
        }
        let mut prior_failure: Option<&str> = None;
        for failure in &self.failures {
            failure.validate()?;
            if failure
                .criterion_id
                .as_ref()
                .is_some_and(|criterion_id| !result_ids.contains(criterion_id.as_str()))
            {
                return Err(invalid(
                    "failure_criterion_not_in_bundle",
                    failure.criterion_id.clone().unwrap_or_default(),
                ));
            }
            if prior_failure.is_some_and(|prior| prior >= failure.failure_id.as_str()) {
                return Err(invalid(
                    "noncanonical_or_duplicate_failure",
                    "failures must be strictly sorted by failure_id",
                ));
            }
            prior_failure = Some(failure.failure_id.as_str());
        }

        match self.verdict {
            VerificationVerdict::Pass => {
                if self.criterion_results.is_empty() {
                    return Err(invalid(
                        "empty_pass_coverage",
                        "a pass bundle requires criterion coverage",
                    ));
                }
                if !self.failures.is_empty() {
                    return Err(invalid("pass_with_failure", "pass cannot contain failures"));
                }
                if self
                    .criterion_results
                    .iter()
                    .any(|result| result.verdict != CriterionResultVerdict::Pass)
                {
                    return Err(invalid(
                        "pass_with_nonpass_result",
                        "every result in a pass bundle must pass",
                    ));
                }
                if self.fingerprints.source_pre != self.fingerprints.source_post {
                    return Err(invalid(
                        "source_drift",
                        "pass requires identical source pre/post digests",
                    ));
                }
            }
            verdict => {
                let has_source_drift_failure = self
                    .failures
                    .iter()
                    .any(|failure| failure.category == VerificationFailureCategory::SourceDrift);
                if !self
                    .failures
                    .iter()
                    .any(|failure| failure_matches_verdict(failure.category, verdict))
                {
                    return Err(invalid(
                        "nonpass_without_matching_failure",
                        "non-pass verdict requires a matching failure category",
                    ));
                }
                if self.fingerprints.source_pre != self.fingerprints.source_post
                    && !(verdict == VerificationVerdict::Invalid && has_source_drift_failure)
                {
                    return Err(invalid(
                        "unclassified_source_drift",
                        "source drift requires invalid verdict and source_drift failure",
                    ));
                }
                if self.fingerprints.source_pre == self.fingerprints.source_post
                    && has_source_drift_failure
                {
                    return Err(invalid(
                        "source_drift_failure_without_drift",
                        "source_drift failure requires different pre/post digests",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        validate_canonical_json(self, || self.validate())
    }
}

const VERIFICATION_TRANSCRIPT_VERSION: &str = "ovca.verification-transcript.v1";
const VERIFICATION_COMMAND_VERSION: &str = "ovca.verification-command.v1";
const VERIFICATION_BUNDLE_IDENTITY_VERSION: &str = "ovca.verification-bundle-identity.v1";

#[derive(Serialize)]
struct VerificationTranscriptPayload<'a> {
    version: &'static str,
    commands: &'a [VerificationTranscriptCommandIdentity],
}

#[derive(Serialize)]
struct VerificationCommandPayload<'a> {
    version: &'static str,
    capability_id: &'a str,
    capability_revision: u64,
    command_index: u32,
    command: &'a VerificationCommand,
}

#[derive(Serialize)]
struct VerificationBundleIdentityPayload<'a> {
    version: &'static str,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    selection_digest: &'a str,
    transcript_sha256: &'a str,
    implementation_actor: &'a WorkerId,
    verifier_actor: &'a WorkerId,
    created_at: &'a DateTime<Utc>,
}

#[derive(Serialize)]
struct CapabilitySetPayload<'a> {
    version: &'static str,
    capabilities: &'a [SelectedCapability],
}

#[derive(Serialize)]
struct CommandSetEntry<'a> {
    capability_id: &'a str,
    capability_revision: u64,
    command_index: u32,
    command_digest: String,
}

#[derive(Serialize)]
struct CommandSetPayload<'a> {
    version: &'static str,
    commands: Vec<CommandSetEntry<'a>>,
}

#[derive(Serialize)]
struct PolicySetEntry<'a> {
    capability_id: &'a str,
    capability_revision: u64,
    policy: &'a LocalMachinePolicy,
}

#[derive(Serialize)]
struct PolicySetPayload<'a> {
    version: &'static str,
    capabilities: Vec<PolicySetEntry<'a>>,
}

fn canonical_json_lf<T: Serialize>(value: &T) -> LocalVerificationResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Dependency-free SHA-256 used by the pure contract layer.
pub fn verification_sha256_hex(input: &[u8]) -> String {
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

pub fn verification_command_digest(
    capability: &CapabilityDefinition,
    command_index: usize,
) -> LocalVerificationResult<String> {
    let command = capability.commands.get(command_index).ok_or_else(|| {
        invalid(
            "invalid_command_index",
            "command index is outside the capability command array",
        )
    })?;
    let command_index = u32::try_from(command_index)
        .map_err(|_| invalid("invalid_command_index", "command index exceeds u32"))?;
    let bytes = canonical_json_lf(&VerificationCommandPayload {
        version: VERIFICATION_COMMAND_VERSION,
        capability_id: &capability.capability_id,
        capability_revision: capability.revision,
        command_index,
        command,
    })?;
    Ok(verification_sha256_hex(&bytes))
}

impl VerificationTranscriptIdentity {
    pub fn validate(&self) -> LocalVerificationResult<()> {
        for (index, command) in self.commands.iter().enumerate() {
            if command.sequence != index as u32 {
                return Err(invalid(
                    "noncanonical_transcript_sequence",
                    "transcript sequence must be contiguous and zero based",
                ));
            }
            validate_digest(&command.command_digest, "transcript.command_digest")?;
            validate_digest(&command.executable_digest, "transcript.executable_digest")?;
            validate_digest(&command.stdout_sha256, "transcript.stdout_sha256")?;
            validate_digest(&command.stderr_sha256, "transcript.stderr_sha256")?;
            match command.termination {
                VerificationTermination::Completed if command.exit_code.is_none() => {
                    return Err(invalid(
                        "missing_completed_exit_code",
                        "completed transcript entries require an exit code",
                    ));
                }
                VerificationTermination::Timeout | VerificationTermination::OutputLimit
                    if command.exit_code.is_some() =>
                {
                    return Err(invalid(
                        "terminal_exit_code_forbidden",
                        "timeout and output-limit entries cannot carry an exit code",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> LocalVerificationResult<Vec<u8>> {
        self.validate()?;
        canonical_json_lf(&VerificationTranscriptPayload {
            version: VERIFICATION_TRANSCRIPT_VERSION,
            commands: &self.commands,
        })
    }

    pub fn sha256(&self) -> LocalVerificationResult<String> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn derive_verification_bundle_id(
    run_id: &RunId,
    goal_id: &GoalId,
    task_id: &TaskId,
    selection_digest: &str,
    transcript: &VerificationTranscriptIdentity,
    implementation_actor: &WorkerId,
    verifier_actor: &WorkerId,
    created_at: &DateTime<Utc>,
) -> LocalVerificationResult<String> {
    validate_digest(selection_digest, "selection_digest")?;
    let transcript_sha256 = transcript.sha256()?;
    let bytes = canonical_json_lf(&VerificationBundleIdentityPayload {
        version: VERIFICATION_BUNDLE_IDENTITY_VERSION,
        run_id,
        goal_id,
        task_id,
        selection_digest,
        transcript_sha256: &transcript_sha256,
        implementation_actor,
        verifier_actor,
        created_at,
    })?;
    Ok(format!("bundle.sha256.{}", verification_sha256_hex(&bytes)))
}

pub fn verification_behavior_digest(
    behavior: &BehavioralAcceptanceContract,
) -> LocalVerificationResult<String> {
    Ok(verification_sha256_hex(&behavior.canonical_json_bytes()?))
}

pub fn verification_capability_set_digest(
    selection: &TargetedRerunSelection,
) -> LocalVerificationResult<String> {
    selection.validate()?;
    verification_selected_capability_set_digest(&selection.capabilities)
}

/// Computes the verifier's canonical capability-set fingerprint from an exact
/// caller-selected immutable capability identity set.
///
/// This is intentionally narrower than a targeted-rerun selection so storage
/// health and archive validation can bind a bundle to the exact selected
/// revision and record digest without reconstructing or inferring rerun input.
pub fn verification_selected_capability_set_digest(
    capabilities: &[SelectedCapability],
) -> LocalVerificationResult<String> {
    if capabilities.is_empty() {
        return Err(invalid(
            "empty_selected_capability_set",
            "selected capability set must not be empty",
        ));
    }
    let mut prior_capability: Option<&str> = None;
    for capability in capabilities {
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
    let bytes = canonical_json_lf(&CapabilitySetPayload {
        version: "ovca.verification-capability-set.v1",
        capabilities,
    })?;
    Ok(verification_sha256_hex(&bytes))
}

pub fn verification_command_set_digest(
    capabilities: &[CapabilityDefinition],
) -> LocalVerificationResult<String> {
    let mut commands = Vec::new();
    for capability in capabilities {
        capability.validate()?;
        for command_index in 0..capability.commands.len() {
            commands.push(CommandSetEntry {
                capability_id: &capability.capability_id,
                capability_revision: capability.revision,
                command_index: command_index as u32,
                command_digest: verification_command_digest(capability, command_index)?,
            });
        }
    }
    let bytes = canonical_json_lf(&CommandSetPayload {
        version: "ovca.verification-command-set.v1",
        commands,
    })?;
    Ok(verification_sha256_hex(&bytes))
}

pub fn verification_policy_digest(
    capabilities: &[CapabilityDefinition],
) -> LocalVerificationResult<String> {
    let mut policies = Vec::new();
    for capability in capabilities {
        capability.validate_non_command_fields()?;
        policies.push(PolicySetEntry {
            capability_id: &capability.capability_id,
            capability_revision: capability.revision,
            policy: &capability.policy,
        });
    }
    let bytes = canonical_json_lf(&PolicySetPayload {
        version: "ovca.verification-policy-set.v1",
        capabilities: policies,
    })?;
    Ok(verification_sha256_hex(&bytes))
}

fn result_verdict_rank(value: CriterionResultVerdict) -> u8 {
    match value {
        CriterionResultVerdict::Pass => 0,
        CriterionResultVerdict::Fail => 1,
        CriterionResultVerdict::Blocked => 2,
        CriterionResultVerdict::Timeout => 3,
        CriterionResultVerdict::Invalid => 4,
    }
}

fn result_verdict_bundle(value: CriterionResultVerdict) -> VerificationVerdict {
    match value {
        CriterionResultVerdict::Pass => VerificationVerdict::Pass,
        CriterionResultVerdict::Fail => VerificationVerdict::Fail,
        CriterionResultVerdict::Blocked => VerificationVerdict::Blocked,
        CriterionResultVerdict::Timeout => VerificationVerdict::Timeout,
        CriterionResultVerdict::Invalid => VerificationVerdict::Invalid,
    }
}

/// Validate all verdicts against the exact Behavior/Capability/Selection and
/// typed transcript identity. This does not confer completion authority.
pub fn validate_verification_bundle_bindings(
    behavior: &BehavioralAcceptanceContract,
    capabilities: &[CapabilityDefinition],
    selection: &TargetedRerunSelection,
    bundle: &VerificationBundle,
    transcript: &VerificationTranscriptIdentity,
) -> LocalVerificationResult<()> {
    behavior.validate()?;
    selection.validate()?;
    bundle.validate()?;
    transcript.validate()?;

    let (behavior_goal_id, behavior_task_id) = behavior.bound_ids()?;
    if behavior_goal_id != &selection.goal_id
        || behavior_task_id != &selection.task_id
        || bundle.run_id != selection.run_id
        || bundle.goal_id != selection.goal_id
        || bundle.task_id != selection.task_id
    {
        return Err(invalid(
            "verification_identity_binding_mismatch",
            "Behavior, selection, and bundle RunId/GoalId/TaskId must match",
        ));
    }
    if bundle.behavior_contract_id != behavior.contract_id {
        return Err(invalid(
            "behavior_contract_id_mismatch",
            "bundle behavior contract ID differs",
        ));
    }

    if capabilities.len() != selection.capabilities.len() {
        return Err(invalid(
            "capability_set_mismatch",
            "selected definitions and selection must have equal length",
        ));
    }
    for (definition, selected) in capabilities.iter().zip(&selection.capabilities) {
        definition.validate()?;
        if definition.capability_id != selected.capability_id
            || definition.revision != selected.revision
            || verification_sha256_hex(&definition.canonical_json_bytes()?)
                != selected.record_digest
        {
            return Err(invalid(
                "capability_selection_binding_mismatch",
                "capability identity, revision, or record digest differs",
            ));
        }
    }
    let expected_capability_ids = selection
        .capabilities
        .iter()
        .map(|value| value.capability_id.clone())
        .collect::<Vec<_>>();
    if bundle.capability_ids != expected_capability_ids {
        return Err(invalid(
            "capability_set_mismatch",
            "bundle capability IDs differ from the exact selection",
        ));
    }

    if bundle.criterion_results.len() != behavior.criteria.len() {
        return Err(invalid(
            "incomplete_criterion_coverage",
            "bundle must cover every behavior criterion exactly once",
        ));
    }
    for (criterion, result) in behavior.criteria.iter().zip(&bundle.criterion_results) {
        if criterion.criterion_id != result.criterion_id
            || criterion.order != result.order
            || criterion.kind != result.kind
            || criterion.text != result.text
        {
            return Err(invalid(
                "criterion_identity_mismatch",
                "criterion identity and declaration order must match",
            ));
        }
        if criterion.capability_ids.is_empty()
            || criterion
                .capability_ids
                .iter()
                .any(|id| expected_capability_ids.binary_search(id).is_err())
        {
            return Err(invalid(
                "capability_criterion_binding_mismatch",
                criterion.criterion_id.clone(),
            ));
        }
        for capability_id in &criterion.capability_ids {
            let capability = capabilities
                .iter()
                .find(|capability| &capability.capability_id == capability_id)
                .ok_or_else(|| invalid("missing_capability_definition", capability_id.clone()))?;
            if capability
                .criterion_ids
                .binary_search(&criterion.criterion_id)
                .is_err()
            {
                return Err(invalid(
                    "capability_criterion_binding_mismatch",
                    capability_id.clone(),
                ));
            }
        }
    }
    for capability in capabilities {
        if capability
            .dependencies
            .iter()
            .any(|id| expected_capability_ids.binary_search(id).is_err())
        {
            return Err(invalid(
                "missing_capability_dependency",
                capability.capability_id.clone(),
            ));
        }
        for criterion_id in &capability.criterion_ids {
            let Some(criterion) = behavior
                .criteria
                .iter()
                .find(|criterion| &criterion.criterion_id == criterion_id)
            else {
                return Err(invalid(
                    "extra_capability_criterion",
                    capability.capability_id.clone(),
                ));
            };
            if criterion
                .capability_ids
                .binary_search(&capability.capability_id)
                .is_err()
            {
                return Err(invalid(
                    "capability_criterion_binding_mismatch",
                    capability.capability_id.clone(),
                ));
            }
        }
    }

    let expected_behavior = verification_behavior_digest(behavior)?;
    let expected_capabilities = verification_capability_set_digest(selection)?;
    let expected_commands = verification_command_set_digest(capabilities)?;
    let expected_policy = verification_policy_digest(capabilities)?;
    if bundle.fingerprints.behavior_contract != expected_behavior
        || bundle.fingerprints.capability_set != expected_capabilities
        || bundle.fingerprints.command != expected_commands
        || bundle.fingerprints.policy != expected_policy
        || selection.policy_digest != expected_policy
        || bundle.fingerprints.source_pre != selection.source_fingerprint
    {
        return Err(invalid(
            "verification_fingerprint_binding_mismatch",
            "bundle fingerprints differ from Behavior, Capability, or selection identities",
        ));
    }

    let planned = capabilities
        .iter()
        .flat_map(|capability| {
            capability
                .commands
                .iter()
                .enumerate()
                .map(move |(index, _)| (capability, index))
        })
        .collect::<Vec<_>>();
    if planned.is_empty() || transcript.commands.len() > planned.len() {
        return Err(invalid(
            "invalid_transcript_coverage",
            "transcript cannot be empty for an empty plan or exceed the command plan",
        ));
    }
    for (entry, (capability, command_index)) in transcript.commands.iter().zip(&planned) {
        if entry.command_digest != verification_command_digest(capability, *command_index)? {
            return Err(invalid(
                "transcript_command_binding_mismatch",
                "transcript command digest differs from the selected command",
            ));
        }
    }

    if bundle.verdict == VerificationVerdict::Pass
        && (transcript.commands.len() != planned.len()
            || transcript.commands.iter().any(|entry| {
                entry.termination != VerificationTermination::Completed
                    || entry.exit_code != Some(0)
            }))
    {
        return Err(invalid(
            "invalid_pass_transcript",
            "PASS requires every planned command to complete with exit zero",
        ));
    }
    if let Some(worst) = bundle
        .criterion_results
        .iter()
        .map(|result| result.verdict)
        .max_by_key(|value| result_verdict_rank(*value))
    {
        if result_verdict_bundle(worst) != bundle.verdict {
            return Err(invalid(
                "bundle_verdict_precedence_mismatch",
                "bundle verdict must equal Invalid > Timeout > Blocked > Fail > Pass reduction",
            ));
        }
    }
    for failure in &bundle.failures {
        if failure.recorded_at != bundle.created_at
            || failure.criterion_id.is_some()
            || failure.supersedes_failure_id.is_some()
        {
            return Err(invalid(
                "invalid_verifier_failure_shape",
                "verifier failures use bundle timestamp and no criterion or supersedes binding",
            ));
        }
    }

    let expected_bundle_id = derive_verification_bundle_id(
        &bundle.run_id,
        &bundle.goal_id,
        &bundle.task_id,
        &selection.selection_digest,
        transcript,
        &bundle.implementation_actor,
        &bundle.verifier_actor,
        &bundle.created_at,
    )?;
    if bundle.bundle_id != expected_bundle_id {
        return Err(invalid(
            "verification_bundle_identity_mismatch",
            "bundle ID does not match the canonical transcript-bound identity",
        ));
    }
    Ok(())
}

impl CurrentBundleProof {
    fn validate(&self) -> LocalVerificationResult<()> {
        validate_version(self.contract_version, "current_bundle_proof")?;
        validate_digest(&self.bundle_digest, "bundle_digest")?;
        validate_digest(&self.current_pointer_digest, "current_pointer_digest")?;
        validate_digest(
            &self.expected_behavior_contract_digest,
            "expected_behavior_contract_digest",
        )?;
        validate_digest(
            &self.expected_capability_set_digest,
            "expected_capability_set_digest",
        )?;
        validate_digest(&self.expected_command_digest, "expected_command_digest")?;
        validate_digest(&self.expected_policy_digest, "expected_policy_digest")?;
        validate_digest(&self.expected_source_digest, "expected_source_digest")?;
        validate_digest(
            &self.expected_environment_digest,
            "expected_environment_digest",
        )?;
        if !self.checksum_verified || !self.integrity_verified {
            return Err(invalid(
                "bundle_integrity_unverified",
                "checksum and integrity assertions must both be true",
            ));
        }
        if !self.current_pointer_verified || self.current_pointer_digest != self.bundle_digest {
            return Err(invalid(
                "current_pointer_mismatch",
                "current pointer must be verified and equal the canonical bundle digest",
            ));
        }
        Ok(())
    }
}

pub fn admit_current_pass_bundle(
    behavior: &BehavioralAcceptanceContract,
    capabilities: &[CapabilityDefinition],
    bundle: &VerificationBundle,
    proof: &CurrentBundleProof,
) -> LocalVerificationResult<AdmittedTaskEvidence> {
    behavior.validate()?;
    bundle.validate()?;
    proof.validate()?;
    let (behavior_goal_id, behavior_task_id) = behavior.bound_ids()?;

    if bundle.verdict != VerificationVerdict::Pass {
        return Err(invalid(
            "nonpass_not_admissible",
            "only a pass bundle may become completion evidence",
        ));
    }
    if &bundle.goal_id != behavior_goal_id || &bundle.task_id != behavior_task_id {
        return Err(invalid(
            "behavior_bundle_binding_mismatch",
            "bundle GoalId/TaskId must match the bound behavior contract",
        ));
    }
    if bundle.behavior_contract_id != behavior.contract_id {
        return Err(invalid(
            "behavior_contract_id_mismatch",
            "bundle behavior contract ID differs",
        ));
    }
    if proof.expected_run_id != bundle.run_id
        || proof.expected_goal_id != bundle.goal_id
        || proof.expected_task_id != bundle.task_id
    {
        return Err(invalid(
            "proof_binding_mismatch",
            "proof RunId/GoalId/TaskId must match the bundle",
        ));
    }
    if bundle.criterion_results.len() != behavior.criteria.len() {
        return Err(invalid(
            "incomplete_criterion_coverage",
            "bundle must cover every declared task criterion",
        ));
    }
    for (criterion, result) in behavior.criteria.iter().zip(&bundle.criterion_results) {
        if criterion.criterion_id != result.criterion_id
            || criterion.order != result.order
            || criterion.kind != result.kind
            || criterion.text != result.text
        {
            return Err(invalid(
                "criterion_identity_mismatch",
                "criterion ID, order, kind, and exact text must match",
            ));
        }
        if criterion.required && result.verdict != CriterionResultVerdict::Pass {
            return Err(invalid(
                "required_criterion_not_passed",
                criterion.criterion_id.clone(),
            ));
        }
    }

    let mut capability_map = BTreeMap::new();
    for capability in capabilities {
        capability.validate()?;
        if capability_map
            .insert(capability.capability_id.as_str(), capability)
            .is_some()
        {
            return Err(invalid(
                "duplicate_capability_definition",
                capability.capability_id.clone(),
            ));
        }
    }
    let provided_ids = capability_map
        .keys()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if provided_ids != bundle.capability_ids {
        return Err(invalid(
            "capability_set_mismatch",
            "provided definitions must exactly match bundle capability IDs",
        ));
    }
    let behavior_criterion_ids = behavior
        .criteria
        .iter()
        .map(|criterion| criterion.criterion_id.as_str())
        .collect::<BTreeSet<_>>();
    for criterion in &behavior.criteria {
        if criterion.capability_ids.is_empty() {
            return Err(invalid(
                "missing_criterion_capability",
                criterion.criterion_id.clone(),
            ));
        }
        for capability_id in &criterion.capability_ids {
            let Some(capability) = capability_map.get(capability_id.as_str()) else {
                return Err(invalid(
                    "missing_capability_definition",
                    capability_id.clone(),
                ));
            };
            if capability
                .criterion_ids
                .binary_search(&criterion.criterion_id)
                .is_err()
            {
                return Err(invalid(
                    "capability_criterion_binding_mismatch",
                    format!("{capability_id}:{}", criterion.criterion_id),
                ));
            }
        }
    }
    for capability in capability_map.values() {
        for dependency in &capability.dependencies {
            if !capability_map.contains_key(dependency.as_str()) {
                return Err(invalid(
                    "missing_capability_dependency",
                    format!("{}:{dependency}", capability.capability_id),
                ));
            }
        }
        if capability
            .criterion_ids
            .iter()
            .any(|id| !behavior_criterion_ids.contains(id.as_str()))
        {
            return Err(invalid(
                "extra_capability_criterion",
                capability.capability_id.clone(),
            ));
        }
    }

    let fingerprints = &bundle.fingerprints;
    let digest_matches = fingerprints.behavior_contract == proof.expected_behavior_contract_digest
        && fingerprints.capability_set == proof.expected_capability_set_digest
        && fingerprints.command == proof.expected_command_digest
        && fingerprints.policy == proof.expected_policy_digest
        && fingerprints.source_pre == proof.expected_source_digest
        && fingerprints.source_post == proof.expected_source_digest
        && fingerprints.environment == proof.expected_environment_digest;
    if !digest_matches {
        return Err(invalid(
            "stale_or_mismatched_fingerprint",
            "one or more expected current digests differ",
        ));
    }

    let evidence_id = EvidenceId::from(format!(
        "verification-bundle-sha256-{}",
        proof.bundle_digest
    ));
    let evidence_ref = EvidenceRef {
        contract_version: ContractVersion::current(),
        id: evidence_id,
        kind: EvidenceKind::TestResult,
        reference: format!("verification-bundles/sha256/{}", proof.bundle_digest),
        producer_role: Role::Coordinator,
        integrity: Some(IntegrityMetadata {
            contract_version: ContractVersion::current(),
            algorithm: "sha256".to_owned(),
            digest: proof.bundle_digest.clone(),
        }),
        produced_at: bundle.created_at,
    };
    validate_logical_path(&evidence_ref.reference)?;

    Ok(AdmittedTaskEvidence {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        run_id: bundle.run_id.clone(),
        goal_id: bundle.goal_id.clone(),
        task_id: bundle.task_id.clone(),
        evidence_ref,
        satisfactions: behavior
            .criteria
            .iter()
            .map(|criterion| AuthoritativeCriterionSatisfaction {
                criterion_id: criterion.criterion_id.clone(),
                kind: criterion.kind,
                text: criterion.text.clone(),
            })
            .collect(),
    })
}

fn insert_goal_criterion(
    expected: &mut BTreeSet<(BehaviorKind, String)>,
    kind: BehaviorKind,
    text: &str,
) -> LocalVerificationResult<()> {
    validate_text(text, "goal criterion")?;
    if !expected.insert((kind, text.to_owned())) {
        return Err(invalid(
            "duplicate_goal_criterion",
            "goal criteria must be unique by kind and exact text",
        ));
    }
    Ok(())
}

fn validate_admitted_task_evidence(admitted: &AdmittedTaskEvidence) -> LocalVerificationResult<()> {
    validate_version(admitted.contract_version, "admitted_task_evidence")?;
    validate_stable_id(admitted.run_id.as_str(), "admitted.run_id")?;
    validate_stable_id(admitted.goal_id.as_str(), "admitted.goal_id")?;
    validate_stable_id(admitted.task_id.as_str(), "admitted.task_id")?;
    if admitted.evidence_ref.contract_version != ContractVersion::current()
        || admitted.evidence_ref.kind != EvidenceKind::TestResult
        || admitted.evidence_ref.producer_role != Role::Coordinator
    {
        return Err(invalid(
            "invalid_admitted_evidence_ref",
            "admitted evidence must be a current TestResult produced by Coordinator",
        ));
    }
    let Some(integrity) = &admitted.evidence_ref.integrity else {
        return Err(invalid(
            "missing_admitted_integrity",
            "admitted evidence requires SHA-256 integrity metadata",
        ));
    };
    if integrity.contract_version != ContractVersion::current() || integrity.algorithm != "sha256" {
        return Err(invalid(
            "invalid_admitted_integrity",
            "admitted integrity must use current contract version and sha256",
        ));
    }
    validate_digest(&integrity.digest, "admitted integrity digest")?;
    let expected_id = format!("verification-bundle-sha256-{}", integrity.digest);
    let expected_reference = format!("verification-bundles/sha256/{}", integrity.digest);
    if admitted.evidence_ref.id.as_str() != expected_id
        || admitted.evidence_ref.reference != expected_reference
    {
        return Err(invalid(
            "forged_admitted_evidence_ref",
            "evidence ID and reference must derive from the integrity digest",
        ));
    }
    validate_logical_path(&admitted.evidence_ref.reference)?;
    if admitted.satisfactions.is_empty() {
        return Err(invalid(
            "empty_admitted_satisfactions",
            "admitted evidence must carry authoritative satisfactions",
        ));
    }
    Ok(())
}

pub fn aggregate_completion_evidence(
    goal: &GoalContract,
    expected_run_id: &RunId,
    admitted: &[AdmittedTaskEvidence],
) -> LocalVerificationResult<CompletionEvidence> {
    validate_version(goal.contract_version, "goal_contract")?;
    validate_version(
        goal.permission_profile.contract_version,
        "permission_profile",
    )?;
    validate_version(
        goal.completion_precondition.contract_version,
        "completion_precondition",
    )?;
    validate_stable_id(goal.id.as_str(), "goal_id")?;
    validate_stable_id(expected_run_id.as_str(), "run_id")?;
    if admitted.is_empty() {
        return Err(invalid(
            "missing_admitted_evidence",
            "at least one admitted task evidence record is required",
        ));
    }

    let mut expected = BTreeSet::new();
    for text in &goal.acceptance_criteria {
        insert_goal_criterion(&mut expected, BehaviorKind::Acceptance, text)?;
    }
    for text in &goal.verification_criteria {
        insert_goal_criterion(&mut expected, BehaviorKind::Verification, text)?;
    }
    for text in &goal.definition_of_done {
        insert_goal_criterion(&mut expected, BehaviorKind::DefinitionOfDone, text)?;
    }

    let mut evidence_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut criterion_ids = BTreeSet::new();
    let mut owners = BTreeMap::new();
    for task_evidence in admitted {
        validate_admitted_task_evidence(task_evidence)?;
        if task_evidence.run_id != *expected_run_id || task_evidence.goal_id != goal.id {
            return Err(invalid(
                "admitted_binding_mismatch",
                "all admitted evidence must share the authoritative run and goal",
            ));
        }
        if !task_ids.insert(task_evidence.task_id.as_str()) {
            return Err(invalid(
                "duplicate_task_evidence",
                task_evidence.task_id.to_string(),
            ));
        }
        if !evidence_ids.insert(task_evidence.evidence_ref.id.as_str()) {
            return Err(invalid(
                "duplicate_evidence_id",
                task_evidence.evidence_ref.id.to_string(),
            ));
        }
        for satisfaction in &task_evidence.satisfactions {
            validate_stable_id(&satisfaction.criterion_id, "criterion_id")?;
            validate_text(&satisfaction.text, "criterion text")?;
            if !criterion_ids.insert(satisfaction.criterion_id.as_str()) {
                return Err(invalid(
                    "duplicate_criterion_id_ownership",
                    satisfaction.criterion_id.clone(),
                ));
            }
            let key = (satisfaction.kind, satisfaction.text.clone());
            if !expected.contains(&key) {
                return Err(invalid(
                    "extra_or_mismatched_criterion",
                    satisfaction.text.clone(),
                ));
            }
            if owners.insert(key, task_evidence.task_id.as_str()).is_some() {
                return Err(invalid(
                    "duplicate_criterion_ownership",
                    satisfaction.text.clone(),
                ));
            }
        }
    }
    if owners.len() != expected.len() {
        return Err(invalid(
            "partial_goal_coverage",
            "admitted task evidence does not cover the full GoalContract",
        ));
    }
    let minimum_evidence = goal.completion_precondition.minimum_evidence_refs.max(1) as usize;
    if evidence_ids.len() < minimum_evidence {
        return Err(invalid(
            "insufficient_goal_evidence",
            format!(
                "goal requires {minimum_evidence} unique evidence refs, got {}",
                evidence_ids.len()
            ),
        ));
    }

    Ok(CompletionEvidence {
        contract_version: ContractVersion::current(),
        evidence_refs: evidence_ids.into_iter().map(EvidenceId::from).collect(),
        satisfied_acceptance_criteria: goal.acceptance_criteria.clone(),
        satisfied_verification_criteria: goal.verification_criteria.clone(),
        satisfied_definition_of_done: goal.definition_of_done.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goal_runtime::{
        validate_run_transition, CompletionPrecondition, PermissionProfile, ProjectId, RiskTier,
        RunStatus, RunTransitionError,
    };
    use chrono::TimeZone;
    use serde_json::json;

    fn timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 9, 12, 0, 0).single().unwrap()
    }

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn policy_with_order(reverse: bool) -> LocalMachinePolicy {
        let executables = if reverse {
            ["python", "cargo"]
        } else {
            ["cargo", "python"]
        };
        let environments = if reverse {
            ["RUST_BACKTRACE", "CARGO_TERM_COLOR"]
        } else {
            ["CARGO_TERM_COLOR", "RUST_BACKTRACE"]
        };
        LocalMachinePolicy {
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
            allowed_executable_ids: executables.into_iter().map(str::to_owned).collect(),
            allowed_environment_names: environments.into_iter().map(str::to_owned).collect(),
        }
    }

    fn behavior(
        task: &str,
        suffix: &str,
        acceptance: &str,
        verification: &str,
        done: &str,
    ) -> BehavioralAcceptanceContract {
        BehavioralAcceptanceContract {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            contract_id: format!("behavior.{task}"),
            binding: BehaviorBinding::Bound {
                goal_id: GoalId::from("goal.local-verification"),
                task_id: TaskId::from(task),
            },
            criteria: vec![
                BehaviorCriterion {
                    criterion_id: format!("criterion.accept.{suffix}"),
                    order: 0,
                    kind: BehaviorKind::Acceptance,
                    text: acceptance.to_owned(),
                    required: true,
                    capability_ids: vec!["cap.core".to_owned()],
                },
                BehaviorCriterion {
                    criterion_id: format!("criterion.verify.{suffix}"),
                    order: 1,
                    kind: BehaviorKind::Verification,
                    text: verification.to_owned(),
                    required: true,
                    capability_ids: vec!["cap.core".to_owned()],
                },
                BehaviorCriterion {
                    criterion_id: format!("criterion.dod.{suffix}"),
                    order: 2,
                    kind: BehaviorKind::DefinitionOfDone,
                    text: done.to_owned(),
                    required: true,
                    capability_ids: vec!["cap.core".to_owned()],
                },
            ],
        }
    }

    fn capability(behavior: &BehavioralAcceptanceContract) -> CapabilityDefinition {
        let mut criterion_ids = behavior
            .criteria
            .iter()
            .map(|criterion| criterion.criterion_id.clone())
            .collect::<Vec<_>>();
        criterion_ids.sort();
        CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "cap.core".to_owned(),
            revision: 1,
            criterion_ids,
            dependencies: vec![],
            changed_path_selectors: vec![
                ChangedPathSelector {
                    kind: PathSelectorKind::Exact,
                    path: "rust/ovca-types/src/goal_runtime.rs".to_owned(),
                },
                ChangedPathSelector {
                    kind: PathSelectorKind::Prefix,
                    path: "rust/ovca-types/src/goal_runtime".to_owned(),
                },
            ],
            policy: policy_with_order(false),
            commands: vec![VerificationCommand {
                command_id: "command.ovca-types-test".to_owned(),
                executable_id: "cargo".to_owned(),
                argv: vec!["test".to_owned(), "-p".to_owned(), "ovca-types".to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: ["CARGO_TERM_COLOR".to_owned()].into_iter().collect(),
            }],
        }
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

    fn bundle(
        behavior: &BehavioralAcceptanceContract,
        digest_character: char,
    ) -> VerificationBundle {
        let (goal_id, task_id) = behavior.bound_ids().unwrap();
        VerificationBundle {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            bundle_id: format!("bundle.{}", task_id.as_str()),
            run_id: RunId::from("run.local-verification"),
            goal_id: goal_id.clone(),
            task_id: task_id.clone(),
            behavior_contract_id: behavior.contract_id.clone(),
            capability_ids: vec!["cap.core".to_owned()],
            implementation_actor: WorkerId::from(format!("engineer.{digest_character}")),
            verifier_actor: WorkerId::from(format!("reviewer.{digest_character}")),
            fingerprints: fingerprints(),
            criterion_results: behavior
                .criteria
                .iter()
                .map(|criterion| CriterionResult {
                    criterion_id: criterion.criterion_id.clone(),
                    order: criterion.order,
                    kind: criterion.kind,
                    text: criterion.text.clone(),
                    verdict: CriterionResultVerdict::Pass,
                })
                .collect(),
            failures: vec![],
            verdict: VerificationVerdict::Pass,
            created_at: timestamp(),
        }
    }

    fn proof(
        behavior: &BehavioralAcceptanceContract,
        digest_character: char,
    ) -> CurrentBundleProof {
        let (goal_id, task_id) = behavior.bound_ids().unwrap();
        CurrentBundleProof {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            bundle_digest: digest(digest_character),
            checksum_verified: true,
            integrity_verified: true,
            current_pointer_verified: true,
            current_pointer_digest: digest(digest_character),
            expected_run_id: RunId::from("run.local-verification"),
            expected_goal_id: goal_id.clone(),
            expected_task_id: task_id.clone(),
            expected_behavior_contract_digest: digest('b'),
            expected_capability_set_digest: digest('c'),
            expected_command_digest: digest('d'),
            expected_policy_digest: digest('e'),
            expected_source_digest: digest('a'),
            expected_environment_digest: digest('f'),
        }
    }

    fn failure(
        id: &str,
        category: VerificationFailureCategory,
        confirmation: FailureConfirmation,
    ) -> VerificationFailure {
        VerificationFailure {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            failure_id: id.to_owned(),
            category,
            confirmation,
            supersedes_failure_id: None,
            criterion_id: None,
            summary: "deterministic failure".to_owned(),
            recorded_at: timestamp(),
        }
    }

    fn goal_contract() -> GoalContract {
        GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from("goal.local-verification"),
            project_id: ProjectId::from("project.oracle"),
            objective: "Use current local verification evidence".to_owned(),
            constraints: vec![],
            acceptance_criteria: vec!["Acceptance A".to_owned(), "Acceptance B".to_owned()],
            verification_criteria: vec!["Verification A".to_owned(), "Verification B".to_owned()],
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R1,
                resource_keys: vec![],
                write_keys: vec![],
                approval_required: false,
                review_required: true,
                audit_required: true,
            },
            definition_of_done: vec!["Done A".to_owned(), "Done B".to_owned()],
            completion_precondition: CompletionPrecondition {
                contract_version: ContractVersion::current(),
                minimum_evidence_refs: 2,
                require_all_acceptance_criteria: true,
                require_all_verification_criteria: true,
            },
            created_at: timestamp(),
            updated_at: timestamp(),
        }
    }

    fn admitted(
        task: &str,
        suffix: &str,
        acceptance: &str,
        verification: &str,
        done: &str,
        digest_character: char,
    ) -> AdmittedTaskEvidence {
        let behavior = behavior(task, suffix, acceptance, verification, done);
        admit_current_pass_bundle(
            &behavior,
            &[capability(&behavior)],
            &bundle(&behavior, digest_character),
            &proof(&behavior, digest_character),
        )
        .unwrap()
    }

    #[test]
    fn deterministic_contract_serialization_is_repeatable_and_set_order_independent() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let first = behavior.canonical_json_bytes().unwrap();
        assert_eq!(first, behavior.canonical_json_bytes().unwrap());

        let mut capability_a = capability(&behavior);
        capability_a.policy = policy_with_order(false);
        let mut capability_b = capability(&behavior);
        capability_b.policy = policy_with_order(true);
        assert_eq!(
            capability_a.canonical_json_bytes().unwrap(),
            capability_b.canonical_json_bytes().unwrap()
        );

        let bundle = bundle(&behavior, '1');
        assert_eq!(
            bundle.canonical_json_bytes().unwrap(),
            bundle.canonical_json_bytes().unwrap()
        );
    }

    #[test]
    fn published_samples_match_the_rust_wire_contracts() {
        let behavior: BehavioralAcceptanceContract = serde_json::from_str(include_str!(
            "../../../../contracts/samples/behavioral_acceptance_contract.v1.sample.json"
        ))
        .unwrap();
        behavior.validate().unwrap();

        let capability: CapabilityDefinition = serde_json::from_str(include_str!(
            "../../../../contracts/samples/capability_definition.v1.sample.json"
        ))
        .unwrap();
        capability.validate().unwrap();

        let failure: VerificationFailure = serde_json::from_str(include_str!(
            "../../../../contracts/samples/verification_failure.v1.sample.json"
        ))
        .unwrap();
        failure.validate().unwrap();

        let bundle: VerificationBundle = serde_json::from_str(include_str!(
            "../../../../contracts/samples/verification_bundle.v1.sample.json"
        ))
        .unwrap();
        bundle.validate().unwrap();
    }

    #[test]
    fn ordered_vectors_reject_noncanonical_or_duplicate_values() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let mut capability = capability(&behavior);
        capability.criterion_ids.reverse();
        assert_eq!(
            capability.validate().unwrap_err().code,
            "noncanonical_or_duplicate_id"
        );

        let mut behavior_bad = behavior.clone();
        behavior_bad.criteria[1].order = 0;
        assert_eq!(
            behavior_bad.validate().unwrap_err().code,
            "noncanonical_criterion_order"
        );

        let mut duplicate = behavior;
        duplicate.criteria[1].criterion_id = duplicate.criteria[0].criterion_id.clone();
        assert_eq!(
            duplicate.validate().unwrap_err().code,
            "duplicate_criterion_id"
        );
    }

    #[test]
    fn unsupported_versions_unknown_fields_and_blank_ids_are_rejected() {
        let mut invalid_behavior =
            behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        invalid_behavior.contract_version = ContractVersion(2);
        assert_eq!(
            invalid_behavior.validate().unwrap_err().code,
            "unsupported_contract_version"
        );

        invalid_behavior.contract_version = LOCAL_VERIFICATION_CONTRACT_VERSION;
        invalid_behavior.contract_id = " ".to_owned();
        assert_eq!(
            invalid_behavior.validate().unwrap_err().code,
            "invalid_stable_id"
        );

        let mut value = serde_json::to_value(behavior(
            "task.a",
            "a",
            "Acceptance A",
            "Verification A",
            "Done A",
        ))
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), json!(true));
        assert!(serde_json::from_value::<BehavioralAcceptanceContract>(value).is_err());
    }

    #[test]
    fn logical_paths_are_platform_independent_and_fail_closed() {
        for unsafe_path in [
            "C:/oracle/file",
            "/oracle/file",
            "//server/share",
            r"oracle\file",
            "https://example.test/file",
            "oracle//file",
            "oracle/./file",
            "oracle/../file",
            "oracle/\tfile",
            "oracle/\0file",
            "oracle/\u{007f}file",
        ] {
            assert_eq!(
                validate_logical_path(unsafe_path).unwrap_err().code,
                "unsafe_logical_path",
                "{unsafe_path}"
            );
        }
        validate_logical_path("verification-bundles/sha256/abc").unwrap();
    }

    #[test]
    fn tagged_working_directories_and_safe_argv_are_host_independent() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let mut capability = capability(&behavior);
        capability.commands[0].cwd = WorkingDirectory::SnapshotRoot;
        capability.commands[0].argv = vec![
            "--manifest-path".to_owned(),
            "rust/Cargo.toml".to_owned(),
            "-p".to_owned(),
            "ovca-types".to_owned(),
            "foo::bar".to_owned(),
            "--feature=value".to_owned(),
        ];
        capability.validate().unwrap();

        capability.commands[0].cwd = WorkingDirectory::Relative {
            path: "rust".to_owned(),
        };
        capability.validate().unwrap();

        capability.commands[0].cwd = WorkingDirectory::Relative {
            path: ".".to_owned(),
        };
        assert_eq!(
            capability.validate().unwrap_err().code,
            "unsafe_logical_path"
        );

        capability.commands[0].cwd = WorkingDirectory::SnapshotRoot;
        for unsafe_argument in [
            "C:/oracle/file",
            r"C:\oracle\file",
            "/absolute/file",
            r"\\server\share",
            "//server/share",
            "https://example.test/file",
            "file://local/file",
            "--path=C:/oracle/file",
            "--path=/absolute/file",
            "https://host/path?x=1",
            "/root?x=1",
            "C:/root?x=1",
            "//server/share?x=1",
            "--path=x=C:/oracle/file",
            "file:/absolute/file",
            "file:C:/absolute/file",
            "--path=file:C:/absolute/file",
            "C:relative/path",
            "--path=C:relative/path",
            "relative/C:/absolute/file",
            "--path:C:relative/path",
            "-IC:relative/include",
            "--wrapper=-IC:relative/include",
            "--path=x=C:relative/path",
            "--path:c:relative/path",
            "-Iz:relative/include",
            "line\nbreak",
            "tab\tvalue",
            "delete\u{007f}value",
        ] {
            capability.commands[0].argv = vec![unsafe_argument.to_owned()];
            assert!(
                matches!(
                    capability.validate().unwrap_err().code,
                    "invalid_argv" | "unsafe_argv_reference"
                ),
                "{unsafe_argument:?}"
            );
        }

        capability.commands[0].argv = vec![
            "--flag=value".to_owned(),
            "relative/path".to_owned(),
            "relative/path?x=1".to_owned(),
            "foo::bar".to_owned(),
            "crate::module::test".to_owned(),
            "--cfg=foo::bar".to_owned(),
            "C%3Arelative/path".to_owned(),
            "--path=C%3Arelative/path".to_owned(),
        ];
        capability.validate().unwrap();
    }

    #[test]
    fn unsafe_shell_executable_environment_and_policy_are_rejected() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let mut invalid_capability = capability(&behavior);
        invalid_capability.policy.local_only = false;
        assert_eq!(
            invalid_capability.validate().unwrap_err().code,
            "unsafe_machine_policy"
        );

        let mut invalid_capability = capability(&behavior);
        invalid_capability.commands[0].executable_id = "python".to_owned();
        invalid_capability
            .policy
            .allowed_executable_ids
            .remove("python");
        assert_eq!(
            invalid_capability.validate().unwrap_err().code,
            "executable_not_allowlisted"
        );

        let mut invalid_capability = capability(&behavior);
        invalid_capability.commands[0].executable_id = "pwsh".to_owned();
        assert_eq!(
            invalid_capability.validate().unwrap_err().code,
            "raw_shell_forbidden"
        );

        for forbidden in [
            "sh",
            "SH.EXE",
            "bash",
            "Bash.Exe",
            "zsh",
            "ZSH.EXE",
            "cmd",
            "CMD.EXE",
            "powershell",
            "PowerShell.Exe",
            "pwsh",
            "PWSH.EXE",
        ] {
            assert!(is_forbidden_verification_shell(forbidden));
        }
        assert!(!is_forbidden_verification_shell("reviewed-runner"));

        for formerly_missing in ["sh.exe", "bash.exe", "zsh.exe", "pwsh.exe"] {
            let mut invalid_capability = capability(&behavior);
            invalid_capability.commands[0].executable_id = formerly_missing.to_owned();
            assert_eq!(
                invalid_capability.validate_commands().unwrap_err().code,
                "raw_shell_forbidden",
                "{formerly_missing}"
            );
        }

        for mixed_case in ["Cargo", "PwSh", "BASH", "PowerShell.EXE"] {
            let mut invalid_capability = capability(&behavior);
            invalid_capability.policy.allowed_executable_ids =
                [mixed_case.to_owned()].into_iter().collect();
            invalid_capability.commands[0].executable_id = mixed_case.to_owned();
            assert_eq!(
                invalid_capability.validate().unwrap_err().code,
                "noncanonical_executable_id",
                "{mixed_case}"
            );
        }

        let mut invalid_capability = capability(&behavior);
        invalid_capability.commands[0]
            .environment_names
            .insert("UNDECLARED_ENV".to_owned());
        assert_eq!(
            invalid_capability.validate().unwrap_err().code,
            "environment_not_allowlisted"
        );
    }

    #[test]
    fn product_bug_and_fragility_require_provisional_then_superseding_confirmation() {
        for category in [
            VerificationFailureCategory::ProductBug,
            VerificationFailureCategory::TestFragility,
        ] {
            let provisional = failure(
                "failure.initial",
                category,
                FailureConfirmation::Provisional,
            );
            provisional.validate().unwrap();

            let direct = failure(
                "failure.confirmed",
                category,
                FailureConfirmation::Confirmed,
            );
            assert_eq!(
                direct.validate().unwrap_err().code,
                "confirmed_failure_requires_superseded_record"
            );

            let mut superseding = direct;
            superseding.supersedes_failure_id = Some("failure.initial".to_owned());
            superseding.validate().unwrap();
        }

        let mut self_superseding = failure(
            "failure.same",
            VerificationFailureCategory::ProductBug,
            FailureConfirmation::Confirmed,
        );
        self_superseding.supersedes_failure_id = Some("failure.same".to_owned());
        assert_eq!(
            self_superseding.validate().unwrap_err().code,
            "self_superseding_failure"
        );

        failure(
            "failure.timeout",
            VerificationFailureCategory::Timeout,
            FailureConfirmation::Confirmed,
        )
        .validate()
        .unwrap();
    }

    #[test]
    fn bundle_verdict_and_failure_semantics_are_closed() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let mut pass_with_failure = bundle(&behavior, '1');
        pass_with_failure.failures.push(failure(
            "failure.test",
            VerificationFailureCategory::TestFailedUnclassified,
            FailureConfirmation::Confirmed,
        ));
        assert_eq!(
            pass_with_failure.validate().unwrap_err().code,
            "pass_with_failure"
        );

        let mut pass_with_nonpass = bundle(&behavior, '1');
        pass_with_nonpass.criterion_results[0].verdict = CriterionResultVerdict::Fail;
        assert_eq!(
            pass_with_nonpass.validate().unwrap_err().code,
            "pass_with_nonpass_result"
        );

        let mut nonpass_without_failure = bundle(&behavior, '1');
        nonpass_without_failure.verdict = VerificationVerdict::Timeout;
        assert_eq!(
            nonpass_without_failure.validate().unwrap_err().code,
            "nonpass_without_matching_failure"
        );

        let mut timeout = nonpass_without_failure;
        timeout.failures.push(failure(
            "failure.timeout",
            VerificationFailureCategory::Timeout,
            FailureConfirmation::Confirmed,
        ));
        timeout.validate().unwrap();

        let mut timeout_with_only_product_bug = bundle(&behavior, '1');
        timeout_with_only_product_bug.verdict = VerificationVerdict::Timeout;
        timeout_with_only_product_bug.failures.push(failure(
            "failure.product",
            VerificationFailureCategory::ProductBug,
            FailureConfirmation::Provisional,
        ));
        assert_eq!(
            timeout_with_only_product_bug.validate().unwrap_err().code,
            "nonpass_without_matching_failure"
        );

        let mut noncanonical_failures = bundle(&behavior, '1');
        noncanonical_failures.verdict = VerificationVerdict::Fail;
        noncanonical_failures.failures = vec![
            failure(
                "failure.z",
                VerificationFailureCategory::TestFailedUnclassified,
                FailureConfirmation::Confirmed,
            ),
            failure(
                "failure.a",
                VerificationFailureCategory::TestFailedUnclassified,
                FailureConfirmation::Confirmed,
            ),
        ];
        assert_eq!(
            noncanonical_failures.validate().unwrap_err().code,
            "noncanonical_or_duplicate_failure"
        );

        let mut false_source_drift = bundle(&behavior, '1');
        false_source_drift.verdict = VerificationVerdict::Invalid;
        false_source_drift.failures.push(failure(
            "failure.source-drift",
            VerificationFailureCategory::SourceDrift,
            FailureConfirmation::Confirmed,
        ));
        assert_eq!(
            false_source_drift.validate().unwrap_err().code,
            "source_drift_failure_without_drift"
        );

        let mut unknown_failure_criterion = bundle(&behavior, '1');
        unknown_failure_criterion.verdict = VerificationVerdict::Fail;
        let mut unknown_criterion = failure(
            "failure.unknown-criterion",
            VerificationFailureCategory::TestFailedUnclassified,
            FailureConfirmation::Confirmed,
        );
        unknown_criterion.criterion_id = Some("criterion.missing".to_owned());
        unknown_failure_criterion.failures.push(unknown_criterion);
        assert_eq!(
            unknown_failure_criterion.validate().unwrap_err().code,
            "failure_criterion_not_in_bundle"
        );
    }

    #[test]
    fn admission_rejects_unbound_mismatched_non_independent_and_incomplete_records() {
        let bound = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let capability = capability(&bound);
        let valid_bundle = bundle(&bound, '1');
        let valid_proof = proof(&bound, '1');

        let mut unbound = bound.clone();
        unbound.binding = BehaviorBinding::Unbound;
        assert_eq!(
            admit_current_pass_bundle(
                &unbound,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &valid_proof,
            )
            .unwrap_err()
            .code,
            "unbound_behavior_contract"
        );

        let mut mismatch = valid_proof.clone();
        mismatch.expected_task_id = TaskId::from("task.other");
        assert_eq!(
            admit_current_pass_bundle(
                &bound,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &mismatch,
            )
            .unwrap_err()
            .code,
            "proof_binding_mismatch"
        );

        let mut same_actor = valid_bundle.clone();
        same_actor.verifier_actor = same_actor.implementation_actor.clone();
        assert_eq!(
            admit_current_pass_bundle(
                &bound,
                std::slice::from_ref(&capability),
                &same_actor,
                &valid_proof,
            )
            .unwrap_err()
            .code,
            "verifier_not_independent"
        );

        let mut incomplete = valid_bundle;
        incomplete.criterion_results.pop();
        assert_eq!(
            admit_current_pass_bundle(&bound, &[capability], &incomplete, &valid_proof)
                .unwrap_err()
                .code,
            "incomplete_criterion_coverage"
        );
    }

    #[test]
    fn run_id_replay_is_rejected_at_admission_and_goal_aggregation() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let capability = capability(&behavior);
        let mut replayed_bundle = bundle(&behavior, '1');
        replayed_bundle.run_id = RunId::from("run.other");
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                &[capability],
                &replayed_bundle,
                &proof(&behavior, '1'),
            )
            .unwrap_err()
            .code,
            "proof_binding_mismatch"
        );

        let task_a = admitted(
            "task.a",
            "a",
            "Acceptance A",
            "Verification A",
            "Done A",
            '1',
        );
        let mut task_b = admitted(
            "task.b",
            "b",
            "Acceptance B",
            "Verification B",
            "Done B",
            '2',
        );
        task_b.run_id = RunId::from("run.replayed");
        assert_eq!(
            aggregate_completion_evidence(
                &goal_contract(),
                &RunId::from("run.local-verification"),
                &[task_a, task_b],
            )
            .unwrap_err()
            .code,
            "admitted_binding_mismatch"
        );
    }

    #[test]
    fn admission_requires_complete_capability_bindings_and_dependency_closure() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let valid_bundle = bundle(&behavior, '1');
        let valid_proof = proof(&behavior, '1');

        let mut missing_binding = behavior.clone();
        missing_binding.criteria[0].capability_ids.clear();
        let missing_binding_capability = capability(&missing_binding);
        assert_eq!(
            admit_current_pass_bundle(
                &missing_binding,
                &[missing_binding_capability],
                &valid_bundle,
                &valid_proof,
            )
            .unwrap_err()
            .code,
            "missing_criterion_capability"
        );

        let mut missing_dependency = capability(&behavior);
        missing_dependency.dependencies = vec!["cap.missing".to_owned()];
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                &[missing_dependency],
                &valid_bundle,
                &valid_proof,
            )
            .unwrap_err()
            .code,
            "missing_capability_dependency"
        );
    }

    #[test]
    fn admission_rejects_text_order_digest_integrity_pointer_and_source_drift() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let capability = capability(&behavior);
        let valid_bundle = bundle(&behavior, '1');
        let valid_proof = proof(&behavior, '1');

        let mut text_mismatch = valid_bundle.clone();
        text_mismatch.criterion_results[0].text = "different bytes".to_owned();
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                std::slice::from_ref(&capability),
                &text_mismatch,
                &valid_proof
            )
            .unwrap_err()
            .code,
            "criterion_identity_mismatch"
        );

        let mut invalid_digest = valid_proof.clone();
        invalid_digest.bundle_digest = "ABC".to_owned();
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &invalid_digest
            )
            .unwrap_err()
            .code,
            "invalid_sha256_digest"
        );

        let mut corrupted = valid_proof.clone();
        corrupted.checksum_verified = false;
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &corrupted,
            )
            .unwrap_err()
            .code,
            "bundle_integrity_unverified"
        );

        let mut pointer_mismatch = valid_proof.clone();
        pointer_mismatch.current_pointer_digest = digest('9');
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &pointer_mismatch
            )
            .unwrap_err()
            .code,
            "current_pointer_mismatch"
        );

        let mut stale = valid_proof.clone();
        stale.expected_command_digest = digest('9');
        assert_eq!(
            admit_current_pass_bundle(
                &behavior,
                std::slice::from_ref(&capability),
                &valid_bundle,
                &stale,
            )
            .unwrap_err()
            .code,
            "stale_or_mismatched_fingerprint"
        );

        let mut drift = valid_bundle;
        drift.fingerprints.source_post = digest('9');
        assert_eq!(
            admit_current_pass_bundle(&behavior, &[capability], &drift, &valid_proof)
                .unwrap_err()
                .code,
            "source_drift"
        );
    }

    #[test]
    fn admitted_evidence_uses_digest_derived_id_and_logical_local_reference() {
        let behavior = behavior("task.a", "a", "Acceptance A", "Verification A", "Done A");
        let admitted = admit_current_pass_bundle(
            &behavior,
            &[capability(&behavior)],
            &bundle(&behavior, '1'),
            &proof(&behavior, '1'),
        )
        .unwrap();
        assert_eq!(
            admitted.evidence_ref.id.as_str(),
            format!("verification-bundle-sha256-{}", digest('1'))
        );
        assert_eq!(
            admitted.evidence_ref.reference,
            format!("verification-bundles/sha256/{}", digest('1'))
        );
        assert_eq!(admitted.evidence_ref.kind, EvidenceKind::TestResult);
        assert_eq!(admitted.evidence_ref.producer_role, Role::Coordinator);
        assert_eq!(
            admitted.evidence_ref.integrity.as_ref().unwrap().digest,
            digest('1')
        );
    }

    #[test]
    fn multi_task_aggregation_is_complete_deterministic_and_goal_ordered() {
        let task_a = admitted(
            "task.a",
            "a",
            "Acceptance A",
            "Verification A",
            "Done A",
            '1',
        );
        let task_b = admitted(
            "task.b",
            "b",
            "Acceptance B",
            "Verification B",
            "Done B",
            '2',
        );
        let goal = goal_contract();
        let completion = aggregate_completion_evidence(
            &goal,
            &RunId::from("run.local-verification"),
            &[task_b, task_a],
        )
        .unwrap();
        assert_eq!(
            completion.satisfied_acceptance_criteria,
            goal.acceptance_criteria
        );
        assert_eq!(
            completion.satisfied_verification_criteria,
            goal.verification_criteria
        );
        assert_eq!(
            completion.satisfied_definition_of_done,
            goal.definition_of_done
        );
        assert_eq!(
            completion
                .evidence_refs
                .iter()
                .map(EvidenceId::as_str)
                .collect::<Vec<_>>(),
            vec![
                format!("verification-bundle-sha256-{}", digest('1')),
                format!("verification-bundle-sha256-{}", digest('2')),
            ]
        );
    }

    #[test]
    fn partial_duplicate_and_extra_goal_coverage_are_rejected() {
        let task_a = admitted(
            "task.a",
            "a",
            "Acceptance A",
            "Verification A",
            "Done A",
            '1',
        );
        let task_b = admitted(
            "task.b",
            "b",
            "Acceptance B",
            "Verification B",
            "Done B",
            '2',
        );
        let goal = goal_contract();
        assert_eq!(
            aggregate_completion_evidence(
                &goal,
                &RunId::from("run.local-verification"),
                std::slice::from_ref(&task_a)
            )
            .unwrap_err()
            .code,
            "partial_goal_coverage"
        );

        let mut duplicate_owner = task_a.clone();
        duplicate_owner.task_id = TaskId::from("task.c");
        duplicate_owner.evidence_ref.id =
            EvidenceId::from(format!("verification-bundle-sha256-{}", digest('3')));
        duplicate_owner.evidence_ref.reference =
            format!("verification-bundles/sha256/{}", digest('3'));
        duplicate_owner
            .evidence_ref
            .integrity
            .as_mut()
            .unwrap()
            .digest = digest('3');
        assert_eq!(
            aggregate_completion_evidence(
                &goal,
                &RunId::from("run.local-verification"),
                &[task_a.clone(), duplicate_owner, task_b.clone()]
            )
            .unwrap_err()
            .code,
            "duplicate_criterion_id_ownership"
        );

        let mut extra = task_b;
        extra.satisfactions[0].text = "Not in the GoalContract".to_owned();
        assert_eq!(
            aggregate_completion_evidence(
                &goal,
                &RunId::from("run.local-verification"),
                &[task_a, extra]
            )
            .unwrap_err()
            .code,
            "extra_or_mismatched_criterion"
        );
    }

    #[test]
    fn aggregation_revalidates_digest_derived_admitted_evidence_refs() {
        let mut task_a = admitted(
            "task.a",
            "a",
            "Acceptance A",
            "Verification A",
            "Done A",
            '1',
        );
        let task_b = admitted(
            "task.b",
            "b",
            "Acceptance B",
            "Verification B",
            "Done B",
            '2',
        );
        task_a.evidence_ref.id = EvidenceId::from("caller.bundle-id");
        assert_eq!(
            aggregate_completion_evidence(
                &goal_contract(),
                &RunId::from("run.local-verification"),
                &[task_a, task_b],
            )
            .unwrap_err()
            .code,
            "forged_admitted_evidence_ref"
        );
    }

    #[test]
    fn existing_reviewer_and_auditor_completion_gates_remain_unchanged() {
        let goal = goal_contract();
        let evidence = CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: vec![
                EvidenceId::from("evidence.1"),
                EvidenceId::from("evidence.2"),
            ],
            satisfied_acceptance_criteria: goal.acceptance_criteria.clone(),
            satisfied_verification_criteria: goal.verification_criteria.clone(),
            satisfied_definition_of_done: goal.definition_of_done.clone(),
        };
        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal),
                Some(&evidence)
            ),
            Err(RunTransitionError::WrongCompletionGate {
                from: RunStatus::Reviewing,
                required: RunStatus::Auditing,
            })
        );
        validate_run_transition(
            RunStatus::Auditing,
            RunStatus::Completed,
            Some(&goal),
            Some(&evidence),
        )
        .unwrap();
    }

    #[test]
    fn v3_capability_validation_phases_preserve_command_error_origin() {
        let behavior = behavior(
            "task.v3",
            "v3",
            "acceptance v3",
            "verification v3",
            "done v3",
        );
        let mut value = capability(&behavior);
        value.commands[0].argv[0] = "C:/machine/path".to_owned();
        value.validate_non_command_fields().unwrap();
        assert_eq!(
            value.validate_commands().unwrap_err().code,
            "unsafe_argv_reference"
        );
        assert_eq!(value.validate().unwrap_err().code, "unsafe_argv_reference");
    }

    #[test]
    fn v3_transcript_identity_is_lf_canonical_and_sha256_is_stable() {
        let transcript = VerificationTranscriptIdentity {
            commands: vec![VerificationTranscriptCommandIdentity {
                sequence: 0,
                command_digest: digest('1'),
                executable_digest: digest('2'),
                termination: VerificationTermination::Completed,
                exit_code: Some(0),
                stdout_sha256: verification_sha256_hex(b"stdout"),
                stderr_sha256: verification_sha256_hex(b""),
                stdout_bytes: 6,
                stderr_bytes: 0,
            }],
        };
        let first = transcript.canonical_json_bytes().unwrap();
        let second = transcript.canonical_json_bytes().unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert!(!first.ends_with(b"\n\n"));
        assert_eq!(
            transcript.sha256().unwrap(),
            verification_sha256_hex(&first)
        );
        assert_eq!(
            verification_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
