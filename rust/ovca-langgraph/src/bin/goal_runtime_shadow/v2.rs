use chrono::{DateTime, Utc};
use ovca_storage::{CasOutcome, CasToken, EvidenceBank, ProjectionExpectation, PublishOutcome};
use ovca_types::{
    verification_sha256_hex, BehavioralAcceptanceContract, CapabilityDefinition,
    TargetedRerunSelection, VerificationVerdict, WorkerId,
};
use ovca_verifier::bundle::{FailureCode, FailureIdentityKey, FailureIdentityMap};
use ovca_verifier::execution::{
    EnvironmentBindings, ExecutableProfile, ExecutableRegistry, ExecutionLimits,
};
use ovca_verifier::snapshot::SourceManifest;
use ovca_verifier::{
    verify_and_publish, VerifierOutcome, VerifierRequest, VerifierRequestRejectionCode,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{DispatchOutcome, RequiredGate, TaskKind};

const INPUT_SCHEMA_VERSION: u32 = 2;
const REQUEST_SCHEMA_VERSION: u32 = 1;
const REQUEST_ID_PREFIX: &str = "vreq.sha256.";
const MAX_REQUEST_BYTES: u64 = 1_048_576;

type ConfigResult<T> = Result<T, ()>;

#[derive(Debug, Clone, Deserialize)]
struct V2Metadata {
    schema_version: u32,
    request_correlation: String,
    task_kind: TaskKind,
    required_gate: RequiredGate,
    dispatch_outcome: DispatchOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Input {
    schema_version: u32,
    request_correlation: String,
    task_kind: TaskKind,
    required_gate: RequiredGate,
    dispatch_outcome: DispatchOutcome,
    verification_request_id: String,
}

impl V2Input {
    fn metadata(&self) -> V2Metadata {
        V2Metadata {
            schema_version: self.schema_version,
            request_correlation: self.request_correlation.clone(),
            task_kind: self.task_kind,
            required_gate: self.required_gate,
            dispatch_outcome: self.dispatch_outcome,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum Output {
    Report(Report),
    MinimalError(MinimalError),
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    schema_version: u32,
    request_correlation: String,
    task_kind: TaskKind,
    required_gate: RequiredGate,
    dispatch_outcome: DispatchOutcome,
    shadow_only: bool,
    status: &'static str,
    verification_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_record_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_verdict: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publication_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    projection_status: Option<&'static str>,
    completion_evidence_recorded: bool,
    egress_enforcement: &'static str,
    production_effect: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct MinimalError {
    schema_version: u32,
    shadow_only: bool,
    status: &'static str,
    verification_status: &'static str,
    completion_evidence_recorded: bool,
    egress_enforcement: &'static str,
    production_effect: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRequestFile {
    schema_version: u32,
    behavior: BehavioralAcceptanceContract,
    capabilities: Vec<CapabilityDefinition>,
    selection: TargetedRerunSelection,
    source_manifest: SourceManifest,
    source_root: PathBuf,
    executable_profiles: Vec<ExecutableProfileRow>,
    environment_bindings: Vec<EnvironmentBindingRow>,
    environment_digest: String,
    limits: ExecutionLimitsRow,
    implementation_actor: WorkerId,
    verifier_actor: WorkerId,
    created_at: String,
    failure_identities: Vec<FailureIdentityRow>,
    projection_expectation: ProjectionExpectationRow,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableProfileRow {
    executable_id: String,
    executable_path: PathBuf,
    sha256: String,
    enabled: bool,
    approved: bool,
    reviewed_offline: bool,
    allowed_environment_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentBindingRow {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum FailureCodeRow {
    TestFailedUnclassified,
    PolicyBlock,
    EnvironmentBlock,
    ExecutableUnavailable,
    ExecutableTamper,
    CommandTimeout,
    OutputLimit,
    SourceDrift,
    SnapshotTamper,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureIdentityRow {
    failure_code: FailureCodeRow,
    command_sequence: Option<u32>,
    failure_id: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionLimitsRow {
    timeout_millis: u64,
    stdout_cap_bytes: u64,
    stderr_cap_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ProjectionExpectationRow {
    Absent,
    Token {
        generation: u64,
        state_digest: String,
    },
}

#[derive(Clone)]
struct ConvertedRequest {
    behavior: BehavioralAcceptanceContract,
    capabilities: Vec<CapabilityDefinition>,
    selection: TargetedRerunSelection,
    source_manifest: SourceManifest,
    source_root: PathBuf,
    executable_registry: ExecutableRegistry,
    environment_bindings: EnvironmentBindings,
    environment_digest: String,
    limits: ExecutionLimits,
    implementation_actor: WorkerId,
    verifier_actor: WorkerId,
    created_at: DateTime<Utc>,
    failure_identities: FailureIdentityMap,
    projection_expectation: ProjectionExpectation,
}

pub(crate) fn schema_version(bytes: &[u8]) -> Option<u32> {
    #[derive(Deserialize)]
    struct VersionOnly {
        schema_version: u32,
    }

    serde_json::from_slice::<VersionOnly>(bytes)
        .ok()
        .map(|value| value.schema_version)
}

pub(crate) fn execute(
    durable_root: Option<&Path>,
    raw_durable_root: Option<&Path>,
    input_file_was_used: bool,
    bytes: &[u8],
) -> Output {
    let input = match serde_json::from_slice::<V2Input>(bytes) {
        Ok(value) if valid_metadata(&value.metadata()) => value,
        _ => return metadata_error(bytes),
    };
    let metadata = input.metadata();
    if input_file_was_used
        || durable_root.is_none()
        || raw_durable_root.is_none()
        || request_digest(&input.verification_request_id).is_none()
    {
        return Output::Report(Report::observer_error(metadata, "configuration_error"));
    }

    let durable_root = durable_root.expect("durable root checked above");
    let raw_durable_root = raw_durable_root.expect("raw durable root checked above");
    let verifier_root = match verifier_root(raw_durable_root, durable_root) {
        Ok(value) => value,
        Err(()) => {
            return Output::Report(Report::observer_error(metadata, "configuration_error"));
        }
    };
    let request =
        read_request(&verifier_root, &input.verification_request_id).and_then(convert_request);
    let request = match request {
        Ok(value) => value,
        Err(()) => {
            return Output::Report(Report::observer_error(metadata, "configuration_error"));
        }
    };

    Output::Report(run_verifier(&verifier_root, metadata, request))
}

fn metadata_error(bytes: &[u8]) -> Output {
    match serde_json::from_slice::<V2Metadata>(bytes) {
        Ok(metadata) if valid_metadata(&metadata) => {
            Output::Report(Report::observer_error(metadata, "configuration_error"))
        }
        _ => Output::MinimalError(MinimalError {
            schema_version: INPUT_SCHEMA_VERSION,
            shadow_only: true,
            status: "configuration_error",
            verification_status: "observer_error",
            completion_evidence_recorded: false,
            egress_enforcement: "policy_only",
            production_effect: "none",
        }),
    }
}

fn valid_metadata(metadata: &V2Metadata) -> bool {
    metadata.schema_version == INPUT_SCHEMA_VERSION
        && valid_correlation(&metadata.request_correlation)
}

fn valid_correlation(value: &str) -> bool {
    value.strip_prefix("grs-").is_some_and(|suffix| {
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn request_digest(request_id: &str) -> Option<&str> {
    let digest = request_id.strip_prefix(REQUEST_ID_PREFIX)?;
    valid_digest(digest).then_some(digest)
}

fn read_request(root: &Path, request_id: &str) -> ConfigResult<VerificationRequestFile> {
    let expected_digest = request_digest(request_id).ok_or(())?;
    let canonical_root = fs::canonicalize(root).map_err(|_| ())?;
    if !same_path(&canonical_root, root) {
        return Err(());
    }
    ensure_ordinary_directory(&canonical_root)?;

    let shadow_root = canonical_root.join("goal-runtime-shadow");
    let request_root = shadow_root.join("verification-requests");
    ensure_ordinary_directory(&shadow_root)?;
    ensure_ordinary_directory(&request_root)?;
    let canonical_request_root = fs::canonicalize(&request_root).map_err(|_| ())?;
    if !same_path(&canonical_request_root, &request_root) {
        return Err(());
    }

    let expected_name = format!("{request_id}.json");
    let request_path = request_root.join(&expected_name);
    let link_metadata = fs::symlink_metadata(&request_path).map_err(|_| ())?;
    if !link_metadata.is_file() || is_reparse_or_symlink(&link_metadata) {
        return Err(());
    }
    let canonical_request = fs::canonicalize(&request_path).map_err(|_| ())?;
    if canonical_request.parent() != Some(canonical_request_root.as_path())
        || canonical_request.file_name().and_then(|name| name.to_str())
            != Some(expected_name.as_str())
    {
        return Err(());
    }

    let mut file = fs::File::open(&canonical_request).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > MAX_REQUEST_BYTES {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES
        || bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || verification_sha256_hex(&bytes) != expected_digest
    {
        return Err(());
    }
    std::str::from_utf8(&bytes).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn convert_request(request: VerificationRequestFile) -> ConfigResult<ConvertedRequest> {
    if request.schema_version != REQUEST_SCHEMA_VERSION
        || !strictly_sorted_by(&request.capabilities, |value| value.capability_id.as_str())
        || !request.source_root.is_absolute()
        || !is_local_source_root(&request.source_root)
        || !valid_digest(&request.environment_digest)
    {
        return Err(());
    }

    let mut profiles = BTreeMap::new();
    let mut prior_profile: Option<String> = None;
    for row in request.executable_profiles {
        if prior_profile
            .as_deref()
            .is_some_and(|prior| prior >= row.executable_id.as_str())
            || !strictly_sorted_strings(&row.allowed_environment_names)
        {
            return Err(());
        }
        prior_profile = Some(row.executable_id.clone());
        let allowed_environment_names = row
            .allowed_environment_names
            .into_iter()
            .collect::<BTreeSet<_>>();
        let key = row.executable_id.clone();
        profiles.insert(
            key,
            ExecutableProfile {
                executable_id: row.executable_id,
                executable_path: row.executable_path,
                sha256: row.sha256,
                enabled: row.enabled,
                approved: row.approved,
                reviewed_offline: row.reviewed_offline,
                allowed_environment_names,
            },
        );
    }

    let mut values = BTreeMap::new();
    let mut prior_binding: Option<String> = None;
    for row in request.environment_bindings {
        if prior_binding
            .as_deref()
            .is_some_and(|prior| prior >= row.name.as_str())
            || row.value.contains('\0')
        {
            return Err(());
        }
        prior_binding = Some(row.name.clone());
        values.insert(row.name, OsString::from(row.value));
    }
    let required_names = request
        .capabilities
        .iter()
        .flat_map(|capability| capability.commands.iter())
        .flat_map(|command| command.environment_names.iter().cloned())
        .collect::<BTreeSet<_>>();
    if values.keys().cloned().collect::<BTreeSet<_>>() != required_names {
        return Err(());
    }
    let environment_bindings = EnvironmentBindings { values };
    if environment_bindings.digest_for(&required_names).as_deref()
        != Some(request.environment_digest.as_str())
    {
        return Err(());
    }

    let mut failure_identities = FailureIdentityMap::new();
    let mut prior_failure: Option<FailureIdentityKey> = None;
    for row in request.failure_identities {
        let key = FailureIdentityKey {
            failure_code: map_failure_code(row.failure_code),
            command_sequence: row.command_sequence,
        };
        if prior_failure.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(());
        }
        prior_failure = Some(key.clone());
        failure_identities.insert(key, row.failure_id);
    }

    let created_at = DateTime::parse_from_rfc3339(&request.created_at).map_err(|_| ())?;
    if !request.created_at.ends_with('Z') || created_at.offset().local_minus_utc() != 0 {
        return Err(());
    }
    let created_at = created_at.with_timezone(&Utc);

    let projection_expectation = match request.projection_expectation {
        ProjectionExpectationRow::Absent => ProjectionExpectation::Absent,
        ProjectionExpectationRow::Token {
            generation,
            state_digest,
        } if generation > 0 && valid_digest(&state_digest) => {
            ProjectionExpectation::Token(CasToken {
                generation,
                state_digest,
            })
        }
        ProjectionExpectationRow::Token { .. } => return Err(()),
    };

    Ok(ConvertedRequest {
        behavior: request.behavior,
        capabilities: request.capabilities,
        selection: request.selection,
        source_manifest: request.source_manifest,
        source_root: request.source_root,
        executable_registry: ExecutableRegistry { profiles },
        environment_bindings,
        environment_digest: request.environment_digest,
        limits: ExecutionLimits {
            timeout_millis: request.limits.timeout_millis,
            stdout_cap_bytes: request.limits.stdout_cap_bytes,
            stderr_cap_bytes: request.limits.stderr_cap_bytes,
        },
        implementation_actor: request.implementation_actor,
        verifier_actor: request.verifier_actor,
        created_at,
        failure_identities,
        projection_expectation,
    })
}

fn run_verifier(root: &Path, metadata: V2Metadata, request: ConvertedRequest) -> Report {
    let result = (|| {
        let snapshot_parent = root.join("goal-runtime-shadow").join("snapshots");
        fs::create_dir_all(&snapshot_parent).map_err(|_| ())?;
        ensure_ordinary_directory(&snapshot_parent)?;
        let snapshot = tempfile::Builder::new()
            .prefix("snapshot-")
            .tempdir_in(&snapshot_parent)
            .map_err(|_| ())?;
        let evidence_bank = EvidenceBank::try_new(root).map_err(|_| ())?;
        verify_and_publish(
            VerifierRequest {
                behavior: &request.behavior,
                capabilities: &request.capabilities,
                selection: &request.selection,
                source_manifest: &request.source_manifest,
                source_root: &request.source_root,
                snapshot_root: snapshot.path(),
                executable_registry: &request.executable_registry,
                environment_bindings: &request.environment_bindings,
                environment_digest: &request.environment_digest,
                limits: request.limits,
                implementation_actor: request.implementation_actor,
                verifier_actor: request.verifier_actor,
                created_at: request.created_at,
                failure_identities: &request.failure_identities,
            },
            &evidence_bank,
            &request.projection_expectation,
        )
        .map_err(|_| ())
    })();

    match result {
        Ok(VerifierOutcome::Rejected(rejected)) => {
            Report::rejected(metadata, rejection_code(rejected.code))
        }
        Ok(VerifierOutcome::Published(published)) => {
            let (publication_status, record_digest) = match &published.storage.publication {
                PublishOutcome::Inserted(record) => ("inserted", record.digest.clone()),
                PublishOutcome::ExistingIdentical(record) => {
                    ("existing_identical", record.digest.clone())
                }
            };
            let projection_status = match &published.storage.projection {
                CasOutcome::Applied(_) => "applied",
                CasOutcome::Unchanged(_) => "unchanged",
                CasOutcome::Conflict(_) => "conflict",
            };
            Report::published(
                metadata,
                published.bundle.bundle_id.clone(),
                record_digest,
                bundle_verdict(published.bundle.verdict),
                publication_status,
                projection_status,
            )
        }
        Err(()) => Report::observer_error(metadata, "observer_error"),
    }
}

impl Report {
    fn base(metadata: V2Metadata, status: &'static str, verification_status: &'static str) -> Self {
        Self {
            schema_version: INPUT_SCHEMA_VERSION,
            request_correlation: metadata.request_correlation,
            task_kind: metadata.task_kind,
            required_gate: metadata.required_gate,
            dispatch_outcome: metadata.dispatch_outcome,
            shadow_only: true,
            status,
            verification_status,
            rejection_code: None,
            bundle_id: None,
            bundle_record_digest: None,
            bundle_verdict: None,
            publication_status: None,
            projection_status: None,
            completion_evidence_recorded: false,
            egress_enforcement: "policy_only",
            production_effect: "none",
        }
    }

    fn observer_error(metadata: V2Metadata, status: &'static str) -> Self {
        Self::base(metadata, status, "observer_error")
    }

    fn rejected(metadata: V2Metadata, code: &'static str) -> Self {
        let mut report = Self::base(metadata, "observed", "rejected");
        report.rejection_code = Some(code);
        report
    }

    fn published(
        metadata: V2Metadata,
        bundle_id: String,
        record_digest: String,
        verdict: &'static str,
        publication_status: &'static str,
        projection_status: &'static str,
    ) -> Self {
        let mut report = Self::base(metadata, "observed", "published");
        report.bundle_id = Some(bundle_id);
        report.bundle_record_digest = Some(record_digest);
        report.bundle_verdict = Some(verdict);
        report.publication_status = Some(publication_status);
        report.projection_status = Some(projection_status);
        report
    }
}

fn bundle_verdict(verdict: VerificationVerdict) -> &'static str {
    match verdict {
        VerificationVerdict::Pass => "pass",
        VerificationVerdict::Fail => "fail",
        VerificationVerdict::Blocked => "blocked",
        VerificationVerdict::Timeout => "timeout",
        VerificationVerdict::Invalid => "invalid",
    }
}

fn rejection_code(code: VerifierRequestRejectionCode) -> &'static str {
    match code {
        VerifierRequestRejectionCode::InvalidContract => "invalid_contract",
        VerifierRequestRejectionCode::InvalidCrossBinding => "invalid_cross_binding",
        VerifierRequestRejectionCode::InvalidActorIdentity => "invalid_actor_identity",
        VerifierRequestRejectionCode::VerifierNotIndependent => "verifier_not_independent",
        VerifierRequestRejectionCode::InvalidSourceManifest => "invalid_source_manifest",
        VerifierRequestRejectionCode::InvalidCommand => "invalid_command",
        VerifierRequestRejectionCode::InvalidExecutionLimits => "invalid_execution_limits",
        VerifierRequestRejectionCode::InvalidFailureIdentity => "invalid_failure_identity",
        VerifierRequestRejectionCode::InvalidExecutableProfile => "invalid_executable_profile",
    }
}

fn map_failure_code(code: FailureCodeRow) -> FailureCode {
    match code {
        FailureCodeRow::TestFailedUnclassified => FailureCode::TestFailedUnclassified,
        FailureCodeRow::PolicyBlock => FailureCode::PolicyBlock,
        FailureCodeRow::EnvironmentBlock => FailureCode::EnvironmentBlock,
        FailureCodeRow::ExecutableUnavailable => FailureCode::ExecutableUnavailable,
        FailureCodeRow::ExecutableTamper => FailureCode::ExecutableTamper,
        FailureCodeRow::CommandTimeout => FailureCode::CommandTimeout,
        FailureCodeRow::OutputLimit => FailureCode::OutputLimit,
        FailureCodeRow::SourceDrift => FailureCode::SourceDrift,
        FailureCodeRow::SnapshotTamper => FailureCode::SnapshotTamper,
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_local_source_root(root: &Path) -> bool {
    if super::is_unc_path(root) {
        return false;
    }
    #[cfg(windows)]
    {
        let text = root.as_os_str().to_string_lossy().replace('/', "\\");
        if text.to_ascii_lowercase().starts_with(r"\\?\unc\") {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn ordinary_drive_root(root: &Path) -> ConfigResult<PathBuf> {
    use std::path::{Component, Prefix};

    let text = root.as_os_str().to_str().ok_or(())?.replace('/', "\\");
    let local = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let path = PathBuf::from(local);
    let mut components = path.components();

    match (components.next(), components.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir))
            if matches!(prefix.kind(), Prefix::Disk(_)) && path.is_absolute() =>
        {
            Ok(path)
        }
        _ => Err(()),
    }
}

#[cfg(windows)]
pub(crate) fn raw_durable_root_allowed(root: &Path) -> bool {
    ordinary_drive_root(root).is_ok()
}

#[cfg(not(windows))]
pub(crate) fn raw_durable_root_allowed(_root: &Path) -> bool {
    true
}

#[cfg(windows)]
fn verifier_root(raw_root: &Path, canonical_root: &Path) -> ConfigResult<PathBuf> {
    ordinary_drive_root(raw_root)?;
    ordinary_drive_root(canonical_root)
}

#[cfg(not(windows))]
fn verifier_root(_raw_root: &Path, canonical_root: &Path) -> ConfigResult<PathBuf> {
    Ok(canonical_root.to_path_buf())
}

fn strictly_sorted_strings(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, F>(values: &[T], key: F) -> bool
where
    F: Fn(&T) -> &str,
{
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn ensure_ordinary_directory(path: &Path) -> ConfigResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.is_dir() && !is_reparse_or_symlink(&metadata) {
        Ok(())
    } else {
        Err(())
    }
}

fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    super::windows_path_key(left) == super::windows_path_key(right)
}

#[cfg(not(windows))]
fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ovca_storage::EvidenceKey;
    use ovca_types::{
        select_targeted_rerun, verification_policy_digest, BehaviorBinding, BehaviorCriterion,
        BehaviorKind, CapabilityRegistryRow, CapabilityRegistrySnapshot, ChangedPathEntry,
        ChangedPathKind, ChangedPathManifest, ChangedPathSelector, DeniedAccess, DigestAlgorithm,
        GoalId, LocalMachinePolicy, PathSelectorKind, RunId, ShellPolicy, TargetedRerunOutcome,
        TargetedRerunRequest, TaskId, UnknownPathPolicy, VerificationCommand, WorkingDirectory,
        LOCAL_VERIFICATION_CONTRACT_VERSION,
    };
    use ovca_verifier::bundle::expected_failure_identity_keys;
    use ovca_verifier::snapshot::SourceFile;
    use serde::Serialize;
    use serde_json::json;
    use tempfile::TempDir;

    const CHILD_MODE: &str = "OVCA_V4A_CHILD_MODE";

    fn metadata() -> V2Metadata {
        V2Metadata {
            schema_version: 2,
            request_correlation: "grs-0123456789abcdef".to_owned(),
            task_kind: TaskKind::CodeChange,
            required_gate: RequiredGate::Auditor,
            dispatch_outcome: DispatchOutcome::Success,
        }
    }

    #[test]
    fn verification_child_probe() {
        if std::env::var(CHILD_MODE).as_deref() == Ok("pass") {
            std::process::exit(0);
        }
    }

    #[test]
    fn selector_is_exact_lowercase_content_address() {
        assert_eq!(
            request_digest(&format!("{REQUEST_ID_PREFIX}{}", "a".repeat(64))),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        for invalid in [
            "vreq.sha256.abc".to_owned(),
            format!("vreq.sha256.{}", "A".repeat(64)),
            format!("vreq-sha256-{}", "a".repeat(64)),
        ] {
            assert!(request_digest(&invalid).is_none());
        }
    }

    #[cfg(windows)]
    #[test]
    fn verifier_root_preserves_raw_namespace_evidence_until_validation() {
        for (raw, canonical, expected) in [
            (
                r"D:\verification",
                r"\\?\D:\verification",
                r"D:\verification",
            ),
            (
                r"\\?\D:\verification",
                r"D:\verification",
                r"D:\verification",
            ),
            (r"d:/verification", r"d:\verification", r"d:\verification"),
        ] {
            assert_eq!(
                verifier_root(Path::new(raw), Path::new(canonical)).unwrap(),
                PathBuf::from(expected),
                "raw={raw} canonical={canonical}"
            );
        }

        let canonical_drive = Path::new(r"C:\verification");
        for raw in [
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\verification",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\verification",
            r"\\?\UNC\server\share\verification",
            r"\\.\C:\verification",
            r"\\server\share\verification",
            r"\verification",
            r"D:verification",
            r"verification",
        ] {
            assert!(
                verifier_root(Path::new(raw), canonical_drive).is_err(),
                "raw namespace survived canonical drive replacement: {raw}"
            );
        }
    }

    #[test]
    fn every_closed_verdict_and_rejection_has_a_stable_wire_token() {
        assert_eq!(bundle_verdict(VerificationVerdict::Pass), "pass");
        assert_eq!(bundle_verdict(VerificationVerdict::Fail), "fail");
        assert_eq!(bundle_verdict(VerificationVerdict::Blocked), "blocked");
        assert_eq!(bundle_verdict(VerificationVerdict::Timeout), "timeout");
        assert_eq!(bundle_verdict(VerificationVerdict::Invalid), "invalid");
        assert_eq!(
            rejection_code(VerifierRequestRejectionCode::InvalidExecutableProfile),
            "invalid_executable_profile"
        );
    }

    #[test]
    fn bounded_report_contains_no_request_or_machine_values() {
        let report = Report::published(
            metadata(),
            format!("bundle.sha256.{}", "b".repeat(64)),
            "c".repeat(64),
            "pass",
            "inserted",
            "applied",
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("verification_request_id"));
        assert!(!encoded.contains("source_root"));
        assert!(!encoded.contains("executable_path"));
        assert!(!encoded.contains("environment"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap()
                ["completion_evidence_recorded"],
            json!(false)
        );
    }

    #[test]
    fn unknown_schema_two_field_is_a_bounded_configuration_error() {
        let bytes = br#"{"schema_version":2,"request_correlation":"grs-0123456789abcdef","task_kind":"code_change","required_gate":"auditor","dispatch_outcome":"success","verification_request_id":"vreq.sha256.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw_task_body":"secret"}"#;
        let output = execute(None, None, false, bytes);
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["status"], "configuration_error");
        assert_eq!(value["verification_status"], "observer_error");
        assert!(!value.to_string().contains("secret"));
    }

    #[test]
    fn real_verifier_publication_uses_evidence_bank_and_cleans_snapshot() {
        let source = TempDir::new().unwrap();
        let durable = TempDir::new().unwrap();
        fs::write(source.path().join("input.txt"), b"frozen source\n").unwrap();
        let manifest = SourceManifest {
            files: vec![SourceFile {
                logical_path: "input.txt".to_owned(),
                sha256: verification_sha256_hex(b"frozen source\n"),
            }],
        };
        let executable = std::env::current_exe().unwrap();
        let executable_digest = verification_sha256_hex(&fs::read(&executable).unwrap());
        let environment_names = BTreeSet::from([CHILD_MODE.to_owned()]);
        let capability = CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "capability.v4a".to_owned(),
            revision: 1,
            criterion_ids: vec!["criterion.v4a".to_owned()],
            dependencies: Vec::new(),
            changed_path_selectors: vec![ChangedPathSelector {
                kind: PathSelectorKind::Exact,
                path: "input.txt".to_owned(),
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
                allowed_executable_ids: BTreeSet::from(["test-runner".to_owned()]),
                allowed_environment_names: environment_names.clone(),
            },
            commands: vec![VerificationCommand {
                command_id: "command.v4a".to_owned(),
                executable_id: "test-runner".to_owned(),
                argv: vec![
                    "v2::tests::verification_child_probe".to_owned(),
                    "--exact".to_owned(),
                    "--nocapture".to_owned(),
                ],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: environment_names.clone(),
            }],
        };
        let behavior = BehavioralAcceptanceContract {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            contract_id: "behavior.v4a".to_owned(),
            binding: BehaviorBinding::Bound {
                goal_id: GoalId::from("goal.v4a"),
                task_id: TaskId::from("task.v4a"),
            },
            criteria: vec![BehaviorCriterion {
                criterion_id: "criterion.v4a".to_owned(),
                order: 0,
                kind: BehaviorKind::Verification,
                text: "the real verifier executes the frozen local request".to_owned(),
                required: true,
                capability_ids: vec!["capability.v4a".to_owned()],
            }],
        };
        let selection = selection(&capability, &manifest);
        let executable_registry = ExecutableRegistry {
            profiles: BTreeMap::from([(
                "test-runner".to_owned(),
                ExecutableProfile {
                    executable_id: "test-runner".to_owned(),
                    executable_path: executable,
                    sha256: executable_digest,
                    enabled: true,
                    approved: true,
                    reviewed_offline: true,
                    allowed_environment_names: environment_names.clone(),
                },
            )]),
        };
        let environment_bindings = EnvironmentBindings {
            values: BTreeMap::from([(CHILD_MODE.to_owned(), OsString::from("pass"))]),
        };
        let environment_digest = environment_bindings.digest_for(&environment_names).unwrap();
        let failure_identities = expected_failure_identity_keys(1)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, format!("failure.v4a.{index:03}")))
            .collect();
        let request = ConvertedRequest {
            behavior,
            capabilities: vec![capability],
            selection,
            source_manifest: manifest,
            source_root: source.path().to_path_buf(),
            executable_registry,
            environment_bindings,
            environment_digest,
            limits: ExecutionLimits {
                timeout_millis: 5_000,
                stdout_cap_bytes: 16_384,
                stderr_cap_bytes: 16_384,
            },
            implementation_actor: WorkerId::from("engineer.implementation"),
            verifier_actor: WorkerId::from("auditor.independent"),
            created_at: Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap(),
            failure_identities,
            projection_expectation: ProjectionExpectation::Absent,
        };

        let mut conflict_request = request.clone();
        conflict_request.created_at = Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 1).unwrap();
        conflict_request.projection_expectation = ProjectionExpectation::Token(CasToken {
            generation: 1,
            state_digest: "f".repeat(64),
        });

        let report = run_verifier(durable.path(), metadata(), request);

        assert_eq!(report.verification_status, "published");
        assert_eq!(report.bundle_verdict, Some("pass"));
        assert_eq!(report.publication_status, Some("inserted"));
        assert_eq!(report.projection_status, Some("applied"));
        assert!(report
            .bundle_record_digest
            .as_deref()
            .is_some_and(valid_digest));
        let first_digest = report.bundle_record_digest.clone().unwrap();
        let bank = EvidenceBank::try_new(durable.path()).unwrap();
        assert!(bank.database_path().exists());
        let conflict = run_verifier(durable.path(), metadata(), conflict_request);
        assert_eq!(conflict.verification_status, "published");
        assert_eq!(conflict.publication_status, Some("inserted"));
        assert_eq!(conflict.projection_status, Some("conflict"));
        assert_ne!(conflict.bundle_record_digest, Some(first_digest.clone()));
        let current = bank
            .load_current(&EvidenceKey {
                run_id: RunId::from("run.v4a"),
                goal_id: GoalId::from("goal.v4a"),
                task_id: TaskId::from("task.v4a"),
            })
            .unwrap()
            .unwrap();
        assert_eq!(current.record_digest, first_digest);
        let snapshot_parent = durable.path().join("goal-runtime-shadow").join("snapshots");
        assert_eq!(fs::read_dir(snapshot_parent).unwrap().count(), 0);
    }

    fn selection(
        capability: &CapabilityDefinition,
        manifest: &SourceManifest,
    ) -> TargetedRerunSelection {
        let record_digest = verification_sha256_hex(&capability.canonical_json_bytes().unwrap());
        #[derive(Serialize)]
        struct State<'a> {
            capability_id: &'a str,
            revision: u64,
            record_digest: &'a str,
            generation: u64,
        }
        let state_digest = verification_sha256_hex(
            &serde_json::to_vec(&State {
                capability_id: &capability.capability_id,
                revision: capability.revision,
                record_digest: &record_digest,
                generation: 1,
            })
            .unwrap(),
        );
        let snapshot = CapabilityRegistrySnapshot::new(vec![CapabilityRegistryRow {
            definition: capability.clone(),
            record_digest,
            generation: 1,
            state_digest,
        }])
        .unwrap();
        let request = TargetedRerunRequest {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            run_id: RunId::from("run.v4a"),
            goal_id: GoalId::from("goal.v4a"),
            task_id: TaskId::from("task.v4a"),
            source_fingerprint: manifest.fingerprint().unwrap(),
            policy_digest: verification_policy_digest(std::slice::from_ref(capability)).unwrap(),
            changed_paths: ChangedPathManifest {
                entries: vec![ChangedPathEntry {
                    kind: ChangedPathKind::Modified,
                    path: "input.txt".to_owned(),
                    previous_path: None,
                }],
            },
            unknown_path_policy: UnknownPathPolicy::Blocked,
        };
        match select_targeted_rerun(&request, &snapshot) {
            TargetedRerunOutcome::Selected { selection } => *selection,
            other => panic!("selection failed: {other:?}"),
        }
    }
}
