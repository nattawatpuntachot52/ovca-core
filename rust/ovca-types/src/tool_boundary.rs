//! Additive V1 wire contracts for disposable-workspace tool capabilities.
//!
//! These values are observations and deterministic validation inputs only.
//! They do not authenticate a caller, prove broker issuance, or grant runtime
//! authority. Runtime admission belongs to `WorkspaceCapabilityBroker`.

use crate::foundation::{
    validate_sha256_digest, validate_stable_id, FoundationAuthorityV1, FoundationScopeV1,
    FoundationValidationError, PrincipalIdentityV1, PrincipalV1,
};
use crate::goal_runtime::verification_sha256_hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const TOOL_BOUNDARY_CONTRACT_VERSION: u32 = 1;
pub const MAX_TOOL_BYTES: u64 = 16_777_216;
pub const MAX_LOGICAL_PATH_BYTES: usize = 512;
pub const MAX_LOGICAL_PATH_SEGMENTS: usize = 32;
pub const MAX_LOGICAL_PATH_SEGMENT_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolBoundaryValidationError {
    #[error("unsupported tool-boundary contract version in {0}")]
    UnsupportedContractVersion(&'static str),
    #[error(transparent)]
    Foundation(#[from] FoundationValidationError),
    #[error("logical path is outside the portable V1 grammar")]
    InvalidLogicalPath,
    #[error("logical path uses a reserved or alias-prone spelling")]
    AliasForbidden,
    #[error("logical paths must be strict byte-ordinal sorted and unique")]
    NonCanonicalPathOrder,
    #[error("logical paths contain a case-fold alias")]
    CaseAlias,
    #[error("workspace files must be strict byte-ordinal sorted and unique")]
    NonCanonicalFileOrder,
    #[error("canonical digest does not match {0}")]
    DigestMismatch(&'static str),
    #[error("validity window is not a non-empty half-open interval")]
    InvalidValidityWindow,
    #[error("byte limit is outside the V1 bound")]
    InvalidByteLimit,
    #[error("role cannot consume this capability grant")]
    InvalidGrantRole,
    #[error("grant write paths are forbidden for this role")]
    ForbiddenGrantWrite,
    #[error("tool operation is malformed")]
    InvalidOperation,
    #[error("tool receipt outcome contradicts its snapshot transition")]
    InvalidReceiptTransition,
    #[error("integer transition overflow")]
    Overflow,
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceFileV1 {
    pub logical_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

impl WorkspaceFileV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_logical_path(&self.logical_path)?;
        validate_sha256_digest(&self.sha256, "workspace_file.sha256")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotV1 {
    pub contract_version: u32,
    pub workspace_id: String,
    pub lease_id: String,
    pub generation: u64,
    pub files: Vec<WorkspaceFileV1>,
    pub snapshot_digest: String,
}

impl WorkspaceSnapshotV1 {
    pub fn try_new(
        workspace_id: String,
        lease_id: String,
        generation: u64,
        files: Vec<WorkspaceFileV1>,
    ) -> Result<Self, ToolBoundaryValidationError> {
        let mut snapshot = Self {
            contract_version: TOOL_BOUNDARY_CONTRACT_VERSION,
            workspace_id,
            lease_id,
            generation,
            files,
            snapshot_digest: String::new(),
        };
        snapshot.validate_without_digest()?;
        snapshot.snapshot_digest = snapshot.computed_snapshot_digest()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        self.validate_without_digest()?;
        validate_sha256_digest(&self.snapshot_digest, "snapshot_digest")?;
        if self.computed_snapshot_digest()? != self.snapshot_digest {
            return Err(ToolBoundaryValidationError::DigestMismatch(
                "snapshot_digest",
            ));
        }
        Ok(())
    }

    pub fn computed_snapshot_digest(&self) -> Result<String, ToolBoundaryValidationError> {
        #[derive(Serialize)]
        struct SnapshotDigestInput<'a> {
            contract_version: u32,
            workspace_id: &'a str,
            lease_id: &'a str,
            generation: u64,
            files: &'a [WorkspaceFileV1],
        }

        let input = SnapshotDigestInput {
            contract_version: self.contract_version,
            workspace_id: &self.workspace_id,
            lease_id: &self.lease_id,
            generation: self.generation,
            files: &self.files,
        };
        Ok(verification_sha256_hex(&canonical_json_bytes(&input)?))
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ToolBoundaryValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    fn validate_without_digest(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_version(self.contract_version, "WorkspaceSnapshotV1")?;
        validate_stable_id(&self.workspace_id, "workspace_id")?;
        validate_stable_id(&self.lease_id, "lease_id")?;
        validate_workspace_files(&self.files)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceLeaseV1 {
    pub contract_version: u32,
    pub lease_id: String,
    pub workspace_id: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub attempt: u32,
    pub scope: FoundationScopeV1,
    pub initial_snapshot_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl WorkspaceLeaseV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_version(self.contract_version, "WorkspaceLeaseV1")?;
        validate_stable_id(&self.lease_id, "lease_id")?;
        validate_stable_id(&self.workspace_id, "workspace_id")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        validate_sha256_digest(&self.invocation_digest, "invocation_digest")?;
        if self.attempt == 0 {
            return Err(ToolBoundaryValidationError::InvalidOperation);
        }
        self.scope.validate()?;
        validate_sha256_digest(&self.initial_snapshot_digest, "initial_snapshot_digest")?;
        validate_window(self.issued_at, self.expires_at)
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ToolBoundaryValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ToolBoundaryValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPolicyV1 {
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantV1 {
    pub contract_version: u32,
    pub grant_id: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub attempt: u32,
    pub issuer: PrincipalIdentityV1,
    pub grantee: PrincipalIdentityV1,
    pub scope: FoundationScopeV1,
    pub grant_authority: FoundationAuthorityV1,
    pub grant_authority_digest: String,
    pub lease_id: String,
    pub lease_digest: String,
    pub workspace_id: String,
    pub snapshot_digest: String,
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub max_read_bytes: u64,
    pub max_write_bytes: u64,
    pub command_policy: CapabilityPolicyV1,
    pub environment_policy: CapabilityPolicyV1,
    pub network_policy: CapabilityPolicyV1,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl CapabilityGrantV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_version(self.contract_version, "CapabilityGrantV1")?;
        validate_stable_id(&self.grant_id, "grant_id")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        validate_sha256_digest(&self.invocation_digest, "invocation_digest")?;
        if self.attempt == 0 {
            return Err(ToolBoundaryValidationError::InvalidOperation);
        }
        self.issuer.validate()?;
        self.grantee.validate()?;
        self.scope.validate()?;
        self.grant_authority.validate()?;
        validate_sha256_digest(&self.grant_authority_digest, "grant_authority_digest")?;
        if canonical_authority_digest(&self.grant_authority)? != self.grant_authority_digest {
            return Err(ToolBoundaryValidationError::DigestMismatch(
                "grant_authority_digest",
            ));
        }
        validate_stable_id(&self.lease_id, "lease_id")?;
        validate_sha256_digest(&self.lease_digest, "lease_digest")?;
        validate_stable_id(&self.workspace_id, "workspace_id")?;
        validate_sha256_digest(&self.snapshot_digest, "snapshot_digest")?;
        validate_path_list(&self.read_paths)?;
        validate_path_list(&self.write_paths)?;
        validate_combined_case_aliases(&self.read_paths, &self.write_paths)?;
        validate_limit(self.max_read_bytes)?;
        validate_limit(self.max_write_bytes)?;
        validate_window(self.valid_from, self.valid_until)?;
        match self.grantee.role {
            PrincipalV1::Engineer => {}
            PrincipalV1::Reviewer | PrincipalV1::Auditor if self.write_paths.is_empty() => {}
            PrincipalV1::Reviewer | PrincipalV1::Auditor => {
                return Err(ToolBoundaryValidationError::ForbiddenGrantWrite)
            }
            PrincipalV1::Owner | PrincipalV1::Coordinator => {
                return Err(ToolBoundaryValidationError::InvalidGrantRole)
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ToolBoundaryValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ToolBoundaryValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedToolKindV1 {
    Command,
    Environment,
    Network,
    Delete,
    Rename,
    Copy,
    CreateDirectory,
    Link,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolOperationV1 {
    ReadFile {
        logical_path: String,
    },
    WriteFile {
        logical_path: String,
        content_sha256: String,
        byte_length: u64,
    },
    Unsupported {
        kind: UnsupportedToolKindV1,
        intent_digest: String,
    },
}

impl ToolOperationV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        match self {
            Self::ReadFile { logical_path } => validate_logical_path(logical_path),
            Self::WriteFile {
                logical_path,
                content_sha256,
                ..
            } => {
                validate_logical_path(logical_path)?;
                validate_sha256_digest(content_sha256, "operation.content_sha256")?;
                Ok(())
            }
            Self::Unsupported { intent_digest, .. } => {
                validate_sha256_digest(intent_digest, "operation.intent_digest")?;
                Ok(())
            }
        }
    }

    pub fn logical_path(&self) -> Option<&str> {
        match self {
            Self::ReadFile { logical_path } | Self::WriteFile { logical_path, .. } => {
                Some(logical_path)
            }
            Self::Unsupported { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequestV1 {
    pub contract_version: u32,
    pub request_id: String,
    pub idempotency_key: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub attempt: u32,
    pub grant_id: String,
    pub grant_digest: String,
    pub lease_id: String,
    pub lease_digest: String,
    pub workspace_id: String,
    pub expected_snapshot_digest: String,
    pub requester: PrincipalIdentityV1,
    pub scope: FoundationScopeV1,
    pub operation: ToolOperationV1,
    pub requested_at: DateTime<Utc>,
}

impl ToolRequestV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_version(self.contract_version, "ToolRequestV1")?;
        validate_stable_id(&self.request_id, "request_id")?;
        validate_stable_id(&self.idempotency_key, "idempotency_key")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        validate_sha256_digest(&self.invocation_digest, "invocation_digest")?;
        if self.attempt == 0 {
            return Err(ToolBoundaryValidationError::InvalidOperation);
        }
        validate_stable_id(&self.grant_id, "grant_id")?;
        validate_sha256_digest(&self.grant_digest, "grant_digest")?;
        validate_stable_id(&self.lease_id, "lease_id")?;
        validate_sha256_digest(&self.lease_digest, "lease_digest")?;
        validate_stable_id(&self.workspace_id, "workspace_id")?;
        validate_sha256_digest(&self.expected_snapshot_digest, "expected_snapshot_digest")?;
        self.requester.validate()?;
        self.scope.validate()?;
        self.operation.validate()
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ToolBoundaryValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ToolBoundaryValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDeniedCodeV1 {
    InvalidBinding,
    Expired,
    StaleSnapshot,
    RoleForbidden,
    PathForbidden,
    UnsupportedOperation,
    PayloadMismatch,
    LimitExceeded,
    WorkspaceInvalid,
    ProtectedRoot,
    AliasForbidden,
    NoChange,
    IdempotencyConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolReceiptOutcomeV1 {
    Read {
        content_sha256: String,
        byte_length: u64,
    },
    Written {
        content_sha256: String,
        byte_length: u64,
    },
    Denied {
        code: ToolDeniedCodeV1,
    },
}

impl ToolReceiptOutcomeV1 {
    fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        match self {
            Self::Read { content_sha256, .. } | Self::Written { content_sha256, .. } => {
                validate_sha256_digest(content_sha256, "outcome.content_sha256")?;
                Ok(())
            }
            Self::Denied { .. } => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReceiptV1 {
    pub contract_version: u32,
    pub receipt_id: String,
    pub runtime_instance_id: String,
    pub sequence: u64,
    pub request_id: String,
    pub request_digest: String,
    pub idempotency_key: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub grant_id: String,
    pub grant_digest: String,
    pub lease_id: String,
    pub lease_digest: String,
    pub workspace_id: String,
    pub actor: PrincipalIdentityV1,
    pub before_snapshot_digest: String,
    pub after_snapshot_digest: String,
    pub before_generation: u64,
    pub after_generation: u64,
    pub outcome: ToolReceiptOutcomeV1,
    pub occurred_at: DateTime<Utc>,
}

impl ToolReceiptV1 {
    pub fn validate(&self) -> Result<(), ToolBoundaryValidationError> {
        validate_version(self.contract_version, "ToolReceiptV1")?;
        validate_stable_id(&self.receipt_id, "receipt_id")?;
        validate_stable_id(&self.runtime_instance_id, "runtime_instance_id")?;
        validate_stable_id(&self.request_id, "request_id")?;
        validate_sha256_digest(&self.request_digest, "request_digest")?;
        validate_stable_id(&self.idempotency_key, "idempotency_key")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        validate_sha256_digest(&self.invocation_digest, "invocation_digest")?;
        validate_stable_id(&self.grant_id, "grant_id")?;
        validate_sha256_digest(&self.grant_digest, "grant_digest")?;
        validate_stable_id(&self.lease_id, "lease_id")?;
        validate_sha256_digest(&self.lease_digest, "lease_digest")?;
        validate_stable_id(&self.workspace_id, "workspace_id")?;
        self.actor.validate()?;
        validate_sha256_digest(&self.before_snapshot_digest, "before_snapshot_digest")?;
        validate_sha256_digest(&self.after_snapshot_digest, "after_snapshot_digest")?;
        self.outcome.validate()?;

        match self.outcome {
            ToolReceiptOutcomeV1::Denied { .. } | ToolReceiptOutcomeV1::Read { .. }
                if self.before_snapshot_digest == self.after_snapshot_digest
                    && self.before_generation == self.after_generation =>
            {
                Ok(())
            }
            ToolReceiptOutcomeV1::Written { .. }
                if self.before_snapshot_digest != self.after_snapshot_digest
                    && self
                        .before_generation
                        .checked_add(1)
                        .is_some_and(|next| next == self.after_generation) =>
            {
                Ok(())
            }
            _ => Err(ToolBoundaryValidationError::InvalidReceiptTransition),
        }
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ToolBoundaryValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }
}

pub fn validate_logical_path(path: &str) -> Result<(), ToolBoundaryValidationError> {
    if path.is_empty()
        || path.len() > MAX_LOGICAL_PATH_BYTES
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
    {
        return Err(ToolBoundaryValidationError::InvalidLogicalPath);
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.is_empty() || segments.len() > MAX_LOGICAL_PATH_SEGMENTS {
        return Err(ToolBoundaryValidationError::InvalidLogicalPath);
    }
    for segment in segments {
        let bytes = segment.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_LOGICAL_PATH_SEGMENT_BYTES
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ToolBoundaryValidationError::InvalidLogicalPath);
        }
        if segment == "." || segment == ".." || segment.ends_with('.') {
            return Err(ToolBoundaryValidationError::AliasForbidden);
        }
        let basename = segment.split('.').next().unwrap_or_default();
        if is_windows_reserved_basename(basename) {
            return Err(ToolBoundaryValidationError::AliasForbidden);
        }
    }
    Ok(())
}

pub fn canonical_authority_digest(
    authority: &FoundationAuthorityV1,
) -> Result<String, ToolBoundaryValidationError> {
    authority.validate()?;
    Ok(verification_sha256_hex(&canonical_json_bytes(authority)?))
}

pub fn permission_key(
    prefix: &str,
    logical_path: &str,
) -> Result<String, ToolBoundaryValidationError> {
    validate_logical_path(logical_path)?;
    Ok(format!(
        "{prefix}:{}",
        verification_sha256_hex(logical_path.as_bytes())
    ))
}

pub fn expected_read_permission_keys(
    paths: &[String],
) -> Result<Vec<String>, ToolBoundaryValidationError> {
    validate_path_list(paths)?;
    let mut keys = paths
        .iter()
        .map(|path| permission_key("workspace.read", path))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    Ok(keys)
}

pub fn expected_write_permission_keys(
    paths: &[String],
) -> Result<Vec<String>, ToolBoundaryValidationError> {
    validate_path_list(paths)?;
    let mut keys = paths
        .iter()
        .map(|path| permission_key("workspace.write", path))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    Ok(keys)
}

fn validate_workspace_files(files: &[WorkspaceFileV1]) -> Result<(), ToolBoundaryValidationError> {
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    for file in files {
        file.validate()?;
        if previous.is_some_and(|value| value.as_bytes() >= file.logical_path.as_bytes()) {
            return Err(ToolBoundaryValidationError::NonCanonicalFileOrder);
        }
        if !folded.insert(file.logical_path.to_ascii_lowercase()) {
            return Err(ToolBoundaryValidationError::CaseAlias);
        }
        previous = Some(&file.logical_path);
    }
    Ok(())
}

fn validate_path_list(paths: &[String]) -> Result<(), ToolBoundaryValidationError> {
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    for path in paths {
        validate_logical_path(path)?;
        if previous.is_some_and(|value| value.as_bytes() >= path.as_bytes()) {
            return Err(ToolBoundaryValidationError::NonCanonicalPathOrder);
        }
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(ToolBoundaryValidationError::CaseAlias);
        }
        previous = Some(path);
    }
    Ok(())
}

fn validate_combined_case_aliases(
    read_paths: &[String],
    write_paths: &[String],
) -> Result<(), ToolBoundaryValidationError> {
    let read_folded: BTreeSet<String> = read_paths
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect();
    for path in write_paths {
        let folded = path.to_ascii_lowercase();
        if read_folded.contains(&folded) && !read_paths.iter().any(|read_path| read_path == path) {
            return Err(ToolBoundaryValidationError::CaseAlias);
        }
    }
    Ok(())
}

fn validate_version(
    version: u32,
    contract: &'static str,
) -> Result<(), ToolBoundaryValidationError> {
    if version == TOOL_BOUNDARY_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ToolBoundaryValidationError::UnsupportedContractVersion(
            contract,
        ))
    }
}

fn validate_window(
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Result<(), ToolBoundaryValidationError> {
    if valid_from < valid_until {
        Ok(())
    } else {
        Err(ToolBoundaryValidationError::InvalidValidityWindow)
    }
}

fn validate_limit(limit: u64) -> Result<(), ToolBoundaryValidationError> {
    if (1..=MAX_TOOL_BYTES).contains(&limit) {
        Ok(())
    } else {
        Err(ToolBoundaryValidationError::InvalidByteLimit)
    }
}

fn is_windows_reserved_basename(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ToolBoundaryValidationError> {
    serde_json::to_vec(value)
        .map_err(|error| ToolBoundaryValidationError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        FoundationNamespaceV1, FoundationPermissionProfileV1, FoundationSensitivityV1,
        FoundationValidityStatusV1, FoundationValidityV1, FoundationVisibilityV1,
    };
    use crate::goal_runtime::RiskTier;
    use chrono::TimeZone;

    fn time(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 16, 10, minute, 0)
            .single()
            .unwrap()
    }

    fn identity(role: PrincipalV1) -> PrincipalIdentityV1 {
        PrincipalIdentityV1 {
            principal_id: format!("principal.{role:?}").to_ascii_lowercase(),
            role,
        }
    }

    fn scope() -> FoundationScopeV1 {
        FoundationScopeV1 {
            project_id: "project.alpha".into(),
            goal_id: Some("goal.alpha".into()),
            task_id: Some("task.alpha".into()),
            run_id: Some("run.alpha".into()),
        }
    }

    fn authority(role: PrincipalV1) -> FoundationAuthorityV1 {
        FoundationAuthorityV1 {
            contract_version: 1,
            authority_id: "authority.grant".into(),
            principal: identity(role),
            scope: scope(),
            namespace: FoundationNamespaceV1::CodeReview,
            permission_profile: FoundationPermissionProfileV1 {
                contract_version: 1,
                risk_tier: RiskTier::R1,
                resource_keys: expected_read_permission_keys(&["src/lib.rs".into()]).unwrap(),
                write_keys: expected_write_permission_keys(&["src/lib.rs".into()]).unwrap(),
                approval_required: true,
                review_required: true,
                audit_required: true,
            },
            visibility: FoundationVisibilityV1::RoleScoped,
            sensitivity: FoundationSensitivityV1::Internal,
            validity: FoundationValidityV1 {
                status: FoundationValidityStatusV1::Active,
                valid_from: time(0),
                valid_until: Some(time(50)),
            },
        }
    }

    fn grant(role: PrincipalV1) -> CapabilityGrantV1 {
        let grant_authority = authority(PrincipalV1::Coordinator);
        CapabilityGrantV1 {
            contract_version: 1,
            grant_id: "grant.alpha".into(),
            invocation_id: "invocation.alpha".into(),
            invocation_digest: "1".repeat(64),
            attempt: 1,
            issuer: identity(PrincipalV1::Coordinator),
            grantee: identity(role),
            scope: scope(),
            grant_authority_digest: canonical_authority_digest(&grant_authority).unwrap(),
            grant_authority,
            lease_id: "lease.alpha".into(),
            lease_digest: "2".repeat(64),
            workspace_id: "workspace.alpha".into(),
            snapshot_digest: "3".repeat(64),
            read_paths: vec!["src/lib.rs".into()],
            write_paths: if role == PrincipalV1::Engineer {
                vec!["src/lib.rs".into()]
            } else {
                vec![]
            },
            max_read_bytes: 1024,
            max_write_bytes: 1024,
            command_policy: CapabilityPolicyV1::Denied,
            environment_policy: CapabilityPolicyV1::Denied,
            network_policy: CapabilityPolicyV1::Denied,
            valid_from: time(5),
            valid_until: time(40),
        }
    }

    #[test]
    fn logical_path_grammar_closes_portable_aliases_and_boundaries() {
        for valid in ["README", ".config", "src/lib.rs", "a-b/c_d/9.txt"] {
            assert_eq!(validate_logical_path(valid), Ok(()), "{valid}");
        }
        for invalid in [
            "",
            "/abs",
            "../escape",
            "a/../b",
            "a\\b",
            "C:/x",
            "//server/x",
            "file:x",
            "a//b",
            "a b",
            "a\u{7f}b",
        ] {
            assert!(validate_logical_path(invalid).is_err(), "{invalid:?}");
        }
        for alias in [".", "..", "CON", "con.txt", "Lpt9.log", "name."] {
            assert_eq!(
                validate_logical_path(alias),
                Err(ToolBoundaryValidationError::AliasForbidden),
                "{alias}"
            );
        }
        assert!(validate_logical_path(&vec!["a"; 33].join("/")).is_err());
        assert!(validate_logical_path(&"a".repeat(129)).is_err());
        assert!(validate_logical_path(&format!("{}/x", "a".repeat(511))).is_err());
    }

    #[test]
    fn snapshot_digest_excludes_digest_field_and_preserves_declared_order() {
        let file = WorkspaceFileV1 {
            logical_path: "src/lib.rs".into(),
            sha256: verification_sha256_hex(b"hello"),
            byte_length: 5,
        };
        let snapshot = WorkspaceSnapshotV1::try_new(
            "workspace.alpha".into(),
            "lease.alpha".into(),
            0,
            vec![file],
        )
        .unwrap();
        snapshot.validate().unwrap();
        let wire = serde_json::to_string(&snapshot).unwrap();
        assert!(wire.starts_with(
            r#"{"contract_version":1,"workspace_id":"workspace.alpha","lease_id":"lease.alpha","generation":0,"files":["#
        ));
        let mut changed = snapshot.clone();
        changed.generation = 1;
        assert!(matches!(
            changed.validate(),
            Err(ToolBoundaryValidationError::DigestMismatch(
                "snapshot_digest"
            ))
        ));
    }

    #[test]
    fn grant_role_matrix_and_exact_authority_digest_are_closed() {
        grant(PrincipalV1::Engineer).validate().unwrap();
        grant(PrincipalV1::Reviewer).validate().unwrap();
        grant(PrincipalV1::Auditor).validate().unwrap();
        assert_eq!(
            grant(PrincipalV1::Owner).validate(),
            Err(ToolBoundaryValidationError::InvalidGrantRole)
        );
        assert_eq!(
            grant(PrincipalV1::Coordinator).validate(),
            Err(ToolBoundaryValidationError::InvalidGrantRole)
        );
        let mut reviewer = grant(PrincipalV1::Reviewer);
        reviewer.write_paths = vec!["src/lib.rs".into()];
        assert_eq!(
            reviewer.validate(),
            Err(ToolBoundaryValidationError::ForbiddenGrantWrite)
        );
        let mut bad_digest = grant(PrincipalV1::Engineer);
        bad_digest.grant_authority_digest = "0".repeat(64);
        assert!(matches!(
            bad_digest.validate(),
            Err(ToolBoundaryValidationError::DigestMismatch(
                "grant_authority_digest"
            ))
        ));
    }

    #[test]
    fn serde_closes_unknown_fields_and_unsupported_kinds() {
        let request = ToolRequestV1 {
            contract_version: 1,
            request_id: "request.alpha".into(),
            idempotency_key: "key.alpha".into(),
            invocation_id: "invocation.alpha".into(),
            invocation_digest: "1".repeat(64),
            attempt: 1,
            grant_id: "grant.alpha".into(),
            grant_digest: "2".repeat(64),
            lease_id: "lease.alpha".into(),
            lease_digest: "3".repeat(64),
            workspace_id: "workspace.alpha".into(),
            expected_snapshot_digest: "4".repeat(64),
            requester: identity(PrincipalV1::Engineer),
            scope: scope(),
            operation: ToolOperationV1::ReadFile {
                logical_path: "src/lib.rs".into(),
            },
            requested_at: time(10),
        };
        request.validate().unwrap();
        let mut value = serde_json::to_value(&request).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ToolRequestV1>(value).is_err());
        assert!(serde_json::from_str::<ToolOperationV1>(
            r#"{"type":"unsupported","kind":"shell","intent_digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#
        )
        .is_err());
    }

    #[test]
    fn receipt_transitions_are_exact() {
        let mut receipt = ToolReceiptV1 {
            contract_version: 1,
            receipt_id: "receipt.1".into(),
            runtime_instance_id: "runtime.alpha".into(),
            sequence: 1,
            request_id: "request.alpha".into(),
            request_digest: "1".repeat(64),
            idempotency_key: "key.alpha".into(),
            invocation_id: "invocation.alpha".into(),
            invocation_digest: "2".repeat(64),
            grant_id: "grant.alpha".into(),
            grant_digest: "3".repeat(64),
            lease_id: "lease.alpha".into(),
            lease_digest: "4".repeat(64),
            workspace_id: "workspace.alpha".into(),
            actor: identity(PrincipalV1::Engineer),
            before_snapshot_digest: "5".repeat(64),
            after_snapshot_digest: "5".repeat(64),
            before_generation: 0,
            after_generation: 0,
            outcome: ToolReceiptOutcomeV1::Denied {
                code: ToolDeniedCodeV1::InvalidBinding,
            },
            occurred_at: time(10),
        };
        receipt.validate().unwrap();
        receipt.outcome = ToolReceiptOutcomeV1::Written {
            content_sha256: "6".repeat(64),
            byte_length: 1,
        };
        assert_eq!(
            receipt.validate(),
            Err(ToolBoundaryValidationError::InvalidReceiptTransition)
        );
        receipt.after_snapshot_digest = "7".repeat(64);
        receipt.after_generation = 1;
        receipt.validate().unwrap();
    }

    #[test]
    fn public_samples_round_trip_with_exact_cross_linked_digests() {
        let snapshot: WorkspaceSnapshotV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_workspace_snapshot.v1.sample.json"
        ))
        .unwrap();
        let lease: WorkspaceLeaseV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_workspace_lease.v1.sample.json"
        ))
        .unwrap();
        let grant: CapabilityGrantV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_capability_grant.v1.sample.json"
        ))
        .unwrap();
        let request: ToolRequestV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_tool_request.v1.sample.json"
        ))
        .unwrap();
        let receipt: ToolReceiptV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_tool_receipt.v1.sample.json"
        ))
        .unwrap();

        snapshot.validate().unwrap();
        lease.validate().unwrap();
        grant.validate().unwrap();
        request.validate().unwrap();
        receipt.validate().unwrap();
        assert_eq!(lease.initial_snapshot_digest, snapshot.snapshot_digest);
        assert_eq!(lease.canonical_digest().unwrap(), grant.lease_digest);
        assert_eq!(grant.canonical_digest().unwrap(), request.grant_digest);
        assert_eq!(request.canonical_digest().unwrap(), receipt.request_digest);
        assert_eq!(request.lease_digest, receipt.lease_digest);
        assert_eq!(request.grant_digest, receipt.grant_digest);

        for (wire, round_trip) in [
            (
                snapshot.canonical_json_bytes().unwrap(),
                serde_json::to_vec(&snapshot).unwrap(),
            ),
            (
                lease.canonical_json_bytes().unwrap(),
                serde_json::to_vec(&lease).unwrap(),
            ),
            (
                grant.canonical_json_bytes().unwrap(),
                serde_json::to_vec(&grant).unwrap(),
            ),
            (
                request.canonical_json_bytes().unwrap(),
                serde_json::to_vec(&request).unwrap(),
            ),
            (
                receipt.canonical_json_bytes().unwrap(),
                serde_json::to_vec(&receipt).unwrap(),
            ),
        ] {
            assert_eq!(wire, round_trip);
        }
    }
}
