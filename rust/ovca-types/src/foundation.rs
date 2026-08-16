//! Additive V1 contracts shared by the public control plane and governed brain.
//!
//! This module defines closed wire types and pure semantic validation only. It
//! performs no I/O, grants no authority, and does not upgrade legacy records.

use crate::goal_runtime::{ContractVersion, EvidenceKind, PermissionProfile, RiskTier, Role};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FOUNDATION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FoundationValidationError {
    #[error("unsupported foundation contract version")]
    UnsupportedContractVersion,
    #[error("invalid stable identifier in {0}")]
    InvalidStableId(&'static str),
    #[error("invalid lowercase SHA-256 digest in {0}")]
    InvalidDigest(&'static str),
    #[error("invalid logical path")]
    InvalidLogicalPath,
    #[error("scope hierarchy is incomplete")]
    IncompleteScopeHierarchy,
    #[error("permission keys must be valid, strictly ordered, and unique")]
    InvalidPermissionKeys,
    #[error("owner has no legacy runtime role")]
    OwnerHasNoLegacyRole,
    #[error("decision actor is not authoritative for its kind")]
    InvalidDecisionActor,
    #[error("decision status is not valid for its kind")]
    InvalidDecisionStatus,
    #[error("actor and subject principal_id must differ")]
    SelfDecision,
    #[error("decision transition is not allowed")]
    InvalidDecisionTransition,
    #[error("validity transition is not allowed")]
    InvalidValidityTransition,
    #[error("valid_until must be strictly later than valid_from")]
    InvalidValidityWindow,
    #[error("visibility widening requires an explicit owner approval")]
    VisibilityWideningRequiresOwnerApproval,
    #[error("identifier collection in {0} must not be empty")]
    EmptyIdentifierCollection(&'static str),
    #[error("identifier collection in {0} must use strict ordinal order")]
    NonCanonicalIdentifierOrder(&'static str),
    #[error("supersedes_decision_id is inconsistent with decision status")]
    InvalidSupersession,
    #[error("event sequence and previous_event_id are inconsistent")]
    InvalidEventSequence,
    #[error("event kind does not match its domain")]
    InvalidEventKind,
    #[error("identifier collection must be unique")]
    DuplicateIdentifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalV1 {
    Owner,
    Coordinator,
    Engineer,
    Reviewer,
    Auditor,
}

impl From<Role> for PrincipalV1 {
    fn from(value: Role) -> Self {
        match value {
            Role::Coordinator => Self::Coordinator,
            Role::Engineer => Self::Engineer,
            Role::Reviewer => Self::Reviewer,
            Role::Auditor => Self::Auditor,
        }
    }
}

impl TryFrom<PrincipalV1> for Role {
    type Error = FoundationValidationError;

    fn try_from(value: PrincipalV1) -> Result<Self, Self::Error> {
        match value {
            PrincipalV1::Owner => Err(FoundationValidationError::OwnerHasNoLegacyRole),
            PrincipalV1::Coordinator => Ok(Self::Coordinator),
            PrincipalV1::Engineer => Ok(Self::Engineer),
            PrincipalV1::Reviewer => Ok(Self::Reviewer),
            PrincipalV1::Auditor => Ok(Self::Auditor),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalIdentityV1 {
    pub principal_id: String,
    pub role: PrincipalV1,
}

impl PrincipalIdentityV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_stable_id(&self.principal_id, "principal_id")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationPermissionProfileV1 {
    pub contract_version: u32,
    pub risk_tier: RiskTier,
    pub resource_keys: Vec<String>,
    pub write_keys: Vec<String>,
    pub approval_required: bool,
    pub review_required: bool,
    pub audit_required: bool,
}

impl FoundationPermissionProfileV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_version(self.contract_version)?;
        validate_permission_keys(&self.resource_keys)?;
        validate_permission_keys(&self.write_keys)
    }

    pub fn try_from_legacy(value: &PermissionProfile) -> Result<Self, FoundationValidationError> {
        Self::try_from(value)
    }

    pub fn try_into_legacy(&self) -> Result<PermissionProfile, FoundationValidationError> {
        PermissionProfile::try_from(self)
    }
}

impl TryFrom<&PermissionProfile> for FoundationPermissionProfileV1 {
    type Error = FoundationValidationError;

    fn try_from(value: &PermissionProfile) -> Result<Self, Self::Error> {
        let converted = Self {
            contract_version: value.contract_version.0,
            risk_tier: value.risk_tier,
            resource_keys: value.resource_keys.clone(),
            write_keys: value.write_keys.clone(),
            approval_required: value.approval_required,
            review_required: value.review_required,
            audit_required: value.audit_required,
        };
        converted.validate()?;
        Ok(converted)
    }
}

impl TryFrom<PermissionProfile> for FoundationPermissionProfileV1 {
    type Error = FoundationValidationError;

    fn try_from(value: PermissionProfile) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&FoundationPermissionProfileV1> for PermissionProfile {
    type Error = FoundationValidationError;

    fn try_from(value: &FoundationPermissionProfileV1) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            contract_version: ContractVersion(value.contract_version),
            risk_tier: value.risk_tier,
            resource_keys: value.resource_keys.clone(),
            write_keys: value.write_keys.clone(),
            approval_required: value.approval_required,
            review_required: value.review_required,
            audit_required: value.audit_required,
        })
    }
}

impl TryFrom<FoundationPermissionProfileV1> for PermissionProfile {
    type Error = FoundationValidationError;

    fn try_from(value: FoundationPermissionProfileV1) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationScopeV1 {
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

impl FoundationScopeV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_stable_id(&self.project_id, "project_id")?;
        validate_optional_stable_id(self.goal_id.as_deref(), "goal_id")?;
        validate_optional_stable_id(self.task_id.as_deref(), "task_id")?;
        validate_optional_stable_id(self.run_id.as_deref(), "run_id")?;
        if (self.goal_id.is_none() && (self.task_id.is_some() || self.run_id.is_some()))
            || (self.task_id.is_none() && self.run_id.is_some())
        {
            return Err(FoundationValidationError::IncompleteScopeHierarchy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FoundationLocatorV1 {
    StableId(String),
    LogicalPath(String),
}

impl FoundationLocatorV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        match self {
            Self::StableId(value) => validate_stable_id(value, "locator.value"),
            Self::LogicalPath(value) => validate_logical_path(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationNamespaceV1 {
    CodeReview,
    KnowledgeReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationVisibilityV1 {
    Private,
    RoleScoped,
    Shared,
}

impl FoundationVisibilityV1 {
    const fn rank(self) -> u8 {
        match self {
            Self::Private => 0,
            Self::RoleScoped => 1,
            Self::Shared => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationSensitivityV1 {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationValidityStatusV1 {
    Pending,
    Active,
    Rejected,
    Stale,
    Revoked,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationValidityV1 {
    pub status: FoundationValidityStatusV1,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

impl FoundationValidityV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        if self
            .valid_until
            .is_some_and(|valid_until| valid_until <= self.valid_from)
        {
            return Err(FoundationValidationError::InvalidValidityWindow);
        }
        Ok(())
    }

    pub fn validate_transition_to(
        &self,
        next: FoundationValidityStatusV1,
    ) -> Result<(), FoundationValidationError> {
        validate_validity_transition(self.status, next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationAuthorityV1 {
    pub contract_version: u32,
    pub authority_id: String,
    pub principal: PrincipalIdentityV1,
    pub scope: FoundationScopeV1,
    pub namespace: FoundationNamespaceV1,
    pub permission_profile: FoundationPermissionProfileV1,
    pub visibility: FoundationVisibilityV1,
    pub sensitivity: FoundationSensitivityV1,
    pub validity: FoundationValidityV1,
}

impl FoundationAuthorityV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.authority_id, "authority_id")?;
        self.principal.validate()?;
        self.scope.validate()?;
        self.permission_profile.validate()?;
        self.validity.validate()
    }

    pub fn validate_visibility_transition(
        &self,
        next: FoundationVisibilityV1,
        current_authority_digest: &str,
        owner_approval: Option<&FoundationDecisionV1>,
    ) -> Result<(), FoundationValidationError> {
        validate_visibility_transition(self, next, current_authority_digest, owner_approval)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationEvidenceRefV1 {
    pub contract_version: u32,
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub digest: String,
    pub producer: PrincipalIdentityV1,
    pub scope: FoundationScopeV1,
    pub namespace: FoundationNamespaceV1,
    pub locator: FoundationLocatorV1,
    pub produced_at: DateTime<Utc>,
}

impl FoundationEvidenceRefV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.evidence_id, "evidence_id")?;
        validate_sha256_digest(&self.digest, "digest")?;
        self.producer.validate()?;
        self.scope.validate()?;
        self.locator.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationDecisionKindV1 {
    Approval,
    Review,
    Audit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationDecisionStatusV1 {
    Pending,
    Approved,
    Rejected,
    Passed,
    Failed,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationDecisionV1 {
    pub contract_version: u32,
    pub decision_id: String,
    pub kind: FoundationDecisionKindV1,
    pub status: FoundationDecisionStatusV1,
    pub namespace: FoundationNamespaceV1,
    pub actor: PrincipalIdentityV1,
    pub subject: PrincipalIdentityV1,
    pub scope: FoundationScopeV1,
    pub subject_digest: String,
    pub evidence_ids: Vec<String>,
    pub decided_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
}

impl FoundationDecisionV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.decision_id, "decision_id")?;
        self.actor.validate()?;
        self.subject.validate()?;
        self.scope.validate()?;
        validate_sha256_digest(&self.subject_digest, "subject_digest")?;
        validate_identifier_collection(&self.evidence_ids, "evidence_ids")?;
        validate_optional_stable_id(
            self.supersedes_decision_id.as_deref(),
            "supersedes_decision_id",
        )?;
        if (self.status == FoundationDecisionStatusV1::Superseded)
            != self.supersedes_decision_id.is_some()
        {
            return Err(FoundationValidationError::InvalidSupersession);
        }
        if self.supersedes_decision_id.as_deref() == Some(self.decision_id.as_str()) {
            return Err(FoundationValidationError::InvalidStableId(
                "supersedes_decision_id",
            ));
        }
        if self.actor.principal_id == self.subject.principal_id {
            return Err(FoundationValidationError::SelfDecision);
        }
        let expected_actor = match self.kind {
            FoundationDecisionKindV1::Approval => PrincipalV1::Owner,
            FoundationDecisionKindV1::Review => PrincipalV1::Reviewer,
            FoundationDecisionKindV1::Audit => PrincipalV1::Auditor,
        };
        if self.actor.role != expected_actor {
            return Err(FoundationValidationError::InvalidDecisionActor);
        }
        if !decision_status_allowed(self.kind, self.status) {
            return Err(FoundationValidationError::InvalidDecisionStatus);
        }
        Ok(())
    }

    pub fn validate_transition_to(
        &self,
        next: FoundationDecisionStatusV1,
    ) -> Result<(), FoundationValidationError> {
        validate_decision_transition(self.kind, self.status, next)
    }

    pub fn is_explicit_owner_approval(&self) -> bool {
        self.kind == FoundationDecisionKindV1::Approval
            && self.status == FoundationDecisionStatusV1::Approved
            && self.actor.role == PrincipalV1::Owner
            && self.validate().is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationDomainV1 {
    ControlPlane,
    GovernedBrain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationEventEnvelopeV1 {
    pub contract_version: u32,
    pub event_id: String,
    pub domain: FoundationDomainV1,
    pub scope: FoundationScopeV1,
    pub producer: PrincipalIdentityV1,
    pub event_kind: String,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_event_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub payload_digest: String,
}

impl FoundationEventEnvelopeV1 {
    pub fn validate(&self) -> Result<(), FoundationValidationError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.event_id, "event_id")?;
        self.scope.validate()?;
        self.producer.validate()?;
        validate_stable_id(&self.event_kind, "event_kind")?;
        validate_sha256_digest(&self.payload_digest, "payload_digest")?;
        validate_optional_stable_id(self.previous_event_id.as_deref(), "previous_event_id")?;
        if (self.sequence == 0) != self.previous_event_id.is_none()
            || self.previous_event_id.as_deref() == Some(self.event_id.as_str())
        {
            return Err(FoundationValidationError::InvalidEventSequence);
        }
        let valid_prefix = match self.domain {
            FoundationDomainV1::ControlPlane => "control.",
            FoundationDomainV1::GovernedBrain => "memory.",
        };
        if !self.event_kind.starts_with(valid_prefix) || self.event_kind.len() == valid_prefix.len()
        {
            return Err(FoundationValidationError::InvalidEventKind);
        }
        Ok(())
    }
}

pub fn validate_stable_id(
    value: &str,
    field: &'static str,
) -> Result<(), FoundationValidationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !value.is_ascii()
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(FoundationValidationError::InvalidStableId(field));
    }
    Ok(())
}

pub fn validate_sha256_digest(
    value: &str,
    field: &'static str,
) -> Result<(), FoundationValidationError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(FoundationValidationError::InvalidDigest(field));
    }
    Ok(())
}

pub fn validate_logical_path(value: &str) -> Result<(), FoundationValidationError> {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return Err(FoundationValidationError::InvalidLogicalPath);
    }
    for segment in value.split('/') {
        let bytes = segment.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 128
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .skip(1)
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(FoundationValidationError::InvalidLogicalPath);
        }
    }
    Ok(())
}

pub fn validate_decision_transition(
    kind: FoundationDecisionKindV1,
    current: FoundationDecisionStatusV1,
    next: FoundationDecisionStatusV1,
) -> Result<(), FoundationValidationError> {
    let allowed = match kind {
        FoundationDecisionKindV1::Approval => matches!(
            (current, next),
            (
                FoundationDecisionStatusV1::Pending,
                FoundationDecisionStatusV1::Approved | FoundationDecisionStatusV1::Rejected
            ) | (
                FoundationDecisionStatusV1::Approved | FoundationDecisionStatusV1::Rejected,
                FoundationDecisionStatusV1::Superseded
            )
        ),
        FoundationDecisionKindV1::Review | FoundationDecisionKindV1::Audit => matches!(
            (current, next),
            (
                FoundationDecisionStatusV1::Pending,
                FoundationDecisionStatusV1::Passed | FoundationDecisionStatusV1::Failed
            ) | (
                FoundationDecisionStatusV1::Passed | FoundationDecisionStatusV1::Failed,
                FoundationDecisionStatusV1::Superseded
            )
        ),
    };
    if allowed {
        Ok(())
    } else {
        Err(FoundationValidationError::InvalidDecisionTransition)
    }
}

pub fn validate_validity_transition(
    current: FoundationValidityStatusV1,
    next: FoundationValidityStatusV1,
) -> Result<(), FoundationValidationError> {
    let allowed = matches!(
        (current, next),
        (
            FoundationValidityStatusV1::Pending,
            FoundationValidityStatusV1::Active | FoundationValidityStatusV1::Rejected
        ) | (
            FoundationValidityStatusV1::Active,
            FoundationValidityStatusV1::Stale
                | FoundationValidityStatusV1::Revoked
                | FoundationValidityStatusV1::Superseded
        ) | (
            FoundationValidityStatusV1::Stale,
            FoundationValidityStatusV1::Revoked | FoundationValidityStatusV1::Superseded
        )
    );
    if allowed {
        Ok(())
    } else {
        Err(FoundationValidationError::InvalidValidityTransition)
    }
}

pub fn validate_visibility_transition(
    authority: &FoundationAuthorityV1,
    next: FoundationVisibilityV1,
    current_authority_digest: &str,
    owner_approval: Option<&FoundationDecisionV1>,
) -> Result<(), FoundationValidationError> {
    if next.rank() <= authority.visibility.rank() {
        return Ok(());
    }
    validate_sha256_digest(current_authority_digest, "current_authority_digest")?;
    let Some(owner_approval) = owner_approval else {
        return Err(FoundationValidationError::VisibilityWideningRequiresOwnerApproval);
    };
    if owner_approval.is_explicit_owner_approval()
        && owner_approval.namespace == authority.namespace
        && owner_approval.scope == authority.scope
        && owner_approval.subject == authority.principal
        && owner_approval.subject_digest == current_authority_digest
    {
        return Ok(());
    }
    Err(FoundationValidationError::VisibilityWideningRequiresOwnerApproval)
}

fn validate_version(value: u32) -> Result<(), FoundationValidationError> {
    if value == FOUNDATION_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(FoundationValidationError::UnsupportedContractVersion)
    }
}

fn validate_optional_stable_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), FoundationValidationError> {
    value.map_or(Ok(()), |value| validate_stable_id(value, field))
}

fn validate_permission_keys(values: &[String]) -> Result<(), FoundationValidationError> {
    for value in values {
        if validate_stable_id(value, "permission_key").is_err() {
            return Err(FoundationValidationError::InvalidPermissionKeys);
        }
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(FoundationValidationError::InvalidPermissionKeys);
    }
    Ok(())
}

fn validate_identifier_collection(
    values: &[String],
    field: &'static str,
) -> Result<(), FoundationValidationError> {
    if values.is_empty() {
        return Err(FoundationValidationError::EmptyIdentifierCollection(field));
    }
    for value in values {
        validate_stable_id(value, field)?;
    }
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(FoundationValidationError::DuplicateIdentifier);
        }
        if pair[0].as_bytes() > pair[1].as_bytes() {
            return Err(FoundationValidationError::NonCanonicalIdentifierOrder(
                field,
            ));
        }
    }
    Ok(())
}

fn decision_status_allowed(
    kind: FoundationDecisionKindV1,
    status: FoundationDecisionStatusV1,
) -> bool {
    match kind {
        FoundationDecisionKindV1::Approval => matches!(
            status,
            FoundationDecisionStatusV1::Pending
                | FoundationDecisionStatusV1::Approved
                | FoundationDecisionStatusV1::Rejected
                | FoundationDecisionStatusV1::Superseded
        ),
        FoundationDecisionKindV1::Review | FoundationDecisionKindV1::Audit => matches!(
            status,
            FoundationDecisionStatusV1::Pending
                | FoundationDecisionStatusV1::Passed
                | FoundationDecisionStatusV1::Failed
                | FoundationDecisionStatusV1::Superseded
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentId;
    use chrono::TimeZone;
    use serde_json::json;

    fn timestamp(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 16, hour, 0, 0)
            .single()
            .unwrap()
    }

    fn identity(principal_id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
        PrincipalIdentityV1 {
            principal_id: principal_id.to_owned(),
            role,
        }
    }

    fn scope() -> FoundationScopeV1 {
        FoundationScopeV1 {
            project_id: "project.public".to_owned(),
            goal_id: Some("goal.foundation".to_owned()),
            task_id: Some("task.contract".to_owned()),
            run_id: Some("run.001".to_owned()),
        }
    }

    fn permission_profile() -> FoundationPermissionProfileV1 {
        FoundationPermissionProfileV1 {
            contract_version: 1,
            risk_tier: RiskTier::R1,
            resource_keys: vec!["contracts.foundation".to_owned()],
            write_keys: vec![],
            approval_required: true,
            review_required: true,
            audit_required: false,
        }
    }

    fn authority() -> FoundationAuthorityV1 {
        FoundationAuthorityV1 {
            contract_version: 1,
            authority_id: "authority.foundation.001".to_owned(),
            principal: identity("principal.engineer", PrincipalV1::Engineer),
            scope: scope(),
            namespace: FoundationNamespaceV1::CodeReview,
            permission_profile: permission_profile(),
            visibility: FoundationVisibilityV1::Private,
            sensitivity: FoundationSensitivityV1::Internal,
            validity: FoundationValidityV1 {
                status: FoundationValidityStatusV1::Active,
                valid_from: timestamp(9),
                valid_until: None,
            },
        }
    }

    fn evidence() -> FoundationEvidenceRefV1 {
        FoundationEvidenceRefV1 {
            contract_version: 1,
            evidence_id: "evidence.foundation.001".to_owned(),
            kind: EvidenceKind::TestResult,
            digest: "c".repeat(64),
            producer: identity("principal.engineer", PrincipalV1::Engineer),
            scope: scope(),
            namespace: FoundationNamespaceV1::CodeReview,
            locator: FoundationLocatorV1::StableId("artifact.foundation.001".to_owned()),
            produced_at: timestamp(10),
        }
    }

    fn approval() -> FoundationDecisionV1 {
        FoundationDecisionV1 {
            contract_version: 1,
            decision_id: "decision.visibility.001".to_owned(),
            kind: FoundationDecisionKindV1::Approval,
            status: FoundationDecisionStatusV1::Approved,
            namespace: FoundationNamespaceV1::CodeReview,
            actor: identity("principal.owner", PrincipalV1::Owner),
            subject: identity("principal.engineer", PrincipalV1::Engineer),
            scope: scope(),
            subject_digest: "a".repeat(64),
            evidence_ids: vec!["evidence.review.001".to_owned()],
            decided_at: timestamp(10),
            supersedes_decision_id: None,
        }
    }

    #[test]
    fn principal_and_permission_legacy_conversions_are_explicit_and_fallible() {
        assert_eq!(PrincipalV1::from(Role::Reviewer), PrincipalV1::Reviewer);
        assert_eq!(Role::try_from(PrincipalV1::Auditor), Ok(Role::Auditor));
        assert_eq!(
            Role::try_from(PrincipalV1::Owner),
            Err(FoundationValidationError::OwnerHasNoLegacyRole)
        );

        let legacy = PermissionProfile {
            contract_version: ContractVersion(1),
            risk_tier: RiskTier::R2,
            resource_keys: vec!["resource.core".to_owned()],
            write_keys: vec!["resource.core".to_owned()],
            approval_required: true,
            review_required: true,
            audit_required: true,
        };
        let foundation = FoundationPermissionProfileV1::try_from_legacy(&legacy).unwrap();
        assert_eq!(foundation.try_into_legacy().unwrap(), legacy);

        let empty = FoundationPermissionProfileV1 {
            resource_keys: vec![],
            write_keys: vec![],
            ..foundation.clone()
        };
        assert!(empty.validate().is_ok());
        for (resource_keys, write_keys) in [
            (
                vec!["resource.z".to_owned(), "resource.a".to_owned()],
                vec![],
            ),
            (vec![], vec!["write.z".to_owned(), "write.a".to_owned()]),
        ] {
            let invalid = FoundationPermissionProfileV1 {
                resource_keys,
                write_keys,
                ..foundation.clone()
            };
            assert_eq!(
                invalid.validate(),
                Err(FoundationValidationError::InvalidPermissionKeys)
            );
        }

        let mut unsupported = legacy;
        unsupported.contract_version = ContractVersion(2);
        assert_eq!(
            FoundationPermissionProfileV1::try_from_legacy(&unsupported),
            Err(FoundationValidationError::UnsupportedContractVersion)
        );
    }

    #[test]
    fn stable_id_digest_logical_path_and_scope_are_closed() {
        assert!(validate_stable_id("resource:key-1", "id").is_ok());
        for value in ["", ".hidden", "white space", "line\nfeed", &"a".repeat(129)] {
            assert!(validate_stable_id(value, "id").is_err(), "{value:?}");
        }
        assert!(validate_sha256_digest(&"a".repeat(64), "digest").is_ok());
        for value in [
            "A".repeat(64),
            "a".repeat(63),
            format!("{}\n", "a".repeat(64)),
        ] {
            assert!(validate_sha256_digest(&value, "digest").is_err());
        }
        assert!(validate_logical_path("contracts/samples/foundation_v1.json").is_ok());
        for value in [
            "/absolute",
            "trailing/",
            "double//segment",
            "dot/./segment",
            "dot/../segment",
            "C:/drive",
            r"unc\share",
            "https://example.invalid/file",
            "$ENV/value",
            "raw body",
        ] {
            assert!(validate_logical_path(value).is_err(), "{value:?}");
        }

        assert!(scope().validate().is_ok());
        let invalid = FoundationScopeV1 {
            project_id: "project.public".to_owned(),
            goal_id: None,
            task_id: Some("task.contract".to_owned()),
            run_id: None,
        };
        assert_eq!(
            invalid.validate(),
            Err(FoundationValidationError::IncompleteScopeHierarchy)
        );
    }

    #[test]
    fn decision_roles_statuses_transitions_and_self_decisions_fail_closed() {
        let valid = approval();
        assert!(valid.validate().is_ok());
        assert!(valid.is_explicit_owner_approval());
        assert!(validate_decision_transition(
            FoundationDecisionKindV1::Approval,
            FoundationDecisionStatusV1::Pending,
            FoundationDecisionStatusV1::Approved,
        )
        .is_ok());
        assert!(validate_decision_transition(
            FoundationDecisionKindV1::Review,
            FoundationDecisionStatusV1::Passed,
            FoundationDecisionStatusV1::Superseded,
        )
        .is_ok());
        assert!(validate_decision_transition(
            FoundationDecisionKindV1::Audit,
            FoundationDecisionStatusV1::Superseded,
            FoundationDecisionStatusV1::Pending,
        )
        .is_err());

        let mut wrong_actor = valid.clone();
        wrong_actor.actor.role = PrincipalV1::Reviewer;
        assert_eq!(
            wrong_actor.validate(),
            Err(FoundationValidationError::InvalidDecisionActor)
        );
        let mut wrong_status = valid.clone();
        wrong_status.status = FoundationDecisionStatusV1::Passed;
        assert_eq!(
            wrong_status.validate(),
            Err(FoundationValidationError::InvalidDecisionStatus)
        );
        let mut self_decision = valid;
        self_decision.subject.principal_id = self_decision.actor.principal_id.clone();
        assert_eq!(
            self_decision.validate(),
            Err(FoundationValidationError::SelfDecision)
        );

        let mut empty_evidence = approval();
        empty_evidence.evidence_ids.clear();
        assert_eq!(
            empty_evidence.validate(),
            Err(FoundationValidationError::EmptyIdentifierCollection(
                "evidence_ids"
            ))
        );
        let mut unsorted_evidence = approval();
        unsorted_evidence.evidence_ids = vec![
            "evidence.review.002".to_owned(),
            "evidence.review.001".to_owned(),
        ];
        assert_eq!(
            unsorted_evidence.validate(),
            Err(FoundationValidationError::NonCanonicalIdentifierOrder(
                "evidence_ids"
            ))
        );
        let mut duplicate_evidence = approval();
        duplicate_evidence.evidence_ids = vec![
            "evidence.review.001".to_owned(),
            "evidence.review.001".to_owned(),
        ];
        assert_eq!(
            duplicate_evidence.validate(),
            Err(FoundationValidationError::DuplicateIdentifier)
        );

        let mut missing_predecessor = approval();
        missing_predecessor.status = FoundationDecisionStatusV1::Superseded;
        assert_eq!(
            missing_predecessor.validate(),
            Err(FoundationValidationError::InvalidSupersession)
        );

        for (kind, status, actor_role) in [
            (
                FoundationDecisionKindV1::Approval,
                FoundationDecisionStatusV1::Pending,
                PrincipalV1::Owner,
            ),
            (
                FoundationDecisionKindV1::Approval,
                FoundationDecisionStatusV1::Approved,
                PrincipalV1::Owner,
            ),
            (
                FoundationDecisionKindV1::Approval,
                FoundationDecisionStatusV1::Rejected,
                PrincipalV1::Owner,
            ),
            (
                FoundationDecisionKindV1::Review,
                FoundationDecisionStatusV1::Passed,
                PrincipalV1::Reviewer,
            ),
            (
                FoundationDecisionKindV1::Review,
                FoundationDecisionStatusV1::Failed,
                PrincipalV1::Reviewer,
            ),
        ] {
            let mut inconsistent = approval();
            inconsistent.kind = kind;
            inconsistent.status = status;
            inconsistent.actor.role = actor_role;
            inconsistent.supersedes_decision_id = Some("decision.previous.001".to_owned());
            assert_eq!(
                inconsistent.validate(),
                Err(FoundationValidationError::InvalidSupersession)
            );
        }

        let mut self_supersession = approval();
        self_supersession.status = FoundationDecisionStatusV1::Superseded;
        self_supersession.supersedes_decision_id = Some(self_supersession.decision_id.clone());
        assert_eq!(
            self_supersession.validate(),
            Err(FoundationValidationError::InvalidStableId(
                "supersedes_decision_id"
            ))
        );
        let mut valid_supersession = approval();
        valid_supersession.status = FoundationDecisionStatusV1::Superseded;
        valid_supersession.supersedes_decision_id = Some("decision.previous.001".to_owned());
        assert!(valid_supersession.validate().is_ok());
    }

    #[test]
    fn validity_and_visibility_transitions_require_the_frozen_authority() {
        let validity = FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: timestamp(9),
            valid_until: Some(timestamp(11)),
        };
        assert!(validity.validate().is_ok());
        assert!(validity
            .validate_transition_to(FoundationValidityStatusV1::Stale)
            .is_ok());
        assert!(validity
            .validate_transition_to(FoundationValidityStatusV1::Rejected)
            .is_err());
        let invalid_window = FoundationValidityV1 {
            valid_until: Some(timestamp(9)),
            ..validity
        };
        assert_eq!(
            invalid_window.validate(),
            Err(FoundationValidationError::InvalidValidityWindow)
        );

        let mut target = authority();
        target.visibility = FoundationVisibilityV1::Shared;
        assert!(
            validate_visibility_transition(&target, FoundationVisibilityV1::Private, "", None,)
                .is_ok()
        );
        assert!(target
            .validate_visibility_transition(FoundationVisibilityV1::Shared, "", None)
            .is_ok());
        target.visibility = FoundationVisibilityV1::Private;
        assert_eq!(
            validate_visibility_transition(
                &target,
                FoundationVisibilityV1::RoleScoped,
                &"a".repeat(64),
                None,
            ),
            Err(FoundationValidationError::VisibilityWideningRequiresOwnerApproval)
        );
        assert!(validate_visibility_transition(
            &target,
            FoundationVisibilityV1::Shared,
            &"a".repeat(64),
            Some(&approval()),
        )
        .is_ok());

        let mut mismatches = Vec::new();
        let mut wrong_namespace = approval();
        wrong_namespace.namespace = FoundationNamespaceV1::KnowledgeReview;
        mismatches.push(wrong_namespace);
        let mut wrong_scope = approval();
        wrong_scope.scope.run_id = Some("run.other".to_owned());
        mismatches.push(wrong_scope);
        let mut wrong_subject = approval();
        wrong_subject.subject = identity("principal.reviewer", PrincipalV1::Reviewer);
        mismatches.push(wrong_subject);
        let mut wrong_digest = approval();
        wrong_digest.subject_digest = "b".repeat(64);
        mismatches.push(wrong_digest);
        for mismatch in mismatches {
            assert_eq!(
                target.validate_visibility_transition(
                    FoundationVisibilityV1::Shared,
                    &"a".repeat(64),
                    Some(&mismatch),
                ),
                Err(FoundationValidationError::VisibilityWideningRequiresOwnerApproval)
            );
        }
        assert_eq!(
            target.validate_visibility_transition(
                FoundationVisibilityV1::Shared,
                &"b".repeat(64),
                Some(&approval()),
            ),
            Err(FoundationValidationError::VisibilityWideningRequiresOwnerApproval)
        );
        assert_eq!(
            target.validate_visibility_transition(
                FoundationVisibilityV1::Shared,
                &"A".repeat(64),
                Some(&approval()),
            ),
            Err(FoundationValidationError::InvalidDigest(
                "current_authority_digest"
            ))
        );
    }

    #[test]
    fn event_sequence_domain_prefix_and_payload_digest_are_closed() {
        let event = FoundationEventEnvelopeV1 {
            contract_version: 1,
            event_id: "event.control.001".to_owned(),
            domain: FoundationDomainV1::ControlPlane,
            scope: scope(),
            producer: identity("principal.coordinator", PrincipalV1::Coordinator),
            event_kind: "control.authority_recorded".to_owned(),
            sequence: 0,
            previous_event_id: None,
            occurred_at: timestamp(10),
            payload_digest: "b".repeat(64),
        };
        assert!(event.validate().is_ok());
        let mut wrong_prefix = event.clone();
        wrong_prefix.event_kind = "memory.authority_recorded".to_owned();
        assert_eq!(
            wrong_prefix.validate(),
            Err(FoundationValidationError::InvalidEventKind)
        );
        let mut missing_previous = event;
        missing_previous.sequence = 1;
        assert_eq!(
            missing_previous.validate(),
            Err(FoundationValidationError::InvalidEventSequence)
        );
    }

    #[test]
    fn closed_serde_shapes_and_legacy_agent_bytes_remain_exact() {
        let locator = FoundationLocatorV1::LogicalPath(
            "contracts/samples/foundation_authority.v1.sample.json".to_owned(),
        );
        assert_eq!(
            serde_json::to_value(&locator).unwrap(),
            json!({"type": "logical_path", "value": "contracts/samples/foundation_authority.v1.sample.json"})
        );
        assert!(serde_json::from_value::<FoundationScopeV1>(json!({
            "project_id": "project.public",
            "unknown": true
        }))
        .is_err());
        assert_eq!(
            serde_json::to_string(&AgentId::Coordinator).unwrap(),
            "\"coordinator\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Engineer).unwrap(),
            "\"engineer\""
        );
        let mut unknown_evidence_kind = serde_json::to_value(evidence()).unwrap();
        unknown_evidence_kind["kind"] = json!("made_up_kind");
        assert!(serde_json::from_value::<FoundationEvidenceRefV1>(unknown_evidence_kind).is_err());
    }

    #[test]
    fn every_top_level_contract_validates() {
        assert!(authority().validate().is_ok());
        assert!(evidence().validate().is_ok());
        assert!(approval().validate().is_ok());
    }

    #[test]
    fn published_samples_match_the_rust_wire_contracts() {
        let authority_json =
            include_str!("../../../contracts/samples/foundation_authority.v1.sample.json");
        let authority: FoundationAuthorityV1 = serde_json::from_str(authority_json).unwrap();
        assert!(authority.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&authority).unwrap(),
            serde_json::from_str::<serde_json::Value>(authority_json).unwrap()
        );

        let evidence_json =
            include_str!("../../../contracts/samples/foundation_evidence_ref.v1.sample.json");
        let evidence: FoundationEvidenceRefV1 = serde_json::from_str(evidence_json).unwrap();
        assert!(evidence.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&evidence).unwrap(),
            serde_json::from_str::<serde_json::Value>(evidence_json).unwrap()
        );

        let decision_json =
            include_str!("../../../contracts/samples/foundation_decision.v1.sample.json");
        let decision: FoundationDecisionV1 = serde_json::from_str(decision_json).unwrap();
        assert!(decision.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&decision).unwrap(),
            serde_json::from_str::<serde_json::Value>(decision_json).unwrap()
        );

        let event_json =
            include_str!("../../../contracts/samples/foundation_event_envelope.v1.sample.json");
        let event: FoundationEventEnvelopeV1 = serde_json::from_str(event_json).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::from_str::<serde_json::Value>(event_json).unwrap()
        );
    }
}
