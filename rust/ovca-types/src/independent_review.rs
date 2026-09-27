//! Provider-neutral contracts for independent Reviewer/Auditor execution.
//!
//! These values are immutable inputs and results. They grant no execution,
//! filesystem, network, persistence, or repair authority.

use crate::control_plane::RoleInvocationV1;
use crate::foundation::{
    validate_sha256_digest, validate_stable_id, PrincipalIdentityV1, PrincipalV1,
};
use crate::goal_runtime::{
    verification_sha256_hex, AuditDecision, CompletionEvidence, ContractVersion, CriterionKind,
    EvidenceId, EvidenceKind, EvidenceRef, GoalContract, GoalId, ReviewDecision, Role, RunId, Task,
    TaskId, VerificationBundle, VerificationTranscriptCommandIdentity, WorkerId,
};
use crate::tool_boundary::{validate_logical_path, WorkspaceFileV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const INDEPENDENT_REVIEW_CONTRACT_VERSION: u32 = 1;

const MANIFEST_DOMAIN: &str = "ovca.independent-review-manifest.v1";
const FROZEN_DIFF_DOMAIN: &str = "ovca.independent-review-frozen-diff.v1";
const REVIEW_PACKET_DOMAIN: &str = "ovca.independent-review-packet.v1";
const AUDIT_PACKET_DOMAIN: &str = "ovca.independent-audit-packet.v1";
const REPAIR_DIRECTIVE_DOMAIN: &str = "ovca.independent-repair-directive.v1";
const SUCCESSOR_RUN_DOMAIN: &str = "ovca.independent-repair-successor.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentReviewContractError {
    UnsupportedContractVersion,
    InvalidIdentity,
    InvalidRole,
    InvalidBinding,
    InvalidDigest,
    InvalidManifest,
    InvalidFrozenDiff,
    InvalidRepairDirective,
    Serialization,
}

impl fmt::Display for IndependentReviewContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedContractVersion => "unsupported independent-review contract version",
            Self::InvalidIdentity => "invalid independent-review identity",
            Self::InvalidRole => "invalid independent-review role binding",
            Self::InvalidBinding => "invalid independent-review contract binding",
            Self::InvalidDigest => "independent-review canonical digest mismatch",
            Self::InvalidManifest => "invalid independent-review evidence manifest",
            Self::InvalidFrozenDiff => "invalid independent-review frozen diff",
            Self::InvalidRepairDirective => "invalid independent-review repair directive",
            Self::Serialization => "independent-review canonical serialization failed",
        })
    }
}

impl std::error::Error for IndependentReviewContractError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCurrentAnchorV1 {
    pub bundle_id: String,
    pub record_digest: String,
    pub generation: u64,
    pub state_digest: String,
}

impl EvidenceCurrentAnchorV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_stable_id(&self.bundle_id, "bundle_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        validate_digest(&self.record_digest)?;
        validate_digest(&self.state_digest)?;
        if self.generation == 0 {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifestEntryV1 {
    pub criterion_kind: CriterionKind,
    pub criterion: String,
    pub evidence_id: EvidenceId,
    pub evidence_kind: EvidenceKind,
    pub producer: IndependentEvidenceActorV1,
    pub content_digest: String,
}

impl EvidenceManifestEntryV1 {
    fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_text(&self.criterion)?;
        validate_stable_id(self.evidence_id.as_str(), "evidence_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        self.producer.validate()?;
        validate_digest(&self.content_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifestV1 {
    pub contract_version: u32,
    pub actor: PrincipalIdentityV1,
    pub criteria_namespace: String,
    pub entries: Vec<EvidenceManifestEntryV1>,
    pub manifest_digest: String,
}

#[derive(Serialize)]
struct EvidenceManifestDigestInputV1<'a> {
    contract_version: u32,
    actor: &'a PrincipalIdentityV1,
    criteria_namespace: &'a str,
    entries: &'a [EvidenceManifestEntryV1],
}

impl EvidenceManifestV1 {
    pub fn validate_for(
        &self,
        expected_actor: &PrincipalIdentityV1,
        expected_role: PrincipalV1,
    ) -> Result<(), IndependentReviewContractError> {
        validate_version(self.contract_version)?;
        self.actor
            .validate()
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        if &self.actor != expected_actor || self.actor.role != expected_role {
            return Err(IndependentReviewContractError::InvalidRole);
        }
        validate_stable_id(&self.criteria_namespace, "criteria_namespace")
            .map_err(|_| IndependentReviewContractError::InvalidManifest)?;
        if self.entries.is_empty() {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
        let mut prior: Option<(&CriterionKind, &str, &str)> = None;
        for entry in &self.entries {
            entry.validate()?;
            if entry.producer.actor_id == self.actor.principal_id {
                return Err(IndependentReviewContractError::InvalidManifest);
            }
            let current = (
                &entry.criterion_kind,
                entry.criterion.as_str(),
                entry.evidence_id.as_str(),
            );
            if prior.is_some_and(|previous| previous >= current) {
                return Err(IndependentReviewContractError::InvalidManifest);
            }
            prior = Some(current);
        }
        validate_digest(&self.manifest_digest)?;
        if self.computed_digest()? != self.manifest_digest {
            return Err(IndependentReviewContractError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, IndependentReviewContractError> {
        domain_digest(
            MANIFEST_DOMAIN,
            &EvidenceManifestDigestInputV1 {
                contract_version: self.contract_version,
                actor: &self.actor,
                criteria_namespace: &self.criteria_namespace,
                entries: &self.entries,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewContractError> {
        self.manifest_digest = self.computed_digest()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentEvidenceActorRoleV1 {
    Engineer,
    Verifier,
    Reviewer,
    Auditor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentEvidenceActorV1 {
    pub actor_id: String,
    pub role: IndependentEvidenceActorRoleV1,
}

impl IndependentEvidenceActorV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_stable_id(&self.actor_id, "evidence_actor_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPathDiffV1 {
    pub contract_version: u32,
    pub logical_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_bytes: Option<Vec<u8>>,
    pub after_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_file: Option<WorkspaceFileV1>,
    pub after_file: WorkspaceFileV1,
    pub issue6_diff_digest: String,
    pub frozen_diff_digest: String,
}

#[derive(Serialize)]
struct FrozenPathDiffDigestInputV1<'a> {
    contract_version: u32,
    logical_path: &'a str,
    before_bytes: &'a Option<Vec<u8>>,
    after_bytes: &'a [u8],
    before_file: &'a Option<WorkspaceFileV1>,
    after_file: &'a WorkspaceFileV1,
    issue6_diff_digest: &'a str,
}

impl FrozenPathDiffV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_version(self.contract_version)?;
        validate_logical_path(&self.logical_path)
            .map_err(|_| IndependentReviewContractError::InvalidFrozenDiff)?;
        validate_digest(&self.issue6_diff_digest)?;
        validate_digest(&self.frozen_diff_digest)?;
        self.after_file
            .validate()
            .map_err(|_| IndependentReviewContractError::InvalidFrozenDiff)?;
        if self.after_file.logical_path != self.logical_path
            || !bytes_match_file(&self.after_bytes, &self.after_file)
        {
            return Err(IndependentReviewContractError::InvalidFrozenDiff);
        }
        match (&self.before_bytes, &self.before_file) {
            (None, None) => {}
            (Some(bytes), Some(file)) => {
                file.validate()
                    .map_err(|_| IndependentReviewContractError::InvalidFrozenDiff)?;
                if file.logical_path != self.logical_path || !bytes_match_file(bytes, file) {
                    return Err(IndependentReviewContractError::InvalidFrozenDiff);
                }
            }
            _ => return Err(IndependentReviewContractError::InvalidFrozenDiff),
        }
        if self.before_file.as_ref() == Some(&self.after_file) {
            return Err(IndependentReviewContractError::InvalidFrozenDiff);
        }
        if self.computed_digest()? != self.frozen_diff_digest {
            return Err(IndependentReviewContractError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, IndependentReviewContractError> {
        domain_digest(
            FROZEN_DIFF_DOMAIN,
            &FrozenPathDiffDigestInputV1 {
                contract_version: self.contract_version,
                logical_path: &self.logical_path,
                before_bytes: &self.before_bytes,
                after_bytes: &self.after_bytes,
                before_file: &self.before_file,
                after_file: &self.after_file,
                issue6_diff_digest: &self.issue6_diff_digest,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewContractError> {
        self.frozen_diff_digest = self.computed_digest()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPacketV1 {
    pub contract_version: u32,
    pub packet_id: String,
    pub root_run_id: RunId,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub candidate_cycle: u32,
    pub max_repair_cycles: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_run_id: Option<RunId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_repair_directive_digest: Option<String>,
    pub task: Task,
    pub goal_contract: GoalContract,
    pub completion_evidence: CompletionEvidence,
    pub evidence_catalog: Vec<EvidenceRef>,
    pub engineer: PrincipalIdentityV1,
    pub verifier: WorkerId,
    pub reviewer: PrincipalIdentityV1,
    pub reviewer_invocation: RoleInvocationV1,
    pub reviewer_invocation_digest: String,
    pub issue6_state_digest: String,
    pub logical_plan_digest: String,
    pub resolved_effect_ledger_digest: String,
    pub engineer_result_digest: String,
    pub verifier_replay_plan_digest: String,
    pub verifier_transcript_digest: String,
    pub frozen_diff: FrozenPathDiffV1,
    pub verification_bundle: VerificationBundle,
    pub verification_bundle_record_digest: String,
    pub evidence_current: EvidenceCurrentAnchorV1,
    pub verifier_receipts: Vec<VerificationTranscriptCommandIdentity>,
    pub evidence_manifest: EvidenceManifestV1,
    pub packet_digest: String,
}

#[derive(Serialize)]
struct ReviewPacketDigestInputV1<'a> {
    contract_version: u32,
    packet_id: &'a str,
    root_run_id: &'a RunId,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    candidate_cycle: u32,
    max_repair_cycles: u32,
    prior_run_id: &'a Option<RunId>,
    prior_repair_directive_digest: Option<&'a str>,
    task: &'a Task,
    goal_contract: &'a GoalContract,
    completion_evidence: &'a CompletionEvidence,
    evidence_catalog: &'a [EvidenceRef],
    engineer: &'a PrincipalIdentityV1,
    verifier: &'a WorkerId,
    reviewer: &'a PrincipalIdentityV1,
    reviewer_invocation: &'a RoleInvocationV1,
    reviewer_invocation_digest: &'a str,
    issue6_state_digest: &'a str,
    logical_plan_digest: &'a str,
    resolved_effect_ledger_digest: &'a str,
    engineer_result_digest: &'a str,
    verifier_replay_plan_digest: &'a str,
    verifier_transcript_digest: &'a str,
    frozen_diff: &'a FrozenPathDiffV1,
    verification_bundle: &'a VerificationBundle,
    verification_bundle_record_digest: &'a str,
    evidence_current: &'a EvidenceCurrentAnchorV1,
    verifier_receipts: &'a [VerificationTranscriptCommandIdentity],
    evidence_manifest: &'a EvidenceManifestV1,
}

impl ReviewPacketV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.packet_id, "packet_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        validate_core_ids(&self.run_id, &self.goal_id, &self.task_id)?;
        validate_stable_id(self.root_run_id.as_str(), "root_run_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        if self.max_repair_cycles == 0 || self.candidate_cycle > self.max_repair_cycles {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        validate_optional_digest(&self.prior_repair_directive_digest)?;
        if (self.candidate_cycle == 0) != self.prior_repair_directive_digest.is_none()
            || (self.candidate_cycle == 0) != self.prior_run_id.is_none()
            || (self.candidate_cycle == 0 && self.root_run_id != self.run_id)
        {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        if let Some(prior_run_id) = &self.prior_run_id {
            validate_stable_id(prior_run_id.as_str(), "prior_run_id")
                .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        }
        validate_principal(&self.engineer, PrincipalV1::Engineer)?;
        validate_stable_id(self.verifier.as_str(), "verifier")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        validate_principal(&self.reviewer, PrincipalV1::Reviewer)?;
        if self.engineer.principal_id == self.verifier.as_str()
            || self.engineer.principal_id == self.reviewer.principal_id
            || self.verifier.as_str() == self.reviewer.principal_id
        {
            return Err(IndependentReviewContractError::InvalidRole);
        }
        self.reviewer_invocation
            .validate()
            .map_err(|_| IndependentReviewContractError::InvalidBinding)?;
        validate_digest(&self.reviewer_invocation_digest)?;
        if self.reviewer_invocation.target != self.reviewer
            || self.reviewer_invocation.target.role != PrincipalV1::Reviewer
            || !self
                .reviewer_invocation
                .authority
                .permission_profile
                .resource_keys
                .is_empty()
            || !self
                .reviewer_invocation
                .authority
                .permission_profile
                .write_keys
                .is_empty()
            || self.reviewer_invocation.run_id != self.run_id
            || self.reviewer_invocation.task_id != self.task_id
            || self.reviewer_invocation.scope.goal_id.as_deref() != Some(self.goal_id.as_str())
            || self.reviewer_invocation.scope.run_id.as_deref() != Some(self.run_id.as_str())
            || self.reviewer_invocation.scope.task_id.as_deref() != Some(self.task_id.as_str())
            || self
                .reviewer_invocation
                .canonical_digest()
                .map_err(|_| IndependentReviewContractError::InvalidBinding)?
                != self.reviewer_invocation_digest
        {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        for digest in [
            &self.issue6_state_digest,
            &self.logical_plan_digest,
            &self.resolved_effect_ledger_digest,
            &self.engineer_result_digest,
            &self.verifier_replay_plan_digest,
            &self.verifier_transcript_digest,
            &self.verification_bundle_record_digest,
            &self.packet_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.task.id != self.task_id
            || self.task.goal_id != self.goal_id
            || self.goal_contract.id != self.goal_id
            || self.verification_bundle.run_id != self.run_id
            || self.verification_bundle.goal_id != self.goal_id
            || self.verification_bundle.task_id != self.task_id
            || self.verification_bundle.verdict != crate::VerificationVerdict::Pass
            || self.verification_bundle.bundle_id != self.evidence_current.bundle_id
            || self.verification_bundle_record_digest != self.evidence_current.record_digest
            || self.verifier_receipts.is_empty()
        {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        self.frozen_diff.validate()?;
        self.evidence_current.validate()?;
        validate_evidence_context(
            &self.goal_contract,
            &self.completion_evidence,
            &self.evidence_catalog,
        )?;
        self.evidence_manifest
            .validate_for(&self.reviewer, PrincipalV1::Reviewer)?;
        validate_manifest_bindings(
            &self.evidence_manifest,
            &self.goal_contract,
            &self.completion_evidence,
            &self.evidence_catalog,
            &[
                (
                    self.engineer.principal_id.as_str(),
                    IndependentEvidenceActorRoleV1::Engineer,
                ),
                (
                    self.verifier.as_str(),
                    IndependentEvidenceActorRoleV1::Verifier,
                ),
            ],
        )?;
        if self.computed_digest()? != self.packet_digest {
            return Err(IndependentReviewContractError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, IndependentReviewContractError> {
        domain_digest(
            REVIEW_PACKET_DOMAIN,
            &ReviewPacketDigestInputV1 {
                contract_version: self.contract_version,
                packet_id: &self.packet_id,
                root_run_id: &self.root_run_id,
                run_id: &self.run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                candidate_cycle: self.candidate_cycle,
                max_repair_cycles: self.max_repair_cycles,
                prior_run_id: &self.prior_run_id,
                prior_repair_directive_digest: self.prior_repair_directive_digest.as_deref(),
                task: &self.task,
                goal_contract: &self.goal_contract,
                completion_evidence: &self.completion_evidence,
                evidence_catalog: &self.evidence_catalog,
                engineer: &self.engineer,
                verifier: &self.verifier,
                reviewer: &self.reviewer,
                reviewer_invocation: &self.reviewer_invocation,
                reviewer_invocation_digest: &self.reviewer_invocation_digest,
                issue6_state_digest: &self.issue6_state_digest,
                logical_plan_digest: &self.logical_plan_digest,
                resolved_effect_ledger_digest: &self.resolved_effect_ledger_digest,
                engineer_result_digest: &self.engineer_result_digest,
                verifier_replay_plan_digest: &self.verifier_replay_plan_digest,
                verifier_transcript_digest: &self.verifier_transcript_digest,
                frozen_diff: &self.frozen_diff,
                verification_bundle: &self.verification_bundle,
                verification_bundle_record_digest: &self.verification_bundle_record_digest,
                evidence_current: &self.evidence_current,
                verifier_receipts: &self.verifier_receipts,
                evidence_manifest: &self.evidence_manifest,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewContractError> {
        self.packet_digest = self.computed_digest()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPacketV1 {
    pub contract_version: u32,
    pub packet_id: String,
    pub review_packet: ReviewPacketV1,
    pub review_packet_digest: String,
    pub review_result_digest: String,
    pub review_decision: ReviewDecision,
    pub auditor: PrincipalIdentityV1,
    pub auditor_invocation: RoleInvocationV1,
    pub auditor_invocation_digest: String,
    pub evidence_manifest: EvidenceManifestV1,
    pub packet_digest: String,
}

#[derive(Serialize)]
struct AuditPacketDigestInputV1<'a> {
    contract_version: u32,
    packet_id: &'a str,
    review_packet: &'a ReviewPacketV1,
    review_packet_digest: &'a str,
    review_result_digest: &'a str,
    review_decision: &'a ReviewDecision,
    auditor: &'a PrincipalIdentityV1,
    auditor_invocation: &'a RoleInvocationV1,
    auditor_invocation_digest: &'a str,
    evidence_manifest: &'a EvidenceManifestV1,
}

impl AuditPacketV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.packet_id, "packet_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        self.review_packet.validate()?;
        validate_principal(&self.auditor, PrincipalV1::Auditor)?;
        if [
            self.review_packet.engineer.principal_id.as_str(),
            self.review_packet.verifier.as_str(),
            self.review_packet.reviewer.principal_id.as_str(),
        ]
        .contains(&self.auditor.principal_id.as_str())
        {
            return Err(IndependentReviewContractError::InvalidRole);
        }
        self.auditor_invocation
            .validate()
            .map_err(|_| IndependentReviewContractError::InvalidBinding)?;
        for digest in [
            &self.review_packet_digest,
            &self.review_result_digest,
            &self.auditor_invocation_digest,
            &self.packet_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.review_packet_digest != self.review_packet.packet_digest
            || self.review_decision.run_id != self.review_packet.run_id
            || self.review_decision.goal_id != self.review_packet.goal_id
            || self.review_decision.producer_role != crate::Role::Reviewer
            || self.auditor_invocation.target != self.auditor
            || self.auditor_invocation.target.role != PrincipalV1::Auditor
            || !self
                .auditor_invocation
                .authority
                .permission_profile
                .resource_keys
                .is_empty()
            || !self
                .auditor_invocation
                .authority
                .permission_profile
                .write_keys
                .is_empty()
            || self.auditor_invocation.run_id != self.review_packet.run_id
            || self.auditor_invocation.task_id != self.review_packet.task_id
            || self.auditor_invocation.scope.goal_id.as_deref()
                != Some(self.review_packet.goal_id.as_str())
            || self.auditor_invocation.scope.run_id.as_deref()
                != Some(self.review_packet.run_id.as_str())
            || self.auditor_invocation.scope.task_id.as_deref()
                != Some(self.review_packet.task_id.as_str())
            || self
                .auditor_invocation
                .canonical_digest()
                .map_err(|_| IndependentReviewContractError::InvalidBinding)?
                != self.auditor_invocation_digest
            || self.evidence_manifest.criteria_namespace
                == self.review_packet.evidence_manifest.criteria_namespace
        {
            return Err(IndependentReviewContractError::InvalidBinding);
        }
        self.evidence_manifest
            .validate_for(&self.auditor, PrincipalV1::Auditor)?;
        validate_manifest_bindings(
            &self.evidence_manifest,
            &self.review_packet.goal_contract,
            &self.review_packet.completion_evidence,
            &self.review_packet.evidence_catalog,
            &[
                (
                    self.review_packet.engineer.principal_id.as_str(),
                    IndependentEvidenceActorRoleV1::Engineer,
                ),
                (
                    self.review_packet.verifier.as_str(),
                    IndependentEvidenceActorRoleV1::Verifier,
                ),
                (
                    self.review_packet.reviewer.principal_id.as_str(),
                    IndependentEvidenceActorRoleV1::Reviewer,
                ),
            ],
        )?;
        if self.computed_digest()? != self.packet_digest {
            return Err(IndependentReviewContractError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, IndependentReviewContractError> {
        domain_digest(
            AUDIT_PACKET_DOMAIN,
            &AuditPacketDigestInputV1 {
                contract_version: self.contract_version,
                packet_id: &self.packet_id,
                review_packet: &self.review_packet,
                review_packet_digest: &self.review_packet_digest,
                review_result_digest: &self.review_result_digest,
                review_decision: &self.review_decision,
                auditor: &self.auditor,
                auditor_invocation: &self.auditor_invocation,
                auditor_invocation_digest: &self.auditor_invocation_digest,
                evidence_manifest: &self.evidence_manifest,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewContractError> {
        self.packet_digest = self.computed_digest()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsatisfiedCriterionV1 {
    pub kind: CriterionKind,
    pub criterion: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairDirectiveV1 {
    pub contract_version: u32,
    pub directive_id: String,
    pub root_run_id: RunId,
    pub failed_run_id: RunId,
    pub successor_run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub failed_candidate_cycle: u32,
    pub successor_candidate_cycle: u32,
    pub max_repair_cycles: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_repair_directive_digest: Option<String>,
    pub review_packet_digest: String,
    pub review_result_digest: String,
    pub audit_packet_digest: String,
    pub audit_result_digest: String,
    pub repair_paths: Vec<String>,
    pub unsatisfied_criteria: Vec<UnsatisfiedCriterionV1>,
    pub routed_by: PrincipalIdentityV1,
    pub grants_authority: bool,
    pub directive_digest: String,
}

#[derive(Serialize)]
struct RepairDirectiveDigestInputV1<'a> {
    contract_version: u32,
    directive_id: &'a str,
    root_run_id: &'a RunId,
    failed_run_id: &'a RunId,
    successor_run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    failed_candidate_cycle: u32,
    successor_candidate_cycle: u32,
    max_repair_cycles: u32,
    prior_repair_directive_digest: Option<&'a str>,
    review_packet_digest: &'a str,
    review_result_digest: &'a str,
    audit_packet_digest: &'a str,
    audit_result_digest: &'a str,
    repair_paths: &'a [String],
    unsatisfied_criteria: &'a [UnsatisfiedCriterionV1],
    routed_by: &'a PrincipalIdentityV1,
    grants_authority: bool,
}

impl RepairDirectiveV1 {
    pub fn validate(&self) -> Result<(), IndependentReviewContractError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.directive_id, "directive_id")
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        validate_core_ids(&self.failed_run_id, &self.goal_id, &self.task_id)?;
        validate_stable_id(self.root_run_id.as_str(), "root_run_id")
            .and_then(|_| validate_stable_id(self.successor_run_id.as_str(), "successor_run_id"))
            .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
        validate_principal(&self.routed_by, PrincipalV1::Coordinator)?;
        validate_optional_digest(&self.prior_repair_directive_digest)?;
        for digest in [
            &self.review_packet_digest,
            &self.review_result_digest,
            &self.audit_packet_digest,
            &self.audit_result_digest,
            &self.directive_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.max_repair_cycles == 0
            || self.failed_candidate_cycle >= self.max_repair_cycles
            || (self.failed_candidate_cycle == 0) != self.prior_repair_directive_digest.is_none()
            || self.successor_candidate_cycle
                != self
                    .failed_candidate_cycle
                    .checked_add(1)
                    .ok_or(IndependentReviewContractError::InvalidRepairDirective)?
            || self.grants_authority
            || self.repair_paths.is_empty()
            || self.unsatisfied_criteria.is_empty()
            || self.successor_run_id
                != derive_repair_successor_run_id(
                    &self.root_run_id,
                    self.successor_candidate_cycle,
                    &self.review_result_digest,
                    &self.audit_result_digest,
                )?
        {
            return Err(IndependentReviewContractError::InvalidRepairDirective);
        }
        validate_strict_paths(&self.repair_paths)?;
        let mut criteria = BTreeSet::new();
        let mut prior: Option<(&CriterionKind, &str)> = None;
        for criterion in &self.unsatisfied_criteria {
            validate_text(&criterion.criterion)?;
            let current = (&criterion.kind, criterion.criterion.as_str());
            if prior.is_some_and(|value| value >= current) || !criteria.insert(current) {
                return Err(IndependentReviewContractError::InvalidRepairDirective);
            }
            prior = Some(current);
        }
        if self.computed_digest()? != self.directive_digest {
            return Err(IndependentReviewContractError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, IndependentReviewContractError> {
        domain_digest(
            REPAIR_DIRECTIVE_DOMAIN,
            &RepairDirectiveDigestInputV1 {
                contract_version: self.contract_version,
                directive_id: &self.directive_id,
                root_run_id: &self.root_run_id,
                failed_run_id: &self.failed_run_id,
                successor_run_id: &self.successor_run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                failed_candidate_cycle: self.failed_candidate_cycle,
                successor_candidate_cycle: self.successor_candidate_cycle,
                max_repair_cycles: self.max_repair_cycles,
                prior_repair_directive_digest: self.prior_repair_directive_digest.as_deref(),
                review_packet_digest: &self.review_packet_digest,
                review_result_digest: &self.review_result_digest,
                audit_packet_digest: &self.audit_packet_digest,
                audit_result_digest: &self.audit_result_digest,
                repair_paths: &self.repair_paths,
                unsatisfied_criteria: &self.unsatisfied_criteria,
                routed_by: &self.routed_by,
                grants_authority: self.grants_authority,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewContractError> {
        self.directive_digest = self.computed_digest()?;
        Ok(())
    }
}

pub fn derive_repair_successor_run_id(
    root_run_id: &RunId,
    successor_candidate_cycle: u32,
    review_result_digest: &str,
    audit_result_digest: &str,
) -> Result<RunId, IndependentReviewContractError> {
    validate_stable_id(root_run_id.as_str(), "root_run_id")
        .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
    validate_digest(review_result_digest)?;
    validate_digest(audit_result_digest)?;
    if successor_candidate_cycle == 0 {
        return Err(IndependentReviewContractError::InvalidRepairDirective);
    }
    #[derive(Serialize)]
    struct Input<'a> {
        root_run_id: &'a RunId,
        successor_candidate_cycle: u32,
        review_result_digest: &'a str,
        audit_result_digest: &'a str,
    }
    let digest = domain_digest(
        SUCCESSOR_RUN_DOMAIN,
        &Input {
            root_run_id,
            successor_candidate_cycle,
            review_result_digest,
            audit_result_digest,
        },
    )?;
    Ok(RunId::from(format!(
        "repair.{successor_candidate_cycle}.{digest}"
    )))
}

pub fn review_decision_from_payload(
    payload: &crate::control_plane::RoleResultPayloadV1,
) -> Option<(&str, &ReviewDecision)> {
    match payload {
        crate::control_plane::RoleResultPayloadV1::Reviewer {
            packet_digest,
            decision,
        } => Some((packet_digest, decision)),
        _ => None,
    }
}

pub fn audit_decision_from_payload(
    payload: &crate::control_plane::RoleResultPayloadV1,
) -> Option<(&str, &AuditDecision)> {
    match payload {
        crate::control_plane::RoleResultPayloadV1::Auditor {
            packet_digest,
            decision,
        } => Some((packet_digest, decision)),
        _ => None,
    }
}

fn validate_evidence_context(
    goal: &GoalContract,
    completion: &CompletionEvidence,
    catalog: &[EvidenceRef],
) -> Result<(), IndependentReviewContractError> {
    if goal.contract_version != ContractVersion::current()
        || goal.permission_profile.contract_version != ContractVersion::current()
        || goal.completion_precondition.contract_version != ContractVersion::current()
        || completion.contract_version != ContractVersion::current()
    {
        return Err(IndependentReviewContractError::UnsupportedContractVersion);
    }
    let mut catalog_by_id = BTreeMap::new();
    let mut prior_catalog_id: Option<&EvidenceId> = None;
    for evidence in catalog {
        if evidence.contract_version != ContractVersion::current() {
            return Err(IndependentReviewContractError::UnsupportedContractVersion);
        }
        validate_stable_id(evidence.id.as_str(), "evidence_id")
            .map_err(|_| IndependentReviewContractError::InvalidManifest)?;
        validate_text(&evidence.reference)?;
        if prior_catalog_id.is_some_and(|prior| prior >= &evidence.id)
            || catalog_by_id
                .insert(evidence.id.as_str(), evidence)
                .is_some()
        {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
        prior_catalog_id = Some(&evidence.id);
    }

    let required = goal.completion_precondition.minimum_evidence_refs.max(1) as usize;
    if completion.evidence_refs.len() < required {
        return Err(IndependentReviewContractError::InvalidManifest);
    }
    let mut prior_completion_id: Option<&EvidenceId> = None;
    for evidence_id in &completion.evidence_refs {
        if prior_completion_id.is_some_and(|prior| prior >= evidence_id)
            || !catalog_by_id.contains_key(evidence_id.as_str())
        {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
        prior_completion_id = Some(evidence_id);
    }

    validate_satisfied_criteria(
        &goal.acceptance_criteria,
        &completion.satisfied_acceptance_criteria,
    )?;
    validate_satisfied_criteria(
        &goal.verification_criteria,
        &completion.satisfied_verification_criteria,
    )?;
    validate_satisfied_criteria(
        &goal.definition_of_done,
        &completion.satisfied_definition_of_done,
    )?;
    Ok(())
}

fn validate_satisfied_criteria(
    declared: &[String],
    satisfied: &[String],
) -> Result<(), IndependentReviewContractError> {
    let mut declared_positions = BTreeMap::new();
    for (index, criterion) in declared.iter().enumerate() {
        validate_text(criterion)?;
        if declared_positions
            .insert(criterion.as_str(), index)
            .is_some()
        {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
    }
    let mut prior = None;
    let mut seen = BTreeSet::new();
    for criterion in satisfied {
        let position = declared_positions
            .get(criterion.as_str())
            .copied()
            .ok_or(IndependentReviewContractError::InvalidManifest)?;
        if !seen.insert(criterion.as_str()) || prior.is_some_and(|value| value >= position) {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
        prior = Some(position);
    }
    Ok(())
}

fn validate_manifest_bindings(
    manifest: &EvidenceManifestV1,
    goal: &GoalContract,
    completion: &CompletionEvidence,
    catalog: &[EvidenceRef],
    known_producers: &[(&str, IndependentEvidenceActorRoleV1)],
) -> Result<(), IndependentReviewContractError> {
    let catalog_by_id = catalog
        .iter()
        .map(|evidence| (evidence.id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let completion_ids = completion
        .evidence_refs
        .iter()
        .map(EvidenceId::as_str)
        .collect::<BTreeSet<_>>();
    let mut covered_completion_ids = BTreeSet::new();
    for entry in &manifest.entries {
        let declared = match entry.criterion_kind {
            CriterionKind::Acceptance => &goal.acceptance_criteria,
            CriterionKind::Verification => &goal.verification_criteria,
            CriterionKind::DefinitionOfDone => &goal.definition_of_done,
        };
        let evidence = catalog_by_id
            .get(entry.evidence_id.as_str())
            .copied()
            .ok_or(IndependentReviewContractError::InvalidManifest)?;
        let integrity = evidence
            .integrity
            .as_ref()
            .ok_or(IndependentReviewContractError::InvalidManifest)?;
        let expected_catalog_role = match entry.producer.role {
            IndependentEvidenceActorRoleV1::Engineer | IndependentEvidenceActorRoleV1::Verifier => {
                Role::Engineer
            }
            IndependentEvidenceActorRoleV1::Reviewer => Role::Reviewer,
            IndependentEvidenceActorRoleV1::Auditor => Role::Auditor,
        };
        if !declared.contains(&entry.criterion)
            || !completion_ids.contains(entry.evidence_id.as_str())
            || evidence.kind != entry.evidence_kind
            || evidence.producer_role != expected_catalog_role
            || integrity.contract_version != ContractVersion::current()
            || integrity.algorithm != "sha256"
            || integrity.digest != entry.content_digest
            || !known_producers.iter().any(|(actor_id, role)| {
                *actor_id == entry.producer.actor_id && *role == entry.producer.role
            })
        {
            return Err(IndependentReviewContractError::InvalidManifest);
        }
        validate_digest(&integrity.digest)?;
        covered_completion_ids.insert(entry.evidence_id.as_str());
    }
    if covered_completion_ids != completion_ids {
        return Err(IndependentReviewContractError::InvalidManifest);
    }
    Ok(())
}

fn validate_core_ids(
    run_id: &RunId,
    goal_id: &GoalId,
    task_id: &TaskId,
) -> Result<(), IndependentReviewContractError> {
    validate_stable_id(run_id.as_str(), "run_id")
        .and_then(|_| validate_stable_id(goal_id.as_str(), "goal_id"))
        .and_then(|_| validate_stable_id(task_id.as_str(), "task_id"))
        .map_err(|_| IndependentReviewContractError::InvalidIdentity)
}

fn validate_principal(
    principal: &PrincipalIdentityV1,
    expected: PrincipalV1,
) -> Result<(), IndependentReviewContractError> {
    principal
        .validate()
        .map_err(|_| IndependentReviewContractError::InvalidIdentity)?;
    if principal.role != expected {
        return Err(IndependentReviewContractError::InvalidRole);
    }
    Ok(())
}

fn validate_version(value: u32) -> Result<(), IndependentReviewContractError> {
    if value != INDEPENDENT_REVIEW_CONTRACT_VERSION {
        return Err(IndependentReviewContractError::UnsupportedContractVersion);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), IndependentReviewContractError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(IndependentReviewContractError::InvalidBinding);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), IndependentReviewContractError> {
    validate_sha256_digest(value, "digest")
        .map_err(|_| IndependentReviewContractError::InvalidDigest)
}

fn validate_optional_digest(value: &Option<String>) -> Result<(), IndependentReviewContractError> {
    if let Some(value) = value {
        validate_digest(value)?;
    }
    Ok(())
}

fn validate_strict_paths(paths: &[String]) -> Result<(), IndependentReviewContractError> {
    for path in paths {
        validate_logical_path(path)
            .map_err(|_| IndependentReviewContractError::InvalidRepairDirective)?;
    }
    if paths
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(IndependentReviewContractError::InvalidRepairDirective);
    }
    Ok(())
}

fn bytes_match_file(bytes: &[u8], file: &WorkspaceFileV1) -> bool {
    u64::try_from(bytes.len()).ok() == Some(file.byte_length)
        && verification_sha256_hex(bytes) == file.sha256
}

fn domain_digest<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<String, IndependentReviewContractError> {
    let json =
        serde_json::to_vec(value).map_err(|_| IndependentReviewContractError::Serialization)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + json.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&json);
    Ok(verification_sha256_hex(&bytes))
}
