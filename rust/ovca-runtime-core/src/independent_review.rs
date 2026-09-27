//! Durable contracts and the packet-aware execution port for A05.

use crate::engineer_verifier::PersistedRoleExecutionOutcomeV1;
use crate::review_audit::{
    validate_audit_decision, validate_review_decision, validate_review_evidence_context,
    AuditDecisionValidationContext, ReviewDecisionValidationContext,
};
use crate::role_executor::{RoleExecutionOutcome, RoleExecutionRequest, RoleExecutorError};
use chrono::{DateTime, Utc};
use ovca_types::control_plane::{ControlPlaneState, RoleResultPayloadV1, RoleResultV1};
use ovca_types::foundation::{validate_sha256_digest, PrincipalV1};
use ovca_types::goal_runtime::{
    verification_sha256_hex, CriterionAssessment, CriterionAssessmentVerdict, ReviewVerdict,
};
use ovca_types::independent_review::{
    AuditPacketV1, IndependentReviewContractError, RepairDirectiveV1, ReviewPacketV1,
    UnsatisfiedCriterionV1, INDEPENDENT_REVIEW_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::fmt;

const EXECUTION_REQUEST_DOMAIN: &str = "ovca.independent-review-execution-request.v1";
const STATE_DOMAIN: &str = "ovca.independent-review-state.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentReviewError {
    Contract,
    InvalidState,
    InvalidTransition,
    InvalidExecutionRequest,
    InvalidExecutorOutcome,
    InvalidDigest,
    Serialization,
}

impl fmt::Display for IndependentReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Contract => "independent-review contract validation failed",
            Self::InvalidState => "invalid independent-review durable state",
            Self::InvalidTransition => "invalid independent-review durable transition",
            Self::InvalidExecutionRequest => "invalid packet-aware role execution request",
            Self::InvalidExecutorOutcome => "invalid independent-review executor outcome",
            Self::InvalidDigest => "independent-review durable digest mismatch",
            Self::Serialization => "independent-review durable serialization failed",
        })
    }
}

impl std::error::Error for IndependentReviewError {}

impl From<IndependentReviewContractError> for IndependentReviewError {
    fn from(_: IndependentReviewContractError) -> Self {
        Self::Contract
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndependentRolePacketV1 {
    Review(Box<ReviewPacketV1>),
    Audit(Box<AuditPacketV1>),
}

impl IndependentRolePacketV1 {
    pub fn digest(&self) -> &str {
        match self {
            Self::Review(packet) => &packet.packet_digest,
            Self::Audit(packet) => &packet.packet_digest,
        }
    }

    pub fn validate(&self) -> Result<(), IndependentReviewError> {
        match self {
            Self::Review(packet) => packet.validate()?,
            Self::Audit(packet) => packet.validate()?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentRoleExecutionRequest {
    pub packet: IndependentRolePacketV1,
    pub role_request: RoleExecutionRequest,
}

#[derive(Serialize)]
struct IndependentExecutionRequestDigestInputV1<'a> {
    packet_digest: &'a str,
    invocation: &'a ovca_types::control_plane::RoleInvocationV1,
    attempt: u32,
}

impl IndependentRoleExecutionRequest {
    pub fn validate(&self) -> Result<(), IndependentReviewError> {
        self.packet.validate()?;
        self.role_request
            .validate()
            .map_err(|_| IndependentReviewError::InvalidExecutionRequest)?;
        if self.role_request.attempt != 1
            || self.role_request.invocation.budget.max_attempts != 1
            || !self
                .role_request
                .invocation
                .authority
                .permission_profile
                .write_keys
                .is_empty()
        {
            return Err(IndependentReviewError::InvalidExecutionRequest);
        }
        let valid = match &self.packet {
            IndependentRolePacketV1::Review(packet) => {
                self.role_request.invocation == packet.reviewer_invocation
                    && self.role_request.invocation.target.role == PrincipalV1::Reviewer
            }
            IndependentRolePacketV1::Audit(packet) => {
                self.role_request.invocation == packet.auditor_invocation
                    && self.role_request.invocation.target.role == PrincipalV1::Auditor
            }
        };
        if !valid {
            return Err(IndependentReviewError::InvalidExecutionRequest);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, IndependentReviewError> {
        self.validate()?;
        domain_digest(
            EXECUTION_REQUEST_DOMAIN,
            &IndependentExecutionRequestDigestInputV1 {
                packet_digest: self.packet.digest(),
                invocation: &self.role_request.invocation,
                attempt: self.role_request.attempt,
            },
        )
    }
}

/// Provider-neutral A05 port. The executor receives the exact packet and the
/// existing write-free role request together; no host capability is present.
pub trait IndependentReviewExecutor {
    fn invoke(
        &self,
        request: IndependentRoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentReviewPhaseV1 {
    Reviewing,
    Auditing,
    ResolvedPass,
    RepairDirected,
    OwnerEscalated,
}

impl IndependentReviewPhaseV1 {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ResolvedPass | Self::RepairDirected | Self::OwnerEscalated
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerEscalationReasonV1 {
    ReviewerOutcomeUnknown,
    AuditorOutcomeUnknown,
    ReviewerExecutionFailed,
    AuditorExecutionFailed,
    VerdictDisagreement,
    RepairBudgetExhausted,
    EvidenceInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndependentReviewResolutionV1 {
    Pass {
        review_result_digest: String,
        audit_result_digest: String,
    },
    Repair {
        directive_digest: String,
        successor_run_id: ovca_types::RunId,
    },
    OwnerEscalation {
        reason: OwnerEscalationReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndependentCallStateV1 {
    NotStarted,
    Started {
        request_digest: String,
        started_at: DateTime<Utc>,
    },
    OutcomeRecorded {
        request_digest: String,
        started_at: DateTime<Utc>,
        outcome: Box<PersistedRoleExecutionOutcomeV1>,
        outcome_digest: String,
        recorded_at: DateTime<Utc>,
    },
}

impl IndependentCallStateV1 {
    fn validate(
        &self,
        request: &IndependentRoleExecutionRequest,
    ) -> Result<(), IndependentReviewError> {
        let expected_digest = request.canonical_digest()?;
        match self {
            Self::NotStarted => Ok(()),
            Self::Started {
                request_digest,
                started_at,
            } => {
                if request_digest != &expected_digest || !is_millisecond_precision(*started_at) {
                    return Err(IndependentReviewError::InvalidState);
                }
                Ok(())
            }
            Self::OutcomeRecorded {
                request_digest,
                started_at,
                outcome,
                outcome_digest,
                recorded_at,
            } => {
                if request_digest != &expected_digest
                    || !is_millisecond_precision(*started_at)
                    || !is_millisecond_precision(*recorded_at)
                    || recorded_at < started_at
                    || outcome
                        .outcome_digest()
                        .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?
                        != *outcome_digest
                {
                    return Err(IndependentReviewError::InvalidState);
                }
                outcome
                    .validate_against(&request.role_request)
                    .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?;
                validate_typed_completed_outcome(&request.packet, outcome)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReviewStateV1 {
    pub contract_version: u32,
    pub phase: IndependentReviewPhaseV1,
    pub review_packet: ReviewPacketV1,
    pub review_call: IndependentCallStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_packet: Option<AuditPacketV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_call: Option<IndependentCallStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_directive: Option<RepairDirectiveV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<IndependentReviewResolutionV1>,
    pub controller_time: DateTime<Utc>,
    pub state_digest: String,
}

#[derive(Serialize)]
struct IndependentReviewStateDigestInputV1<'a> {
    contract_version: u32,
    phase: IndependentReviewPhaseV1,
    review_packet_digest: &'a str,
    review_call: &'a IndependentCallStateV1,
    audit_packet_digest: Option<&'a str>,
    audit_call: &'a Option<IndependentCallStateV1>,
    repair_directive_digest: Option<&'a str>,
    resolution: &'a Option<IndependentReviewResolutionV1>,
    controller_time: DateTime<Utc>,
}

impl IndependentReviewStateV1 {
    pub fn initial(
        review_packet: ReviewPacketV1,
        controller_time: DateTime<Utc>,
    ) -> Result<Self, IndependentReviewError> {
        review_packet.validate()?;
        let mut value = Self {
            contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
            phase: IndependentReviewPhaseV1::Reviewing,
            review_packet,
            review_call: IndependentCallStateV1::NotStarted,
            audit_packet: None,
            audit_call: None,
            repair_directive: None,
            resolution: None,
            controller_time,
            state_digest: String::new(),
        };
        value.refresh_digest()?;
        value.validate_initial_install()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), IndependentReviewError> {
        if self.contract_version != INDEPENDENT_REVIEW_CONTRACT_VERSION
            || !is_millisecond_precision(self.controller_time)
        {
            return Err(IndependentReviewError::InvalidState);
        }
        self.review_packet.validate()?;
        validate_review_evidence_context(&ReviewDecisionValidationContext {
            expected_run_id: &self.review_packet.run_id,
            goal_contract: &self.review_packet.goal_contract,
            completion_evidence: &self.review_packet.completion_evidence,
            evidence_catalog: &self.review_packet.evidence_catalog,
        })
        .map_err(|_| IndependentReviewError::InvalidState)?;
        self.review_call
            .validate(&review_execution_request(&self.review_packet))?;
        match (&self.audit_packet, &self.audit_call) {
            (Some(packet), Some(call)) => {
                packet.validate()?;
                if packet.review_packet != self.review_packet {
                    return Err(IndependentReviewError::InvalidState);
                }
                call.validate(&audit_execution_request(packet))?;
            }
            (None, None) => {}
            _ => return Err(IndependentReviewError::InvalidState),
        }
        if let Some(directive) = &self.repair_directive {
            directive.validate()?;
            if directive.failed_run_id != self.review_packet.run_id
                || directive.root_run_id != self.review_packet.root_run_id
                || directive.goal_id != self.review_packet.goal_id
                || directive.task_id != self.review_packet.task_id
                || directive.failed_candidate_cycle != self.review_packet.candidate_cycle
                || directive.max_repair_cycles != self.review_packet.max_repair_cycles
                || directive.review_packet_digest != self.review_packet.packet_digest
            {
                return Err(IndependentReviewError::InvalidState);
            }
        }
        validate_phase_shape(self)?;
        validate_audit_packet_binding(self)?;
        validate_terminal_semantics(self)?;
        validate_digest(&self.state_digest)?;
        if self.computed_state_digest()? != self.state_digest {
            return Err(IndependentReviewError::InvalidDigest);
        }
        Ok(())
    }

    pub fn validate_initial_install(&self) -> Result<(), IndependentReviewError> {
        self.validate()?;
        if self.phase != IndependentReviewPhaseV1::Reviewing
            || !matches!(self.review_call, IndependentCallStateV1::NotStarted)
            || self.audit_packet.is_some()
            || self.audit_call.is_some()
            || self.repair_directive.is_some()
            || self.resolution.is_some()
        {
            return Err(IndependentReviewError::InvalidTransition);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), IndependentReviewError> {
        self.validate()?;
        next.validate()?;
        if self.phase.is_terminal()
            || self.contract_version != next.contract_version
            || self.review_packet != next.review_packet
            || next.controller_time < self.controller_time
        {
            return Err(IndependentReviewError::InvalidTransition);
        }
        let allowed = match self.phase {
            IndependentReviewPhaseV1::Reviewing => match (&self.review_call, &next.review_call) {
                (IndependentCallStateV1::NotStarted, IndependentCallStateV1::Started { .. }) => {
                    next.phase == self.phase
                        && next.audit_packet.is_none()
                        && next.audit_call.is_none()
                        && next.resolution.is_none()
                }
                (IndependentCallStateV1::NotStarted, after) if after == &self.review_call => {
                    next.phase == IndependentReviewPhaseV1::OwnerEscalated
                        && next.resolution
                            == Some(IndependentReviewResolutionV1::OwnerEscalation {
                                reason: OwnerEscalationReasonV1::EvidenceInvalid,
                            })
                }
                (
                    IndependentCallStateV1::Started { .. },
                    IndependentCallStateV1::OutcomeRecorded { .. },
                ) => {
                    next.phase == self.phase
                        && next.audit_packet.is_none()
                        && next.audit_call.is_none()
                        && next.resolution.is_none()
                }
                (IndependentCallStateV1::OutcomeRecorded { .. }, after)
                    if after == &self.review_call =>
                {
                    (next.phase == IndependentReviewPhaseV1::Auditing
                        && next.audit_packet.is_some()
                        && matches!(next.audit_call, Some(IndependentCallStateV1::NotStarted))
                        && next.resolution.is_none())
                        || (next.phase == IndependentReviewPhaseV1::OwnerEscalated
                            && next.audit_packet.is_none()
                            && next.audit_call.is_none()
                            && matches!(
                                next.resolution,
                                Some(IndependentReviewResolutionV1::OwnerEscalation {
                                    reason: OwnerEscalationReasonV1::ReviewerExecutionFailed
                                        | OwnerEscalationReasonV1::EvidenceInvalid,
                                })
                            ))
                }
                (IndependentCallStateV1::Started { .. }, after) if after == &self.review_call => {
                    next.phase == IndependentReviewPhaseV1::OwnerEscalated
                        && next.resolution
                            == Some(IndependentReviewResolutionV1::OwnerEscalation {
                                reason: OwnerEscalationReasonV1::ReviewerOutcomeUnknown,
                            })
                }
                _ => false,
            },
            IndependentReviewPhaseV1::Auditing => {
                self.review_call == next.review_call
                    && self.audit_packet == next.audit_packet
                    && match (&self.audit_call, &next.audit_call) {
                        (
                            Some(IndependentCallStateV1::NotStarted),
                            Some(IndependentCallStateV1::Started { .. }),
                        ) => next.phase == self.phase && next.resolution.is_none(),
                        (Some(IndependentCallStateV1::NotStarted), after)
                            if after == &self.audit_call =>
                        {
                            next.phase == IndependentReviewPhaseV1::OwnerEscalated
                                && next.resolution
                                    == Some(IndependentReviewResolutionV1::OwnerEscalation {
                                        reason: OwnerEscalationReasonV1::EvidenceInvalid,
                                    })
                        }
                        (
                            Some(IndependentCallStateV1::Started { .. }),
                            Some(IndependentCallStateV1::OutcomeRecorded { .. }),
                        ) => next.phase == self.phase && next.resolution.is_none(),
                        (Some(IndependentCallStateV1::OutcomeRecorded { .. }), after)
                            if after == &self.audit_call =>
                        {
                            next.phase.is_terminal()
                        }
                        (Some(IndependentCallStateV1::Started { .. }), after)
                            if after == &self.audit_call =>
                        {
                            next.phase == IndependentReviewPhaseV1::OwnerEscalated
                                && next.resolution
                                    == Some(IndependentReviewResolutionV1::OwnerEscalation {
                                        reason: OwnerEscalationReasonV1::AuditorOutcomeUnknown,
                                    })
                        }
                        _ => false,
                    }
            }
            IndependentReviewPhaseV1::ResolvedPass
            | IndependentReviewPhaseV1::RepairDirected
            | IndependentReviewPhaseV1::OwnerEscalated => false,
        };
        if !allowed {
            return Err(IndependentReviewError::InvalidTransition);
        }
        Ok(())
    }

    pub fn computed_state_digest(&self) -> Result<String, IndependentReviewError> {
        domain_digest(
            STATE_DOMAIN,
            &IndependentReviewStateDigestInputV1 {
                contract_version: self.contract_version,
                phase: self.phase,
                review_packet_digest: &self.review_packet.packet_digest,
                review_call: &self.review_call,
                audit_packet_digest: self
                    .audit_packet
                    .as_ref()
                    .map(|value| value.packet_digest.as_str()),
                audit_call: &self.audit_call,
                repair_directive_digest: self
                    .repair_directive
                    .as_ref()
                    .map(|value| value.directive_digest.as_str()),
                resolution: &self.resolution,
                controller_time: self.controller_time,
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), IndependentReviewError> {
        self.state_digest = self.computed_state_digest()?;
        self.validate()
    }
}

pub fn review_execution_request(packet: &ReviewPacketV1) -> IndependentRoleExecutionRequest {
    IndependentRoleExecutionRequest {
        packet: IndependentRolePacketV1::Review(Box::new(packet.clone())),
        role_request: RoleExecutionRequest {
            invocation: packet.reviewer_invocation.clone(),
            attempt: 1,
        },
    }
}

pub fn audit_execution_request(packet: &AuditPacketV1) -> IndependentRoleExecutionRequest {
    IndependentRoleExecutionRequest {
        packet: IndependentRolePacketV1::Audit(Box::new(packet.clone())),
        role_request: RoleExecutionRequest {
            invocation: packet.auditor_invocation.clone(),
            attempt: 1,
        },
    }
}

pub fn completed_result(
    call: &IndependentCallStateV1,
) -> Result<&RoleResultV1, IndependentReviewError> {
    let IndependentCallStateV1::OutcomeRecorded { outcome, .. } = call else {
        return Err(IndependentReviewError::InvalidExecutorOutcome);
    };
    let PersistedRoleExecutionOutcomeV1::Completed { result, .. } = outcome.as_ref() else {
        return Err(IndependentReviewError::InvalidExecutorOutcome);
    };
    Ok(result)
}

pub fn typed_review_verdict(
    call: &IndependentCallStateV1,
) -> Result<ReviewVerdict, IndependentReviewError> {
    let result = completed_result(call)?;
    let RoleResultPayloadV1::Reviewer { decision, .. } = &result.payload else {
        return Err(IndependentReviewError::InvalidExecutorOutcome);
    };
    Ok(decision.verdict)
}

pub fn typed_audit_verdict(
    call: &IndependentCallStateV1,
) -> Result<ReviewVerdict, IndependentReviewError> {
    let result = completed_result(call)?;
    let RoleResultPayloadV1::Auditor { decision, .. } = &result.payload else {
        return Err(IndependentReviewError::InvalidExecutorOutcome);
    };
    Ok(decision.verdict)
}

fn validate_typed_completed_outcome(
    packet: &IndependentRolePacketV1,
    outcome: &PersistedRoleExecutionOutcomeV1,
) -> Result<(), IndependentReviewError> {
    let PersistedRoleExecutionOutcomeV1::Completed { result, .. } = outcome else {
        return Ok(());
    };
    if result.state != ControlPlaneState::Completed {
        return Err(IndependentReviewError::InvalidExecutorOutcome);
    }
    let valid = match (packet, &result.payload) {
        (
            IndependentRolePacketV1::Review(packet),
            RoleResultPayloadV1::Reviewer {
                packet_digest,
                decision,
            },
        ) => {
            packet_digest == &packet.packet_digest
                && decision.run_id == packet.run_id
                && decision.goal_id == packet.goal_id
                && decision.producer_role == ovca_types::Role::Reviewer
                && decision_manifest_bindings(&decision.assessments, &packet.evidence_manifest)
                    .is_ok()
        }
        (
            IndependentRolePacketV1::Audit(packet),
            RoleResultPayloadV1::Auditor {
                packet_digest,
                decision,
            },
        ) => {
            packet_digest == &packet.packet_digest
                && decision.run_id == packet.review_packet.run_id
                && decision.goal_id == packet.review_packet.goal_id
                && decision.review_decision_id == packet.review_decision.id
                && decision.producer_role == ovca_types::Role::Auditor
                && decision_manifest_bindings(&decision.assessments, &packet.evidence_manifest)
                    .is_ok()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(IndependentReviewError::InvalidExecutorOutcome)
    }
}

fn decision_manifest_bindings(
    assessments: &[CriterionAssessment],
    manifest: &ovca_types::independent_review::EvidenceManifestV1,
) -> Result<(), IndependentReviewError> {
    for assessment in assessments {
        for evidence_id in &assessment.evidence_refs {
            if !manifest.entries.iter().any(|entry| {
                entry.criterion_kind == assessment.kind
                    && entry.criterion == assessment.criterion
                    && entry.evidence_id == *evidence_id
            }) {
                return Err(IndependentReviewError::InvalidExecutorOutcome);
            }
        }
    }
    Ok(())
}

fn completed_decisions(
    state: &IndependentReviewStateV1,
) -> Result<
    (
        &RoleResultV1,
        &RoleResultV1,
        &ovca_types::ReviewDecision,
        &ovca_types::AuditDecision,
    ),
    IndependentReviewError,
> {
    let review_result = completed_result(&state.review_call)?;
    let audit_result = completed_result(
        state
            .audit_call
            .as_ref()
            .ok_or(IndependentReviewError::InvalidState)?,
    )?;
    let RoleResultPayloadV1::Reviewer {
        decision: review_decision,
        ..
    } = &review_result.payload
    else {
        return Err(IndependentReviewError::InvalidState);
    };
    let RoleResultPayloadV1::Auditor {
        decision: audit_decision,
        ..
    } = &audit_result.payload
    else {
        return Err(IndependentReviewError::InvalidState);
    };
    Ok((review_result, audit_result, review_decision, audit_decision))
}

fn validate_audit_packet_binding(
    state: &IndependentReviewStateV1,
) -> Result<(), IndependentReviewError> {
    let Some(packet) = state.audit_packet.as_ref() else {
        return Ok(());
    };
    let review_result = completed_result(&state.review_call)?;
    let RoleResultPayloadV1::Reviewer { decision, .. } = &review_result.payload else {
        return Err(IndependentReviewError::InvalidState);
    };
    let review_result_digest = review_result
        .canonical_digest()
        .map_err(|_| IndependentReviewError::InvalidState)?;
    if packet.review_result_digest != review_result_digest || packet.review_decision != *decision {
        return Err(IndependentReviewError::InvalidState);
    }
    validate_review_decision(
        &ReviewDecisionValidationContext {
            expected_run_id: &state.review_packet.run_id,
            goal_contract: &state.review_packet.goal_contract,
            completion_evidence: &state.review_packet.completion_evidence,
            evidence_catalog: &state.review_packet.evidence_catalog,
        },
        decision,
    )
    .map_err(|_| IndependentReviewError::InvalidState)?;
    Ok(())
}

fn validated_decisions(
    state: &IndependentReviewStateV1,
) -> Result<(ReviewVerdict, ReviewVerdict, String, String), IndependentReviewError> {
    let (review_result, audit_result, review_decision, audit_decision) =
        completed_decisions(state)?;
    let validated_review = validate_review_decision(
        &ReviewDecisionValidationContext {
            expected_run_id: &state.review_packet.run_id,
            goal_contract: &state.review_packet.goal_contract,
            completion_evidence: &state.review_packet.completion_evidence,
            evidence_catalog: &state.review_packet.evidence_catalog,
        },
        review_decision,
    )
    .map_err(|_| IndependentReviewError::InvalidState)?;
    validate_audit_decision(
        &AuditDecisionValidationContext {
            expected_run_id: &state.review_packet.run_id,
            goal_contract: &state.review_packet.goal_contract,
            completion_evidence: &state.review_packet.completion_evidence,
            evidence_catalog: &state.review_packet.evidence_catalog,
            validated_review_decision: &validated_review,
        },
        audit_decision,
    )
    .map_err(|_| IndependentReviewError::InvalidState)?;
    Ok((
        review_decision.verdict,
        audit_decision.verdict,
        review_result
            .canonical_digest()
            .map_err(|_| IndependentReviewError::InvalidState)?,
        audit_result
            .canonical_digest()
            .map_err(|_| IndependentReviewError::InvalidState)?,
    ))
}

fn expected_unsatisfied_criteria(
    state: &IndependentReviewStateV1,
) -> Result<Vec<UnsatisfiedCriterionV1>, IndependentReviewError> {
    let (_, _, review, audit) = completed_decisions(state)?;
    let mut criteria = review
        .assessments
        .iter()
        .chain(&audit.assessments)
        .filter(|assessment| assessment.verdict == CriterionAssessmentVerdict::Unsatisfied)
        .map(|assessment| UnsatisfiedCriterionV1 {
            kind: assessment.kind,
            criterion: assessment.criterion.clone(),
        })
        .collect::<Vec<_>>();
    criteria.sort();
    criteria.dedup();
    Ok(criteria)
}

fn validate_terminal_semantics(
    state: &IndependentReviewStateV1,
) -> Result<(), IndependentReviewError> {
    match (&state.phase, &state.resolution) {
        (
            IndependentReviewPhaseV1::ResolvedPass,
            Some(IndependentReviewResolutionV1::Pass {
                review_result_digest,
                audit_result_digest,
            }),
        ) => {
            let (review, audit, actual_review_digest, actual_audit_digest) =
                validated_decisions(state)?;
            if (review, audit) != (ReviewVerdict::Pass, ReviewVerdict::Pass)
                || review_result_digest != &actual_review_digest
                || audit_result_digest != &actual_audit_digest
            {
                return Err(IndependentReviewError::InvalidState);
            }
        }
        (
            IndependentReviewPhaseV1::RepairDirected,
            Some(IndependentReviewResolutionV1::Repair { .. }),
        ) => {
            let (review, audit, actual_review_digest, actual_audit_digest) =
                validated_decisions(state)?;
            let directive = state
                .repair_directive
                .as_ref()
                .ok_or(IndependentReviewError::InvalidState)?;
            let audit_packet = state
                .audit_packet
                .as_ref()
                .ok_or(IndependentReviewError::InvalidState)?;
            if (review, audit) != (ReviewVerdict::Fail, ReviewVerdict::Fail)
                || state.review_packet.candidate_cycle >= state.review_packet.max_repair_cycles
                || directive.review_result_digest != actual_review_digest
                || directive.audit_result_digest != actual_audit_digest
                || directive.audit_packet_digest != audit_packet.packet_digest
                || directive.prior_repair_directive_digest
                    != state.review_packet.prior_repair_directive_digest
                || directive.repair_paths != [state.review_packet.frozen_diff.logical_path.clone()]
                || directive.unsatisfied_criteria != expected_unsatisfied_criteria(state)?
            {
                return Err(IndependentReviewError::InvalidState);
            }
        }
        (
            IndependentReviewPhaseV1::OwnerEscalated,
            Some(IndependentReviewResolutionV1::OwnerEscalation { reason }),
        ) => validate_owner_escalation(state, *reason)?,
        (phase, _) if !phase.is_terminal() => {}
        _ => return Err(IndependentReviewError::InvalidState),
    }
    Ok(())
}

fn validate_owner_escalation(
    state: &IndependentReviewStateV1,
    reason: OwnerEscalationReasonV1,
) -> Result<(), IndependentReviewError> {
    let valid = match reason {
        OwnerEscalationReasonV1::ReviewerOutcomeUnknown => {
            state.audit_packet.is_none()
                && matches!(state.review_call, IndependentCallStateV1::Started { .. })
        }
        OwnerEscalationReasonV1::ReviewerExecutionFailed => {
            state.audit_packet.is_none()
                && matches!(
                    state.review_call,
                    IndependentCallStateV1::OutcomeRecorded { .. }
                )
                && completed_result(&state.review_call).is_err()
        }
        OwnerEscalationReasonV1::AuditorOutcomeUnknown => matches!(
            state.audit_call,
            Some(IndependentCallStateV1::Started { .. })
        ),
        OwnerEscalationReasonV1::AuditorExecutionFailed => {
            state.audit_call.as_ref().is_some_and(|call| {
                matches!(call, IndependentCallStateV1::OutcomeRecorded { .. })
                    && completed_result(call).is_err()
            })
        }
        OwnerEscalationReasonV1::VerdictDisagreement => {
            validated_decisions(state).is_ok_and(|(review, audit, _, _)| review != audit)
        }
        OwnerEscalationReasonV1::RepairBudgetExhausted => {
            validated_decisions(state).is_ok_and(|(review, audit, _, _)| {
                (review, audit) == (ReviewVerdict::Fail, ReviewVerdict::Fail)
                    && state.review_packet.candidate_cycle == state.review_packet.max_repair_cycles
            })
        }
        OwnerEscalationReasonV1::EvidenceInvalid => match state.audit_call.as_ref() {
            None => match &state.review_call {
                IndependentCallStateV1::NotStarted => true,
                IndependentCallStateV1::OutcomeRecorded { .. } => {
                    completed_result(&state.review_call).is_ok()
                        && state.audit_packet.is_none()
                        && validate_review_decision(
                            &ReviewDecisionValidationContext {
                                expected_run_id: &state.review_packet.run_id,
                                goal_contract: &state.review_packet.goal_contract,
                                completion_evidence: &state.review_packet.completion_evidence,
                                evidence_catalog: &state.review_packet.evidence_catalog,
                            },
                            match &completed_result(&state.review_call)
                                .map_err(|_| IndependentReviewError::InvalidState)?
                                .payload
                            {
                                RoleResultPayloadV1::Reviewer { decision, .. } => decision,
                                _ => return Err(IndependentReviewError::InvalidState),
                            },
                        )
                        .is_err()
                }
                IndependentCallStateV1::Started { .. } => false,
            },
            Some(IndependentCallStateV1::NotStarted) => true,
            Some(IndependentCallStateV1::OutcomeRecorded { .. }) => {
                validated_decisions(state).is_err()
                    || validated_decisions(state).is_ok_and(|(review, audit, _, _)| {
                        (review, audit) == (ReviewVerdict::Pass, ReviewVerdict::Pass)
                    })
            }
            Some(IndependentCallStateV1::Started { .. }) => false,
        },
    };
    if valid {
        Ok(())
    } else {
        Err(IndependentReviewError::InvalidState)
    }
}

fn validate_phase_shape(state: &IndependentReviewStateV1) -> Result<(), IndependentReviewError> {
    let shape_valid = match state.phase {
        IndependentReviewPhaseV1::Reviewing => {
            state.audit_packet.is_none()
                && state.audit_call.is_none()
                && state.repair_directive.is_none()
                && state.resolution.is_none()
        }
        IndependentReviewPhaseV1::Auditing => {
            matches!(
                state.review_call,
                IndependentCallStateV1::OutcomeRecorded { .. }
            ) && state.audit_packet.is_some()
                && state.audit_call.is_some()
                && state.repair_directive.is_none()
                && state.resolution.is_none()
        }
        IndependentReviewPhaseV1::ResolvedPass => {
            matches!(
                state.review_call,
                IndependentCallStateV1::OutcomeRecorded { .. }
            ) && matches!(
                state.audit_call,
                Some(IndependentCallStateV1::OutcomeRecorded { .. })
            ) && state.repair_directive.is_none()
                && matches!(
                    state.resolution,
                    Some(IndependentReviewResolutionV1::Pass { .. })
                )
        }
        IndependentReviewPhaseV1::RepairDirected => {
            matches!(
                state.review_call,
                IndependentCallStateV1::OutcomeRecorded { .. }
            ) && matches!(
                state.audit_call,
                Some(IndependentCallStateV1::OutcomeRecorded { .. })
            ) && state.repair_directive.is_some()
                && matches!(
                    state.resolution,
                    Some(IndependentReviewResolutionV1::Repair { .. })
                )
        }
        IndependentReviewPhaseV1::OwnerEscalated => {
            state.repair_directive.is_none()
                && matches!(
                    state.resolution,
                    Some(IndependentReviewResolutionV1::OwnerEscalation { .. })
                )
        }
    };
    if !shape_valid {
        return Err(IndependentReviewError::InvalidState);
    }
    if let Some(IndependentReviewResolutionV1::Pass {
        review_result_digest,
        audit_result_digest,
    }) = &state.resolution
    {
        validate_digest(review_result_digest)?;
        validate_digest(audit_result_digest)?;
    }
    if let Some(IndependentReviewResolutionV1::Repair {
        directive_digest,
        successor_run_id,
    }) = &state.resolution
    {
        let directive = state
            .repair_directive
            .as_ref()
            .ok_or(IndependentReviewError::InvalidState)?;
        if directive_digest != &directive.directive_digest
            || successor_run_id != &directive.successor_run_id
        {
            return Err(IndependentReviewError::InvalidState);
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), IndependentReviewError> {
    validate_sha256_digest(value, "digest").map_err(|_| IndependentReviewError::InvalidDigest)
}

fn is_millisecond_precision(value: DateTime<Utc>) -> bool {
    value.timestamp_subsec_nanos() % 1_000_000 == 0
}

fn domain_digest<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<String, IndependentReviewError> {
    let json = serde_json::to_vec(value).map_err(|_| IndependentReviewError::Serialization)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + json.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&json);
    Ok(verification_sha256_hex(&bytes))
}
