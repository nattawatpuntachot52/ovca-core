//! Durable independent Reviewer/Auditor controller for terminal A04 candidates.

use crate::engineer_verifier_loop::validate_terminal_reviewing_projection_chain;
use chrono::{DateTime, TimeZone, Utc};
use ovca_runtime_core::{
    audit_execution_request, review_execution_request, validate_review_evidence_context,
    AuditDecisionValidationContext, DurableExecutionAuthority, DurableExecutionError,
    IndependentCallStateV1, IndependentReviewCasOutcome, IndependentReviewError,
    IndependentReviewExecutor, IndependentReviewPhaseV1, IndependentReviewResolutionV1,
    IndependentReviewStateV1, LoadedExecutionRun, OwnerEscalationReasonV1,
    PersistedRoleExecutionOutcomeV1, ReviewDecisionValidationContext, VerifierExecutionStateV1,
};
use ovca_storage::{
    CompletionAdmissionSnapshot, EvidenceBank, EvidenceKey, LocalVerificationStoreError,
    RunEventLog, RunEventLogError,
};
use ovca_types::control_plane::{RoleInvocationV1, RoleResultPayloadV1};
use ovca_types::foundation::{PrincipalIdentityV1, PrincipalV1};
use ovca_types::independent_review::{
    derive_repair_successor_run_id, AuditPacketV1, EvidenceManifestV1, RepairDirectiveV1,
    ReviewPacketV1, UnsatisfiedCriterionV1, INDEPENDENT_REVIEW_CONTRACT_VERSION,
};
use ovca_types::{
    ContractVersion, CriterionAssessmentVerdict, EventId, ReviewVerdict, Role, RunEvent,
    RunEventPayload,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

pub trait ReviewAuditClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default)]
pub struct SystemReviewAuditClock;

impl ReviewAuditClock for SystemReviewAuditClock {
    fn now(&self) -> DateTime<Utc> {
        Utc.timestamp_millis_opt(Utc::now().timestamp_millis())
            .single()
            .expect("current timestamp is representable")
    }
}

#[derive(Debug, Clone)]
pub struct ReviewAuditLoopInput {
    pub review_packet: ReviewPacketV1,
    pub auditor_invocation: RoleInvocationV1,
    pub audit_manifest: EvidenceManifestV1,
    pub coordinator: PrincipalIdentityV1,
    pub repair_successor_run_id: Option<ovca_types::RunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewAuditLoopOutcome {
    ResolvedPass {
        state_digest: String,
    },
    RepairDirected {
        state_digest: String,
        directive: Box<RepairDirectiveV1>,
    },
    OwnerEscalated {
        state_digest: String,
        reason: OwnerEscalationReasonV1,
    },
    InProgress,
}

enum ReviewAuditStep {
    Continue(LoadedExecutionRun),
    Complete(Box<ReviewAuditLoopOutcome>),
}

fn complete_step(outcome: ReviewAuditLoopOutcome) -> ReviewAuditStep {
    ReviewAuditStep::Complete(Box::new(outcome))
}

#[derive(Debug)]
pub enum ReviewAuditLoopError {
    InvalidInput,
    ProjectionConflict,
    Durable(DurableExecutionError),
    State(IndependentReviewError),
    Storage(LocalVerificationStoreError),
    Events(RunEventLogError),
}

impl fmt::Display for ReviewAuditLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid independent review/audit input",
            Self::ProjectionConflict => "independent review/audit projection conflict",
            Self::Durable(_) => "durable independent review/audit operation failed",
            Self::State(_) => "independent review/audit state validation failed",
            Self::Storage(_) => "independent review/audit evidence operation failed",
            Self::Events(_) => "independent review/audit event projection failed",
        })
    }
}

impl std::error::Error for ReviewAuditLoopError {}

impl From<DurableExecutionError> for ReviewAuditLoopError {
    fn from(value: DurableExecutionError) -> Self {
        Self::Durable(value)
    }
}

impl From<IndependentReviewError> for ReviewAuditLoopError {
    fn from(value: IndependentReviewError) -> Self {
        Self::State(value)
    }
}

impl From<LocalVerificationStoreError> for ReviewAuditLoopError {
    fn from(value: LocalVerificationStoreError) -> Self {
        Self::Storage(value)
    }
}

impl From<RunEventLogError> for ReviewAuditLoopError {
    fn from(value: RunEventLogError) -> Self {
        Self::Events(value)
    }
}

pub struct ReviewAuditLoop {
    log: RunEventLog,
    execution: DurableExecutionAuthority,
    evidence: EvidenceBank,
    clock: Box<dyn ReviewAuditClock>,
}

impl ReviewAuditLoop {
    pub fn try_new(
        root: impl AsRef<Path>,
        clock: Box<dyn ReviewAuditClock>,
    ) -> Result<Self, ReviewAuditLoopError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ReviewAuditLoopError::InvalidInput);
        }
        Ok(Self {
            log: RunEventLog::new(root),
            execution: DurableExecutionAuthority::new(root),
            evidence: EvidenceBank::try_new(root)?,
            clock,
        })
    }

    pub fn execution(&self) -> &DurableExecutionAuthority {
        &self.execution
    }

    pub fn evidence(&self) -> &EvidenceBank {
        &self.evidence
    }

    pub fn log(&self) -> &RunEventLog {
        &self.log
    }

    pub fn drive(
        &self,
        executor: &dyn IndependentReviewExecutor,
        input: &ReviewAuditLoopInput,
    ) -> Result<ReviewAuditLoopOutcome, ReviewAuditLoopError> {
        validate_input(input)?;
        let mut loaded = self.execution.load(&input.review_packet.run_id)?;
        validate_candidate(&loaded, &input.review_packet)?;
        validate_repair_chain(&self.execution, &input.review_packet)?;

        if let Some(existing) = loaded.envelope.independent_review.as_ref() {
            if existing.review_packet != input.review_packet {
                return Err(ReviewAuditLoopError::ProjectionConflict);
            }
        } else {
            let initial =
                IndependentReviewStateV1::initial(input.review_packet.clone(), self.clock.now())?;
            loaded = match self.execution.compare_and_swap_independent_review(
                &input.review_packet.run_id,
                loaded.revision,
                None,
                initial,
            )? {
                IndependentReviewCasOutcome::Applied(value)
                | IndependentReviewCasOutcome::Unchanged(value) => value,
                IndependentReviewCasOutcome::Conflict(_) => {
                    return Ok(ReviewAuditLoopOutcome::InProgress)
                }
            };
        }

        loop {
            match self.resume_step(executor, input, loaded)? {
                ReviewAuditStep::Continue(next) => loaded = next,
                ReviewAuditStep::Complete(outcome) => return Ok(*outcome),
            }
        }
    }

    fn resume_step(
        &self,
        executor: &dyn IndependentReviewExecutor,
        input: &ReviewAuditLoopInput,
        loaded: LoadedExecutionRun,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let state = projection(&loaded)?.clone();
        match state.phase {
            IndependentReviewPhaseV1::ResolvedPass => {
                self.project_passing_pair(&state)?;
                Ok(complete_step(outcome_from_state(&state)?))
            }
            IndependentReviewPhaseV1::RepairDirected => {
                let successor_run_id = state
                    .repair_directive
                    .as_ref()
                    .map(|directive| &directive.successor_run_id)
                    .ok_or(ReviewAuditLoopError::ProjectionConflict)?;
                if input.repair_successor_run_id.as_ref() != Some(successor_run_id) {
                    return Err(ReviewAuditLoopError::ProjectionConflict);
                }
                Ok(complete_step(outcome_from_state(&state)?))
            }
            IndependentReviewPhaseV1::OwnerEscalated => {
                Ok(complete_step(outcome_from_state(&state)?))
            }
            IndependentReviewPhaseV1::Reviewing => match state.review_call {
                IndependentCallStateV1::NotStarted => self.start_review(executor, input, loaded),
                IndependentCallStateV1::Started { .. } => {
                    self.escalate(loaded, OwnerEscalationReasonV1::ReviewerOutcomeUnknown)
                }
                IndependentCallStateV1::OutcomeRecorded { .. } => self.after_review(input, loaded),
            },
            IndependentReviewPhaseV1::Auditing => match state
                .audit_call
                .clone()
                .ok_or(ReviewAuditLoopError::ProjectionConflict)?
            {
                IndependentCallStateV1::NotStarted => self.start_audit(executor, input, loaded),
                IndependentCallStateV1::Started { .. } => {
                    self.escalate(loaded, OwnerEscalationReasonV1::AuditorOutcomeUnknown)
                }
                IndependentCallStateV1::OutcomeRecorded { .. } => self.resolve(input, loaded),
            },
        }
    }

    fn start_review(
        &self,
        executor: &dyn IndependentReviewExecutor,
        input: &ReviewAuditLoopInput,
        loaded: LoadedExecutionRun,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let request = review_execution_request(&input.review_packet);
        let request_digest = request.canonical_digest()?;
        let started_at = self.clock.now();
        let key = evidence_key(&input.review_packet);
        let started = self.evidence.with_completion_admission_lease(
            &[key],
            |snapshot| -> Result<_, ReviewAuditLoopError> {
                validate_current(snapshot, &input.review_packet)?;
                validate_candidate(&loaded, &input.review_packet)?;
                let mut next = projection(&loaded)?.clone();
                next.review_call = IndependentCallStateV1::Started {
                    request_digest: request_digest.clone(),
                    started_at,
                };
                next.controller_time = started_at;
                next.refresh_digest()?;
                cas_replace(&self.execution, loaded.clone(), next)
            },
        );
        let started = match started {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(complete_step(ReviewAuditLoopOutcome::InProgress)),
            Err(ReviewAuditLoopError::Storage(_)) | Err(ReviewAuditLoopError::InvalidInput) => {
                return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid)
            }
            Err(error) => return Err(error),
        };

        let outcome = executor
            .invoke(request.clone())
            .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?;
        let persisted =
            PersistedRoleExecutionOutcomeV1::try_from_live(&outcome, &request.role_request)
                .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?;
        let recorded_at = self.clock.now();
        let mut next = projection(&started)?.clone();
        next.review_call = IndependentCallStateV1::OutcomeRecorded {
            request_digest,
            started_at,
            outcome_digest: persisted
                .outcome_digest()
                .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?,
            outcome: Box::new(persisted),
            recorded_at,
        };
        next.controller_time = recorded_at;
        next.refresh_digest()?;
        let Some(recorded) = cas_replace(&self.execution, started, next)? else {
            return Ok(complete_step(ReviewAuditLoopOutcome::InProgress));
        };
        Ok(ReviewAuditStep::Continue(recorded))
    }

    fn after_review(
        &self,
        input: &ReviewAuditLoopInput,
        loaded: LoadedExecutionRun,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let state = projection(&loaded)?.clone();
        let review_result = match ovca_runtime_core::completed_result(&state.review_call) {
            Ok(result) => result,
            Err(_) => {
                return self.escalate(loaded, OwnerEscalationReasonV1::ReviewerExecutionFailed)
            }
        };
        let RoleResultPayloadV1::Reviewer { decision, .. } = &review_result.payload else {
            return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid);
        };
        if ovca_runtime_core::validate_review_decision(
            &ReviewDecisionValidationContext {
                expected_run_id: &state.review_packet.run_id,
                goal_contract: &state.review_packet.goal_contract,
                completion_evidence: &state.review_packet.completion_evidence,
                evidence_catalog: &state.review_packet.evidence_catalog,
            },
            decision,
        )
        .is_err()
        {
            return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid);
        }
        let review_result_digest = review_result
            .canonical_digest()
            .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
        let mut audit_packet = AuditPacketV1 {
            contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
            packet_id: format!("audit.{review_result_digest}"),
            review_packet: state.review_packet.clone(),
            review_packet_digest: state.review_packet.packet_digest.clone(),
            review_result_digest,
            review_decision: decision.clone(),
            auditor: input.auditor_invocation.target.clone(),
            auditor_invocation: input.auditor_invocation.clone(),
            auditor_invocation_digest: input
                .auditor_invocation
                .canonical_digest()
                .map_err(|_| ReviewAuditLoopError::InvalidInput)?,
            evidence_manifest: input.audit_manifest.clone(),
            packet_digest: String::new(),
        };
        audit_packet
            .refresh_digest()
            .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
        audit_packet
            .validate()
            .map_err(|_| ReviewAuditLoopError::InvalidInput)?;

        let now = self.clock.now();
        let mut next = state;
        next.phase = IndependentReviewPhaseV1::Auditing;
        next.audit_packet = Some(audit_packet);
        next.audit_call = Some(IndependentCallStateV1::NotStarted);
        next.controller_time = now;
        next.refresh_digest()?;
        let Some(auditing) = cas_replace(&self.execution, loaded, next)? else {
            return Ok(complete_step(ReviewAuditLoopOutcome::InProgress));
        };
        Ok(ReviewAuditStep::Continue(auditing))
    }

    fn start_audit(
        &self,
        executor: &dyn IndependentReviewExecutor,
        input: &ReviewAuditLoopInput,
        loaded: LoadedExecutionRun,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let state = projection(&loaded)?.clone();
        let packet = state
            .audit_packet
            .clone()
            .ok_or(ReviewAuditLoopError::ProjectionConflict)?;
        if packet.auditor_invocation != input.auditor_invocation
            || packet.evidence_manifest != input.audit_manifest
        {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        }
        let request = audit_execution_request(&packet);
        let request_digest = request.canonical_digest()?;
        let started_at = self.clock.now();
        let key = evidence_key(&state.review_packet);
        let started = self.evidence.with_completion_admission_lease(
            &[key],
            |snapshot| -> Result<_, ReviewAuditLoopError> {
                validate_current(snapshot, &state.review_packet)?;
                validate_candidate(&loaded, &state.review_packet)?;
                let mut next = state.clone();
                next.audit_call = Some(IndependentCallStateV1::Started {
                    request_digest: request_digest.clone(),
                    started_at,
                });
                next.controller_time = started_at;
                next.refresh_digest()?;
                cas_replace(&self.execution, loaded.clone(), next)
            },
        );
        let started = match started {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(complete_step(ReviewAuditLoopOutcome::InProgress)),
            Err(ReviewAuditLoopError::Storage(_)) | Err(ReviewAuditLoopError::InvalidInput) => {
                return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid)
            }
            Err(error) => return Err(error),
        };
        let outcome = executor
            .invoke(request.clone())
            .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?;
        let persisted =
            PersistedRoleExecutionOutcomeV1::try_from_live(&outcome, &request.role_request)
                .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?;
        let recorded_at = self.clock.now();
        let mut next = projection(&started)?.clone();
        next.audit_call = Some(IndependentCallStateV1::OutcomeRecorded {
            request_digest,
            started_at,
            outcome_digest: persisted
                .outcome_digest()
                .map_err(|_| IndependentReviewError::InvalidExecutorOutcome)?,
            outcome: Box::new(persisted),
            recorded_at,
        });
        next.controller_time = recorded_at;
        next.refresh_digest()?;
        let Some(recorded) = cas_replace(&self.execution, started, next)? else {
            return Ok(complete_step(ReviewAuditLoopOutcome::InProgress));
        };
        Ok(ReviewAuditStep::Continue(recorded))
    }

    fn resolve(
        &self,
        input: &ReviewAuditLoopInput,
        loaded: LoadedExecutionRun,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let state = projection(&loaded)?.clone();
        let review_result = ovca_runtime_core::completed_result(&state.review_call)
            .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?;
        let audit_call = state
            .audit_call
            .as_ref()
            .ok_or(ReviewAuditLoopError::ProjectionConflict)?;
        let audit_result = match ovca_runtime_core::completed_result(audit_call) {
            Ok(result) => result,
            Err(_) => {
                return self.escalate(loaded, OwnerEscalationReasonV1::AuditorExecutionFailed)
            }
        };
        let RoleResultPayloadV1::Reviewer {
            decision: review_decision,
            ..
        } = &review_result.payload
        else {
            return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid);
        };
        let RoleResultPayloadV1::Auditor {
            decision: audit_decision,
            ..
        } = &audit_result.payload
        else {
            return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid);
        };
        let validated_review = match ovca_runtime_core::validate_review_decision(
            &ReviewDecisionValidationContext {
                expected_run_id: &state.review_packet.run_id,
                goal_contract: &state.review_packet.goal_contract,
                completion_evidence: &state.review_packet.completion_evidence,
                evidence_catalog: &state.review_packet.evidence_catalog,
            },
            review_decision,
        ) {
            Ok(value) => value,
            Err(_) => return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid),
        };
        if ovca_runtime_core::validate_audit_decision(
            &AuditDecisionValidationContext {
                expected_run_id: &state.review_packet.run_id,
                goal_contract: &state.review_packet.goal_contract,
                completion_evidence: &state.review_packet.completion_evidence,
                evidence_catalog: &state.review_packet.evidence_catalog,
                validated_review_decision: &validated_review,
            },
            audit_decision,
        )
        .is_err()
        {
            return self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid);
        }

        let review_result_digest = review_result
            .canonical_digest()
            .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
        let audit_result_digest = audit_result
            .canonical_digest()
            .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
        match (review_decision.verdict, audit_decision.verdict) {
            (ReviewVerdict::Pass, ReviewVerdict::Pass) => {
                let now = self.clock.now();
                let key = evidence_key(&state.review_packet);
                let resolved = self.evidence.with_completion_admission_lease(
                    &[key],
                    |snapshot| -> Result<_, ReviewAuditLoopError> {
                        validate_current(snapshot, &state.review_packet)?;
                        validate_candidate(&loaded, &state.review_packet)?;
                        let mut next = state.clone();
                        next.phase = IndependentReviewPhaseV1::ResolvedPass;
                        next.resolution = Some(IndependentReviewResolutionV1::Pass {
                            review_result_digest: review_result_digest.clone(),
                            audit_result_digest: audit_result_digest.clone(),
                        });
                        next.controller_time = now;
                        next.refresh_digest()?;
                        cas_replace(&self.execution, loaded.clone(), next)
                    },
                );
                match resolved {
                    Ok(Some(value)) => {
                        let resolved = projection(&value)?;
                        self.project_passing_pair(resolved)?;
                        Ok(complete_step(outcome_from_state(resolved)?))
                    }
                    Ok(None) => Ok(complete_step(ReviewAuditLoopOutcome::InProgress)),
                    Err(ReviewAuditLoopError::Storage(_))
                    | Err(ReviewAuditLoopError::InvalidInput) => {
                        self.escalate(loaded, OwnerEscalationReasonV1::EvidenceInvalid)
                    }
                    Err(error) => Err(error),
                }
            }
            (ReviewVerdict::Fail, ReviewVerdict::Fail)
                if state.review_packet.candidate_cycle < state.review_packet.max_repair_cycles =>
            {
                let successor_cycle = state
                    .review_packet
                    .candidate_cycle
                    .checked_add(1)
                    .ok_or(ReviewAuditLoopError::InvalidInput)?;
                let expected_successor_run_id = derive_repair_successor_run_id(
                    &state.review_packet.root_run_id,
                    successor_cycle,
                    &review_result_digest,
                    &audit_result_digest,
                )
                .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
                if input.repair_successor_run_id.as_ref() != Some(&expected_successor_run_id) {
                    return Err(ReviewAuditLoopError::InvalidInput);
                }
                let directive = build_directive(
                    &state,
                    review_decision,
                    audit_decision,
                    &review_result_digest,
                    &audit_result_digest,
                    &input.coordinator,
                    expected_successor_run_id,
                )?;
                let now = self.clock.now();
                let mut next = state;
                next.phase = IndependentReviewPhaseV1::RepairDirected;
                next.resolution = Some(IndependentReviewResolutionV1::Repair {
                    directive_digest: directive.directive_digest.clone(),
                    successor_run_id: directive.successor_run_id.clone(),
                });
                next.repair_directive = Some(directive);
                next.controller_time = now;
                next.refresh_digest()?;
                match cas_replace(&self.execution, loaded, next)? {
                    Some(value) => Ok(complete_step(outcome_from_state(projection(&value)?)?)),
                    None => Ok(complete_step(ReviewAuditLoopOutcome::InProgress)),
                }
            }
            (ReviewVerdict::Fail, ReviewVerdict::Fail) => {
                self.escalate(loaded, OwnerEscalationReasonV1::RepairBudgetExhausted)
            }
            _ => self.escalate(loaded, OwnerEscalationReasonV1::VerdictDisagreement),
        }
    }

    fn escalate(
        &self,
        loaded: LoadedExecutionRun,
        reason: OwnerEscalationReasonV1,
    ) -> Result<ReviewAuditStep, ReviewAuditLoopError> {
        let mut next = projection(&loaded)?.clone();
        let prior_phase = next.phase;
        next.phase = IndependentReviewPhaseV1::OwnerEscalated;
        next.audit_packet = match reason {
            OwnerEscalationReasonV1::ReviewerOutcomeUnknown
            | OwnerEscalationReasonV1::ReviewerExecutionFailed
            | OwnerEscalationReasonV1::EvidenceInvalid
                if prior_phase == IndependentReviewPhaseV1::Reviewing =>
            {
                None
            }
            _ => next.audit_packet,
        };
        if next.audit_packet.is_none() {
            next.audit_call = None;
        }
        next.repair_directive = None;
        next.resolution = Some(IndependentReviewResolutionV1::OwnerEscalation { reason });
        next.controller_time = self.clock.now();
        next.refresh_digest()?;
        match cas_replace(&self.execution, loaded, next)? {
            Some(value) => Ok(complete_step(outcome_from_state(projection(&value)?)?)),
            None => Ok(complete_step(ReviewAuditLoopOutcome::InProgress)),
        }
    }

    fn project_passing_pair(
        &self,
        state: &IndependentReviewStateV1,
    ) -> Result<(), ReviewAuditLoopError> {
        let key = evidence_key(&state.review_packet);
        self.evidence.with_completion_admission_lease(
            &[key],
            |snapshot| -> Result<(), ReviewAuditLoopError> {
                validate_current(snapshot, &state.review_packet)?;
                self.project_passing_pair_under_lease(state)
            },
        )
    }

    fn project_passing_pair_under_lease(
        &self,
        state: &IndependentReviewStateV1,
    ) -> Result<(), ReviewAuditLoopError> {
        let review_result = ovca_runtime_core::completed_result(&state.review_call)
            .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?;
        let audit_result = ovca_runtime_core::completed_result(
            state
                .audit_call
                .as_ref()
                .ok_or(ReviewAuditLoopError::ProjectionConflict)?,
        )
        .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?;
        let RoleResultPayloadV1::Reviewer {
            decision: review_decision,
            ..
        } = &review_result.payload
        else {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        };
        let RoleResultPayloadV1::Auditor {
            decision: audit_decision,
            ..
        } = &audit_result.payload
        else {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        };
        let Some(IndependentReviewResolutionV1::Pass {
            review_result_digest,
            audit_result_digest,
        }) = &state.resolution
        else {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        };
        if state.phase != IndependentReviewPhaseV1::ResolvedPass
            || review_decision.verdict != ReviewVerdict::Pass
            || audit_decision.verdict != ReviewVerdict::Pass
            || review_result
                .canonical_digest()
                .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?
                != *review_result_digest
            || audit_result
                .canonical_digest()
                .map_err(|_| ReviewAuditLoopError::ProjectionConflict)?
                != *audit_result_digest
        {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        }

        let review_event_id = EventId::from(format!("a05.review.{review_result_digest}"));
        let audit_event_id = EventId::from(format!("a05.audit.{audit_result_digest}"));
        let mut events = self.load_validated_projection_events(state)?;
        let base_sequence = state.review_packet.run_id.clone();
        let issue6_sequence = self
            .execution
            .load(&base_sequence)?
            .envelope
            .engineer_verifier
            .as_ref()
            .and_then(|issue6| issue6.projected_sequence)
            .ok_or(ReviewAuditLoopError::ProjectionConflict)?;
        let projection = classify_decision_projection(
            &events,
            issue6_sequence,
            review_decision,
            audit_decision,
            &review_event_id,
            &audit_event_id,
        )?;

        if projection == DecisionProjectionState::Absent {
            let event = next_projection_event(
                &events,
                review_event_id.clone(),
                state.review_packet.run_id.clone(),
                review_decision.decided_at,
                Role::Reviewer,
                RunEventPayload::ReviewDecisionRecorded {
                    decision: review_decision.clone(),
                },
            )?;
            self.log.append(&event)?;
            events = self.load_validated_projection_events(state)?;
            if classify_decision_projection(
                &events,
                issue6_sequence,
                review_decision,
                audit_decision,
                &review_event_id,
                &audit_event_id,
            )? != DecisionProjectionState::ReviewOnly
            {
                return Err(ReviewAuditLoopError::ProjectionConflict);
            }
        }

        if classify_decision_projection(
            &events,
            issue6_sequence,
            review_decision,
            audit_decision,
            &review_event_id,
            &audit_event_id,
        )? == DecisionProjectionState::ReviewOnly
        {
            let event = next_projection_event(
                &events,
                audit_event_id.clone(),
                state.review_packet.run_id.clone(),
                audit_decision.decided_at,
                Role::Auditor,
                RunEventPayload::AuditDecisionRecorded {
                    decision: audit_decision.clone(),
                },
            )?;
            self.log.append(&event)?;
            events = self.load_validated_projection_events(state)?;
        }

        if classify_decision_projection(
            &events,
            issue6_sequence,
            review_decision,
            audit_decision,
            &review_event_id,
            &audit_event_id,
        )? != DecisionProjectionState::Complete
        {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        }
        Ok(())
    }

    fn load_validated_projection_events(
        &self,
        state: &IndependentReviewStateV1,
    ) -> Result<Vec<RunEvent>, ReviewAuditLoopError> {
        let loaded = self.execution.load(&state.review_packet.run_id)?;
        validate_candidate(&loaded, &state.review_packet)?;
        if projection(&loaded)? != state {
            return Err(ReviewAuditLoopError::ProjectionConflict);
        }
        let issue6 = loaded
            .envelope
            .engineer_verifier
            .as_ref()
            .ok_or(ReviewAuditLoopError::ProjectionConflict)?;
        validate_terminal_reviewing_projection_chain(&self.log, issue6)
            .map_err(|_| ReviewAuditLoopError::ProjectionConflict)
    }
}

fn next_projection_event(
    events: &[RunEvent],
    id: EventId,
    run_id: ovca_types::RunId,
    occurred_at: DateTime<Utc>,
    producer_role: Role,
    payload: RunEventPayload,
) -> Result<RunEvent, ReviewAuditLoopError> {
    let sequence = u64::try_from(events.len()).map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    Ok(RunEvent {
        contract_version: ContractVersion::current(),
        id,
        run_id,
        sequence,
        previous_event_id: events.last().map(|event| event.id.clone()),
        occurred_at,
        producer_role,
        payload,
        metadata: BTreeMap::new(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionProjectionState {
    Absent,
    ReviewOnly,
    Complete,
}

fn classify_decision_projection(
    events: &[RunEvent],
    issue6_sequence: u64,
    review: &ovca_types::ReviewDecision,
    audit: &ovca_types::AuditDecision,
    review_event_id: &EventId,
    audit_event_id: &EventId,
) -> Result<DecisionProjectionState, ReviewAuditLoopError> {
    let issue6_index =
        usize::try_from(issue6_sequence).map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    if events
        .get(issue6_index)
        .is_none_or(|event| event.run_id != review.run_id)
    {
        return Err(ReviewAuditLoopError::ProjectionConflict);
    }

    let mut review_index = None;
    let mut audit_index = None;
    for (index, event) in events.iter().enumerate().skip(issue6_index + 1) {
        if event.id == *review_event_id {
            let expected = next_projection_event(
                &events[..index],
                review_event_id.clone(),
                review.run_id.clone(),
                review.decided_at,
                Role::Reviewer,
                RunEventPayload::ReviewDecisionRecorded {
                    decision: review.clone(),
                },
            )?;
            if event != &expected || review_index.replace(index).is_some() {
                return Err(ReviewAuditLoopError::ProjectionConflict);
            }
        }
        if event.id == *audit_event_id {
            let expected = next_projection_event(
                &events[..index],
                audit_event_id.clone(),
                audit.run_id.clone(),
                audit.decided_at,
                Role::Auditor,
                RunEventPayload::AuditDecisionRecorded {
                    decision: audit.clone(),
                },
            )?;
            if event != &expected || audit_index.replace(index).is_some() {
                return Err(ReviewAuditLoopError::ProjectionConflict);
            }
        }
        match &event.payload {
            RunEventPayload::ReviewDecisionRecorded { decision } => {
                if decision != review || event.id != *review_event_id {
                    return Err(ReviewAuditLoopError::ProjectionConflict);
                }
            }
            RunEventPayload::AuditDecisionRecorded { decision } => {
                if decision != audit || event.id != *audit_event_id {
                    return Err(ReviewAuditLoopError::ProjectionConflict);
                }
            }
            _ => {}
        }
    }

    match (review_index, audit_index) {
        (None, None) if events.len() == issue6_index + 1 => Ok(DecisionProjectionState::Absent),
        (Some(review_index), None)
            if review_index == issue6_index + 1 && review_index + 1 == events.len() =>
        {
            Ok(DecisionProjectionState::ReviewOnly)
        }
        (Some(review_index), Some(audit_index))
            if review_index == issue6_index + 1 && audit_index == review_index + 1 =>
        {
            Ok(DecisionProjectionState::Complete)
        }
        _ => Err(ReviewAuditLoopError::ProjectionConflict),
    }
}

fn validate_input(input: &ReviewAuditLoopInput) -> Result<(), ReviewAuditLoopError> {
    input
        .review_packet
        .validate()
        .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    validate_review_evidence_context(&ReviewDecisionValidationContext {
        expected_run_id: &input.review_packet.run_id,
        goal_contract: &input.review_packet.goal_contract,
        completion_evidence: &input.review_packet.completion_evidence,
        evidence_catalog: &input.review_packet.evidence_catalog,
    })
    .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    input
        .auditor_invocation
        .validate()
        .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    input
        .coordinator
        .validate()
        .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    if input.coordinator.role != PrincipalV1::Coordinator
        || input.auditor_invocation.target.role != PrincipalV1::Auditor
        || input.auditor_invocation.run_id != input.review_packet.run_id
        || input.auditor_invocation.task_id != input.review_packet.task_id
        || input.auditor_invocation.budget.max_attempts != 1
    {
        return Err(ReviewAuditLoopError::InvalidInput);
    }
    Ok(())
}

fn validate_repair_chain(
    execution: &DurableExecutionAuthority,
    packet: &ReviewPacketV1,
) -> Result<(), ReviewAuditLoopError> {
    if packet.candidate_cycle == 0 {
        return Ok(());
    }
    let prior_run_id = packet
        .prior_run_id
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    let prior = execution.load(prior_run_id)?;
    let prior_state = prior
        .envelope
        .independent_review
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    let directive = prior_state
        .repair_directive
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    if prior_state.phase != IndependentReviewPhaseV1::RepairDirected
        || Some(&directive.directive_digest) != packet.prior_repair_directive_digest.as_ref()
        || directive.successor_run_id != packet.run_id
        || directive.failed_run_id != *prior_run_id
        || directive.root_run_id != packet.root_run_id
        || directive.goal_id != packet.goal_id
        || directive.task_id != packet.task_id
        || directive.successor_candidate_cycle != packet.candidate_cycle
        || directive.max_repair_cycles != packet.max_repair_cycles
    {
        return Err(ReviewAuditLoopError::InvalidInput);
    }
    Ok(())
}

fn validate_candidate(
    loaded: &LoadedExecutionRun,
    packet: &ReviewPacketV1,
) -> Result<(), ReviewAuditLoopError> {
    let issue6 = loaded
        .envelope
        .engineer_verifier
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    let bridge = issue6
        .workspace_bridge
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    let workspace = issue6
        .workspace
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
    let VerifierExecutionStateV1::Admitted { transcript, .. } = issue6
        .verifier
        .as_ref()
        .ok_or(ReviewAuditLoopError::InvalidInput)?
    else {
        return Err(ReviewAuditLoopError::InvalidInput);
    };
    let path = &packet.frozen_diff.logical_path;
    if bridge.changed_paths.len() != 1
        || bridge.changed_paths[0] != *path
        || bridge.before_file_identities.len() != 1
        || bridge.after_file_identities.len() != 1
        || bridge.before_file_identities[0].file != packet.frozen_diff.before_file
        || bridge.after_file_identities[0].file.as_ref() != Some(&packet.frozen_diff.after_file)
        || packet.verifier_receipts != transcript.commands
        || !workspace.grant.write_paths.contains(path)
        || u64::try_from(packet.frozen_diff.after_bytes.len())
            .ok()
            .is_none_or(|length| length > workspace.grant.max_write_bytes)
        || packet
            .frozen_diff
            .before_bytes
            .as_ref()
            .and_then(|bytes| u64::try_from(bytes.len()).ok())
            .is_some_and(|length| length > workspace.grant.max_read_bytes)
    {
        return Err(ReviewAuditLoopError::InvalidInput);
    }
    Ok(())
}

fn validate_current(
    snapshot: &CompletionAdmissionSnapshot,
    packet: &ReviewPacketV1,
) -> Result<(), ReviewAuditLoopError> {
    let [bundle] = snapshot.bundles.as_slice() else {
        return Err(ReviewAuditLoopError::InvalidInput);
    };
    if bundle.current.key != evidence_key(packet)
        || bundle.current.bundle_id != packet.evidence_current.bundle_id
        || bundle.current.record_digest != packet.evidence_current.record_digest
        || bundle.current.token.generation != packet.evidence_current.generation
        || bundle.current.token.state_digest != packet.evidence_current.state_digest
        || bundle.record.digest != packet.verification_bundle_record_digest
        || bundle.record.bundle != packet.verification_bundle
    {
        return Err(ReviewAuditLoopError::InvalidInput);
    }
    Ok(())
}

fn evidence_key(packet: &ReviewPacketV1) -> EvidenceKey {
    EvidenceKey {
        run_id: packet.run_id.clone(),
        goal_id: packet.goal_id.clone(),
        task_id: packet.task_id.clone(),
    }
}

fn build_directive(
    state: &IndependentReviewStateV1,
    review: &ovca_types::ReviewDecision,
    audit: &ovca_types::AuditDecision,
    review_result_digest: &str,
    audit_result_digest: &str,
    coordinator: &PrincipalIdentityV1,
    successor_run_id: ovca_types::RunId,
) -> Result<RepairDirectiveV1, ReviewAuditLoopError> {
    let successor_cycle = state
        .review_packet
        .candidate_cycle
        .checked_add(1)
        .ok_or(ReviewAuditLoopError::InvalidInput)?;
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
    if criteria.is_empty() {
        return Err(ReviewAuditLoopError::InvalidInput);
    }
    let mut directive = RepairDirectiveV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        directive_id: format!("repair-directive.{successor_cycle}.{review_result_digest}"),
        root_run_id: state.review_packet.root_run_id.clone(),
        failed_run_id: state.review_packet.run_id.clone(),
        successor_run_id,
        goal_id: state.review_packet.goal_id.clone(),
        task_id: state.review_packet.task_id.clone(),
        failed_candidate_cycle: state.review_packet.candidate_cycle,
        successor_candidate_cycle: successor_cycle,
        max_repair_cycles: state.review_packet.max_repair_cycles,
        prior_repair_directive_digest: state.review_packet.prior_repair_directive_digest.clone(),
        review_packet_digest: state.review_packet.packet_digest.clone(),
        review_result_digest: review_result_digest.to_owned(),
        audit_packet_digest: state
            .audit_packet
            .as_ref()
            .ok_or(ReviewAuditLoopError::InvalidInput)?
            .packet_digest
            .clone(),
        audit_result_digest: audit_result_digest.to_owned(),
        repair_paths: vec![state.review_packet.frozen_diff.logical_path.clone()],
        unsatisfied_criteria: criteria,
        routed_by: coordinator.clone(),
        grants_authority: false,
        directive_digest: String::new(),
    };
    directive
        .refresh_digest()
        .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    directive
        .validate()
        .map_err(|_| ReviewAuditLoopError::InvalidInput)?;
    Ok(directive)
}

fn projection(
    loaded: &LoadedExecutionRun,
) -> Result<&IndependentReviewStateV1, ReviewAuditLoopError> {
    loaded
        .envelope
        .independent_review
        .as_deref()
        .ok_or(ReviewAuditLoopError::ProjectionConflict)
}

fn cas_replace(
    execution: &DurableExecutionAuthority,
    loaded: LoadedExecutionRun,
    next: IndependentReviewStateV1,
) -> Result<Option<LoadedExecutionRun>, ReviewAuditLoopError> {
    let prior_digest = projection(&loaded)?.state_digest.clone();
    let run_id = next.review_packet.run_id.clone();
    match execution.compare_and_swap_independent_review(
        &run_id,
        loaded.revision,
        Some(&prior_digest),
        next,
    )? {
        IndependentReviewCasOutcome::Applied(value)
        | IndependentReviewCasOutcome::Unchanged(value) => Ok(Some(value)),
        IndependentReviewCasOutcome::Conflict(_) => Ok(None),
    }
}

fn outcome_from_state(
    state: &IndependentReviewStateV1,
) -> Result<ReviewAuditLoopOutcome, ReviewAuditLoopError> {
    match (&state.phase, &state.resolution) {
        (
            IndependentReviewPhaseV1::ResolvedPass,
            Some(IndependentReviewResolutionV1::Pass { .. }),
        ) => Ok(ReviewAuditLoopOutcome::ResolvedPass {
            state_digest: state.state_digest.clone(),
        }),
        (
            IndependentReviewPhaseV1::RepairDirected,
            Some(IndependentReviewResolutionV1::Repair { .. }),
        ) => Ok(ReviewAuditLoopOutcome::RepairDirected {
            state_digest: state.state_digest.clone(),
            directive: Box::new(
                state
                    .repair_directive
                    .clone()
                    .ok_or(ReviewAuditLoopError::ProjectionConflict)?,
            ),
        }),
        (
            IndependentReviewPhaseV1::OwnerEscalated,
            Some(IndependentReviewResolutionV1::OwnerEscalation { reason }),
        ) => Ok(ReviewAuditLoopOutcome::OwnerEscalated {
            state_digest: state.state_digest.clone(),
            reason: *reason,
        }),
        _ => Err(ReviewAuditLoopError::ProjectionConflict),
    }
}
