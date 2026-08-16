//! Additive V1 contracts for the provider-independent four-role control plane.
//!
//! These types perform deterministic validation only. They do not authenticate
//! principals, resolve current authority, schedule work, persist events, or call
//! providers.

use crate::foundation::{
    validate_sha256_digest, validate_stable_id, FoundationAuthorityV1, FoundationDomainV1,
    FoundationEventEnvelopeV1, FoundationNamespaceV1, FoundationScopeV1, FoundationValidationError,
    FoundationValidityStatusV1, PrincipalIdentityV1, PrincipalV1,
};
use crate::goal_runtime::{
    verification_sha256_hex, ContractVersion, CoordinatorFinalResponse, EvidenceId, IdempotencyKey,
    RetryBudget, Role, RunId, SpecialistOutput, TaskId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const CONTROL_PLANE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlPlaneValidationError {
    #[error("unsupported control-plane contract version in {0}")]
    UnsupportedContractVersion(&'static str),
    #[error(transparent)]
    Foundation(#[from] FoundationValidationError),
    #[error("execution budget must allow at least one attempt")]
    InvalidExecutionBudget,
    #[error("invoker-target role pair is not allowed")]
    InvalidRolePair,
    #[error("invoker and target must be different principals")]
    SelfInvocation,
    #[error("invocation requires an exact project/goal/task/run scope binding")]
    InvalidScopeBinding,
    #[error("embedded authority is not valid for this invocation")]
    InvalidAuthorityBinding,
    #[error("canonical digest does not match {0}")]
    DigestMismatch(&'static str),
    #[error("text in {0} is not canonical bounded text")]
    InvalidText(&'static str),
    #[error("result is not bound to the invocation")]
    InvalidResultBinding,
    #[error("result state and payload are inconsistent")]
    InvalidResultPayload,
    #[error("evidence identifiers are not canonical for this result")]
    InvalidEvidence,
    #[error("control-plane event envelope and payload are inconsistent")]
    InvalidEventEnvelope,
    #[error("control-plane event chain is not contiguous")]
    InvalidEventChain,
    #[error("control-plane state transition is not allowed")]
    InvalidTransition,
    #[error("attempt ordinal is not valid for the invocation budget")]
    InvalidAttempt,
    #[error("event or result timestamp violates deterministic replay order")]
    InvalidTimestamp,
    #[error("terminal event requires exactly one matching result")]
    MissingTerminalResult,
    #[error("a result exists without its matching terminal event")]
    UnexpectedResult,
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBudget {
    pub contract_version: u32,
    pub max_attempts: u32,
}

impl ExecutionBudget {
    pub fn validate(&self) -> Result<(), ControlPlaneValidationError> {
        validate_version(self.contract_version, "ExecutionBudget")?;
        if self.max_attempts == 0 {
            return Err(ControlPlaneValidationError::InvalidExecutionBudget);
        }
        Ok(())
    }
}

impl TryFrom<&RetryBudget> for ExecutionBudget {
    type Error = ControlPlaneValidationError;

    fn try_from(value: &RetryBudget) -> Result<Self, Self::Error> {
        if value.contract_version != ContractVersion::current() {
            return Err(ControlPlaneValidationError::UnsupportedContractVersion(
                "RetryBudget",
            ));
        }
        let budget = Self {
            contract_version: CONTROL_PLANE_CONTRACT_VERSION,
            max_attempts: value.max_attempts,
        };
        budget.validate()?;
        Ok(budget)
    }
}

impl TryFrom<&ExecutionBudget> for RetryBudget {
    type Error = ControlPlaneValidationError;

    fn try_from(value: &ExecutionBudget) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            contract_version: ContractVersion::current(),
            max_attempts: value.max_attempts,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleInvocationV1 {
    pub contract_version: u32,
    pub invocation_id: String,
    pub invoker: PrincipalIdentityV1,
    pub target: PrincipalIdentityV1,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub scope: FoundationScopeV1,
    pub budget: ExecutionBudget,
    pub idempotency_key: IdempotencyKey,
    pub authority: FoundationAuthorityV1,
    pub authority_digest: String,
    pub input_digest: String,
    pub invoked_at: DateTime<Utc>,
}

impl RoleInvocationV1 {
    pub fn validate(&self) -> Result<(), ControlPlaneValidationError> {
        validate_version(self.contract_version, "RoleInvocationV1")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        self.invoker.validate()?;
        self.target.validate()?;
        validate_stable_id(self.task_id.as_str(), "task_id")?;
        validate_stable_id(self.run_id.as_str(), "run_id")?;
        validate_stable_id(self.idempotency_key.as_str(), "idempotency_key")?;
        validate_sha256_digest(&self.authority_digest, "authority_digest")?;
        validate_sha256_digest(&self.input_digest, "input_digest")?;
        self.budget.validate()?;
        validate_role_pair(&self.invoker, &self.target)?;
        validate_full_scope(&self.scope, &self.task_id, &self.run_id)?;

        self.authority.validate()?;
        if self.authority.namespace != FoundationNamespaceV1::CodeReview
            || self.authority.principal != self.invoker
            || self.authority.scope != self.scope
            || self.authority.validity.status != FoundationValidityStatusV1::Active
            || self.invoked_at < self.authority.validity.valid_from
            || self
                .authority
                .validity
                .valid_until
                .is_some_and(|until| self.invoked_at >= until)
        {
            return Err(ControlPlaneValidationError::InvalidAuthorityBinding);
        }
        if canonical_authority_digest(&self.authority)? != self.authority_digest {
            return Err(ControlPlaneValidationError::DigestMismatch(
                "authority_digest",
            ));
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ControlPlaneValidationError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ControlPlaneValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }
}

pub fn canonical_authority_digest(
    authority: &FoundationAuthorityV1,
) -> Result<String, ControlPlaneValidationError> {
    authority.validate()?;
    Ok(verification_sha256_hex(&canonical_json_bytes(authority)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ControlPlaneState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoleResultPayloadV1 {
    Specialist { summary: String },
    OwnerFinal { response: String },
    Failure { code: String, message: String },
    Cancellation { reason: String },
}

impl RoleResultPayloadV1 {
    fn validate(&self) -> Result<(), ControlPlaneValidationError> {
        match self {
            Self::Specialist { summary } => validate_text(summary, "summary"),
            Self::OwnerFinal { response } => validate_text(response, "response"),
            Self::Failure { code, message } => {
                validate_stable_id(code, "failure.code")?;
                validate_text(message, "message")
            }
            Self::Cancellation { reason } => validate_text(reason, "reason"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleResultV1 {
    pub contract_version: u32,
    pub result_id: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub producer: PrincipalIdentityV1,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub scope: FoundationScopeV1,
    pub idempotency_key: IdempotencyKey,
    pub attempt: u32,
    pub state: ControlPlaneState,
    pub payload: RoleResultPayloadV1,
    pub evidence_ids: Vec<EvidenceId>,
    pub occurred_at: DateTime<Utc>,
}

impl RoleResultV1 {
    pub fn validate_against(
        &self,
        invocation: &RoleInvocationV1,
    ) -> Result<(), ControlPlaneValidationError> {
        invocation.validate()?;
        self.validate_shape()?;
        if self.invocation_id != invocation.invocation_id
            || self.invocation_digest != invocation.canonical_digest()?
            || self.producer != invocation.target
            || self.task_id != invocation.task_id
            || self.run_id != invocation.run_id
            || self.scope != invocation.scope
            || self.idempotency_key != invocation.idempotency_key
        {
            return Err(ControlPlaneValidationError::InvalidResultBinding);
        }
        if self.attempt == 0 || self.attempt > invocation.budget.max_attempts {
            return Err(ControlPlaneValidationError::InvalidAttempt);
        }
        if self.occurred_at < invocation.invoked_at {
            return Err(ControlPlaneValidationError::InvalidTimestamp);
        }
        validate_result_payload(self.state, self.producer.role, &self.payload)?;
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ControlPlaneValidationError> {
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ControlPlaneValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }

    fn validate_shape(&self) -> Result<(), ControlPlaneValidationError> {
        validate_version(self.contract_version, "RoleResultV1")?;
        validate_stable_id(&self.result_id, "result_id")?;
        validate_stable_id(&self.invocation_id, "invocation_id")?;
        validate_sha256_digest(&self.invocation_digest, "invocation_digest")?;
        self.producer.validate()?;
        validate_stable_id(self.task_id.as_str(), "task_id")?;
        validate_stable_id(self.run_id.as_str(), "run_id")?;
        self.scope.validate()?;
        validate_stable_id(self.idempotency_key.as_str(), "idempotency_key")?;
        if self.attempt == 0 || !self.state.is_terminal() {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        }
        self.payload.validate()?;
        validate_evidence(
            &self.evidence_ids,
            self.state == ControlPlaneState::Completed,
        )
    }
}

impl TryFrom<&RoleResultV1> for CoordinatorFinalResponse {
    type Error = ControlPlaneValidationError;

    fn try_from(value: &RoleResultV1) -> Result<Self, Self::Error> {
        value.validate_shape()?;
        let RoleResultPayloadV1::OwnerFinal { response } = &value.payload else {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        };
        if value.state != ControlPlaneState::Completed
            || value.producer.role != PrincipalV1::Coordinator
        {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        }
        Ok(Self {
            contract_version: ContractVersion::current(),
            response: response.clone(),
            evidence_refs: value.evidence_ids.clone(),
        })
    }
}

impl TryFrom<&RoleResultV1> for SpecialistOutput {
    type Error = ControlPlaneValidationError;

    fn try_from(value: &RoleResultV1) -> Result<Self, Self::Error> {
        value.validate_shape()?;
        let RoleResultPayloadV1::Specialist { summary } = &value.payload else {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        };
        if value.state != ControlPlaneState::Completed {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        }
        let specialist_role = Role::try_from(value.producer.role)?;
        if specialist_role == Role::Coordinator {
            return Err(ControlPlaneValidationError::InvalidResultPayload);
        }
        Ok(Self {
            contract_version: ContractVersion::current(),
            task_id: value.task_id.clone(),
            specialist_role,
            summary: summary.clone(),
            evidence_refs: value.evidence_ids.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlPlaneEventPayload {
    InvocationSubmitted {
        invocation_id: String,
        invocation_digest: String,
    },
    AttemptStarted {
        invocation_id: String,
        invocation_digest: String,
        attempt: u32,
    },
    RetryScheduled {
        invocation_id: String,
        invocation_digest: String,
        completed_attempt: u32,
        next_attempt: u32,
    },
    InvocationCompleted {
        invocation_id: String,
        invocation_digest: String,
        attempt: u32,
        result_id: String,
        result_digest: String,
    },
    InvocationFailed {
        invocation_id: String,
        invocation_digest: String,
        attempt: u32,
        result_id: String,
        result_digest: String,
    },
    InvocationCancelled {
        invocation_id: String,
        invocation_digest: String,
        attempt: u32,
        result_id: String,
        result_digest: String,
    },
}

impl ControlPlaneEventPayload {
    pub const fn event_kind(&self) -> &'static str {
        match self {
            Self::InvocationSubmitted { .. } => "control.invocation_submitted",
            Self::AttemptStarted { .. } => "control.attempt_started",
            Self::RetryScheduled { .. } => "control.retry_scheduled",
            Self::InvocationCompleted { .. } => "control.invocation_completed",
            Self::InvocationFailed { .. } => "control.invocation_failed",
            Self::InvocationCancelled { .. } => "control.invocation_cancelled",
        }
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ControlPlaneValidationError> {
        self.validate_shape()?;
        canonical_json_bytes(self)
    }

    pub fn canonical_digest(&self) -> Result<String, ControlPlaneValidationError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }

    fn invocation_binding(&self) -> (&str, &str) {
        match self {
            Self::InvocationSubmitted {
                invocation_id,
                invocation_digest,
            }
            | Self::AttemptStarted {
                invocation_id,
                invocation_digest,
                ..
            }
            | Self::RetryScheduled {
                invocation_id,
                invocation_digest,
                ..
            }
            | Self::InvocationCompleted {
                invocation_id,
                invocation_digest,
                ..
            }
            | Self::InvocationFailed {
                invocation_id,
                invocation_digest,
                ..
            }
            | Self::InvocationCancelled {
                invocation_id,
                invocation_digest,
                ..
            } => (invocation_id, invocation_digest),
        }
    }

    fn validate_shape(&self) -> Result<(), ControlPlaneValidationError> {
        let (invocation_id, invocation_digest) = self.invocation_binding();
        validate_stable_id(invocation_id, "event.invocation_id")?;
        validate_sha256_digest(invocation_digest, "event.invocation_digest")?;
        match self {
            Self::InvocationSubmitted { .. } => {}
            Self::AttemptStarted { attempt, .. } => validate_nonzero_attempt(*attempt)?,
            Self::RetryScheduled {
                completed_attempt,
                next_attempt,
                ..
            } => {
                validate_nonzero_attempt(*completed_attempt)?;
                validate_nonzero_attempt(*next_attempt)?;
            }
            Self::InvocationCompleted {
                attempt,
                result_id,
                result_digest,
                ..
            }
            | Self::InvocationFailed {
                attempt,
                result_id,
                result_digest,
                ..
            }
            | Self::InvocationCancelled {
                attempt,
                result_id,
                result_digest,
                ..
            } => {
                validate_nonzero_attempt(*attempt)?;
                validate_stable_id(result_id, "event.result_id")?;
                validate_sha256_digest(result_digest, "event.result_digest")?;
            }
        }
        Ok(())
    }

    fn attempts_within_budget(&self, max_attempts: u32) -> bool {
        match self {
            Self::InvocationSubmitted { .. } => true,
            Self::AttemptStarted { attempt, .. }
            | Self::InvocationCompleted { attempt, .. }
            | Self::InvocationFailed { attempt, .. }
            | Self::InvocationCancelled { attempt, .. } => *attempt <= max_attempts,
            Self::RetryScheduled {
                completed_attempt,
                next_attempt,
                ..
            } => *completed_attempt <= max_attempts && *next_attempt <= max_attempts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneEvent {
    pub contract_version: u32,
    pub envelope: FoundationEventEnvelopeV1,
    pub payload: ControlPlaneEventPayload,
}

impl ControlPlaneEvent {
    pub fn validate_against(
        &self,
        invocation: &RoleInvocationV1,
    ) -> Result<(), ControlPlaneValidationError> {
        invocation.validate()?;
        validate_version(self.contract_version, "ControlPlaneEvent")?;
        self.envelope.validate()?;
        self.payload.validate_shape()?;
        let (invocation_id, invocation_digest) = self.payload.invocation_binding();
        if self.envelope.domain != FoundationDomainV1::ControlPlane
            || self.envelope.event_kind != self.payload.event_kind()
            || self.envelope.scope != invocation.scope
            || self.envelope.payload_digest != self.payload.canonical_digest()?
            || invocation_id != invocation.invocation_id
            || invocation_digest != invocation.canonical_digest()?
        {
            return Err(ControlPlaneValidationError::InvalidEventEnvelope);
        }
        if !self
            .payload
            .attempts_within_budget(invocation.budget.max_attempts)
        {
            return Err(ControlPlaneValidationError::InvalidAttempt);
        }
        let expected_producer = if matches!(
            self.payload,
            ControlPlaneEventPayload::InvocationSubmitted { .. }
        ) {
            &invocation.invoker
        } else {
            &invocation.target
        };
        if &self.envelope.producer != expected_producer {
            return Err(ControlPlaneValidationError::InvalidEventEnvelope);
        }
        if self.envelope.occurred_at < invocation.invoked_at {
            return Err(ControlPlaneValidationError::InvalidTimestamp);
        }
        Ok(())
    }
}

/// Validates an immutable invocation's complete or in-progress event replay.
///
/// Results are accepted only when exactly one terminal event binds them. The
/// returned state is derived exclusively from the validated event sequence.
pub fn validate_control_plane_replay(
    invocation: &RoleInvocationV1,
    events: &[ControlPlaneEvent],
    results: &[RoleResultV1],
) -> Result<ControlPlaneState, ControlPlaneValidationError> {
    invocation.validate()?;
    if events.is_empty() {
        return Err(ControlPlaneValidationError::InvalidEventChain);
    }

    let mut result_ids = BTreeSet::new();
    for result in results {
        validate_stable_id(&result.result_id, "result_id")?;
        if !result_ids.insert(result.result_id.as_str()) {
            return Err(ControlPlaneValidationError::UnexpectedResult);
        }
    }

    let mut state: Option<ControlPlaneState> = None;
    let mut current_attempt = 1_u32;
    let mut terminal_result_used = false;
    let mut previous: Option<&ControlPlaneEvent> = None;
    let mut event_ids = BTreeSet::new();

    for event in events {
        event.validate_against(invocation)?;
        if !event_ids.insert(event.envelope.event_id.as_str()) {
            return Err(ControlPlaneValidationError::InvalidEventChain);
        }
        match previous {
            None => {
                if event.envelope.sequence != 0 || event.envelope.previous_event_id.is_some() {
                    return Err(ControlPlaneValidationError::InvalidEventChain);
                }
            }
            Some(previous_event) => {
                if previous_event.envelope.sequence.checked_add(1) != Some(event.envelope.sequence)
                    || event.envelope.previous_event_id.as_deref()
                        != Some(previous_event.envelope.event_id.as_str())
                {
                    return Err(ControlPlaneValidationError::InvalidEventChain);
                }
                if event.envelope.occurred_at < previous_event.envelope.occurred_at {
                    return Err(ControlPlaneValidationError::InvalidTimestamp);
                }
            }
        }

        state = Some(match (state, &event.payload) {
            (None, ControlPlaneEventPayload::InvocationSubmitted { .. }) => {
                current_attempt = 1;
                ControlPlaneState::Pending
            }
            (
                Some(ControlPlaneState::Pending),
                ControlPlaneEventPayload::AttemptStarted { attempt, .. },
            ) if *attempt == current_attempt && *attempt <= invocation.budget.max_attempts => {
                ControlPlaneState::Running
            }
            (
                Some(ControlPlaneState::Running),
                ControlPlaneEventPayload::RetryScheduled {
                    completed_attempt,
                    next_attempt,
                    ..
                },
            ) if *completed_attempt == current_attempt
                && completed_attempt.checked_add(1) == Some(*next_attempt)
                && *next_attempt <= invocation.budget.max_attempts =>
            {
                current_attempt = *next_attempt;
                ControlPlaneState::Pending
            }
            (
                Some(ControlPlaneState::Running),
                ControlPlaneEventPayload::InvocationCompleted { attempt, .. },
            ) if *attempt == current_attempt => {
                validate_terminal_result(
                    invocation,
                    event,
                    results,
                    ControlPlaneState::Completed,
                    &mut terminal_result_used,
                )?;
                ControlPlaneState::Completed
            }
            (
                Some(ControlPlaneState::Running),
                ControlPlaneEventPayload::InvocationFailed { attempt, .. },
            ) if *attempt == current_attempt => {
                validate_terminal_result(
                    invocation,
                    event,
                    results,
                    ControlPlaneState::Failed,
                    &mut terminal_result_used,
                )?;
                ControlPlaneState::Failed
            }
            (
                Some(ControlPlaneState::Pending | ControlPlaneState::Running),
                ControlPlaneEventPayload::InvocationCancelled { attempt, .. },
            ) if *attempt == current_attempt => {
                validate_terminal_result(
                    invocation,
                    event,
                    results,
                    ControlPlaneState::Cancelled,
                    &mut terminal_result_used,
                )?;
                ControlPlaneState::Cancelled
            }
            _ => return Err(ControlPlaneValidationError::InvalidTransition),
        });
        previous = Some(event);
    }

    let final_state = state.ok_or(ControlPlaneValidationError::InvalidEventChain)?;
    if terminal_result_used == results.is_empty() || results.len() > 1 {
        return Err(ControlPlaneValidationError::UnexpectedResult);
    }
    Ok(final_state)
}

fn validate_terminal_result(
    invocation: &RoleInvocationV1,
    event: &ControlPlaneEvent,
    results: &[RoleResultV1],
    expected_state: ControlPlaneState,
    used: &mut bool,
) -> Result<(), ControlPlaneValidationError> {
    if *used || results.len() != 1 {
        return Err(ControlPlaneValidationError::MissingTerminalResult);
    }
    let (event_attempt, result_id, result_digest) = match &event.payload {
        ControlPlaneEventPayload::InvocationCompleted {
            attempt,
            result_id,
            result_digest,
            ..
        }
        | ControlPlaneEventPayload::InvocationFailed {
            attempt,
            result_id,
            result_digest,
            ..
        }
        | ControlPlaneEventPayload::InvocationCancelled {
            attempt,
            result_id,
            result_digest,
            ..
        } => (*attempt, result_id, result_digest),
        _ => return Err(ControlPlaneValidationError::MissingTerminalResult),
    };
    let result = &results[0];
    result.validate_against(invocation)?;
    if result.state != expected_state
        || result.attempt != event_attempt
        || &result.result_id != result_id
        || &result.canonical_digest()? != result_digest
    {
        return Err(ControlPlaneValidationError::InvalidResultBinding);
    }
    if result.occurred_at > event.envelope.occurred_at {
        return Err(ControlPlaneValidationError::InvalidTimestamp);
    }
    *used = true;
    Ok(())
}

fn validate_result_payload(
    state: ControlPlaneState,
    producer: PrincipalV1,
    payload: &RoleResultPayloadV1,
) -> Result<(), ControlPlaneValidationError> {
    let allowed = matches!(
        (state, producer, payload),
        (
            ControlPlaneState::Completed,
            PrincipalV1::Coordinator,
            RoleResultPayloadV1::OwnerFinal { .. },
        ) | (
            ControlPlaneState::Completed,
            PrincipalV1::Engineer | PrincipalV1::Reviewer | PrincipalV1::Auditor,
            RoleResultPayloadV1::Specialist { .. },
        ) | (
            ControlPlaneState::Failed,
            _,
            RoleResultPayloadV1::Failure { .. }
        ) | (
            ControlPlaneState::Cancelled,
            _,
            RoleResultPayloadV1::Cancellation { .. }
        )
    );
    if allowed {
        Ok(())
    } else {
        Err(ControlPlaneValidationError::InvalidResultPayload)
    }
}

fn validate_role_pair(
    invoker: &PrincipalIdentityV1,
    target: &PrincipalIdentityV1,
) -> Result<(), ControlPlaneValidationError> {
    if invoker.principal_id == target.principal_id {
        return Err(ControlPlaneValidationError::SelfInvocation);
    }
    let allowed = matches!(
        (invoker.role, target.role),
        (PrincipalV1::Owner, PrincipalV1::Coordinator)
            | (PrincipalV1::Coordinator, PrincipalV1::Engineer)
            | (PrincipalV1::Coordinator, PrincipalV1::Reviewer)
            | (PrincipalV1::Coordinator, PrincipalV1::Auditor)
    );
    if allowed {
        Ok(())
    } else {
        Err(ControlPlaneValidationError::InvalidRolePair)
    }
}

fn validate_full_scope(
    scope: &FoundationScopeV1,
    task_id: &TaskId,
    run_id: &RunId,
) -> Result<(), ControlPlaneValidationError> {
    scope.validate()?;
    if scope.goal_id.is_none()
        || scope.task_id.as_deref() != Some(task_id.as_str())
        || scope.run_id.as_deref() != Some(run_id.as_str())
    {
        return Err(ControlPlaneValidationError::InvalidScopeBinding);
    }
    Ok(())
}

fn validate_evidence(
    evidence_ids: &[EvidenceId],
    required: bool,
) -> Result<(), ControlPlaneValidationError> {
    if required && evidence_ids.is_empty() {
        return Err(ControlPlaneValidationError::InvalidEvidence);
    }
    for evidence_id in evidence_ids {
        validate_stable_id(evidence_id.as_str(), "evidence_id")?;
    }
    if evidence_ids
        .windows(2)
        .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
    {
        return Err(ControlPlaneValidationError::InvalidEvidence);
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ControlPlaneValidationError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(ControlPlaneValidationError::InvalidText(field));
    }
    Ok(())
}

fn validate_nonzero_attempt(attempt: u32) -> Result<(), ControlPlaneValidationError> {
    if attempt == 0 {
        Err(ControlPlaneValidationError::InvalidAttempt)
    } else {
        Ok(())
    }
}

fn validate_version(value: u32, contract: &'static str) -> Result<(), ControlPlaneValidationError> {
    if value == CONTROL_PLANE_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ControlPlaneValidationError::UnsupportedContractVersion(
            contract,
        ))
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ControlPlaneValidationError> {
    serde_json::to_vec(value)
        .map_err(|error| ControlPlaneValidationError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        FoundationPermissionProfileV1, FoundationSensitivityV1, FoundationValidityV1,
        FoundationVisibilityV1,
    };
    use crate::goal_runtime::RiskTier;
    use chrono::TimeZone;
    use serde_json::json;

    fn timestamp(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 16, 10, minute, 0)
            .single()
            .unwrap()
    }

    fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
        PrincipalIdentityV1 {
            principal_id: id.to_owned(),
            role,
        }
    }

    fn scope() -> FoundationScopeV1 {
        FoundationScopeV1 {
            project_id: "project.public".into(),
            goal_id: Some("goal.control".into()),
            task_id: Some("task.contract".into()),
            run_id: Some("run.001".into()),
        }
    }

    fn authority(invoker: PrincipalIdentityV1) -> FoundationAuthorityV1 {
        FoundationAuthorityV1 {
            contract_version: 1,
            authority_id: "authority.control.001".into(),
            principal: invoker,
            scope: scope(),
            namespace: FoundationNamespaceV1::CodeReview,
            permission_profile: FoundationPermissionProfileV1 {
                contract_version: 1,
                risk_tier: RiskTier::R1,
                resource_keys: vec!["contracts.control".into()],
                write_keys: Vec::new(),
                approval_required: true,
                review_required: true,
                audit_required: true,
            },
            visibility: FoundationVisibilityV1::Private,
            sensitivity: FoundationSensitivityV1::Internal,
            validity: FoundationValidityV1 {
                status: FoundationValidityStatusV1::Active,
                valid_from: timestamp(0),
                valid_until: Some(timestamp(59)),
            },
        }
    }

    fn invocation(invoker_role: PrincipalV1, target_role: PrincipalV1) -> RoleInvocationV1 {
        let invoker = identity("principal.invoker", invoker_role);
        let authority = authority(invoker.clone());
        RoleInvocationV1 {
            contract_version: 1,
            invocation_id: "invocation.001".into(),
            invoker,
            target: identity("principal.target", target_role),
            task_id: TaskId::from("task.contract"),
            run_id: RunId::from("run.001"),
            scope: scope(),
            budget: ExecutionBudget {
                contract_version: 1,
                max_attempts: 2,
            },
            idempotency_key: IdempotencyKey::from("idempotency.001"),
            authority_digest: canonical_authority_digest(&authority).unwrap(),
            authority,
            input_digest: "a".repeat(64),
            invoked_at: timestamp(1),
        }
    }

    fn result(invocation: &RoleInvocationV1, state: ControlPlaneState) -> RoleResultV1 {
        let payload = match state {
            ControlPlaneState::Completed if invocation.target.role == PrincipalV1::Coordinator => {
                RoleResultPayloadV1::OwnerFinal {
                    response: "Owner-ready response".into(),
                }
            }
            ControlPlaneState::Completed => RoleResultPayloadV1::Specialist {
                summary: "Bounded specialist result".into(),
            },
            ControlPlaneState::Failed => RoleResultPayloadV1::Failure {
                code: "execution_failed".into(),
                message: "Execution failed safely".into(),
            },
            ControlPlaneState::Cancelled => RoleResultPayloadV1::Cancellation {
                reason: "Cancelled by caller".into(),
            },
            _ => panic!("test result requires terminal state"),
        };
        RoleResultV1 {
            contract_version: 1,
            result_id: "result.001".into(),
            invocation_id: invocation.invocation_id.clone(),
            invocation_digest: invocation.canonical_digest().unwrap(),
            producer: invocation.target.clone(),
            task_id: invocation.task_id.clone(),
            run_id: invocation.run_id.clone(),
            scope: invocation.scope.clone(),
            idempotency_key: invocation.idempotency_key.clone(),
            attempt: 1,
            state,
            payload,
            evidence_ids: if state == ControlPlaneState::Completed {
                vec![EvidenceId::from("evidence.001")]
            } else {
                Vec::new()
            },
            occurred_at: timestamp(3),
        }
    }

    fn event(
        invocation: &RoleInvocationV1,
        sequence: u64,
        previous_event_id: Option<&str>,
        minute: u32,
        payload: ControlPlaneEventPayload,
    ) -> ControlPlaneEvent {
        let producer = if matches!(
            payload,
            ControlPlaneEventPayload::InvocationSubmitted { .. }
        ) {
            invocation.invoker.clone()
        } else {
            invocation.target.clone()
        };
        let payload_digest = payload.canonical_digest().unwrap();
        ControlPlaneEvent {
            contract_version: 1,
            envelope: FoundationEventEnvelopeV1 {
                contract_version: 1,
                event_id: format!("event.{sequence}"),
                domain: FoundationDomainV1::ControlPlane,
                scope: invocation.scope.clone(),
                producer,
                event_kind: payload.event_kind().into(),
                sequence,
                previous_event_id: previous_event_id.map(str::to_owned),
                occurred_at: timestamp(minute),
                payload_digest,
            },
            payload,
        }
    }

    fn submitted(invocation: &RoleInvocationV1) -> ControlPlaneEvent {
        event(
            invocation,
            0,
            None,
            1,
            ControlPlaneEventPayload::InvocationSubmitted {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
            },
        )
    }

    fn started(invocation: &RoleInvocationV1, sequence: u64, previous: &str) -> ControlPlaneEvent {
        event(
            invocation,
            sequence,
            Some(previous),
            sequence as u32 + 1,
            ControlPlaneEventPayload::AttemptStarted {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                attempt: 1,
            },
        )
    }

    fn terminal(
        invocation: &RoleInvocationV1,
        result: &RoleResultV1,
        sequence: u64,
        previous: &str,
    ) -> ControlPlaneEvent {
        let common = (
            invocation.invocation_id.clone(),
            invocation.canonical_digest().unwrap(),
            result.result_id.clone(),
            result.canonical_digest().unwrap(),
        );
        let payload = match result.state {
            ControlPlaneState::Completed => ControlPlaneEventPayload::InvocationCompleted {
                invocation_id: common.0,
                invocation_digest: common.1,
                attempt: result.attempt,
                result_id: common.2,
                result_digest: common.3,
            },
            ControlPlaneState::Failed => ControlPlaneEventPayload::InvocationFailed {
                invocation_id: common.0,
                invocation_digest: common.1,
                attempt: result.attempt,
                result_id: common.2,
                result_digest: common.3,
            },
            ControlPlaneState::Cancelled => ControlPlaneEventPayload::InvocationCancelled {
                invocation_id: common.0,
                invocation_digest: common.1,
                attempt: result.attempt,
                result_id: common.2,
                result_digest: common.3,
            },
            _ => unreachable!(),
        };
        event(
            invocation,
            sequence,
            Some(previous),
            sequence as u32 + 1,
            payload,
        )
    }

    #[test]
    fn role_matrix_is_exact_and_owner_is_not_a_target() {
        let roles = [
            PrincipalV1::Owner,
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            PrincipalV1::Reviewer,
            PrincipalV1::Auditor,
        ];
        for invoker in roles {
            for target in roles {
                let allowed = matches!(
                    (invoker, target),
                    (PrincipalV1::Owner, PrincipalV1::Coordinator)
                        | (PrincipalV1::Coordinator, PrincipalV1::Engineer)
                        | (PrincipalV1::Coordinator, PrincipalV1::Reviewer)
                        | (PrincipalV1::Coordinator, PrincipalV1::Auditor)
                );
                assert_eq!(invocation(invoker, target).validate().is_ok(), allowed);
            }
        }
        let mut self_call = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        self_call.target.principal_id = self_call.invoker.principal_id.clone();
        assert_eq!(
            self_call.validate(),
            Err(ControlPlaneValidationError::SelfInvocation)
        );
    }

    #[test]
    fn budget_is_exact_v1_nonzero_u32_and_converts_explicitly() {
        assert!(ExecutionBudget {
            contract_version: 1,
            max_attempts: 1
        }
        .validate()
        .is_ok());
        assert!(ExecutionBudget {
            contract_version: 1,
            max_attempts: u32::MAX
        }
        .validate()
        .is_ok());
        assert_eq!(
            ExecutionBudget {
                contract_version: 1,
                max_attempts: 0
            }
            .validate(),
            Err(ControlPlaneValidationError::InvalidExecutionBudget)
        );
        let legacy = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 3,
        };
        let budget = ExecutionBudget::try_from(&legacy).unwrap();
        assert_eq!(RetryBudget::try_from(&budget).unwrap(), legacy);
    }

    #[test]
    fn invocation_binds_full_scope_authority_and_canonical_digests() {
        let value = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        assert!(value.validate().is_ok());
        assert_eq!(value.canonical_json_bytes().unwrap().last(), Some(&b'}'));

        let mut invalid = value.clone();
        invalid.scope.run_id = None;
        assert!(matches!(
            invalid.validate(),
            Err(ControlPlaneValidationError::Foundation(_))
                | Err(ControlPlaneValidationError::InvalidScopeBinding)
        ));
        let mut invalid = value.clone();
        invalid.authority_digest = "b".repeat(64);
        assert_eq!(
            invalid.validate(),
            Err(ControlPlaneValidationError::DigestMismatch(
                "authority_digest"
            ))
        );
        let mut invalid = value.clone();
        invalid.authority.namespace = FoundationNamespaceV1::KnowledgeReview;
        invalid.authority_digest = canonical_authority_digest(&invalid.authority).unwrap();
        assert_eq!(
            invalid.validate(),
            Err(ControlPlaneValidationError::InvalidAuthorityBinding)
        );
    }

    #[test]
    fn authority_status_window_principal_and_scope_fail_closed() {
        let value = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let mutations: [fn(&mut RoleInvocationV1); 5] = [
            |v| v.authority.validity.status = FoundationValidityStatusV1::Pending,
            |v| v.invoked_at = timestamp(0) - chrono::Duration::seconds(1),
            |v| v.invoked_at = timestamp(59),
            |v| v.authority.principal.principal_id = "principal.other".into(),
            |v| v.authority.scope.run_id = Some("run.other".into()),
        ];
        for mutate in mutations {
            let mut invalid = value.clone();
            mutate(&mut invalid);
            invalid.authority_digest = canonical_authority_digest(&invalid.authority).unwrap();
            assert_eq!(
                invalid.validate(),
                Err(ControlPlaneValidationError::InvalidAuthorityBinding)
            );
        }
    }

    #[test]
    fn state_is_a_plain_closed_string_and_tagged_payloads_reject_unknown_fields() {
        assert_eq!(
            serde_json::to_value(ControlPlaneState::Pending).unwrap(),
            json!("pending")
        );
        assert!(serde_json::from_value::<ControlPlaneState>(json!({"type":"pending"})).is_err());
        assert!(serde_json::from_value::<RoleResultPayloadV1>(json!({
            "type":"owner_final", "response":"ok", "extra":true
        }))
        .is_err());
        assert!(serde_json::from_value::<ControlPlaneEventPayload>(json!({
            "type":"attempt_started", "invocation_id":"invocation.001",
            "invocation_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "attempt":1, "extra":true
        }))
        .is_err());
    }

    #[test]
    fn completed_result_payload_and_evidence_are_role_bound() {
        let owner_invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let owner_result = result(&owner_invocation, ControlPlaneState::Completed);
        assert!(owner_result.validate_against(&owner_invocation).is_ok());
        assert!(CoordinatorFinalResponse::try_from(&owner_result).is_ok());
        assert!(SpecialistOutput::try_from(&owner_result).is_err());

        let specialist_invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Engineer);
        let specialist_result = result(&specialist_invocation, ControlPlaneState::Completed);
        assert!(specialist_result
            .validate_against(&specialist_invocation)
            .is_ok());
        assert!(SpecialistOutput::try_from(&specialist_result).is_ok());
        assert!(CoordinatorFinalResponse::try_from(&specialist_result).is_err());

        let mut invalid = specialist_result.clone();
        invalid.evidence_ids.clear();
        assert_eq!(
            invalid.validate_against(&specialist_invocation),
            Err(ControlPlaneValidationError::InvalidEvidence)
        );
        let mut invalid = specialist_result;
        invalid.evidence_ids = vec![
            EvidenceId::from("evidence.002"),
            EvidenceId::from("evidence.001"),
        ];
        assert_eq!(
            invalid.validate_against(&specialist_invocation),
            Err(ControlPlaneValidationError::InvalidEvidence)
        );
    }

    #[test]
    fn result_bindings_attempts_text_and_unknown_versions_fail_closed() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Reviewer);
        let value = result(&invocation, ControlPlaneState::Completed);
        for mutate in [
            |v: &mut RoleResultV1| v.invocation_digest = "b".repeat(64),
            |v: &mut RoleResultV1| v.task_id = TaskId::from("task.other"),
            |v: &mut RoleResultV1| v.attempt = 0,
            |v: &mut RoleResultV1| v.contract_version = 2,
        ] {
            let mut invalid = value.clone();
            mutate(&mut invalid);
            assert!(invalid.validate_against(&invocation).is_err());
        }
        let mut invalid = value;
        invalid.payload = RoleResultPayloadV1::Specialist {
            summary: " trailing ".into(),
        };
        assert!(matches!(
            invalid.validate_against(&invocation),
            Err(ControlPlaneValidationError::InvalidText("summary"))
        ));
    }

    #[test]
    fn event_envelope_is_composed_once_and_exactly_bound() {
        let invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let value = submitted(&invocation);
        assert!(value.validate_against(&invocation).is_ok());
        let serialized = serde_json::to_value(&value).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 3);
        for forbidden in [
            "event_id",
            "scope",
            "producer",
            "sequence",
            "occurred_at",
            "payload_digest",
        ] {
            assert!(serialized.get(forbidden).is_none());
        }

        let mut invalid = value.clone();
        invalid.envelope.event_kind = "control.attempt_started".into();
        assert_eq!(
            invalid.validate_against(&invocation),
            Err(ControlPlaneValidationError::InvalidEventEnvelope)
        );
        let mut invalid = value;
        invalid.envelope.payload_digest = "b".repeat(64);
        assert_eq!(
            invalid.validate_against(&invocation),
            Err(ControlPlaneValidationError::InvalidEventEnvelope)
        );
    }

    #[test]
    fn completed_replay_requires_exact_terminal_result() {
        let invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let result = result(&invocation, ControlPlaneState::Completed);
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        let third = terminal(&invocation, &result, 2, &second.envelope.event_id);
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, third], &[result]),
            Ok(ControlPlaneState::Completed)
        );
    }

    #[test]
    fn implicit_completion_unmatched_result_and_terminal_mutation_fail_closed() {
        let invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let result = result(&invocation, ControlPlaneState::Completed);
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        assert_eq!(
            validate_control_plane_replay(
                &invocation,
                &[first.clone(), second.clone()],
                std::slice::from_ref(&result)
            ),
            Err(ControlPlaneValidationError::UnexpectedResult)
        );
        let third = terminal(&invocation, &result, 2, &second.envelope.event_id);
        let fourth = event(
            &invocation,
            3,
            Some(&third.envelope.event_id),
            5,
            ControlPlaneEventPayload::AttemptStarted {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                attempt: 2,
            },
        );
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, third, fourth], &[result]),
            Err(ControlPlaneValidationError::InvalidTransition)
        );
    }

    #[test]
    fn retry_replay_owns_the_next_attempt_and_enforces_budget() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Auditor);
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        let retry = event(
            &invocation,
            2,
            Some(&second.envelope.event_id),
            3,
            ControlPlaneEventPayload::RetryScheduled {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                completed_attempt: 1,
                next_attempt: 2,
            },
        );
        let mut second_start = event(
            &invocation,
            3,
            Some(&retry.envelope.event_id),
            4,
            ControlPlaneEventPayload::AttemptStarted {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                attempt: 2,
            },
        );
        assert_eq!(
            validate_control_plane_replay(
                &invocation,
                &[
                    first.clone(),
                    second.clone(),
                    retry.clone(),
                    second_start.clone()
                ],
                &[]
            ),
            Ok(ControlPlaneState::Running)
        );
        if let ControlPlaneEventPayload::AttemptStarted { attempt, .. } = &mut second_start.payload
        {
            *attempt = 1;
        }
        second_start.envelope.payload_digest = second_start.payload.canonical_digest().unwrap();
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, retry, second_start], &[]),
            Err(ControlPlaneValidationError::InvalidTransition)
        );
    }

    #[test]
    fn non_adjacent_duplicate_event_id_with_new_payload_fails_closed() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Auditor);
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        let mut retry = event(
            &invocation,
            2,
            Some(&second.envelope.event_id),
            3,
            ControlPlaneEventPayload::RetryScheduled {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                completed_attempt: 1,
                next_attempt: 2,
            },
        );
        retry.envelope.event_id = first.envelope.event_id.clone();
        assert_ne!(retry.payload, first.payload);
        assert_eq!(
            retry.envelope.payload_digest,
            retry.payload.canonical_digest().unwrap()
        );

        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, retry], &[]),
            Err(ControlPlaneValidationError::InvalidEventChain)
        );
    }

    #[test]
    fn pending_cancellation_uses_current_attempt_and_result() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Engineer);
        let mut result = result(&invocation, ControlPlaneState::Cancelled);
        result.occurred_at = timestamp(2);
        let first = submitted(&invocation);
        let cancellation = terminal(&invocation, &result, 1, &first.envelope.event_id);
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, cancellation], &[result]),
            Ok(ControlPlaneState::Cancelled)
        );
    }

    #[test]
    fn wrong_pending_cancellation_attempt_and_result_digest_fail_closed() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Engineer);
        let mut result = result(&invocation, ControlPlaneState::Cancelled);
        result.occurred_at = timestamp(2);
        let first = submitted(&invocation);
        let mut cancellation = terminal(&invocation, &result, 1, &first.envelope.event_id);
        if let ControlPlaneEventPayload::InvocationCancelled { attempt, .. } =
            &mut cancellation.payload
        {
            *attempt = 2;
        }
        cancellation.envelope.payload_digest = cancellation.payload.canonical_digest().unwrap();
        assert_eq!(
            validate_control_plane_replay(
                &invocation,
                &[first.clone(), cancellation],
                std::slice::from_ref(&result)
            ),
            Err(ControlPlaneValidationError::InvalidTransition)
        );

        let mut cancellation = terminal(&invocation, &result, 1, &first.envelope.event_id);
        if let ControlPlaneEventPayload::InvocationCancelled { result_digest, .. } =
            &mut cancellation.payload
        {
            *result_digest = "f".repeat(64);
        }
        cancellation.envelope.payload_digest = cancellation.payload.canonical_digest().unwrap();
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, cancellation], &[result]),
            Err(ControlPlaneValidationError::InvalidResultBinding)
        );
    }

    #[test]
    fn terminal_event_attempt_cannot_bind_a_rehashed_prior_attempt_result() {
        let invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Reviewer);
        let result = result(&invocation, ControlPlaneState::Completed);
        assert_eq!(result.attempt, 1);

        let first = submitted(&invocation);
        let first_start = started(&invocation, 1, &first.envelope.event_id);
        let retry = event(
            &invocation,
            2,
            Some(&first_start.envelope.event_id),
            3,
            ControlPlaneEventPayload::RetryScheduled {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                completed_attempt: 1,
                next_attempt: 2,
            },
        );
        let second_start = event(
            &invocation,
            3,
            Some(&retry.envelope.event_id),
            4,
            ControlPlaneEventPayload::AttemptStarted {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                attempt: 2,
            },
        );
        let mut terminal = terminal(&invocation, &result, 4, &second_start.envelope.event_id);
        if let ControlPlaneEventPayload::InvocationCompleted { attempt, .. } = &mut terminal.payload
        {
            *attempt = 2;
        }
        terminal.envelope.payload_digest = terminal.payload.canonical_digest().unwrap();

        assert_eq!(
            validate_control_plane_replay(
                &invocation,
                &[first, first_start, retry, second_start, terminal],
                &[result]
            ),
            Err(ControlPlaneValidationError::InvalidResultBinding)
        );
    }

    #[test]
    fn retry_over_budget_and_overflow_fail_closed() {
        let mut invocation = invocation(PrincipalV1::Coordinator, PrincipalV1::Reviewer);
        invocation.budget.max_attempts = 1;
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        let retry = event(
            &invocation,
            2,
            Some(&second.envelope.event_id),
            3,
            ControlPlaneEventPayload::RetryScheduled {
                invocation_id: invocation.invocation_id.clone(),
                invocation_digest: invocation.canonical_digest().unwrap(),
                completed_attempt: 1,
                next_attempt: 2,
            },
        );
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, retry], &[]),
            Err(ControlPlaneValidationError::InvalidAttempt)
        );

        let payload = ControlPlaneEventPayload::RetryScheduled {
            invocation_id: invocation.invocation_id.clone(),
            invocation_digest: invocation.canonical_digest().unwrap(),
            completed_attempt: u32::MAX,
            next_attempt: 1,
        };
        assert!(payload.validate_shape().is_ok());
        assert_eq!(u32::MAX.checked_add(1), None);
    }

    #[test]
    fn replay_rejects_broken_chain_and_reversed_time() {
        let invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let mut too_early = submitted(&invocation);
        too_early.envelope.occurred_at = invocation.invoked_at - chrono::Duration::seconds(1);
        assert_eq!(
            validate_control_plane_replay(&invocation, &[too_early], &[]),
            Err(ControlPlaneValidationError::InvalidTimestamp)
        );

        let first = submitted(&invocation);
        let mut second = started(&invocation, 1, &first.envelope.event_id);
        second.envelope.previous_event_id = Some("event.other".into());
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first.clone(), second], &[]),
            Err(ControlPlaneValidationError::InvalidEventChain)
        );
        let mut second = started(&invocation, 1, &first.envelope.event_id);
        second.envelope.occurred_at = timestamp(0);
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second], &[]),
            Err(ControlPlaneValidationError::InvalidTimestamp)
        );
    }

    #[test]
    fn terminal_result_time_is_bounded_by_invocation_and_event() {
        let invocation = invocation(PrincipalV1::Owner, PrincipalV1::Coordinator);
        let mut result = result(&invocation, ControlPlaneState::Completed);
        result.occurred_at = timestamp(5);
        let first = submitted(&invocation);
        let second = started(&invocation, 1, &first.envelope.event_id);
        let third = terminal(&invocation, &result, 2, &second.envelope.event_id);
        assert_eq!(
            validate_control_plane_replay(&invocation, &[first, second, third], &[result]),
            Err(ControlPlaneValidationError::InvalidTimestamp)
        );
    }

    #[test]
    fn unknown_versions_fields_states_and_payloads_fail_closed() {
        assert!(serde_json::from_value::<ExecutionBudget>(json!({
            "contract_version":1,"max_attempts":1,"extra":true
        }))
        .is_err());
        assert!(serde_json::from_value::<ControlPlaneState>(json!("unknown")).is_err());
        assert!(serde_json::from_value::<RoleResultPayloadV1>(json!({
            "type":"unknown","summary":"x"
        }))
        .is_err());
        let invalid = ExecutionBudget {
            contract_version: 2,
            max_attempts: 1,
        };
        assert!(matches!(
            invalid.validate(),
            Err(ControlPlaneValidationError::UnsupportedContractVersion(_))
        ));
    }

    #[test]
    fn published_samples_match_the_rust_wire_contracts_and_digests() {
        let budget: ExecutionBudget = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_execution_budget.v1.sample.json"
        ))
        .unwrap();
        budget.validate().unwrap();
        let state: ControlPlaneState = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_state.v1.sample.json"
        ))
        .unwrap();
        assert_eq!(state, ControlPlaneState::Completed);

        let invocation: RoleInvocationV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_role_invocation.v1.sample.json"
        ))
        .unwrap();
        invocation.validate().unwrap();
        let result: RoleResultV1 = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_role_result.v1.sample.json"
        ))
        .unwrap();
        result.validate_against(&invocation).unwrap();
        let event: ControlPlaneEvent = serde_json::from_str(include_str!(
            "../../../contracts/samples/control_plane_event.v1.sample.json"
        ))
        .unwrap();
        event.validate_against(&invocation).unwrap();

        assert_eq!(
            result.invocation_digest,
            invocation.canonical_digest().unwrap()
        );
        let (_, event_invocation_digest) = event.payload.invocation_binding();
        assert_eq!(event_invocation_digest, result.invocation_digest);
        assert_eq!(
            event.envelope.payload_digest,
            event.payload.canonical_digest().unwrap()
        );
        let ControlPlaneEventPayload::InvocationCompleted { result_digest, .. } = event.payload
        else {
            panic!("published event sample must be invocation_completed")
        };
        assert_eq!(result_digest, result.canonical_digest().unwrap());
    }
}
