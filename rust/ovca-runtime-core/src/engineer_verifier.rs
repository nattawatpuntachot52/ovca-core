//! Durable, provider-neutral Engineer-to-Verifier control-plane contracts.
//!
//! This module is deliberately limited to canonical identities, closed state
//! transitions, and values persisted inside the existing execution envelope.
//! Native workspace effects remain owned by [`crate::WorkspaceCapabilityBroker`]
//! and reviewed command execution remains owned by `ovca-verifier`.

use crate::role_executor::{
    RoleExecutionOutcome, RoleExecutionRequest, RoleExecutionUsage, RoleRetryCause,
};
use chrono::{DateTime, Utc};
use ovca_storage::{EvidenceCurrent, EvidenceKey};
use ovca_types::control_plane::{ControlPlaneState, RoleInvocationV1, RoleResultV1};
use ovca_types::foundation::{
    validate_sha256_digest, validate_stable_id, FoundationAuthorityV1, FoundationValidityStatusV1,
    PrincipalV1,
};
use ovca_types::goal_runtime::{verification_sha256_hex, GoalId, RunId, TaskId, WorkerId};
use ovca_types::tool_boundary::{
    ToolDeniedCodeV1, ToolOperationV1, ToolReceiptOutcomeV1, ToolReceiptV1, ToolRequestV1,
    WorkspaceFileV1, WorkspaceLeaseV1, WorkspaceSnapshotV1,
};
use ovca_types::{
    ContractVersion, EventId, Role, RunEvent, RunEventPayload, VerificationBundle,
    VerificationTranscriptCommandIdentity, VerificationTranscriptIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const ENGINEER_VERIFIER_CONTRACT_VERSION: u32 = 1;
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const LOGICAL_PLAN_DOMAIN: &str = "ovca.engineer-logical-plan.v1";
const EXECUTION_BINDING_DOMAIN: &str = "ovca.engineer-execution-binding.v1";
const TOOL_REQUEST_DOMAIN: &str = "ovca.engineer-tool-request.v1";
const TOOL_IDEMPOTENCY_DOMAIN: &str = "ovca.engineer-tool-idempotency.v1";
const RESOLVED_LEDGER_DOMAIN: &str = "ovca.engineer-resolved-effect-ledger.v1";
const STATE_DOMAIN: &str = "ovca.engineer-verifier-state.v1";
const WORKSPACE_DIFF_DOMAIN: &str = "ovca.engineer-workspace-diff.v1";
const PHASE_EVENT_DOMAIN: &str = "ovca.engineer-verifier-event.v1";
const PHASE_EVENT_METADATA_KEY: &str = "engineer_verifier_phase_v1";
const PHASE_EVENT_NOTE: &str = "engineer_verifier_phase_v1";
const ROLE_OUTCOME_DOMAIN: &str = "ovca.engineer-role-outcome.v1";
const VERIFIER_REPLAY_DOMAIN: &str = "ovca.engineer-verifier-replay-plan.v1";
const RECONCILIATION_DOMAIN: &str = "ovca.engineer-write-reconciliation.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineerVerifierError {
    UnsupportedContractVersion,
    InvalidPlan,
    InvalidBinding,
    InvalidDigest,
    InvalidEffectOrder,
    InvalidPayload,
    InvalidLedger,
    InvalidWorkspaceDiff,
    InvalidState,
    InvalidTransition,
    InvalidExecutorOutcome,
    InvalidVerifierReplay,
    InvalidProjection,
    Overflow,
    Serialization,
}

impl fmt::Display for EngineerVerifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedContractVersion => "unsupported engineer-verifier contract version",
            Self::InvalidPlan => "invalid engineer logical plan",
            Self::InvalidBinding => "invalid engineer-verifier binding",
            Self::InvalidDigest => "engineer-verifier canonical digest mismatch",
            Self::InvalidEffectOrder => "invalid engineer effect order",
            Self::InvalidPayload => "invalid engineer effect payload",
            Self::InvalidLedger => "invalid resolved-effect ledger",
            Self::InvalidWorkspaceDiff => "invalid workspace diff bridge",
            Self::InvalidState => "invalid durable engineer-verifier state",
            Self::InvalidTransition => "invalid engineer-verifier transition",
            Self::InvalidExecutorOutcome => "invalid persisted role-executor outcome",
            Self::InvalidVerifierReplay => "invalid verifier replay plan",
            Self::InvalidProjection => "invalid engineer-verifier event projection",
            Self::Overflow => "engineer-verifier integer transition overflow",
            Self::Serialization => "engineer-verifier canonical serialization failed",
        })
    }
}

impl std::error::Error for EngineerVerifierError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedToolEffectTemplateV1 {
    pub contract_version: u32,
    pub ordinal: u32,
    pub effect_id: String,
    pub operation: ToolOperationV1,
    pub payload_sha256: String,
}

impl PlannedToolEffectTemplateV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.effect_id, "effect_id")
            .map_err(|_| EngineerVerifierError::InvalidPlan)?;
        self.operation
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidPlan)?;
        validate_sha256_digest(&self.payload_sha256, "payload_sha256")
            .map_err(|_| EngineerVerifierError::InvalidPayload)?;
        match &self.operation {
            ToolOperationV1::ReadFile { .. } if self.payload_sha256 == EMPTY_PAYLOAD_SHA256 => {
                Ok(())
            }
            ToolOperationV1::WriteFile { content_sha256, .. }
                if content_sha256 == &self.payload_sha256 =>
            {
                Ok(())
            }
            ToolOperationV1::Unsupported { .. } => Err(EngineerVerifierError::InvalidEffectOrder),
            _ => Err(EngineerVerifierError::InvalidPayload),
        }
    }

    pub fn validate_payload(&self, payload: Option<&[u8]>) -> Result<(), EngineerVerifierError> {
        self.validate()?;
        match &self.operation {
            ToolOperationV1::ReadFile { .. } => {
                if payload.is_some() {
                    return Err(EngineerVerifierError::InvalidPayload);
                }
            }
            ToolOperationV1::WriteFile { byte_length, .. } => {
                let bytes = payload.ok_or(EngineerVerifierError::InvalidPayload)?;
                let length =
                    u64::try_from(bytes.len()).map_err(|_| EngineerVerifierError::Overflow)?;
                if length != *byte_length || verification_sha256_hex(bytes) != self.payload_sha256 {
                    return Err(EngineerVerifierError::InvalidPayload);
                }
            }
            ToolOperationV1::Unsupported { .. } => {
                return Err(EngineerVerifierError::InvalidEffectOrder)
            }
        }
        Ok(())
    }
}

impl EngineerVerifierStateV1 {
    pub(crate) fn validate_initial_install(&self) -> Result<(), EngineerVerifierError> {
        self.validate()?;
        if self.phase == EngineerVerifierPhaseV1::Planned
            && self.phase_revision == 0
            && self.attempt == 1
            && matches!(self.executor, ExecutorCallStateV1::NotStarted)
            && self.workspace.is_none()
            && self.ledger.entries.is_empty()
            && self.prepared_write.is_none()
            && self.tool_observations.is_empty()
            && self.write_reconciliation.is_none()
            && self.engineer_result.is_none()
            && self.workspace_bridge.is_none()
            && self.cancellation.is_none()
            && self.verifier_replay_plan.is_none()
            && self.verifier.is_none()
            && self.pending_projection.is_none()
            && self.projected_sequence.is_none()
            && self.projected_event_id.is_none()
        {
            return Ok(());
        }
        if self.phase != EngineerVerifierPhaseV1::Engineering
            || self.phase_revision != 1
            || self.attempt != 1
            || !matches!(self.executor, ExecutorCallStateV1::NotStarted)
            || self
                .workspace
                .as_ref()
                .is_none_or(|workspace| workspace.closed || workspace.cleanup_required)
            || !self.ledger.entries.is_empty()
            || self.prepared_write.is_some()
            || !self.tool_observations.is_empty()
            || self.write_reconciliation.is_some()
            || self.engineer_result.is_some()
            || self.workspace_bridge.is_some()
            || self.cancellation.is_some()
            || self.verifier_replay_plan.is_some()
            || self.verifier.is_some()
            || self.pending_projection.is_none()
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
        validate_pending_transition(EngineerVerifierPhaseV1::Planned, self)
    }

    pub(crate) fn validate_successor(&self, next: &Self) -> Result<(), EngineerVerifierError> {
        self.validate()?;
        next.validate()?;
        if self.contract_version != next.contract_version
            || self.run_id != next.run_id
            || self.goal_id != next.goal_id
            || self.task_id != next.task_id
            || self.plan != next.plan
            || next.controller_time < self.controller_time
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }

        if let Some(pending) = &self.pending_projection {
            let mut expected = self.clone();
            expected.pending_projection = None;
            expected.projected_sequence = Some(pending.sequence);
            expected.projected_event_id = Some(pending.event_id.clone());
            if &expected != next {
                return Err(EngineerVerifierError::InvalidTransition);
            }
            return Ok(());
        }

        let phase_changed = self.phase != next.phase;
        if phase_changed {
            if self.phase.is_terminal()
                || next.phase_revision
                    != self
                        .phase_revision
                        .checked_add(1)
                        .ok_or(EngineerVerifierError::Overflow)?
                || next.pending_projection.is_none()
                || self.projected_sequence != next.projected_sequence
                || self.projected_event_id != next.projected_event_id
            {
                return Err(EngineerVerifierError::InvalidTransition);
            }
            validate_pending_transition(self.phase, next)?;
        } else if self.phase_revision != next.phase_revision
            || next.pending_projection.is_some()
            || self.projected_sequence != next.projected_sequence
            || self.projected_event_id != next.projected_event_id
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }

        if next.attempt != self.attempt {
            return self.validate_retry_successor(next);
        }
        if self.execution_binding != next.execution_binding
            || !next.ledger.entries.starts_with(&self.ledger.entries)
            || next.ledger.entries.len() > self.ledger.entries.len().saturating_add(1)
            || !next.tool_observations.starts_with(&self.tool_observations)
            || next.tool_observations.len() > self.tool_observations.len().saturating_add(1)
            || !option_is_monotonic(&self.engineer_result, &next.engineer_result)
            || !option_is_monotonic(&self.engineer_result_digest, &next.engineer_result_digest)
            || !option_is_monotonic(&self.workspace_bridge, &next.workspace_bridge)
            || !option_is_monotonic(&self.verifier_replay_plan, &next.verifier_replay_plan)
            || !option_is_monotonic(&self.write_reconciliation, &next.write_reconciliation)
            || !option_is_monotonic(&self.cancellation, &next.cancellation)
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
        validate_executor_successor(&self.executor, &next.executor)?;
        if self.executor != next.executor
            && (self.ledger != next.ledger
                || self.prepared_write != next.prepared_write
                || self.tool_observations != next.tool_observations
                || self.engineer_result != next.engineer_result
                || self.workspace_bridge != next.workspace_bridge
                || self.verifier_replay_plan != next.verifier_replay_plan
                || self.verifier != next.verifier
                || self.cancellation != next.cancellation
                || self.workspace != next.workspace
                || phase_changed)
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
        if self.cancellation != next.cancellation
            && (self.executor != next.executor
                || self.ledger != next.ledger
                || self.prepared_write != next.prepared_write
                || self.tool_observations != next.tool_observations
                || self.engineer_result != next.engineer_result
                || self.workspace_bridge != next.workspace_bridge
                || self.verifier_replay_plan != next.verifier_replay_plan
                || self.verifier != next.verifier
                || self.workspace != next.workspace
                || phase_changed)
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
        validate_verifier_successor(self.verifier.as_ref(), next.verifier.as_ref())?;
        validate_prepared_successor(self, next)?;
        validate_workspace_successor(self, next)?;
        Ok(())
    }

    fn validate_retry_successor(&self, next: &Self) -> Result<(), EngineerVerifierError> {
        let next_attempt = self
            .attempt
            .checked_add(1)
            .ok_or(EngineerVerifierError::Overflow)?;
        let before_workspace = self
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierError::InvalidTransition)?;
        let after_workspace = next
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierError::InvalidTransition)?;
        if self.phase != EngineerVerifierPhaseV1::RetryPending
            || next.phase != EngineerVerifierPhaseV1::Engineering
            || next.attempt != next_attempt
            || !before_workspace.closed
            || before_workspace.cleanup_required
            || after_workspace.closed
            || after_workspace.cleanup_required
            || before_workspace.initial_snapshot.files != after_workspace.initial_snapshot.files
            || !matches!(
                self.executor,
                ExecutorCallStateV1::OutcomeRecorded {
                    outcome: PersistedRoleExecutionOutcomeV1::RetryRequired { .. },
                    ..
                }
            )
            || !matches!(next.executor, ExecutorCallStateV1::NotStarted)
            || !next.ledger.entries.is_empty()
            || next.prepared_write.is_some()
            || !next.tool_observations.is_empty()
            || next.write_reconciliation.is_some()
            || next.engineer_result.is_some()
            || next.engineer_result_digest.is_some()
            || next.workspace_bridge.is_some()
            || next.verifier_replay_plan.is_some()
            || next.verifier.is_some()
            || self.cancellation != next.cancellation
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
        Ok(())
    }
}

fn option_is_monotonic<T: PartialEq>(before: &Option<T>, after: &Option<T>) -> bool {
    before.is_none() || before == after
}

fn validate_executor_successor(
    before: &ExecutorCallStateV1,
    after: &ExecutorCallStateV1,
) -> Result<(), EngineerVerifierError> {
    let allowed = before == after
        || matches!(
            (before, after),
            (
                ExecutorCallStateV1::NotStarted,
                ExecutorCallStateV1::Started { .. }
            ) | (
                ExecutorCallStateV1::Started { .. },
                ExecutorCallStateV1::OutcomeRecorded { .. }
            )
        );
    if allowed {
        Ok(())
    } else {
        Err(EngineerVerifierError::InvalidTransition)
    }
}

fn validate_verifier_successor(
    before: Option<&VerifierExecutionStateV1>,
    after: Option<&VerifierExecutionStateV1>,
) -> Result<(), EngineerVerifierError> {
    let allowed = before == after
        || matches!(
            (before, after),
            (None, Some(VerifierExecutionStateV1::NotStarted { .. }))
                | (
                    Some(VerifierExecutionStateV1::NotStarted { .. }),
                    Some(VerifierExecutionStateV1::Started { .. })
                )
                | (
                    Some(VerifierExecutionStateV1::Started { .. }),
                    Some(VerifierExecutionStateV1::PublicationObserved { .. })
                )
                | (
                    Some(VerifierExecutionStateV1::PublicationObserved { .. }),
                    Some(VerifierExecutionStateV1::Admitted { .. })
                )
        );
    if allowed {
        Ok(())
    } else {
        Err(EngineerVerifierError::InvalidTransition)
    }
}

fn validate_prepared_successor(
    before: &EngineerVerifierStateV1,
    after: &EngineerVerifierStateV1,
) -> Result<(), EngineerVerifierError> {
    let allowed = before.prepared_write == after.prepared_write
        || (before.prepared_write.is_none()
            && after.prepared_write.is_some()
            && before.ledger == after.ledger)
        || (before.prepared_write.is_some()
            && after.prepared_write.is_none()
            && (after.ledger.entries.len() == before.ledger.entries.len().saturating_add(1)
                || after.phase == EngineerVerifierPhaseV1::Cancelled));
    if allowed {
        Ok(())
    } else {
        Err(EngineerVerifierError::InvalidTransition)
    }
}

fn validate_workspace_successor(
    before_state: &EngineerVerifierStateV1,
    after_state: &EngineerVerifierStateV1,
) -> Result<(), EngineerVerifierError> {
    let (Some(before), Some(after_workspace)) = (&before_state.workspace, &after_state.workspace)
    else {
        return if before_state.workspace == after_state.workspace {
            Ok(())
        } else {
            Err(EngineerVerifierError::InvalidTransition)
        };
    };
    if before.lease != after_workspace.lease
        || before.lease_digest != after_workspace.lease_digest
        || before.initial_snapshot != after_workspace.initial_snapshot
        || before.grant != after_workspace.grant
        || before.grant_digest != after_workspace.grant_digest
        || before.recovery_token != after_workspace.recovery_token
        || (before.closed && !after_workspace.closed)
        || (before.cleanup_required && !after_workspace.cleanup_required && !after_workspace.closed)
        || after_workspace.next_receipt_sequence < before.next_receipt_sequence
        || after_workspace.next_receipt_sequence > before.next_receipt_sequence.saturating_add(1)
        || after_workspace.current_snapshot.generation < before.current_snapshot.generation
        || after_workspace.heartbeat_at < before.heartbeat_at
    {
        return Err(EngineerVerifierError::InvalidTransition);
    }
    if before.runtime_instance_id == after_workspace.runtime_instance_id {
        if before.runtime_epoch != after_workspace.runtime_epoch
            || before.fence != after_workspace.fence
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
    } else if after_workspace.runtime_epoch != before.runtime_epoch.saturating_add(1)
        || after_workspace.fence != before.fence.saturating_add(1)
        || after_workspace.heartbeat_at <= before.heartbeat_at
        || before.current_snapshot != after_workspace.current_snapshot
        || before.next_receipt_sequence != after_workspace.next_receipt_sequence
        || before.cleanup_required != after_workspace.cleanup_required
        || before.closed != after_workspace.closed
    {
        return Err(EngineerVerifierError::InvalidTransition);
    }
    if after_workspace.current_snapshot != before.current_snapshot {
        let Some(entry) = after_state.ledger.entries.last() else {
            return Err(EngineerVerifierError::InvalidTransition);
        };
        if after_state.ledger.entries.len() != before_state.ledger.entries.len().saturating_add(1)
            || entry.after_snapshot_digest != after_workspace.current_snapshot.snapshot_digest
        {
            return Err(EngineerVerifierError::InvalidTransition);
        }
    }
    if after_workspace.next_receipt_sequence != before.next_receipt_sequence
        && (after_workspace.next_receipt_sequence != before.next_receipt_sequence.saturating_add(1)
            || after_state.tool_observations.len()
                != before_state.tool_observations.len().saturating_add(1))
    {
        return Err(EngineerVerifierError::InvalidTransition);
    }
    Ok(())
}

fn validate_pending_transition(
    from: EngineerVerifierPhaseV1,
    state: &EngineerVerifierStateV1,
) -> Result<(), EngineerVerifierError> {
    let pending = state
        .pending_projection
        .as_ref()
        .ok_or(EngineerVerifierError::InvalidProjection)?;
    let event: RunEvent = serde_json::from_slice(&pending.event_bytes)
        .map_err(|_| EngineerVerifierError::InvalidProjection)?;
    if serde_json::to_vec(&event).map_err(|_| EngineerVerifierError::Serialization)?
        != pending.event_bytes
        || event.contract_version != ContractVersion::current()
        || event.id.as_str() != pending.event_id
        || event.run_id != state.run_id
        || event.sequence != pending.sequence
        || event.previous_event_id.as_ref().map(EventId::as_str)
            != pending.previous_event_id.as_deref()
        || event.occurred_at != state.controller_time
        || event.producer_role != Role::Coordinator
        || !matches!(
            &event.payload,
            RunEventPayload::NoteRecorded { message } if message == PHASE_EVENT_NOTE
        )
        || event.metadata.len() != 1
    {
        return Err(EngineerVerifierError::InvalidProjection);
    }
    let serde_json::Value::String(canonical_projection) = event
        .metadata
        .get(PHASE_EVENT_METADATA_KEY)
        .ok_or(EngineerVerifierError::InvalidProjection)?
    else {
        return Err(EngineerVerifierError::InvalidProjection);
    };
    let projection: EngineerVerifierPhaseProjectionV1 = serde_json::from_str(canonical_projection)
        .map_err(|_| EngineerVerifierError::InvalidProjection)?;
    if projection.canonical_json_bytes()? != canonical_projection.as_bytes()
        || derive_phase_event_id(&projection)? != pending.event_id
        || projection.run_id != state.run_id
        || projection.goal_id != state.goal_id
        || projection.task_id != state.task_id
        || projection.from != from
        || projection.to != state.phase
        || projection.phase_revision != state.phase_revision
        || projection.attempt != state.attempt
        || projection.execution_binding_digest != state.execution_binding.execution_binding_digest
        || projection.logical_plan_digest != state.plan.logical_plan_digest
        || projection.state_digest != state.state_digest
        || projection.resolved_effect_ledger_digest != state.ledger.resolved_effect_ledger_digest
        || projection.engineer_result_digest != state.engineer_result_digest
        || projection.verifier_transcript_digest
            != state
                .verifier
                .as_ref()
                .and_then(VerifierExecutionStateV1::transcript_digest)
                .map(str::to_owned)
        || projection.controller_time != state.controller_time
    {
        return Err(EngineerVerifierError::InvalidProjection);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineerLogicalPlanV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub invocation: RoleInvocationV1,
    pub invocation_digest: String,
    pub ordered_effects: Vec<PlannedToolEffectTemplateV1>,
    pub logical_plan_digest: String,
}

#[derive(Serialize)]
struct EngineerLogicalPlanDigestInputV1<'a> {
    contract_version: u32,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    invocation: &'a RoleInvocationV1,
    invocation_digest: &'a str,
    ordered_effects: &'a [PlannedToolEffectTemplateV1],
}

impl EngineerLogicalPlanV1 {
    pub fn try_new(
        run_id: RunId,
        goal_id: GoalId,
        task_id: TaskId,
        invocation: RoleInvocationV1,
        ordered_effects: Vec<PlannedToolEffectTemplateV1>,
    ) -> Result<Self, EngineerVerifierError> {
        let invocation_digest = invocation
            .canonical_digest()
            .map_err(|_| EngineerVerifierError::InvalidPlan)?;
        let mut plan = Self {
            contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
            run_id,
            goal_id,
            task_id,
            invocation,
            invocation_digest,
            ordered_effects,
            logical_plan_digest: String::new(),
        };
        plan.validate_without_digest()?;
        plan.logical_plan_digest = plan.computed_logical_plan_digest()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        self.validate_without_digest()?;
        validate_digest(&self.logical_plan_digest)?;
        if self.computed_logical_plan_digest()? != self.logical_plan_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, EngineerVerifierError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn computed_logical_plan_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            LOGICAL_PLAN_DOMAIN,
            &EngineerLogicalPlanDigestInputV1 {
                contract_version: self.contract_version,
                run_id: &self.run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                invocation: &self.invocation,
                invocation_digest: &self.invocation_digest,
                ordered_effects: &self.ordered_effects,
            },
        )
    }

    fn validate_without_digest(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        validate_stable_id(self.run_id.as_str(), "run_id")
            .and_then(|_| validate_stable_id(self.goal_id.as_str(), "goal_id"))
            .and_then(|_| validate_stable_id(self.task_id.as_str(), "task_id"))
            .map_err(|_| EngineerVerifierError::InvalidPlan)?;
        self.invocation
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidPlan)?;
        validate_digest(&self.invocation_digest)?;
        if self.invocation.target.role != PrincipalV1::Engineer
            || self.invocation.run_id != self.run_id
            || self.invocation.task_id != self.task_id
            || self.invocation.scope.goal_id.as_deref() != Some(self.goal_id.as_str())
            || self.invocation.scope.task_id.as_deref() != Some(self.task_id.as_str())
            || self.invocation.scope.run_id.as_deref() != Some(self.run_id.as_str())
            || self
                .invocation
                .canonical_digest()
                .map_err(|_| EngineerVerifierError::InvalidPlan)?
                != self.invocation_digest
        {
            return Err(EngineerVerifierError::InvalidBinding);
        }

        let mut ids = BTreeSet::new();
        let mut write_seen = false;
        for (index, effect) in self.ordered_effects.iter().enumerate() {
            effect.validate()?;
            let ordinal = u32::try_from(index).map_err(|_| EngineerVerifierError::Overflow)?;
            if effect.ordinal != ordinal || !ids.insert(effect.effect_id.as_str()) {
                return Err(EngineerVerifierError::InvalidEffectOrder);
            }
            match effect.operation {
                ToolOperationV1::ReadFile { .. } if !write_seen => {}
                ToolOperationV1::WriteFile { .. }
                    if !write_seen && index + 1 == self.ordered_effects.len() =>
                {
                    write_seen = true;
                }
                _ => return Err(EngineerVerifierError::InvalidEffectOrder),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineerExecutionBindingV1 {
    pub contract_version: u32,
    pub invocation_digest: String,
    pub attempt: u32,
    pub execution_binding_digest: String,
}

#[derive(Serialize)]
struct EngineerExecutionBindingDigestInputV1<'a> {
    contract_version: u32,
    invocation_digest: &'a str,
    attempt: u32,
}

impl EngineerExecutionBindingV1 {
    pub fn try_new(
        invocation_digest: impl Into<String>,
        attempt: u32,
    ) -> Result<Self, EngineerVerifierError> {
        let mut value = Self {
            contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
            invocation_digest: invocation_digest.into(),
            attempt,
            execution_binding_digest: String::new(),
        };
        value.validate_without_digest()?;
        value.execution_binding_digest = value.computed_digest()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        self.validate_without_digest()?;
        validate_digest(&self.execution_binding_digest)?;
        if self.computed_digest()? != self.execution_binding_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            EXECUTION_BINDING_DOMAIN,
            &EngineerExecutionBindingDigestInputV1 {
                contract_version: self.contract_version,
                invocation_digest: &self.invocation_digest,
                attempt: self.attempt,
            },
        )
    }

    fn validate_without_digest(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        validate_digest(&self.invocation_digest)?;
        if self.attempt == 0 {
            return Err(EngineerVerifierError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DerivedToolIdentityInputV1<'a> {
    contract_version: u32,
    invocation_digest: &'a str,
    logical_plan_digest: &'a str,
    effect_id: &'a str,
    attempt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedToolIdentityV1 {
    pub request_id: String,
    pub idempotency_key: String,
}

pub fn derive_tool_identity(
    plan: &EngineerLogicalPlanV1,
    effect_id: &str,
    attempt: u32,
) -> Result<DerivedToolIdentityV1, EngineerVerifierError> {
    plan.validate()?;
    if attempt == 0 || attempt > plan.invocation.budget.max_attempts {
        return Err(EngineerVerifierError::InvalidBinding);
    }
    let effect = plan
        .ordered_effects
        .iter()
        .find(|candidate| candidate.effect_id == effect_id)
        .ok_or(EngineerVerifierError::InvalidPlan)?;
    let input = DerivedToolIdentityInputV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        invocation_digest: &plan.invocation_digest,
        logical_plan_digest: &plan.logical_plan_digest,
        effect_id: &effect.effect_id,
        attempt,
    };
    let request_id = format!("request.{}", domain_digest(TOOL_REQUEST_DOMAIN, &input)?);
    let idempotency_key = format!(
        "idempotency.{}",
        domain_digest(TOOL_IDEMPOTENCY_DOMAIN, &input)?
    );
    validate_stable_id(&request_id, "request_id")
        .and_then(|_| validate_stable_id(&idempotency_key, "idempotency_key"))
        .map_err(|_| EngineerVerifierError::InvalidBinding)?;
    Ok(DerivedToolIdentityV1 {
        request_id,
        idempotency_key,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedEffectResolutionV1 {
    ReadObserved,
    WriteApplied,
    WriteReconciledApplied,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectLedgerEntryV1 {
    pub contract_version: u32,
    pub ordinal: u32,
    pub effect_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub idempotency_key: String,
    pub resolution: ResolvedEffectResolutionV1,
    pub tool_receipt_digest: Option<String>,
    pub reconciliation_digest: Option<String>,
    pub before_snapshot_digest: String,
    pub after_snapshot_digest: String,
}

impl ResolvedEffectLedgerEntryV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        for (value, field) in [
            (&self.effect_id, "effect_id"),
            (&self.request_id, "request_id"),
            (&self.idempotency_key, "idempotency_key"),
        ] {
            validate_stable_id(value, field).map_err(|_| EngineerVerifierError::InvalidLedger)?;
        }
        for value in [
            &self.request_digest,
            &self.before_snapshot_digest,
            &self.after_snapshot_digest,
        ] {
            validate_digest(value)?;
        }
        if let Some(value) = &self.tool_receipt_digest {
            validate_digest(value)?;
        }
        if let Some(value) = &self.reconciliation_digest {
            validate_digest(value)?;
        }
        let valid_identity = match self.resolution {
            ResolvedEffectResolutionV1::ReadObserved
            | ResolvedEffectResolutionV1::WriteApplied
            | ResolvedEffectResolutionV1::Denied => {
                self.tool_receipt_digest.is_some() && self.reconciliation_digest.is_none()
            }
            ResolvedEffectResolutionV1::WriteReconciledApplied => {
                self.tool_receipt_digest.is_none() && self.reconciliation_digest.is_some()
            }
        };
        if !valid_identity {
            return Err(EngineerVerifierError::InvalidLedger);
        }
        match self.resolution {
            ResolvedEffectResolutionV1::ReadObserved | ResolvedEffectResolutionV1::Denied
                if self.before_snapshot_digest == self.after_snapshot_digest => {}
            ResolvedEffectResolutionV1::WriteApplied
            | ResolvedEffectResolutionV1::WriteReconciledApplied
                if self.before_snapshot_digest != self.after_snapshot_digest => {}
            _ => return Err(EngineerVerifierError::InvalidLedger),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectLedgerV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub invocation_digest: String,
    pub logical_plan_digest: String,
    pub attempt: u32,
    pub entries: Vec<ResolvedEffectLedgerEntryV1>,
    pub resolved_effect_ledger_digest: String,
}

#[derive(Serialize)]
struct ResolvedEffectLedgerDigestInputV1<'a> {
    contract_version: u32,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    invocation_digest: &'a str,
    logical_plan_digest: &'a str,
    attempt: u32,
    entries: &'a [ResolvedEffectLedgerEntryV1],
}

impl ResolvedEffectLedgerV1 {
    pub fn empty(
        plan: &EngineerLogicalPlanV1,
        attempt: u32,
    ) -> Result<Self, EngineerVerifierError> {
        plan.validate()?;
        let mut value = Self {
            contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
            run_id: plan.run_id.clone(),
            goal_id: plan.goal_id.clone(),
            task_id: plan.task_id.clone(),
            invocation_digest: plan.invocation_digest.clone(),
            logical_plan_digest: plan.logical_plan_digest.clone(),
            attempt,
            entries: Vec::new(),
            resolved_effect_ledger_digest: String::new(),
        };
        value.validate_without_digest(plan)?;
        value.resolved_effect_ledger_digest = value.computed_digest()?;
        Ok(value)
    }

    pub fn append(
        &self,
        plan: &EngineerLogicalPlanV1,
        entry: ResolvedEffectLedgerEntryV1,
    ) -> Result<Self, EngineerVerifierError> {
        self.validate_against(plan)?;
        let mut next = self.clone();
        next.entries.push(entry);
        next.validate_without_digest(plan)?;
        next.resolved_effect_ledger_digest = next.computed_digest()?;
        Ok(next)
    }

    pub fn validate_against(
        &self,
        plan: &EngineerLogicalPlanV1,
    ) -> Result<(), EngineerVerifierError> {
        self.validate_without_digest(plan)?;
        validate_digest(&self.resolved_effect_ledger_digest)?;
        if self.computed_digest()? != self.resolved_effect_ledger_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    fn validate_without_digest(
        &self,
        plan: &EngineerLogicalPlanV1,
    ) -> Result<(), EngineerVerifierError> {
        plan.validate()?;
        validate_version(self.contract_version)?;
        if self.run_id != plan.run_id
            || self.goal_id != plan.goal_id
            || self.task_id != plan.task_id
            || self.invocation_digest != plan.invocation_digest
            || self.logical_plan_digest != plan.logical_plan_digest
            || self.attempt == 0
            || self.attempt > plan.invocation.budget.max_attempts
            || self.entries.len() > plan.ordered_effects.len()
        {
            return Err(EngineerVerifierError::InvalidLedger);
        }
        let mut denied = false;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            let ordinal = u32::try_from(index).map_err(|_| EngineerVerifierError::Overflow)?;
            let template = plan
                .ordered_effects
                .get(index)
                .ok_or(EngineerVerifierError::InvalidLedger)?;
            let identity = derive_tool_identity(plan, &template.effect_id, self.attempt)?;
            if denied
                || entry.ordinal != ordinal
                || entry.effect_id != template.effect_id
                || entry.request_id != identity.request_id
                || entry.idempotency_key != identity.idempotency_key
            {
                return Err(EngineerVerifierError::InvalidLedger);
            }
            denied = entry.resolution == ResolvedEffectResolutionV1::Denied;
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            RESOLVED_LEDGER_DOMAIN,
            &ResolvedEffectLedgerDigestInputV1 {
                contract_version: self.contract_version,
                run_id: &self.run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                invocation_digest: &self.invocation_digest,
                logical_plan_digest: &self.logical_plan_digest,
                attempt: self.attempt,
                entries: &self.entries,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDiffPathIdentityV1 {
    pub logical_path: String,
    pub file: Option<WorkspaceFileV1>,
}

impl WorkspaceDiffPathIdentityV1 {
    fn validate(&self, allow_absence: bool) -> Result<(), EngineerVerifierError> {
        ovca_types::tool_boundary::validate_logical_path(&self.logical_path)
            .map_err(|_| EngineerVerifierError::InvalidWorkspaceDiff)?;
        match &self.file {
            Some(file) if file.logical_path == self.logical_path => file
                .validate()
                .map_err(|_| EngineerVerifierError::InvalidWorkspaceDiff),
            None if allow_absence => Ok(()),
            _ => Err(EngineerVerifierError::InvalidWorkspaceDiff),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDiffBridgeV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub attempt: u32,
    pub broker_before_snapshot_digest: String,
    pub broker_after_snapshot_digest: String,
    pub changed_paths: Vec<String>,
    pub before_file_identities: Vec<WorkspaceDiffPathIdentityV1>,
    pub after_file_identities: Vec<WorkspaceDiffPathIdentityV1>,
    pub verifier_source_manifest_fingerprint: String,
    pub source_copy_digest: String,
    pub snapshot_copy_digest: String,
    pub invocation_digest: String,
    pub engineer_result_digest: String,
    pub command_set_digest: String,
    pub capability_set_digest: String,
    pub policy_digest: String,
    pub environment_digest: String,
    pub canonical_diff_digest: String,
}

#[derive(Serialize)]
struct WorkspaceDiffBridgeDigestInputV1<'a> {
    contract_version: u32,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    attempt: u32,
    broker_before_snapshot_digest: &'a str,
    broker_after_snapshot_digest: &'a str,
    changed_paths: &'a [String],
    before_file_identities: &'a [WorkspaceDiffPathIdentityV1],
    after_file_identities: &'a [WorkspaceDiffPathIdentityV1],
    verifier_source_manifest_fingerprint: &'a str,
    source_copy_digest: &'a str,
    snapshot_copy_digest: &'a str,
    invocation_digest: &'a str,
    engineer_result_digest: &'a str,
    command_set_digest: &'a str,
    capability_set_digest: &'a str,
    policy_digest: &'a str,
    environment_digest: &'a str,
}

impl WorkspaceDiffBridgeV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        if self.attempt == 0
            || self.changed_paths.len() != self.before_file_identities.len()
            || self.changed_paths.len() != self.after_file_identities.len()
        {
            return Err(EngineerVerifierError::InvalidWorkspaceDiff);
        }
        for value in [
            &self.broker_before_snapshot_digest,
            &self.broker_after_snapshot_digest,
            &self.verifier_source_manifest_fingerprint,
            &self.source_copy_digest,
            &self.snapshot_copy_digest,
            &self.invocation_digest,
            &self.engineer_result_digest,
            &self.command_set_digest,
            &self.capability_set_digest,
            &self.policy_digest,
            &self.environment_digest,
            &self.canonical_diff_digest,
        ] {
            validate_digest(value)?;
        }
        for pair in self.changed_paths.windows(2) {
            if pair[0].as_bytes() >= pair[1].as_bytes() {
                return Err(EngineerVerifierError::InvalidWorkspaceDiff);
            }
        }
        for (index, path) in self.changed_paths.iter().enumerate() {
            let before = &self.before_file_identities[index];
            let after = &self.after_file_identities[index];
            if before.logical_path != *path || after.logical_path != *path {
                return Err(EngineerVerifierError::InvalidWorkspaceDiff);
            }
            before.validate(true)?;
            after.validate(false)?;
            if before.file == after.file {
                return Err(EngineerVerifierError::InvalidWorkspaceDiff);
            }
        }
        if self.changed_paths.is_empty()
            && self.broker_before_snapshot_digest != self.broker_after_snapshot_digest
        {
            return Err(EngineerVerifierError::InvalidWorkspaceDiff);
        }
        if self.computed_digest()? != self.canonical_diff_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            WORKSPACE_DIFF_DOMAIN,
            &WorkspaceDiffBridgeDigestInputV1 {
                contract_version: self.contract_version,
                run_id: &self.run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                attempt: self.attempt,
                broker_before_snapshot_digest: &self.broker_before_snapshot_digest,
                broker_after_snapshot_digest: &self.broker_after_snapshot_digest,
                changed_paths: &self.changed_paths,
                before_file_identities: &self.before_file_identities,
                after_file_identities: &self.after_file_identities,
                verifier_source_manifest_fingerprint: &self.verifier_source_manifest_fingerprint,
                source_copy_digest: &self.source_copy_digest,
                snapshot_copy_digest: &self.snapshot_copy_digest,
                invocation_digest: &self.invocation_digest,
                engineer_result_digest: &self.engineer_result_digest,
                command_set_digest: &self.command_set_digest,
                capability_set_digest: &self.capability_set_digest,
                policy_digest: &self.policy_digest,
                environment_digest: &self.environment_digest,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineerVerifierPhaseV1 {
    Planned,
    Engineering,
    RetryPending,
    Verifying,
    Reviewing,
    Failed,
    Cancelled,
}

impl EngineerVerifierPhaseV1 {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Reviewing | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineerVerifierTriggerV1 {
    ClaimAccepted,
    CancellationAccepted,
    EngineerCompleted,
    ExecutorOutcomeUnknown,
    RetryRequired,
    RetryClaimAccepted,
    RetryExhausted,
    FailureRecorded,
    VerificationEvidenceAccepted,
}

pub fn transition_allowed(
    from: EngineerVerifierPhaseV1,
    trigger: EngineerVerifierTriggerV1,
    to: EngineerVerifierPhaseV1,
) -> bool {
    use EngineerVerifierPhaseV1 as P;
    use EngineerVerifierTriggerV1 as T;
    matches!(
        (from, trigger, to),
        (P::Planned, T::ClaimAccepted, P::Engineering)
            | (P::Planned, T::CancellationAccepted, P::Cancelled)
            | (P::Engineering, T::EngineerCompleted, P::Verifying)
            | (P::Engineering, T::RetryRequired, P::RetryPending)
            | (P::Engineering, T::ExecutorOutcomeUnknown, P::Failed)
            | (P::Engineering, T::FailureRecorded, P::Failed)
            | (P::Engineering, T::CancellationAccepted, P::Cancelled)
            | (P::RetryPending, T::RetryClaimAccepted, P::Engineering)
            | (P::RetryPending, T::RetryExhausted, P::Failed)
            | (P::RetryPending, T::CancellationAccepted, P::Cancelled)
            | (P::Verifying, T::VerificationEvidenceAccepted, P::Reviewing)
            | (P::Verifying, T::FailureRecorded, P::Failed)
            | (P::Verifying, T::CancellationAccepted, P::Cancelled)
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersistedRoleExecutionUsageV1 {
    Unavailable,
    Reported { input_units: u64, output_units: u64 },
}

impl From<&RoleExecutionUsage> for PersistedRoleExecutionUsageV1 {
    fn from(value: &RoleExecutionUsage) -> Self {
        match value {
            RoleExecutionUsage::Unavailable => Self::Unavailable,
            RoleExecutionUsage::Reported {
                input_units,
                output_units,
            } => Self::Reported {
                input_units: *input_units,
                output_units: *output_units,
            },
        }
    }
}

impl PersistedRoleExecutionUsageV1 {
    fn validate(&self) -> Result<(), EngineerVerifierError> {
        if let Self::Reported {
            input_units,
            output_units,
        } = self
        {
            input_units
                .checked_add(*output_units)
                .ok_or(EngineerVerifierError::Overflow)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedRoleRetryCauseV1 {
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersistedRoleExecutionOutcomeV1 {
    Completed {
        result: RoleResultV1,
        usage: PersistedRoleExecutionUsageV1,
    },
    Failed {
        result: RoleResultV1,
        usage: PersistedRoleExecutionUsageV1,
    },
    TimedOut {
        result: RoleResultV1,
        usage: PersistedRoleExecutionUsageV1,
    },
    Cancelled {
        result: RoleResultV1,
        usage: PersistedRoleExecutionUsageV1,
    },
    RetryRequired {
        completed_attempt: u32,
        next_attempt: u32,
        cause: PersistedRoleRetryCauseV1,
        usage: PersistedRoleExecutionUsageV1,
    },
}

impl PersistedRoleExecutionOutcomeV1 {
    pub fn try_from_live(
        outcome: &RoleExecutionOutcome,
        request: &RoleExecutionRequest,
    ) -> Result<Self, EngineerVerifierError> {
        outcome
            .validate_against(request)
            .map_err(|_| EngineerVerifierError::InvalidExecutorOutcome)?;
        let persisted = match outcome {
            RoleExecutionOutcome::Completed { result, usage } => Self::Completed {
                result: result.clone(),
                usage: usage.into(),
            },
            RoleExecutionOutcome::Failed { result, usage } => Self::Failed {
                result: result.clone(),
                usage: usage.into(),
            },
            RoleExecutionOutcome::TimedOut { result, usage } => Self::TimedOut {
                result: result.clone(),
                usage: usage.into(),
            },
            RoleExecutionOutcome::Cancelled { result, usage } => Self::Cancelled {
                result: result.clone(),
                usage: usage.into(),
            },
            RoleExecutionOutcome::RetryRequired {
                completed_attempt,
                next_attempt,
                cause,
                usage,
            } => Self::RetryRequired {
                completed_attempt: *completed_attempt,
                next_attempt: *next_attempt,
                cause: match cause {
                    RoleRetryCause::Failed => PersistedRoleRetryCauseV1::Failed,
                    RoleRetryCause::TimedOut => PersistedRoleRetryCauseV1::TimedOut,
                },
                usage: usage.into(),
            },
        };
        persisted.validate_against(request)?;
        Ok(persisted)
    }

    pub fn validate_against(
        &self,
        request: &RoleExecutionRequest,
    ) -> Result<(), EngineerVerifierError> {
        request
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidExecutorOutcome)?;
        let (result, state, usage) = match self {
            Self::Completed { result, usage } => {
                (Some(result), Some(ControlPlaneState::Completed), usage)
            }
            Self::Failed { result, usage } => {
                (Some(result), Some(ControlPlaneState::Failed), usage)
            }
            Self::TimedOut { result, usage } => {
                (Some(result), Some(ControlPlaneState::Failed), usage)
            }
            Self::Cancelled { result, usage } => {
                (Some(result), Some(ControlPlaneState::Cancelled), usage)
            }
            Self::RetryRequired {
                completed_attempt,
                next_attempt,
                usage,
                ..
            } => {
                let expected = request
                    .attempt
                    .checked_add(1)
                    .ok_or(EngineerVerifierError::Overflow)?;
                if *completed_attempt != request.attempt
                    || *next_attempt != expected
                    || *next_attempt > request.invocation.budget.max_attempts
                {
                    return Err(EngineerVerifierError::InvalidExecutorOutcome);
                }
                (None, None, usage)
            }
        };
        usage.validate()?;
        if let (Some(result), Some(state)) = (result, state) {
            result
                .validate_against(&request.invocation)
                .map_err(|_| EngineerVerifierError::InvalidExecutorOutcome)?;
            if result.attempt != request.attempt || result.state != state {
                return Err(EngineerVerifierError::InvalidExecutorOutcome);
            }
        }
        Ok(())
    }

    pub fn outcome_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(ROLE_OUTCOME_DOMAIN, self)
    }

    pub fn result(&self) -> Option<&RoleResultV1> {
        match self {
            Self::Completed { result, .. }
            | Self::Failed { result, .. }
            | Self::TimedOut { result, .. }
            | Self::Cancelled { result, .. } => Some(result),
            Self::RetryRequired { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // Frozen V1 DTO keeps the outcome inline and byte-stable.
pub enum ExecutorCallStateV1 {
    NotStarted,
    Started {
        request_digest: String,
        attempt: u32,
        started_at: DateTime<Utc>,
    },
    OutcomeRecorded {
        request_digest: String,
        attempt: u32,
        started_at: DateTime<Utc>,
        outcome: PersistedRoleExecutionOutcomeV1,
        outcome_digest: String,
        recorded_at: DateTime<Utc>,
    },
}

impl ExecutorCallStateV1 {
    fn validate(
        &self,
        binding: &EngineerExecutionBindingV1,
        invocation: &RoleInvocationV1,
    ) -> Result<(), EngineerVerifierError> {
        binding.validate()?;
        match self {
            Self::NotStarted => Ok(()),
            Self::Started {
                request_digest,
                attempt,
                started_at,
            } => validate_executor_binding(request_digest, *attempt, *started_at, binding),
            Self::OutcomeRecorded {
                request_digest,
                attempt,
                started_at,
                outcome,
                outcome_digest,
                recorded_at,
            } => {
                validate_executor_binding(request_digest, *attempt, *started_at, binding)?;
                if *recorded_at < *started_at || outcome.outcome_digest()? != *outcome_digest {
                    return Err(EngineerVerifierError::InvalidExecutorOutcome);
                }
                outcome.validate_against(&RoleExecutionRequest {
                    invocation: invocation.clone(),
                    attempt: *attempt,
                })
            }
        }
    }
}

fn validate_executor_binding(
    request_digest: &str,
    attempt: u32,
    started_at: DateTime<Utc>,
    binding: &EngineerExecutionBindingV1,
) -> Result<(), EngineerVerifierError> {
    if request_digest != binding.execution_binding_digest
        || attempt != binding.attempt
        || !is_millisecond_precision(started_at)
    {
        return Err(EngineerVerifierError::InvalidExecutorOutcome);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableToolObservationV1 {
    pub receipt: ToolReceiptV1,
    pub receipt_bytes: Vec<u8>,
    pub receipt_digest: String,
    pub after_snapshot: WorkspaceSnapshotV1,
    pub admitted_at: DateTime<Utc>,
}

impl DurableToolObservationV1 {
    pub fn try_new(
        receipt: ToolReceiptV1,
        after_snapshot: WorkspaceSnapshotV1,
        admitted_at: DateTime<Utc>,
    ) -> Result<Self, EngineerVerifierError> {
        receipt
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        after_snapshot
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        let receipt_bytes = receipt
            .canonical_json_bytes()
            .map_err(|_| EngineerVerifierError::Serialization)?;
        let receipt_digest = verification_sha256_hex(&receipt_bytes);
        let value = Self {
            receipt,
            receipt_bytes,
            receipt_digest,
            after_snapshot,
            admitted_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        self.receipt
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        self.after_snapshot
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        if self
            .receipt
            .canonical_json_bytes()
            .map_err(|_| EngineerVerifierError::Serialization)?
            != self.receipt_bytes
            || verification_sha256_hex(&self.receipt_bytes) != self.receipt_digest
            || self.receipt.after_snapshot_digest != self.after_snapshot.snapshot_digest
            || self.receipt.after_generation != self.after_snapshot.generation
            || !is_millisecond_precision(self.admitted_at)
        {
            return Err(EngineerVerifierError::InvalidLedger);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWriteEffectV1 {
    pub contract_version: u32,
    pub ordinal: u32,
    pub effect_id: String,
    pub request: ToolRequestV1,
    pub request_digest: String,
    pub payload_sha256: String,
    pub lease_digest: String,
    pub grant_digest: String,
    pub expected_before_snapshot: WorkspaceSnapshotV1,
    pub expected_before_file: Option<WorkspaceFileV1>,
    pub intended_after_snapshot: WorkspaceSnapshotV1,
    pub intended_after_file: WorkspaceFileV1,
    pub reserved_sequence: u64,
    pub prepared_at: DateTime<Utc>,
}

impl PreparedWriteEffectV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.effect_id, "effect_id")
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        self.request
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        for digest in [
            &self.request_digest,
            &self.payload_sha256,
            &self.lease_digest,
            &self.grant_digest,
        ] {
            validate_digest(digest)?;
        }
        self.expected_before_snapshot
            .validate()
            .and_then(|_| self.intended_after_snapshot.validate())
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        if let Some(file) = &self.expected_before_file {
            file.validate()
                .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        }
        self.intended_after_file
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        let ToolOperationV1::WriteFile {
            logical_path,
            content_sha256,
            byte_length,
        } = &self.request.operation
        else {
            return Err(EngineerVerifierError::InvalidLedger);
        };
        let actual_before_file = self
            .expected_before_snapshot
            .files
            .iter()
            .find(|file| file.logical_path == *logical_path);
        let mut exact_after_files = self.expected_before_snapshot.files.clone();
        match exact_after_files.binary_search_by(|file| file.logical_path.cmp(logical_path)) {
            Ok(index) => exact_after_files[index] = self.intended_after_file.clone(),
            Err(index) => exact_after_files.insert(index, self.intended_after_file.clone()),
        }
        if self
            .request
            .canonical_digest()
            .map_err(|_| EngineerVerifierError::InvalidLedger)?
            != self.request_digest
            || self.request.lease_digest != self.lease_digest
            || self.request.grant_digest != self.grant_digest
            || self.request.expected_snapshot_digest
                != self.expected_before_snapshot.snapshot_digest
            || self.expected_before_snapshot.generation.checked_add(1)
                != Some(self.intended_after_snapshot.generation)
            || self.expected_before_snapshot.workspace_id
                != self.intended_after_snapshot.workspace_id
            || self.expected_before_snapshot.lease_id != self.intended_after_snapshot.lease_id
            || self.intended_after_file.logical_path != *logical_path
            || self.intended_after_file.sha256 != *content_sha256
            || self.intended_after_file.byte_length != *byte_length
            || self.payload_sha256 != *content_sha256
            || actual_before_file != self.expected_before_file.as_ref()
            || self.expected_before_file.as_ref() == Some(&self.intended_after_file)
            || self.intended_after_snapshot.files != exact_after_files
            || self.reserved_sequence == 0
            || !is_millisecond_precision(self.prepared_at)
        {
            return Err(EngineerVerifierError::InvalidLedger);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteReconciliationV1 {
    pub contract_version: u32,
    pub effect_id: String,
    pub request_digest: String,
    pub expected_before_snapshot_digest: String,
    pub intended_after_snapshot_digest: String,
    pub observed_snapshot_digest: String,
    pub reconciled_at: DateTime<Utc>,
    pub reconciliation_digest: String,
}

#[derive(Serialize)]
struct WriteReconciliationDigestInputV1<'a> {
    contract_version: u32,
    effect_id: &'a str,
    request_digest: &'a str,
    expected_before_snapshot_digest: &'a str,
    intended_after_snapshot_digest: &'a str,
    observed_snapshot_digest: &'a str,
    reconciled_at: DateTime<Utc>,
}

impl WriteReconciliationV1 {
    pub fn try_new(
        prepared: &PreparedWriteEffectV1,
        observed_snapshot_digest: String,
        reconciled_at: DateTime<Utc>,
    ) -> Result<Self, EngineerVerifierError> {
        prepared.validate()?;
        let mut value = Self {
            contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
            effect_id: prepared.effect_id.clone(),
            request_digest: prepared.request_digest.clone(),
            expected_before_snapshot_digest: prepared
                .expected_before_snapshot
                .snapshot_digest
                .clone(),
            intended_after_snapshot_digest: prepared
                .intended_after_snapshot
                .snapshot_digest
                .clone(),
            observed_snapshot_digest,
            reconciled_at,
            reconciliation_digest: String::new(),
        };
        value.reconciliation_digest = value.computed_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        validate_stable_id(&self.effect_id, "effect_id")
            .map_err(|_| EngineerVerifierError::InvalidLedger)?;
        for value in [
            &self.request_digest,
            &self.expected_before_snapshot_digest,
            &self.intended_after_snapshot_digest,
            &self.observed_snapshot_digest,
            &self.reconciliation_digest,
        ] {
            validate_digest(value)?;
        }
        if self.expected_before_snapshot_digest == self.intended_after_snapshot_digest
            || self.observed_snapshot_digest != self.intended_after_snapshot_digest
            || !is_millisecond_precision(self.reconciled_at)
            || self.computed_digest()? != self.reconciliation_digest
        {
            return Err(EngineerVerifierError::InvalidLedger);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            RECONCILIATION_DOMAIN,
            &WriteReconciliationDigestInputV1 {
                contract_version: self.contract_version,
                effect_id: &self.effect_id,
                request_digest: &self.request_digest,
                expected_before_snapshot_digest: &self.expected_before_snapshot_digest,
                intended_after_snapshot_digest: &self.intended_after_snapshot_digest,
                observed_snapshot_digest: &self.observed_snapshot_digest,
                reconciled_at: self.reconciled_at,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierExecutionLimitsV1 {
    pub timeout_millis: u64,
    pub stdout_cap_bytes: u64,
    pub stderr_cap_bytes: u64,
}

impl VerifierExecutionLimitsV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        if self.timeout_millis == 0
            || self.timeout_millis > 86_400_000
            || self.stdout_cap_bytes > 16_777_216
            || self.stderr_cap_bytes > 16_777_216
        {
            return Err(EngineerVerifierError::InvalidVerifierReplay);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedInitialProjectionV1 {
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReplayPlanV1 {
    pub contract_version: u32,
    pub evidence_key: EvidenceKey,
    pub attempt: u32,
    pub created_at: DateTime<Utc>,
    pub implementation_actor: WorkerId,
    pub verifier_actor: WorkerId,
    pub limits: VerifierExecutionLimitsV1,
    pub behavior_sha256: String,
    pub capabilities_sha256: String,
    pub selection_sha256: String,
    pub source_manifest_sha256: String,
    pub failure_identities_sha256: String,
    pub executable_profiles_identity_sha256: String,
    pub environment_names: Vec<String>,
    pub environment_digest: String,
    pub sealed_workspace_snapshot_digest: String,
    pub source_manifest_fingerprint: String,
    pub workspace_bridge_digest: String,
    pub expected_initial_projection: ExpectedInitialProjectionV1,
    pub replay_plan_digest: String,
}

#[derive(Serialize)]
struct VerifierReplayPlanDigestInputV1<'a> {
    contract_version: u32,
    evidence_key: &'a EvidenceKey,
    attempt: u32,
    created_at: DateTime<Utc>,
    implementation_actor: &'a WorkerId,
    verifier_actor: &'a WorkerId,
    limits: &'a VerifierExecutionLimitsV1,
    behavior_sha256: &'a str,
    capabilities_sha256: &'a str,
    selection_sha256: &'a str,
    source_manifest_sha256: &'a str,
    failure_identities_sha256: &'a str,
    executable_profiles_identity_sha256: &'a str,
    environment_names: &'a [String],
    environment_digest: &'a str,
    sealed_workspace_snapshot_digest: &'a str,
    source_manifest_fingerprint: &'a str,
    workspace_bridge_digest: &'a str,
    expected_initial_projection: &'a ExpectedInitialProjectionV1,
}

impl VerifierReplayPlanV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        if self.attempt == 0
            || self.implementation_actor == self.verifier_actor
            || !is_millisecond_precision(self.created_at)
        {
            return Err(EngineerVerifierError::InvalidVerifierReplay);
        }
        for id in [
            self.evidence_key.run_id.as_str(),
            self.evidence_key.goal_id.as_str(),
            self.evidence_key.task_id.as_str(),
            self.implementation_actor.as_str(),
            self.verifier_actor.as_str(),
        ] {
            validate_stable_id(id, "verifier_replay_id")
                .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
        }
        self.limits.validate()?;
        for digest in [
            &self.behavior_sha256,
            &self.capabilities_sha256,
            &self.selection_sha256,
            &self.source_manifest_sha256,
            &self.failure_identities_sha256,
            &self.executable_profiles_identity_sha256,
            &self.environment_digest,
            &self.sealed_workspace_snapshot_digest,
            &self.source_manifest_fingerprint,
            &self.workspace_bridge_digest,
            &self.replay_plan_digest,
        ] {
            validate_digest(digest)?;
        }
        validate_sorted_names(&self.environment_names)?;
        if self.computed_digest()? != self.replay_plan_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            VERIFIER_REPLAY_DOMAIN,
            &VerifierReplayPlanDigestInputV1 {
                contract_version: self.contract_version,
                evidence_key: &self.evidence_key,
                attempt: self.attempt,
                created_at: self.created_at,
                implementation_actor: &self.implementation_actor,
                verifier_actor: &self.verifier_actor,
                limits: &self.limits,
                behavior_sha256: &self.behavior_sha256,
                capabilities_sha256: &self.capabilities_sha256,
                selection_sha256: &self.selection_sha256,
                source_manifest_sha256: &self.source_manifest_sha256,
                failure_identities_sha256: &self.failure_identities_sha256,
                executable_profiles_identity_sha256: &self.executable_profiles_identity_sha256,
                environment_names: &self.environment_names,
                environment_digest: &self.environment_digest,
                sealed_workspace_snapshot_digest: &self.sealed_workspace_snapshot_digest,
                source_manifest_fingerprint: &self.source_manifest_fingerprint,
                workspace_bridge_digest: &self.workspace_bridge_digest,
                expected_initial_projection: &self.expected_initial_projection,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedVerificationTranscriptV1 {
    pub commands: Vec<VerificationTranscriptCommandIdentity>,
}

impl PersistedVerificationTranscriptV1 {
    pub fn from_live(
        value: &VerificationTranscriptIdentity,
    ) -> Result<Self, EngineerVerifierError> {
        value
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
        Ok(Self {
            commands: value.commands.clone(),
        })
    }

    pub fn to_live(&self) -> Result<VerificationTranscriptIdentity, EngineerVerifierError> {
        let value = VerificationTranscriptIdentity {
            commands: self.commands.clone(),
        };
        value
            .validate()
            .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<String, EngineerVerifierError> {
        self.to_live()?
            .sha256()
            .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifierExecutionStateV1 {
    NotStarted {
        replay_plan_digest: String,
    },
    Started {
        replay_plan_digest: String,
        started_at: DateTime<Utc>,
    },
    PublicationObserved {
        replay_plan_digest: String,
        transcript: PersistedVerificationTranscriptV1,
        transcript_digest: String,
        bundle: VerificationBundle,
        bundle_record_digest: String,
        evidence_current: EvidenceCurrent,
        observed_at: DateTime<Utc>,
    },
    Admitted {
        replay_plan_digest: String,
        transcript: PersistedVerificationTranscriptV1,
        transcript_digest: String,
        bundle: VerificationBundle,
        bundle_record_digest: String,
        evidence_current: EvidenceCurrent,
        observed_at: DateTime<Utc>,
        admitted_at: DateTime<Utc>,
    },
}

impl VerifierExecutionStateV1 {
    pub fn validate(&self, plan: &VerifierReplayPlanV1) -> Result<(), EngineerVerifierError> {
        plan.validate()?;
        match self {
            Self::NotStarted { replay_plan_digest } => {
                validate_replay_identity(replay_plan_digest, plan)
            }
            Self::Started {
                replay_plan_digest,
                started_at,
            } => {
                validate_replay_identity(replay_plan_digest, plan)?;
                if !is_millisecond_precision(*started_at) {
                    return Err(EngineerVerifierError::InvalidVerifierReplay);
                }
                Ok(())
            }
            Self::PublicationObserved {
                replay_plan_digest,
                transcript,
                transcript_digest,
                bundle,
                bundle_record_digest,
                evidence_current,
                observed_at,
            } => validate_publication(
                replay_plan_digest,
                transcript,
                transcript_digest,
                bundle,
                bundle_record_digest,
                evidence_current,
                *observed_at,
                None,
                plan,
            ),
            Self::Admitted {
                replay_plan_digest,
                transcript,
                transcript_digest,
                bundle,
                bundle_record_digest,
                evidence_current,
                observed_at,
                admitted_at,
            } => validate_publication(
                replay_plan_digest,
                transcript,
                transcript_digest,
                bundle,
                bundle_record_digest,
                evidence_current,
                *observed_at,
                Some(*admitted_at),
                plan,
            ),
        }
    }

    pub fn transcript_digest(&self) -> Option<&str> {
        match self {
            Self::PublicationObserved {
                transcript_digest, ..
            }
            | Self::Admitted {
                transcript_digest, ..
            } => Some(transcript_digest),
            Self::NotStarted { .. } | Self::Started { .. } => None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_publication(
    replay_plan_digest: &str,
    transcript: &PersistedVerificationTranscriptV1,
    transcript_digest: &str,
    bundle: &VerificationBundle,
    bundle_record_digest: &str,
    evidence_current: &EvidenceCurrent,
    observed_at: DateTime<Utc>,
    admitted_at: Option<DateTime<Utc>>,
    plan: &VerifierReplayPlanV1,
) -> Result<(), EngineerVerifierError> {
    validate_replay_identity(replay_plan_digest, plan)?;
    validate_digest(transcript_digest)?;
    validate_digest(bundle_record_digest)?;
    bundle
        .validate()
        .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
    evidence_current
        .validate_state_digest()
        .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
    let bundle_bytes = bundle
        .canonical_json_bytes()
        .map_err(|_| EngineerVerifierError::InvalidVerifierReplay)?;
    if transcript.digest()? != transcript_digest
        || verification_sha256_hex(&bundle_bytes) != bundle_record_digest
        || evidence_current.key != plan.evidence_key
        || evidence_current.record_digest != bundle_record_digest
        || evidence_current.bundle_id != bundle.bundle_id
        || bundle.run_id != plan.evidence_key.run_id
        || bundle.goal_id != plan.evidence_key.goal_id
        || bundle.task_id != plan.evidence_key.task_id
        || bundle.implementation_actor != plan.implementation_actor
        || bundle.verifier_actor != plan.verifier_actor
        || !is_millisecond_precision(observed_at)
        || admitted_at.is_some_and(|at| at < observed_at || !is_millisecond_precision(at))
    {
        return Err(EngineerVerifierError::InvalidVerifierReplay);
    }
    Ok(())
}

fn validate_replay_identity(
    digest: &str,
    plan: &VerifierReplayPlanV1,
) -> Result<(), EngineerVerifierError> {
    if digest != plan.replay_plan_digest {
        return Err(EngineerVerifierError::InvalidVerifierReplay);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineerVerifierPhaseProjectionV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub from: EngineerVerifierPhaseV1,
    pub to: EngineerVerifierPhaseV1,
    pub trigger: EngineerVerifierTriggerV1,
    pub phase_revision: u64,
    pub attempt: u32,
    pub execution_binding_digest: String,
    pub logical_plan_digest: String,
    pub state_digest: String,
    pub resolved_effect_ledger_digest: String,
    pub engineer_result_digest: Option<String>,
    pub verifier_transcript_digest: Option<String>,
    pub controller_time: DateTime<Utc>,
}

impl EngineerVerifierPhaseProjectionV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        if self.phase_revision == 0
            || self.attempt == 0
            || !transition_allowed(self.from, self.trigger, self.to)
            || !is_millisecond_precision(self.controller_time)
        {
            return Err(EngineerVerifierError::InvalidProjection);
        }
        for value in [
            &self.execution_binding_digest,
            &self.logical_plan_digest,
            &self.state_digest,
            &self.resolved_effect_ledger_digest,
        ] {
            validate_digest(value)?;
        }
        if let Some(value) = &self.engineer_result_digest {
            validate_digest(value)?;
        }
        if let Some(value) = &self.verifier_transcript_digest {
            validate_digest(value)?;
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, EngineerVerifierError> {
        self.validate()?;
        canonical_json(self)
    }
}

#[derive(Serialize)]
struct PhaseEventIdentityInputV1<'a> {
    contract_version: u32,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    phase_revision: u64,
    from: EngineerVerifierPhaseV1,
    to: EngineerVerifierPhaseV1,
    trigger: EngineerVerifierTriggerV1,
    attempt: u32,
    state_digest: &'a str,
}

pub fn derive_phase_event_id(
    projection: &EngineerVerifierPhaseProjectionV1,
) -> Result<String, EngineerVerifierError> {
    projection.validate()?;
    let digest = domain_digest(
        PHASE_EVENT_DOMAIN,
        &PhaseEventIdentityInputV1 {
            contract_version: projection.contract_version,
            run_id: &projection.run_id,
            goal_id: &projection.goal_id,
            task_id: &projection.task_id,
            phase_revision: projection.phase_revision,
            from: projection.from,
            to: projection.to,
            trigger: projection.trigger,
            attempt: projection.attempt,
            state_digest: &projection.state_digest,
        },
    )?;
    let event_id = format!("event.{digest}");
    validate_stable_id(&event_id, "event_id")
        .map_err(|_| EngineerVerifierError::InvalidProjection)?;
    Ok(event_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPhaseProjectionV1 {
    pub event_id: String,
    pub sequence: u64,
    pub previous_event_id: Option<String>,
    pub event_bytes: Vec<u8>,
    pub event_digest: String,
}

impl PendingPhaseProjectionV1 {
    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_stable_id(&self.event_id, "event_id")
            .map_err(|_| EngineerVerifierError::InvalidProjection)?;
        if let Some(previous) = &self.previous_event_id {
            validate_stable_id(previous, "previous_event_id")
                .map_err(|_| EngineerVerifierError::InvalidProjection)?;
        }
        if (self.sequence == 0) != self.previous_event_id.is_none()
            || verification_sha256_hex(&self.event_bytes) != self.event_digest
        {
            return Err(EngineerVerifierError::InvalidProjection);
        }
        validate_digest(&self.event_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableWorkspaceAuthorityV1 {
    pub lease: WorkspaceLeaseV1,
    pub lease_digest: String,
    pub initial_snapshot: WorkspaceSnapshotV1,
    pub grant: ovca_types::tool_boundary::CapabilityGrantV1,
    pub grant_digest: String,
    pub current_snapshot: WorkspaceSnapshotV1,
    pub recovery_token: String,
    pub runtime_instance_id: String,
    pub fence: u64,
    pub runtime_epoch: u64,
    pub heartbeat_at: DateTime<Utc>,
    pub next_receipt_sequence: u64,
    pub cleanup_required: bool,
    pub closed: bool,
}

impl DurableWorkspaceAuthorityV1 {
    pub fn authorizes_time(&self, invocation: &RoleInvocationV1, at: DateTime<Utc>) -> bool {
        at >= self.lease.issued_at
            && at < self.lease.expires_at
            && at >= self.grant.valid_from
            && at < self.grant.valid_until
            && authority_authorizes_time(&invocation.authority, at)
            && authority_authorizes_time(&self.grant.grant_authority, at)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        self.lease
            .validate()
            .and_then(|_| self.initial_snapshot.validate())
            .and_then(|_| self.grant.validate())
            .and_then(|_| self.current_snapshot.validate())
            .map_err(|_| EngineerVerifierError::InvalidBinding)?;
        validate_digest(&self.lease_digest)?;
        validate_digest(&self.grant_digest)?;
        validate_stable_id(&self.recovery_token, "recovery_token")
            .map_err(|_| EngineerVerifierError::InvalidBinding)?;
        validate_stable_id(&self.runtime_instance_id, "runtime_instance_id")
            .map_err(|_| EngineerVerifierError::InvalidBinding)?;
        if self
            .lease
            .canonical_digest()
            .map_err(|_| EngineerVerifierError::InvalidBinding)?
            != self.lease_digest
            || self
                .grant
                .canonical_digest()
                .map_err(|_| EngineerVerifierError::InvalidBinding)?
                != self.grant_digest
            || self.initial_snapshot.snapshot_digest != self.lease.initial_snapshot_digest
            || self.initial_snapshot.workspace_id != self.lease.workspace_id
            || self.initial_snapshot.lease_id != self.lease.lease_id
            || self.initial_snapshot.generation != 0
            || self.grant.lease_id != self.lease.lease_id
            || self.grant.lease_digest != self.lease_digest
            || self.grant.snapshot_digest != self.initial_snapshot.snapshot_digest
            || self.current_snapshot.workspace_id != self.lease.workspace_id
            || self.current_snapshot.lease_id != self.lease.lease_id
            || self.fence == 0
            || self.runtime_epoch == 0
            || self.next_receipt_sequence == 0
            || !is_millisecond_precision(self.heartbeat_at)
            || (self.closed && self.cleanup_required)
        {
            return Err(EngineerVerifierError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRecordV1 {
    pub request_id: String,
    pub requested_at: DateTime<Utc>,
}

impl CancellationRecordV1 {
    pub fn try_new(
        request_id: impl Into<String>,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, EngineerVerifierError> {
        let value = Self {
            request_id: request_id.into(),
            requested_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_stable_id(&self.request_id, "cancellation_request_id")
            .map_err(|_| EngineerVerifierError::InvalidState)?;
        if !is_millisecond_precision(self.requested_at) {
            return Err(EngineerVerifierError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineerVerifierStateV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub goal_id: GoalId,
    pub task_id: TaskId,
    pub plan: EngineerLogicalPlanV1,
    pub phase: EngineerVerifierPhaseV1,
    pub phase_revision: u64,
    pub attempt: u32,
    pub execution_binding: EngineerExecutionBindingV1,
    pub executor: ExecutorCallStateV1,
    pub workspace: Option<DurableWorkspaceAuthorityV1>,
    pub ledger: ResolvedEffectLedgerV1,
    pub prepared_write: Option<PreparedWriteEffectV1>,
    pub tool_observations: Vec<DurableToolObservationV1>,
    pub write_reconciliation: Option<WriteReconciliationV1>,
    pub engineer_result: Option<RoleResultV1>,
    pub engineer_result_digest: Option<String>,
    pub workspace_bridge: Option<WorkspaceDiffBridgeV1>,
    pub cancellation: Option<CancellationRecordV1>,
    pub pending_projection: Option<PendingPhaseProjectionV1>,
    pub projected_sequence: Option<u64>,
    pub projected_event_id: Option<String>,
    pub verifier_replay_plan: Option<VerifierReplayPlanV1>,
    pub verifier: Option<VerifierExecutionStateV1>,
    pub controller_time: DateTime<Utc>,
    pub state_digest: String,
}

#[derive(Serialize)]
struct EngineerVerifierStateDigestInputV1<'a> {
    contract_version: u32,
    run_id: &'a RunId,
    goal_id: &'a GoalId,
    task_id: &'a TaskId,
    phase: EngineerVerifierPhaseV1,
    phase_revision: u64,
    attempt: u32,
    logical_plan_digest: &'a str,
    execution_binding_digest: &'a str,
    resolved_effect_ledger_digest: &'a str,
    engineer_result_digest: Option<&'a str>,
    verifier_transcript_digest: Option<&'a str>,
}

impl EngineerVerifierStateV1 {
    pub fn planned(
        plan: EngineerLogicalPlanV1,
        controller_time: DateTime<Utc>,
    ) -> Result<Self, EngineerVerifierError> {
        plan.validate()?;
        if !is_millisecond_precision(controller_time) {
            return Err(EngineerVerifierError::InvalidState);
        }
        let attempt = 1;
        let execution_binding =
            EngineerExecutionBindingV1::try_new(plan.invocation_digest.clone(), attempt)?;
        let ledger = ResolvedEffectLedgerV1::empty(&plan, attempt)?;
        let mut state = Self {
            contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
            run_id: plan.run_id.clone(),
            goal_id: plan.goal_id.clone(),
            task_id: plan.task_id.clone(),
            plan,
            phase: EngineerVerifierPhaseV1::Planned,
            phase_revision: 0,
            attempt,
            execution_binding,
            executor: ExecutorCallStateV1::NotStarted,
            workspace: None,
            ledger,
            prepared_write: None,
            tool_observations: Vec::new(),
            write_reconciliation: None,
            engineer_result: None,
            engineer_result_digest: None,
            workspace_bridge: None,
            cancellation: None,
            pending_projection: None,
            projected_sequence: None,
            projected_event_id: None,
            verifier_replay_plan: None,
            verifier: None,
            controller_time,
            state_digest: String::new(),
        };
        state.state_digest = state.computed_state_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), EngineerVerifierError> {
        validate_version(self.contract_version)?;
        self.plan.validate()?;
        self.execution_binding.validate()?;
        self.ledger.validate_against(&self.plan)?;
        if self.run_id != self.plan.run_id
            || self.goal_id != self.plan.goal_id
            || self.task_id != self.plan.task_id
            || self.attempt != self.execution_binding.attempt
            || self.attempt != self.ledger.attempt
            || self.attempt > self.plan.invocation.budget.max_attempts
            || !is_millisecond_precision(self.controller_time)
        {
            return Err(EngineerVerifierError::InvalidState);
        }
        self.executor
            .validate(&self.execution_binding, &self.plan.invocation)?;
        if let Some(workspace) = &self.workspace {
            workspace.validate()?;
            if workspace.lease.attempt != self.attempt
                || workspace.lease.invocation_digest != self.plan.invocation_digest
                || !workspace.authorizes_time(&self.plan.invocation, workspace.heartbeat_at)
            {
                return Err(EngineerVerifierError::InvalidState);
            }
        }
        if let Some(prepared) = &self.prepared_write {
            prepared.validate()?;
            let template = self
                .plan
                .ordered_effects
                .get(prepared.ordinal as usize)
                .ok_or(EngineerVerifierError::InvalidState)?;
            let identity = derive_tool_identity(&self.plan, &prepared.effect_id, self.attempt)?;
            let workspace = self
                .workspace
                .as_ref()
                .ok_or(EngineerVerifierError::InvalidState)?;
            if self.ledger.entries.len() != prepared.ordinal as usize
                || template.effect_id != prepared.effect_id
                || template.operation != prepared.request.operation
                || template.payload_sha256 != prepared.payload_sha256
                || prepared.request.request_id != identity.request_id
                || prepared.request.idempotency_key != identity.idempotency_key
                || prepared.request.invocation_digest != self.plan.invocation_digest
                || prepared.request.attempt != self.attempt
                || prepared.request.lease_digest != workspace.lease_digest
                || prepared.request.grant_digest != workspace.grant_digest
                || prepared.expected_before_snapshot != workspace.current_snapshot
                || prepared.reserved_sequence != workspace.next_receipt_sequence
                || prepared.expected_before_file.as_ref() == Some(&prepared.intended_after_file)
            {
                return Err(EngineerVerifierError::InvalidState);
            }
        }
        for observation in &self.tool_observations {
            observation.validate()?;
        }
        let observed_entries = self
            .ledger
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .tool_receipt_digest
                    .as_ref()
                    .map(|digest| (entry, digest))
            })
            .collect::<Vec<_>>();
        if observed_entries.len() != self.tool_observations.len()
            || observed_entries.iter().zip(&self.tool_observations).any(
                |((entry, digest), observation)| {
                    *digest != &observation.receipt_digest
                        || entry.request_id != observation.receipt.request_id
                        || entry.after_snapshot_digest != observation.after_snapshot.snapshot_digest
                },
            )
        {
            return Err(EngineerVerifierError::InvalidState);
        }
        if let Some(reconciliation) = &self.write_reconciliation {
            reconciliation.validate()?;
            if !self.ledger.entries.iter().any(|entry| {
                entry.reconciliation_digest.as_ref() == Some(&reconciliation.reconciliation_digest)
                    && entry.effect_id == reconciliation.effect_id
                    && entry.request_digest == reconciliation.request_digest
            }) {
                return Err(EngineerVerifierError::InvalidState);
            }
        }
        match (&self.engineer_result, &self.engineer_result_digest) {
            (Some(result), Some(digest)) => {
                result
                    .validate_against(&self.plan.invocation)
                    .map_err(|_| EngineerVerifierError::InvalidState)?;
                if result.attempt != self.attempt
                    || result
                        .canonical_digest()
                        .map_err(|_| EngineerVerifierError::InvalidState)?
                        != *digest
                {
                    return Err(EngineerVerifierError::InvalidState);
                }
            }
            (None, None) => {}
            _ => return Err(EngineerVerifierError::InvalidState),
        }
        if let Some(bridge) = &self.workspace_bridge {
            bridge.validate()?;
            if bridge.run_id != self.run_id
                || bridge.goal_id != self.goal_id
                || bridge.task_id != self.task_id
                || bridge.attempt != self.attempt
                || Some(&bridge.engineer_result_digest) != self.engineer_result_digest.as_ref()
            {
                return Err(EngineerVerifierError::InvalidState);
            }
        }
        if let Some(cancellation) = &self.cancellation {
            cancellation.validate()?;
        }
        if let Some(pending) = &self.pending_projection {
            pending.validate()?;
        }
        if (self.projected_sequence.is_some()) != (self.projected_event_id.is_some()) {
            return Err(EngineerVerifierError::InvalidState);
        }
        if let Some(id) = &self.projected_event_id {
            validate_stable_id(id, "projected_event_id")
                .map_err(|_| EngineerVerifierError::InvalidState)?;
        }
        match (&self.verifier_replay_plan, &self.verifier) {
            (Some(plan), Some(state)) => state.validate(plan)?,
            (None, None) => {}
            _ => return Err(EngineerVerifierError::InvalidState),
        }
        let has_completed_result = self
            .engineer_result
            .as_ref()
            .is_some_and(|result| result.state == ControlPlaneState::Completed);
        let effects_complete = self.ledger.entries.len() == self.plan.ordered_effects.len()
            && self
                .ledger
                .entries
                .iter()
                .all(|entry| !matches!(entry.resolution, ResolvedEffectResolutionV1::Denied));
        match self.phase {
            EngineerVerifierPhaseV1::Planned
                if self.phase_revision == 0
                    && matches!(self.executor, ExecutorCallStateV1::NotStarted)
                    && self.ledger.entries.is_empty()
                    && self.engineer_result.is_none()
                    && self.workspace.is_none() => {}
            EngineerVerifierPhaseV1::Verifying
                if has_completed_result
                    && effects_complete
                    && self.prepared_write.is_none()
                    && self.workspace_bridge.is_some()
                    && self.verifier_replay_plan.is_some()
                    && self.verifier.is_some() => {}
            EngineerVerifierPhaseV1::Reviewing
                if has_completed_result
                    && effects_complete
                    && self.prepared_write.is_none()
                    && self.workspace_bridge.is_some()
                    && self.verifier.as_ref().is_some_and(|value| {
                        matches!(value, VerifierExecutionStateV1::Admitted { .. })
                    }) => {}
            EngineerVerifierPhaseV1::Engineering
                if self.workspace.as_ref().is_some_and(|value| {
                    !value.closed
                        || (self.ledger.entries.is_empty()
                            && self.prepared_write.is_none()
                            && (self.cancellation.is_some()
                                || matches!(self.executor, ExecutorCallStateV1::Started { .. })
                                || matches!(
                                    self.executor,
                                    ExecutorCallStateV1::OutcomeRecorded {
                                        outcome:
                                            PersistedRoleExecutionOutcomeV1::RetryRequired { .. }
                                            | PersistedRoleExecutionOutcomeV1::Failed { .. }
                                            | PersistedRoleExecutionOutcomeV1::TimedOut { .. }
                                            | PersistedRoleExecutionOutcomeV1::Cancelled { .. },
                                        ..
                                    }
                                )))
                }) => {}
            EngineerVerifierPhaseV1::RetryPending
                if self.workspace.as_ref().is_some_and(|value| value.closed)
                    && self.ledger.entries.is_empty()
                    && self.prepared_write.is_none() => {}
            EngineerVerifierPhaseV1::Failed | EngineerVerifierPhaseV1::Cancelled => {}
            _ => return Err(EngineerVerifierError::InvalidState),
        }
        validate_digest(&self.state_digest)?;
        if self.computed_state_digest()? != self.state_digest {
            return Err(EngineerVerifierError::InvalidDigest);
        }
        Ok(())
    }

    pub fn computed_state_digest(&self) -> Result<String, EngineerVerifierError> {
        domain_digest(
            STATE_DOMAIN,
            &EngineerVerifierStateDigestInputV1 {
                contract_version: self.contract_version,
                run_id: &self.run_id,
                goal_id: &self.goal_id,
                task_id: &self.task_id,
                phase: self.phase,
                phase_revision: self.phase_revision,
                attempt: self.attempt,
                logical_plan_digest: &self.plan.logical_plan_digest,
                execution_binding_digest: &self.execution_binding.execution_binding_digest,
                resolved_effect_ledger_digest: &self.ledger.resolved_effect_ledger_digest,
                engineer_result_digest: self.engineer_result_digest.as_deref(),
                verifier_transcript_digest: self
                    .verifier
                    .as_ref()
                    .and_then(VerifierExecutionStateV1::transcript_digest),
            },
        )
    }

    pub fn refresh_digest(&mut self) -> Result<(), EngineerVerifierError> {
        self.state_digest = self.computed_state_digest()?;
        self.validate()
    }
}

pub fn ledger_entry_from_receipt(
    template: &PlannedToolEffectTemplateV1,
    request: &ToolRequestV1,
    receipt: &ToolReceiptV1,
) -> Result<ResolvedEffectLedgerEntryV1, EngineerVerifierError> {
    template.validate()?;
    request
        .validate()
        .map_err(|_| EngineerVerifierError::InvalidLedger)?;
    receipt
        .validate()
        .map_err(|_| EngineerVerifierError::InvalidLedger)?;
    let request_digest = request
        .canonical_digest()
        .map_err(|_| EngineerVerifierError::InvalidLedger)?;
    let receipt_digest = verification_sha256_hex(
        &receipt
            .canonical_json_bytes()
            .map_err(|_| EngineerVerifierError::Serialization)?,
    );
    if receipt.request_id != request.request_id
        || receipt.request_digest != request_digest
        || receipt.idempotency_key != request.idempotency_key
    {
        return Err(EngineerVerifierError::InvalidLedger);
    }
    let resolution = match (&template.operation, &receipt.outcome) {
        (ToolOperationV1::ReadFile { .. }, ToolReceiptOutcomeV1::Read { .. }) => {
            ResolvedEffectResolutionV1::ReadObserved
        }
        (ToolOperationV1::WriteFile { .. }, ToolReceiptOutcomeV1::Written { .. }) => {
            ResolvedEffectResolutionV1::WriteApplied
        }
        (_, ToolReceiptOutcomeV1::Denied { .. }) => ResolvedEffectResolutionV1::Denied,
        _ => return Err(EngineerVerifierError::InvalidLedger),
    };
    let value = ResolvedEffectLedgerEntryV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        ordinal: template.ordinal,
        effect_id: template.effect_id.clone(),
        request_id: request.request_id.clone(),
        request_digest,
        idempotency_key: request.idempotency_key.clone(),
        resolution,
        tool_receipt_digest: Some(receipt_digest),
        reconciliation_digest: None,
        before_snapshot_digest: receipt.before_snapshot_digest.clone(),
        after_snapshot_digest: receipt.after_snapshot_digest.clone(),
    };
    value.validate()?;
    Ok(value)
}

pub fn ledger_entry_from_reconciliation(
    template: &PlannedToolEffectTemplateV1,
    prepared: &PreparedWriteEffectV1,
    reconciliation: &WriteReconciliationV1,
) -> Result<ResolvedEffectLedgerEntryV1, EngineerVerifierError> {
    template.validate()?;
    prepared.validate()?;
    reconciliation.validate()?;
    if template.ordinal != prepared.ordinal
        || template.effect_id != prepared.effect_id
        || template.operation != prepared.request.operation
        || template.payload_sha256 != prepared.payload_sha256
        || reconciliation.effect_id != prepared.effect_id
        || reconciliation.request_digest != prepared.request_digest
        || reconciliation.expected_before_snapshot_digest
            != prepared.expected_before_snapshot.snapshot_digest
        || reconciliation.intended_after_snapshot_digest
            != prepared.intended_after_snapshot.snapshot_digest
    {
        return Err(EngineerVerifierError::InvalidLedger);
    }
    let value = ResolvedEffectLedgerEntryV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        ordinal: template.ordinal,
        effect_id: template.effect_id.clone(),
        request_id: prepared.request.request_id.clone(),
        request_digest: prepared.request_digest.clone(),
        idempotency_key: prepared.request.idempotency_key.clone(),
        resolution: ResolvedEffectResolutionV1::WriteReconciledApplied,
        tool_receipt_digest: None,
        reconciliation_digest: Some(reconciliation.reconciliation_digest.clone()),
        before_snapshot_digest: prepared.expected_before_snapshot.snapshot_digest.clone(),
        after_snapshot_digest: prepared.intended_after_snapshot.snapshot_digest.clone(),
    };
    value.validate()?;
    Ok(value)
}

pub fn denial_code(receipt: &ToolReceiptV1) -> Option<ToolDeniedCodeV1> {
    match receipt.outcome {
        ToolReceiptOutcomeV1::Denied { code } => Some(code),
        ToolReceiptOutcomeV1::Read { .. } | ToolReceiptOutcomeV1::Written { .. } => None,
    }
}

fn validate_version(value: u32) -> Result<(), EngineerVerifierError> {
    if value != ENGINEER_VERIFIER_CONTRACT_VERSION {
        return Err(EngineerVerifierError::UnsupportedContractVersion);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), EngineerVerifierError> {
    validate_sha256_digest(value, "digest").map_err(|_| EngineerVerifierError::InvalidDigest)
}

fn validate_sorted_names(values: &[String]) -> Result<(), EngineerVerifierError> {
    for value in values {
        if value.is_empty()
            || !value.is_ascii()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(EngineerVerifierError::InvalidVerifierReplay);
        }
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(EngineerVerifierError::InvalidVerifierReplay);
    }
    Ok(())
}

fn is_millisecond_precision(value: DateTime<Utc>) -> bool {
    value.timestamp_subsec_nanos() % 1_000_000 == 0
}

fn authority_authorizes_time(authority: &FoundationAuthorityV1, at: DateTime<Utc>) -> bool {
    authority.validity.status == FoundationValidityStatusV1::Active
        && at >= authority.validity.valid_from
        && authority
            .validity
            .valid_until
            .is_none_or(|valid_until| at < valid_until)
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EngineerVerifierError> {
    serde_json::to_vec(value).map_err(|_| EngineerVerifierError::Serialization)
}

fn domain_digest<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<String, EngineerVerifierError> {
    if !domain.is_ascii() {
        return Err(EngineerVerifierError::Serialization);
    }
    let json = canonical_json(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + json.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&json);
    Ok(verification_sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_transition_table_rejects_skips_and_terminal_mutation() {
        assert!(transition_allowed(
            EngineerVerifierPhaseV1::Planned,
            EngineerVerifierTriggerV1::ClaimAccepted,
            EngineerVerifierPhaseV1::Engineering
        ));
        assert!(!transition_allowed(
            EngineerVerifierPhaseV1::Planned,
            EngineerVerifierTriggerV1::EngineerCompleted,
            EngineerVerifierPhaseV1::Verifying
        ));
        assert!(!transition_allowed(
            EngineerVerifierPhaseV1::Reviewing,
            EngineerVerifierTriggerV1::FailureRecorded,
            EngineerVerifierPhaseV1::Failed
        ));
    }

    #[test]
    fn domain_separator_is_nul_and_canonical_json_has_no_line_feed() {
        #[derive(Serialize)]
        struct Input {
            first: u32,
            second: &'static str,
        }
        let input = Input {
            first: 1,
            second: "two",
        };
        let mut expected = b"domain\0".to_vec();
        expected.extend_from_slice(br#"{"first":1,"second":"two"}"#);
        assert_eq!(
            domain_digest("domain", &input).unwrap(),
            verification_sha256_hex(&expected)
        );
    }

    #[test]
    fn empty_payload_digest_is_exact_sha256() {
        assert_eq!(EMPTY_PAYLOAD_SHA256, verification_sha256_hex(&[]));
    }
}
