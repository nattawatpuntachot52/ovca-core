//! Durable orchestration for the bounded Engineer-to-Verifier loop.
//!
//! SQLite remains lifecycle/recovery authority, `RunEventLog` remains the
//! append-only projection, `WorkspaceCapabilityBroker` remains the only native
//! file-effect authority, and `EvidenceBank` remains verification truth.

use chrono::{DateTime, TimeZone, Utc};
use ovca_runtime_core::{
    derive_phase_event_id, derive_tool_identity, ledger_entry_from_receipt,
    ledger_entry_from_reconciliation, CleanupReason, DurableExecutionAuthority,
    DurableExecutionError, DurableToolObservationV1, DurableWorkspaceAuthorityV1,
    EngineerExecutionBindingV1, EngineerLogicalPlanV1, EngineerVerifierCasOutcome,
    EngineerVerifierError, EngineerVerifierPhaseProjectionV1, EngineerVerifierPhaseV1,
    EngineerVerifierStateV1, EngineerVerifierTriggerV1, ExecutorCallStateV1,
    PendingPhaseProjectionV1, PersistedRoleExecutionOutcomeV1, PersistedVerificationTranscriptV1,
    PreparedWorkspaceState, PreparedWriteEffectV1, ResolvedEffectLedgerV1, RoleExecutionRequest,
    RoleExecutor, RoleExecutorError, TrustedCapabilityGrant, TrustedSealedWorkspace,
    TrustedWorkspaceLease, VerifierExecutionLimitsV1, VerifierExecutionStateV1,
    VerifierReplayPlanV1, WorkspaceCapabilityBroker, WorkspaceCapabilityError,
    WorkspaceDiffBridgeV1, WorkspaceDiffPathIdentityV1, WorkspaceSeedFile, WriteReconciliationV1,
    ENGINEER_VERIFIER_CONTRACT_VERSION,
};
use ovca_storage::{
    BundleRecord, CasOutcome, CompletionAdmissionSnapshot, EvidenceBank, EvidenceCurrent,
    EvidenceKey, LocalVerificationStoreError, ProjectionExpectation, PublishOutcome, RunEventLog,
    RunEventLogError,
};
use ovca_types::foundation::FoundationAuthorityV1;
use ovca_types::tool_boundary::{
    canonical_authority_digest, CapabilityGrantV1, CapabilityPolicyV1, ToolOperationV1,
    ToolReceiptOutcomeV1, ToolRequestV1, WorkspaceFileV1, WorkspaceSnapshotV1,
    TOOL_BOUNDARY_CONTRACT_VERSION,
};
use ovca_types::{
    verification_capability_set_digest, verification_command_set_digest,
    verification_policy_digest, verification_sha256_hex, BehavioralAcceptanceContract,
    CapabilityDefinition, ContractVersion, EventId, Role, RunEvent, RunEventPayload,
    VerificationBundle, VerificationVerdict, WorkerId,
};
use ovca_verifier::bundle::{validate_failure_identity_map, FailureCode, FailureIdentityMap};
use ovca_verifier::execution::{EnvironmentBindings, ExecutableRegistry, ExecutionLimits};
use ovca_verifier::snapshot::{SourceFile, SourceManifest};
use ovca_verifier::{
    verify_and_publish, PublishedVerification, VerifierError, VerifierOutcome, VerifierRequest,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

const PHASE_METADATA_KEY: &str = "engineer_verifier_phase_v1";
const PHASE_NOTE: &str = "engineer_verifier_phase_v1";

pub trait EngineerVerifierClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default)]
pub struct SystemEngineerVerifierClock;

impl EngineerVerifierClock for SystemEngineerVerifierClock {
    fn now(&self) -> DateTime<Utc> {
        Utc.timestamp_millis_opt(Utc::now().timestamp_millis())
            .single()
            .expect("current timestamp is representable")
    }
}

#[derive(Debug, Clone)]
pub struct EngineerWorkspaceInput {
    pub lease_id: String,
    pub workspace_id: String,
    pub recovery_token: String,
    pub seeds: Vec<WorkspaceSeedFile>,
    pub lease_issued_at: DateTime<Utc>,
    pub lease_expires_at: DateTime<Utc>,
    pub grant_id: String,
    pub grant_authority: FoundationAuthorityV1,
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub max_read_bytes: u64,
    pub max_write_bytes: u64,
    pub grant_valid_from: DateTime<Utc>,
    pub grant_valid_until: DateTime<Utc>,
}

pub struct VerifierReplayInputs<'a> {
    pub behavior: &'a BehavioralAcceptanceContract,
    pub capabilities: &'a [CapabilityDefinition],
    pub selection: &'a ovca_types::TargetedRerunSelection,
    pub source_manifest: &'a SourceManifest,
    pub failure_identities: &'a FailureIdentityMap,
    pub executable_registry: &'a ExecutableRegistry,
    pub environment_bindings: &'a EnvironmentBindings,
    pub environment_digest: &'a str,
    pub limits: ExecutionLimits,
    pub implementation_actor: WorkerId,
    pub verifier_actor: WorkerId,
    pub created_at: DateTime<Utc>,
    pub verifier_temp_parent: &'a Path,
}

pub struct EngineerVerifierLoopInput<'a> {
    pub plan: EngineerLogicalPlanV1,
    pub workspace: EngineerWorkspaceInput,
    /// Payloads are keyed by effect ID. Read effects must have no entry.
    pub write_payloads: BTreeMap<String, &'a [u8]>,
    pub verifier: VerifierReplayInputs<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineerVerifierLoopOutcome {
    Reviewing {
        state_digest: String,
        bundle_id: String,
    },
    RetryPending {
        state_digest: String,
    },
    Failed {
        state_digest: String,
        reason: EngineerVerifierFailureReason,
    },
    Cancelled {
        state_digest: String,
    },
    CancellationPending {
        state_digest: String,
    },
    NoChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineerVerifierFailureReason {
    ExecutorOutcomeUnknown,
    ExecutorFailed,
    ExecutorTimedOut,
    ToolDenied,
    VerificationRejected,
    VerificationFailed,
    RecoveryConflict,
}

#[derive(Debug)]
pub enum EngineerVerifierLoopError {
    InvalidInput,
    Durable(DurableExecutionError),
    Kernel(EngineerVerifierError),
    Broker(WorkspaceCapabilityError),
    Executor(RoleExecutorError),
    Events(RunEventLogError),
    Storage(LocalVerificationStoreError),
    Verifier(VerifierError),
    ProjectionConflict,
    Utf8,
    Io,
}

enum RetryClaimDisposition {
    Continue(Box<RetryClaimContinuation>),
    Outcome(EngineerVerifierLoopOutcome),
}

struct RetryClaimContinuation {
    loaded: ovca_runtime_core::LoadedExecutionRun,
    lease: TrustedWorkspaceLease,
    grant: TrustedCapabilityGrant,
}

impl fmt::Display for EngineerVerifierLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid engineer-verifier loop input",
            Self::Durable(_) => "durable execution operation failed",
            Self::Kernel(_) => "engineer-verifier state operation failed",
            Self::Broker(_) => "workspace capability operation failed",
            Self::Executor(_) => "role executor operation failed",
            Self::Events(_) => "run-event projection operation failed",
            Self::Storage(_) => "verification evidence operation failed",
            Self::Verifier(_) => "verifier operation failed",
            Self::ProjectionConflict => "engineer-verifier projection conflicts",
            Self::Utf8 => "canonical UTF-8 conversion failed",
            Self::Io => "bounded local I/O failed",
        })
    }
}

impl std::error::Error for EngineerVerifierLoopError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for EngineerVerifierLoopError {
            fn from(source: $source) -> Self {
                Self::$variant(source)
            }
        }
    };
}

from_error!(DurableExecutionError, Durable);
from_error!(EngineerVerifierError, Kernel);
from_error!(WorkspaceCapabilityError, Broker);
from_error!(RoleExecutorError, Executor);
from_error!(RunEventLogError, Events);
from_error!(LocalVerificationStoreError, Storage);
from_error!(VerifierError, Verifier);

pub struct EngineerVerifierLoop {
    log: RunEventLog,
    execution: DurableExecutionAuthority,
    evidence: EvidenceBank,
    clock: Box<dyn EngineerVerifierClock>,
}

impl EngineerVerifierLoop {
    pub fn try_new(
        root: impl AsRef<Path>,
        clock: Box<dyn EngineerVerifierClock>,
    ) -> Result<Self, EngineerVerifierLoopError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(EngineerVerifierLoopError::InvalidInput);
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

    pub fn heartbeat(
        &self,
        run_id: &ovca_types::RunId,
    ) -> Result<String, EngineerVerifierLoopError> {
        let loaded = self.execution.load(run_id)?;
        let loaded = reconcile_pending(&self.log, &self.execution, loaded)?;
        let mut state = projection(&loaded)?.clone();
        if state.phase.is_terminal() {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        let now = self.clock.now();
        let invocation = state.plan.invocation.clone();
        let workspace = state
            .workspace
            .as_mut()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        if workspace.closed
            || workspace.cleanup_required
            || now <= workspace.heartbeat_at
            || !workspace.authorizes_time(&invocation, now)
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        workspace.heartbeat_at = now;
        state.controller_time = now;
        state.refresh_digest()?;
        let applied = cas_replace(&self.execution, loaded, state)?;
        Ok(projection(&applied)?.state_digest.clone())
    }

    pub fn request_cancellation(
        &self,
        run_id: &ovca_types::RunId,
        request_id: impl Into<String>,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let loaded = self.execution.load(run_id)?;
        let loaded = reconcile_pending(&self.log, &self.execution, loaded)?;
        let state = projection(&loaded)?.clone();
        if state.phase == EngineerVerifierPhaseV1::Cancelled {
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: state.state_digest,
            });
        }
        if state.phase.is_terminal() {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        let request_id = request_id.into();
        if let Some(existing) = &state.cancellation {
            if existing.request_id != request_id {
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
            return Ok(EngineerVerifierLoopOutcome::CancellationPending {
                state_digest: state.state_digest,
            });
        }
        let now = self.clock.now();
        let mut next = state;
        next.cancellation = Some(ovca_runtime_core::CancellationRecordV1::try_new(
            request_id, now,
        )?);
        next.controller_time = now;
        next.refresh_digest()?;
        let loaded = cas_replace(&self.execution, loaded, next)?;
        Ok(EngineerVerifierLoopOutcome::CancellationPending {
            state_digest: projection(&loaded)?.state_digest.clone(),
        })
    }

    pub fn drive(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        executor: &dyn RoleExecutor,
        input: EngineerVerifierLoopInput<'_>,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        input.plan.validate()?;
        validate_payload_set(&input.plan, &input.write_payloads)?;
        let loaded = self.execution.load(&input.plan.run_id)?;
        if let Some(state) = loaded.envelope.engineer_verifier.as_ref() {
            if state.plan != input.plan {
                return Err(EngineerVerifierLoopError::InvalidInput);
            }
            let verifier_identity = VerifierInputIdentity::compute(&input.verifier)?;
            return self.resume_existing(broker, executor, input, loaded, verifier_identity);
        }
        self.drive_fresh(broker, executor, input, loaded)
    }

    fn drive_fresh(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        executor: &dyn RoleExecutor,
        input: EngineerVerifierLoopInput<'_>,
        loaded: ovca_runtime_core::LoadedExecutionRun,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let execution_request = RoleExecutionRequest {
            invocation: input.plan.invocation.clone(),
            attempt: 1,
        };
        let lease = broker.open_recoverable_lease(
            &self.execution,
            &input.plan.run_id,
            loaded.revision,
            None,
            &execution_request,
            input.workspace.lease_id.clone(),
            input.workspace.workspace_id.clone(),
            input.workspace.recovery_token.clone(),
            input.workspace.seeds.clone(),
            input.workspace.lease_issued_at,
            input.workspace.lease_expires_at,
        )?;
        let preparation = (|| {
            let grant_dto = build_grant(&execution_request, &lease, &input.workspace)?;
            let grant = broker.issue_grant(&execution_request, &lease, grant_dto.clone())?;

            if let Some(write) = input
                .plan
                .ordered_effects
                .last()
                .filter(|effect| matches!(effect.operation, ToolOperationV1::WriteFile { .. }))
            {
                let ToolOperationV1::WriteFile {
                    ref logical_path,
                    ref content_sha256,
                    byte_length,
                } = write.operation
                else {
                    unreachable!()
                };
                if broker.target_matches_current(
                    &lease,
                    logical_path,
                    content_sha256,
                    byte_length,
                )? {
                    return Ok(None);
                }
            }

            let verifier_identity = VerifierInputIdentity::compute(&input.verifier)?;
            let now = self.clock.now();
            let mut state = EngineerVerifierStateV1::planned(input.plan.clone(), now)?;
            let initial_cursor = current_run_cursor(&self.log, &input.plan.run_id)?;
            state.projected_sequence = initial_cursor.as_ref().map(|value| value.0);
            state.projected_event_id = initial_cursor.map(|value| value.1);
            state.workspace = Some(DurableWorkspaceAuthorityV1 {
                lease: lease.observation().clone(),
                lease_digest: lease.digest().to_owned(),
                initial_snapshot: lease.initial_snapshot().clone(),
                grant: grant_dto,
                grant_digest: grant.digest().to_owned(),
                current_snapshot: lease.initial_snapshot().clone(),
                recovery_token: input.workspace.recovery_token.clone(),
                runtime_instance_id: broker.runtime_instance_id().to_owned(),
                fence: 1,
                runtime_epoch: 1,
                heartbeat_at: now,
                next_receipt_sequence: broker.next_receipt_sequence(),
                cleanup_required: false,
                closed: false,
            });
            transition_state(
                &mut state,
                EngineerVerifierPhaseV1::Engineering,
                EngineerVerifierTriggerV1::ClaimAccepted,
                now,
            )?;
            attach_pending_projection(
                &self.log,
                &mut state,
                EngineerVerifierPhaseV1::Planned,
                EngineerVerifierTriggerV1::ClaimAccepted,
            )?;
            Ok(Some((grant, verifier_identity, state)))
        })();
        let (grant, verifier_identity, state) = match preparation {
            Ok(Some(prepared)) => prepared,
            Ok(None) => {
                broker.close_lease(&lease, CleanupReason::Cancelled)?;
                return Ok(EngineerVerifierLoopOutcome::NoChange);
            }
            Err(error) => {
                let _ = broker.close_lease(&lease, CleanupReason::Failed);
                return Err(error);
            }
        };
        let run_id = state.run_id.clone();
        let outcome = self.execution.compare_and_swap_engineer_verifier(
            &run_id,
            loaded.revision,
            None,
            state,
        );
        let loaded = match outcome {
            Ok(EngineerVerifierCasOutcome::Applied(loaded)) => loaded,
            Ok(EngineerVerifierCasOutcome::Conflict(_)) => {
                let _ = broker.close_lease(&lease, CleanupReason::Failed);
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
            Ok(EngineerVerifierCasOutcome::Unchanged(_)) => {
                return Err(EngineerVerifierLoopError::ProjectionConflict)
            }
            Err(error) => {
                let _ = broker.close_lease(&lease, CleanupReason::Failed);
                return Err(error.into());
            }
        };
        let loaded = reconcile_pending(&self.log, &self.execution, loaded)?;
        self.invoke_and_continue(
            broker,
            executor,
            input,
            loaded,
            verifier_identity,
            lease,
            grant,
        )
    }

    fn resume_existing(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        executor: &dyn RoleExecutor,
        input: EngineerVerifierLoopInput<'_>,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        verifier_identity: VerifierInputIdentity,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let loaded = reconcile_pending(&self.log, &self.execution, loaded)?;
        let needs_terminal_cleanup = {
            let state = projection(&loaded)?;
            state.phase.is_terminal()
                && state
                    .workspace
                    .as_ref()
                    .is_some_and(|workspace| !workspace.closed)
        };
        let loaded = if needs_terminal_cleanup {
            self.cleanup_terminal_resume(broker, loaded)?
        } else {
            loaded
        };
        let phase = projection(&loaded)?.phase;
        if phase == EngineerVerifierPhaseV1::Reviewing {
            let state = projection(&loaded)?;
            let bundle_id = admitted_bundle(state)
                .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
                .bundle_id
                .clone();
            return Ok(EngineerVerifierLoopOutcome::Reviewing {
                state_digest: state.state_digest.clone(),
                bundle_id,
            });
        }
        if phase == EngineerVerifierPhaseV1::Failed {
            return Ok(EngineerVerifierLoopOutcome::Failed {
                state_digest: projection(&loaded)?.state_digest.clone(),
                reason: EngineerVerifierFailureReason::RecoveryConflict,
            });
        }
        if phase == EngineerVerifierPhaseV1::Cancelled {
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: projection(&loaded)?.state_digest.clone(),
            });
        }
        if phase == EngineerVerifierPhaseV1::RetryPending {
            if projection(&loaded)?.cancellation.is_some() {
                let cancelled = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Cancelled,
                    EngineerVerifierTriggerV1::CancellationAccepted,
                )?;
                return Ok(EngineerVerifierLoopOutcome::Cancelled {
                    state_digest: projection(&cancelled)?.state_digest.clone(),
                });
            }
            return match self.claim_retry(broker, &input.workspace, loaded)? {
                RetryClaimDisposition::Continue(continuation) => {
                    let RetryClaimContinuation {
                        loaded,
                        lease,
                        grant,
                    } = *continuation;
                    self.invoke_and_continue(
                        broker,
                        executor,
                        input,
                        loaded,
                        verifier_identity,
                        lease,
                        grant,
                    )
                }
                RetryClaimDisposition::Outcome(outcome) => Ok(outcome),
            };
        }
        if projection(&loaded)?.verifier_replay_plan.is_some() {
            validate_replay_resupply(projection(&loaded)?, &verifier_identity, &input.verifier)?;
        }
        let (run_id, state_digest) = {
            let state = projection(&loaded)?;
            (state.run_id.clone(), state.state_digest.clone())
        };
        let claim = self
            .execution
            .claim_workspace_recovery(
                &run_id,
                loaded.revision,
                &state_digest,
                broker.runtime_instance_id().to_owned(),
                self.clock.now(),
            )?
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        let loaded = claim.state;
        let (lease, grant) = broker.recover_lease(claim.permit)?;
        if matches!(
            projection(&loaded)?.executor,
            ExecutorCallStateV1::Started { .. }
        ) {
            broker.close_lease(&lease, CleanupReason::Failed)?;
            let mut next = projection(&loaded)?.clone();
            close_durable_workspace(&mut next);
            let loaded = cas_replace(&self.execution, loaded, next)?;
            let failed = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Failed,
                EngineerVerifierTriggerV1::ExecutorOutcomeUnknown,
            )?;
            return Ok(EngineerVerifierLoopOutcome::Failed {
                state_digest: projection(&failed)?.state_digest.clone(),
                reason: EngineerVerifierFailureReason::ExecutorOutcomeUnknown,
            });
        }
        if projection(&loaded)?.phase == EngineerVerifierPhaseV1::Verifying {
            return self.resume_verifying(broker, input.verifier, verifier_identity, loaded, lease);
        }
        if projection(&loaded)?.cancellation.is_some()
            && matches!(
                projection(&loaded)?.executor,
                ExecutorCallStateV1::NotStarted
            )
        {
            broker.close_lease(&lease, CleanupReason::Cancelled)?;
            let mut next = projection(&loaded)?.clone();
            close_durable_workspace(&mut next);
            let loaded = cas_replace(&self.execution, loaded, next)?;
            let cancelled = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Cancelled,
                EngineerVerifierTriggerV1::CancellationAccepted,
            )?;
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: projection(&cancelled)?.state_digest.clone(),
            });
        }
        if matches!(
            projection(&loaded)?.executor,
            ExecutorCallStateV1::NotStarted
        ) {
            return self.invoke_and_continue(
                broker,
                executor,
                input,
                loaded,
                verifier_identity,
                lease,
                grant,
            );
        }
        self.continue_after_executor(broker, input, loaded, verifier_identity, lease, grant)
    }

    fn cleanup_terminal_resume(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        loaded: ovca_runtime_core::LoadedExecutionRun,
    ) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
        let state = projection(&loaded)?.clone();
        if !state.phase.is_terminal() {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        let workspace = state
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        if workspace.closed {
            return Ok(loaded);
        }
        if broker.recoverable_root_is_absent(&workspace.recovery_token, &workspace.lease)? {
            let mut next = state;
            close_durable_workspace(&mut next);
            return cas_replace(&self.execution, loaded, next);
        }
        let claim = self
            .execution
            .claim_workspace_recovery(
                &state.run_id,
                loaded.revision,
                &state.state_digest,
                broker.runtime_instance_id().to_owned(),
                self.clock.now(),
            )?
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        let loaded = claim.state;
        let (lease, _grant) = broker.recover_lease(claim.permit)?;
        let reason = match projection(&loaded)?.phase {
            EngineerVerifierPhaseV1::Reviewing => CleanupReason::Completed,
            EngineerVerifierPhaseV1::Failed => CleanupReason::Failed,
            EngineerVerifierPhaseV1::Cancelled => CleanupReason::Cancelled,
            _ => return Err(EngineerVerifierLoopError::ProjectionConflict),
        };
        broker.close_lease(&lease, reason)?;
        let mut next = projection(&loaded)?.clone();
        close_durable_workspace(&mut next);
        cas_replace(&self.execution, loaded, next)
    }

    fn claim_retry(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        input: &EngineerWorkspaceInput,
        loaded: ovca_runtime_core::LoadedExecutionRun,
    ) -> Result<RetryClaimDisposition, EngineerVerifierLoopError> {
        let state = projection(&loaded)?.clone();
        let prior = state
            .workspace
            .clone()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        if !prior.closed
            || prior.cleanup_required
            || state.prepared_write.is_some()
            || !state.ledger.entries.is_empty()
            || !matches!(
                state.executor,
                ExecutorCallStateV1::OutcomeRecorded {
                    outcome: PersistedRoleExecutionOutcomeV1::RetryRequired { .. },
                    ..
                }
            )
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        if !broker.recoverable_root_is_absent(&prior.recovery_token, &prior.lease)? {
            return Ok(RetryClaimDisposition::Outcome(
                EngineerVerifierLoopOutcome::RetryPending {
                    state_digest: state.state_digest,
                },
            ));
        }
        let next_attempt = state
            .attempt
            .checked_add(1)
            .ok_or(EngineerVerifierError::Overflow)?;
        if next_attempt > state.plan.invocation.budget.max_attempts {
            let failed = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Failed,
                EngineerVerifierTriggerV1::RetryExhausted,
            )?;
            return Ok(RetryClaimDisposition::Outcome(
                EngineerVerifierLoopOutcome::Failed {
                    state_digest: projection(&failed)?.state_digest.clone(),
                    reason: EngineerVerifierFailureReason::ExecutorFailed,
                },
            ));
        }

        let request = RoleExecutionRequest {
            invocation: state.plan.invocation.clone(),
            attempt: next_attempt,
        };
        let lease = broker.open_recoverable_lease(
            &self.execution,
            &state.run_id,
            loaded.revision,
            Some(&state.state_digest),
            &request,
            input.lease_id.clone(),
            input.workspace_id.clone(),
            input.recovery_token.clone(),
            input.seeds.clone(),
            input.lease_issued_at,
            input.lease_expires_at,
        )?;
        let expected_digest = state.state_digest.clone();
        macro_rules! close_on_pre_admission_error {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = broker.close_lease(&lease, CleanupReason::Failed);
                        return Err(error.into());
                    }
                }
            };
        }
        if lease.initial_snapshot().files != prior.initial_snapshot.files {
            let _ = broker.close_lease(&lease, CleanupReason::Failed);
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        let grant_dto = close_on_pre_admission_error!(build_grant(&request, &lease, input));
        let grant =
            close_on_pre_admission_error!(broker.issue_grant(&request, &lease, grant_dto.clone()));
        let now = self.clock.now();
        let mut next = state;
        next.attempt = next_attempt;
        next.execution_binding = close_on_pre_admission_error!(
            EngineerExecutionBindingV1::try_new(next.plan.invocation_digest.clone(), next_attempt,)
        );
        next.executor = ExecutorCallStateV1::NotStarted;
        next.workspace = Some(DurableWorkspaceAuthorityV1 {
            lease: lease.observation().clone(),
            lease_digest: lease.digest().to_owned(),
            initial_snapshot: lease.initial_snapshot().clone(),
            grant: grant_dto,
            grant_digest: grant.digest().to_owned(),
            current_snapshot: lease.initial_snapshot().clone(),
            recovery_token: input.recovery_token.clone(),
            runtime_instance_id: broker.runtime_instance_id().to_owned(),
            fence: 1,
            runtime_epoch: 1,
            heartbeat_at: now,
            next_receipt_sequence: broker.next_receipt_sequence(),
            cleanup_required: false,
            closed: false,
        });
        next.ledger =
            close_on_pre_admission_error!(ResolvedEffectLedgerV1::empty(&next.plan, next_attempt,));
        next.prepared_write = None;
        next.tool_observations.clear();
        next.write_reconciliation = None;
        next.engineer_result = None;
        next.engineer_result_digest = None;
        next.workspace_bridge = None;
        next.verifier_replay_plan = None;
        next.verifier = None;
        close_on_pre_admission_error!(transition_state(
            &mut next,
            EngineerVerifierPhaseV1::Engineering,
            EngineerVerifierTriggerV1::RetryClaimAccepted,
            now,
        ));
        close_on_pre_admission_error!(attach_pending_projection(
            &self.log,
            &mut next,
            EngineerVerifierPhaseV1::RetryPending,
            EngineerVerifierTriggerV1::RetryClaimAccepted,
        ));
        let next_run_id = next.run_id.clone();
        let loaded = match self.execution.compare_and_swap_engineer_verifier(
            &next_run_id,
            loaded.revision,
            Some(&expected_digest),
            next,
        ) {
            Ok(EngineerVerifierCasOutcome::Applied(loaded)) => loaded,
            Ok(EngineerVerifierCasOutcome::Conflict(_)) => {
                let _ = broker.close_lease(&lease, CleanupReason::Failed);
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
            Ok(EngineerVerifierCasOutcome::Unchanged(_)) => {
                return Err(EngineerVerifierLoopError::ProjectionConflict)
            }
            Err(error) => {
                let _ = broker.close_lease(&lease, CleanupReason::Failed);
                return Err(error.into());
            }
        };
        let loaded = reconcile_pending(&self.log, &self.execution, loaded)?;
        Ok(RetryClaimDisposition::Continue(Box::new(
            RetryClaimContinuation {
                loaded,
                lease,
                grant,
            },
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_and_continue(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        executor: &dyn RoleExecutor,
        input: EngineerVerifierLoopInput<'_>,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        verifier_identity: VerifierInputIdentity,
        lease: TrustedWorkspaceLease,
        grant: TrustedCapabilityGrant,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let mut state = projection(&loaded)?.clone();
        let request = RoleExecutionRequest {
            invocation: state.plan.invocation.clone(),
            attempt: state.attempt,
        };
        let started_at = self.clock.now();
        state.executor = ExecutorCallStateV1::Started {
            request_digest: state.execution_binding.execution_binding_digest.clone(),
            attempt: state.attempt,
            started_at,
        };
        state.controller_time = started_at;
        state.refresh_digest()?;
        let loaded = cas_replace(&self.execution, loaded, state)?;

        let outcome = executor.invoke(request.clone())?;
        let persisted = PersistedRoleExecutionOutcomeV1::try_from_live(&outcome, &request)?;
        let outcome_digest = persisted.outcome_digest()?;
        let mut state = projection(&loaded)?.clone();
        let ExecutorCallStateV1::Started {
            request_digest,
            attempt,
            started_at,
        } = state.executor.clone()
        else {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        };
        let recorded_at = self.clock.now();
        state.executor = ExecutorCallStateV1::OutcomeRecorded {
            request_digest,
            attempt,
            started_at,
            outcome: persisted,
            outcome_digest,
            recorded_at,
        };
        state.controller_time = recorded_at;
        state.refresh_digest()?;
        let loaded = cas_replace(&self.execution, loaded, state)?;
        self.continue_after_executor(broker, input, loaded, verifier_identity, lease, grant)
    }

    #[allow(clippy::too_many_arguments)]
    fn continue_after_executor(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        input: EngineerVerifierLoopInput<'_>,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        verifier_identity: VerifierInputIdentity,
        lease: TrustedWorkspaceLease,
        grant: TrustedCapabilityGrant,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let state = projection(&loaded)?;
        let ExecutorCallStateV1::OutcomeRecorded { outcome, .. } = &state.executor else {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        };
        match outcome {
            PersistedRoleExecutionOutcomeV1::RetryRequired { .. } => {
                broker.close_lease(&lease, CleanupReason::Failed)?;
                let mut next = state.clone();
                close_durable_workspace(&mut next);
                let loaded = cas_replace(&self.execution, loaded, next)?;
                let loaded = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::RetryPending,
                    EngineerVerifierTriggerV1::RetryRequired,
                )?;
                return Ok(EngineerVerifierLoopOutcome::RetryPending {
                    state_digest: projection(&loaded)?.state_digest.clone(),
                });
            }
            PersistedRoleExecutionOutcomeV1::Failed { .. } => {
                return self.fail_with_cleanup(
                    broker,
                    &lease,
                    loaded,
                    EngineerVerifierFailureReason::ExecutorFailed,
                )
            }
            PersistedRoleExecutionOutcomeV1::TimedOut { .. } => {
                return self.fail_with_cleanup(
                    broker,
                    &lease,
                    loaded,
                    EngineerVerifierFailureReason::ExecutorTimedOut,
                )
            }
            PersistedRoleExecutionOutcomeV1::Cancelled { .. } => {
                broker.close_lease(&lease, CleanupReason::Cancelled)?;
                let mut next = state.clone();
                close_durable_workspace(&mut next);
                let loaded = cas_replace(&self.execution, loaded, next)?;
                let loaded = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Cancelled,
                    EngineerVerifierTriggerV1::CancellationAccepted,
                )?;
                return Ok(EngineerVerifierLoopOutcome::Cancelled {
                    state_digest: projection(&loaded)?.state_digest.clone(),
                });
            }
            PersistedRoleExecutionOutcomeV1::Completed { result, .. } => {
                if result.state != ovca_types::control_plane::ControlPlaneState::Completed {
                    return Err(EngineerVerifierLoopError::ProjectionConflict);
                }
            }
        }

        let result = outcome
            .result()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
            .clone();
        let result_digest = result
            .canonical_digest()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let mut state = state.clone();
        let mut loaded = loaded;
        if let Some(existing) = &state.engineer_result {
            if existing != &result
                || state.engineer_result_digest.as_deref() != Some(result_digest.as_str())
            {
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
        } else {
            state.engineer_result_digest = Some(result_digest);
            state.engineer_result = Some(result);
            state.controller_time = self.clock.now();
            state.refresh_digest()?;
            loaded = cas_replace(&self.execution, loaded, state)?;
        }
        loaded = self.execute_effects(broker, &input.write_payloads, loaded, &lease, &grant)?;
        if projection(&loaded)?.phase == EngineerVerifierPhaseV1::Failed {
            broker.close_lease(&lease, CleanupReason::Failed)?;
            let mut next = projection(&loaded)?.clone();
            close_durable_workspace(&mut next);
            let loaded = cas_replace(&self.execution, loaded, next)?;
            return Ok(EngineerVerifierLoopOutcome::Failed {
                state_digest: projection(&loaded)?.state_digest.clone(),
                reason: EngineerVerifierFailureReason::ToolDenied,
            });
        }
        if projection(&loaded)?.phase == EngineerVerifierPhaseV1::Cancelled {
            broker.close_lease(&lease, CleanupReason::Cancelled)?;
            let mut next = projection(&loaded)?.clone();
            close_durable_workspace(&mut next);
            let loaded = cas_replace(&self.execution, loaded, next)?;
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: projection(&loaded)?.state_digest.clone(),
            });
        }
        self.verify_and_admit(broker, input.verifier, verifier_identity, loaded, lease)
    }

    fn execute_effects(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        payloads: &BTreeMap<String, &[u8]>,
        mut loaded: ovca_runtime_core::LoadedExecutionRun,
        lease: &TrustedWorkspaceLease,
        grant: &TrustedCapabilityGrant,
    ) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
        loop {
            let state = projection(&loaded)?.clone();
            let index = state.ledger.entries.len();
            if index == state.plan.ordered_effects.len() {
                return Ok(loaded);
            }
            let template = state.plan.ordered_effects[index].clone();
            let workspace = state
                .workspace
                .as_ref()
                .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
            let identity = derive_tool_identity(&state.plan, &template.effect_id, state.attempt)?;
            let requested_at = state.prepared_write.as_ref().map_or_else(
                || self.clock.now(),
                |prepared| prepared.request.requested_at,
            );
            let request = ToolRequestV1 {
                contract_version: TOOL_BOUNDARY_CONTRACT_VERSION,
                request_id: identity.request_id,
                idempotency_key: identity.idempotency_key,
                invocation_id: state.plan.invocation.invocation_id.clone(),
                invocation_digest: state.plan.invocation_digest.clone(),
                attempt: state.attempt,
                grant_id: workspace.grant.grant_id.clone(),
                grant_digest: workspace.grant_digest.clone(),
                lease_id: workspace.lease.lease_id.clone(),
                lease_digest: workspace.lease_digest.clone(),
                workspace_id: workspace.lease.workspace_id.clone(),
                expected_snapshot_digest: workspace.current_snapshot.snapshot_digest.clone(),
                requester: state.plan.invocation.target.clone(),
                scope: state.plan.invocation.scope.clone(),
                operation: template.operation.clone(),
                requested_at,
            };
            request
                .validate()
                .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
            let payload = payloads.get(&template.effect_id).copied();
            template.validate_payload(payload)?;

            if state.cancellation.is_some() && state.prepared_write.is_none() {
                return self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Cancelled,
                    EngineerVerifierTriggerV1::CancellationAccepted,
                );
            }

            if let Some(prepared) = state.prepared_write.clone() {
                if prepared.request != request
                    || prepared.ordinal != template.ordinal
                    || prepared.effect_id != template.effect_id
                    || prepared.payload_sha256 != template.payload_sha256
                {
                    return Err(EngineerVerifierLoopError::ProjectionConflict);
                }
                match broker.inspect_prepared_write(lease, &prepared)? {
                    PreparedWorkspaceState::ExpectedBefore if state.cancellation.is_some() => {
                        let mut next = state;
                        next.prepared_write = None;
                        next.controller_time = self.clock.now();
                        next.refresh_digest()?;
                        let loaded = cas_replace(&self.execution, loaded, next)?;
                        return self.transition_with_event(
                            loaded,
                            EngineerVerifierPhaseV1::Cancelled,
                            EngineerVerifierTriggerV1::CancellationAccepted,
                        );
                    }
                    PreparedWorkspaceState::ExpectedBefore => {}
                    PreparedWorkspaceState::IntendedAfter => {
                        let after = broker.adopt_reconciled_write(lease, &prepared)?;
                        let reconciled_at = self.clock.now();
                        let reconciliation = WriteReconciliationV1::try_new(
                            &prepared,
                            after.snapshot_digest.clone(),
                            reconciled_at,
                        )?;
                        let entry = ledger_entry_from_reconciliation(
                            &template,
                            &prepared,
                            &reconciliation,
                        )?;
                        let mut next = state.clone();
                        next.ledger = next.ledger.append(&next.plan, entry)?;
                        next.write_reconciliation = Some(reconciliation);
                        next.prepared_write = None;
                        let durable_workspace = next
                            .workspace
                            .as_mut()
                            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
                        durable_workspace.current_snapshot = after;
                        next.controller_time = reconciled_at;
                        next.refresh_digest()?;
                        loaded = cas_replace(&self.execution, loaded, next)?;
                        if projection(&loaded)?.cancellation.is_some() {
                            return self.transition_with_event(
                                loaded,
                                EngineerVerifierPhaseV1::Cancelled,
                                EngineerVerifierTriggerV1::CancellationAccepted,
                            );
                        }
                        continue;
                    }
                    PreparedWorkspaceState::Missing | PreparedWorkspaceState::ThirdState => {
                        let mut next = state.clone();
                        next.workspace
                            .as_mut()
                            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
                            .cleanup_required = true;
                        next.controller_time = self.clock.now();
                        next.refresh_digest()?;
                        loaded = cas_replace(&self.execution, loaded, next)?;
                        return self.transition_with_event(
                            loaded,
                            EngineerVerifierPhaseV1::Failed,
                            EngineerVerifierTriggerV1::FailureRecorded,
                        );
                    }
                }
            }

            if matches!(template.operation, ToolOperationV1::WriteFile { .. })
                && state.prepared_write.is_none()
            {
                let prepared =
                    prepare_write(&state, &template, request.clone(), broker, requested_at)?;
                let mut next = state.clone();
                next.prepared_write = Some(prepared);
                next.controller_time = requested_at;
                next.refresh_digest()?;
                loaded = cas_replace(&self.execution, loaded, next)?;
            }

            let result = broker.execute(request.clone(), payload)?;
            if !broker.receipt_is_from_this_broker(result.receipt()) || !broker.grant_is_live(grant)
            {
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
            let receipt = result.receipt().observation().clone();
            let after = broker.snapshot(lease)?;
            let observation = DurableToolObservationV1::try_new(
                receipt.clone(),
                after.clone(),
                self.clock.now(),
            )?;
            let entry = ledger_entry_from_receipt(&template, &request, &receipt)?;
            let mut next = projection(&loaded)?.clone();
            next.ledger = next.ledger.append(&next.plan, entry)?;
            next.tool_observations.push(observation);
            let durable_workspace = next
                .workspace
                .as_mut()
                .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
            durable_workspace.current_snapshot = after;
            durable_workspace.next_receipt_sequence = broker.next_receipt_sequence();
            next.prepared_write = None;
            next.controller_time = self.clock.now();
            next.refresh_digest()?;
            loaded = cas_replace(&self.execution, loaded, next)?;

            if matches!(receipt.outcome, ToolReceiptOutcomeV1::Denied { .. }) {
                loaded = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Failed,
                    EngineerVerifierTriggerV1::FailureRecorded,
                )?;
                return Ok(loaded);
            }
        }
    }

    fn verify_and_admit(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        verifier: VerifierReplayInputs<'_>,
        identity: VerifierInputIdentity,
        mut loaded: ovca_runtime_core::LoadedExecutionRun,
        lease: TrustedWorkspaceLease,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let state = projection(&loaded)?.clone();
        let current_snapshot = state
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
            .current_snapshot
            .clone();
        validate_source_manifest(&current_snapshot, verifier.source_manifest)?;
        let evidence_key = EvidenceKey {
            run_id: state.run_id.clone(),
            goal_id: state.goal_id.clone(),
            task_id: state.task_id.clone(),
        };
        if self.evidence.load_current(&evidence_key)?.is_some() {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        let sealed = broker.seal_workspace(&lease, verifier.verifier_temp_parent)?;
        let bridge = build_workspace_bridge(&state, &sealed, &identity)?;
        let replay_plan = build_replay_plan(&state, &bridge, &identity, &verifier)?;
        let mut next = state;
        next.workspace_bridge = Some(bridge);
        next.verifier_replay_plan = Some(replay_plan.clone());
        next.verifier = Some(VerifierExecutionStateV1::NotStarted {
            replay_plan_digest: replay_plan.replay_plan_digest.clone(),
        });
        next.controller_time = self.clock.now();
        next.refresh_digest()?;
        loaded = cas_replace(&self.execution, loaded, next)?;
        loaded = self.transition_with_event(
            loaded,
            EngineerVerifierPhaseV1::Verifying,
            EngineerVerifierTriggerV1::EngineerCompleted,
        )?;

        let mut state = projection(&loaded)?.clone();
        let started_at = self.clock.now();
        state.verifier = Some(VerifierExecutionStateV1::Started {
            replay_plan_digest: replay_plan.replay_plan_digest.clone(),
            started_at,
        });
        state.controller_time = started_at;
        state.refresh_digest()?;
        loaded = cas_replace(&self.execution, loaded, state)?;

        let verifier_outcome = verify_and_publish(
            verifier_request(&verifier, &sealed),
            &self.evidence,
            &ProjectionExpectation::Absent,
        );
        sealed.cleanup()?;
        let published = match verifier_outcome? {
            VerifierOutcome::Rejected(_) => {
                let failed = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Failed,
                    EngineerVerifierTriggerV1::FailureRecorded,
                )?;
                broker.close_lease(&lease, CleanupReason::Failed)?;
                let mut next = projection(&failed)?.clone();
                close_durable_workspace(&mut next);
                let failed = cas_replace(&self.execution, failed, next)?;
                return Ok(EngineerVerifierLoopOutcome::Failed {
                    state_digest: projection(&failed)?.state_digest.clone(),
                    reason: EngineerVerifierFailureReason::VerificationRejected,
                });
            }
            VerifierOutcome::Published(value) => value,
        };
        if published.bundle.verdict != VerificationVerdict::Pass {
            let failed = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Failed,
                EngineerVerifierTriggerV1::FailureRecorded,
            )?;
            broker.close_lease(&lease, CleanupReason::Failed)?;
            let mut next = projection(&failed)?.clone();
            close_durable_workspace(&mut next);
            let failed = cas_replace(&self.execution, failed, next)?;
            return Ok(EngineerVerifierLoopOutcome::Failed {
                state_digest: projection(&failed)?.state_digest.clone(),
                reason: EngineerVerifierFailureReason::VerificationFailed,
            });
        }
        validate_verifier_publication_binding(
            &replay_plan,
            projection(&loaded)?
                .workspace_bridge
                .as_ref()
                .ok_or(EngineerVerifierLoopError::ProjectionConflict)?,
            &published,
        )?;
        let (record, current) = authoritative_publication(&self.evidence, &published)?;
        let transcript = PersistedVerificationTranscriptV1::from_live(&published.transcript)?;
        let transcript_digest = transcript.digest()?;
        let observed_at = self.clock.now();
        let mut state = projection(&loaded)?.clone();
        state.verifier = Some(VerifierExecutionStateV1::PublicationObserved {
            replay_plan_digest: replay_plan.replay_plan_digest.clone(),
            transcript,
            transcript_digest,
            bundle: record.bundle.clone(),
            bundle_record_digest: record.digest.clone(),
            evidence_current: current.clone(),
            observed_at,
        });
        state.controller_time = observed_at;
        state.refresh_digest()?;
        loaded = cas_replace(&self.execution, loaded, state)?;
        self.admit_observed_publication(broker, loaded, lease, &verifier)
    }

    fn resume_verifying(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        verifier: VerifierReplayInputs<'_>,
        identity: VerifierInputIdentity,
        mut loaded: ovca_runtime_core::LoadedExecutionRun,
        lease: TrustedWorkspaceLease,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let state = projection(&loaded)?.clone();
        let replay_plan = state
            .verifier_replay_plan
            .clone()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        validate_replay_resupply(&state, &identity, &verifier)?;

        if matches!(
            state.verifier,
            Some(VerifierExecutionStateV1::PublicationObserved { .. })
        ) {
            return self.admit_observed_publication(broker, loaded, lease, &verifier);
        }
        if state.cancellation.is_some()
            && matches!(
                state.verifier,
                Some(VerifierExecutionStateV1::NotStarted { .. })
            )
        {
            broker.close_lease(&lease, CleanupReason::Cancelled)?;
            let mut next = state;
            close_durable_workspace(&mut next);
            let loaded = cas_replace(&self.execution, loaded, next)?;
            let cancelled = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Cancelled,
                EngineerVerifierTriggerV1::CancellationAccepted,
            )?;
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: projection(&cancelled)?.state_digest.clone(),
            });
        }
        if matches!(
            state.verifier,
            Some(VerifierExecutionStateV1::Admitted { .. })
        ) {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }

        let current_snapshot = state
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
            .current_snapshot
            .clone();
        validate_source_manifest(&current_snapshot, verifier.source_manifest)?;
        let sealed = broker.seal_workspace(&lease, verifier.verifier_temp_parent)?;
        let recovered_bridge = build_workspace_bridge(&state, &sealed, &identity)?;
        if state.workspace_bridge.as_ref() != Some(&recovered_bridge)
            || sealed.snapshot().snapshot_digest != replay_plan.sealed_workspace_snapshot_digest
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }

        match state.verifier.as_ref() {
            Some(VerifierExecutionStateV1::NotStarted { .. }) => {
                if self
                    .evidence
                    .load_current(&replay_plan.evidence_key)?
                    .is_some()
                {
                    return Err(EngineerVerifierLoopError::ProjectionConflict);
                }
                let mut next = state;
                let started_at = self.clock.now();
                next.verifier = Some(VerifierExecutionStateV1::Started {
                    replay_plan_digest: replay_plan.replay_plan_digest.clone(),
                    started_at,
                });
                next.controller_time = started_at;
                next.refresh_digest()?;
                loaded = cas_replace(&self.execution, loaded, next)?;
            }
            Some(VerifierExecutionStateV1::Started { .. }) => {}
            _ => return Err(EngineerVerifierLoopError::ProjectionConflict),
        }

        let authoritative_current = self.evidence.load_current(&replay_plan.evidence_key)?;
        let published = if authoritative_current.is_none() {
            verify_and_publish(
                verifier_request(&verifier, &sealed),
                &self.evidence,
                &ProjectionExpectation::Absent,
            )
        } else {
            let replay_root = tempfile::Builder::new()
                .prefix("engineer-verifier-replay-")
                .tempdir_in(verifier.verifier_temp_parent)
                .map_err(|_| EngineerVerifierLoopError::Io)?;
            let replay_bank = EvidenceBank::try_new(replay_root.path())?;
            let result = verify_and_publish(
                verifier_request(&verifier, &sealed),
                &replay_bank,
                &ProjectionExpectation::Absent,
            );
            drop(replay_bank);
            replay_root
                .close()
                .map_err(|_| EngineerVerifierLoopError::Io)?;
            result
        };
        sealed.cleanup()?;
        let published = match published? {
            VerifierOutcome::Rejected(_) => {
                let failed = self.transition_with_event(
                    loaded,
                    EngineerVerifierPhaseV1::Failed,
                    EngineerVerifierTriggerV1::FailureRecorded,
                )?;
                broker.close_lease(&lease, CleanupReason::Failed)?;
                let mut next = projection(&failed)?.clone();
                close_durable_workspace(&mut next);
                let failed = cas_replace(&self.execution, failed, next)?;
                return Ok(EngineerVerifierLoopOutcome::Failed {
                    state_digest: projection(&failed)?.state_digest.clone(),
                    reason: EngineerVerifierFailureReason::VerificationRejected,
                });
            }
            VerifierOutcome::Published(value) => value,
        };
        if published.bundle.verdict != VerificationVerdict::Pass {
            let failed = self.transition_with_event(
                loaded,
                EngineerVerifierPhaseV1::Failed,
                EngineerVerifierTriggerV1::FailureRecorded,
            )?;
            broker.close_lease(&lease, CleanupReason::Failed)?;
            let mut next = projection(&failed)?.clone();
            close_durable_workspace(&mut next);
            let failed = cas_replace(&self.execution, failed, next)?;
            return Ok(EngineerVerifierLoopOutcome::Failed {
                state_digest: projection(&failed)?.state_digest.clone(),
                reason: EngineerVerifierFailureReason::VerificationFailed,
            });
        }
        validate_verifier_publication_binding(&replay_plan, &recovered_bridge, &published)?;

        let (record, current) = if let Some(expected_current) = authoritative_current {
            let expected_record = self
                .evidence
                .load_bundle(&expected_current.record_digest)?
                .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
            let candidate_record = match &published.storage.publication {
                PublishOutcome::Inserted(value) | PublishOutcome::ExistingIdentical(value) => value,
            };
            let candidate_current = match &published.storage.projection {
                CasOutcome::Applied(value) | CasOutcome::Unchanged(value) => value,
                CasOutcome::Conflict(_) => {
                    return Err(EngineerVerifierLoopError::ProjectionConflict)
                }
            };
            if candidate_record != &expected_record
                || candidate_current.key != expected_current.key
                || candidate_current.bundle_id != expected_current.bundle_id
                || candidate_current.record_digest != expected_current.record_digest
            {
                return Err(EngineerVerifierLoopError::ProjectionConflict);
            }
            (expected_record, expected_current)
        } else {
            authoritative_publication(&self.evidence, &published)?
        };
        let transcript = PersistedVerificationTranscriptV1::from_live(&published.transcript)?;
        let transcript_digest = transcript.digest()?;
        let observed_at = self.clock.now();
        let mut next = projection(&loaded)?.clone();
        next.verifier = Some(VerifierExecutionStateV1::PublicationObserved {
            replay_plan_digest: replay_plan.replay_plan_digest,
            transcript,
            transcript_digest,
            bundle: record.bundle,
            bundle_record_digest: record.digest,
            evidence_current: current,
            observed_at,
        });
        next.controller_time = observed_at;
        next.refresh_digest()?;
        loaded = cas_replace(&self.execution, loaded, next)?;
        self.admit_observed_publication(broker, loaded, lease, &verifier)
    }

    fn admit_observed_publication(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        lease: TrustedWorkspaceLease,
        verifier: &VerifierReplayInputs<'_>,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        let state = projection(&loaded)?.clone();
        let replay_plan = state
            .verifier_replay_plan
            .as_ref()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        let Some(VerifierExecutionStateV1::PublicationObserved {
            bundle,
            bundle_record_digest,
            evidence_current,
            ..
        }) = state.verifier.as_ref()
        else {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        };
        let current = self
            .evidence
            .load_current(&replay_plan.evidence_key)?
            .filter(|current| current == evidence_current);
        let record = match current.as_ref() {
            Some(current) => self.evidence.load_bundle(&current.record_digest)?,
            None => None,
        };
        let (Some(current), Some(record)) = (current, record) else {
            return self.fail_with_cleanup(
                broker,
                &lease,
                loaded,
                EngineerVerifierFailureReason::RecoveryConflict,
            );
        };
        if record.bundle != *bundle || record.digest != *bundle_record_digest {
            return self.fail_with_cleanup(
                broker,
                &lease,
                loaded,
                EngineerVerifierFailureReason::RecoveryConflict,
            );
        }

        let key = replay_plan.evidence_key.clone();
        let admitted = self
            .evidence
            .with_completion_admission_lease(&[key], |snapshot| {
                validate_admission_snapshot(
                    snapshot,
                    &record,
                    &current,
                    replay_plan,
                    state
                        .workspace_bridge
                        .as_ref()
                        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?,
                    verifier,
                )?;
                let mut next = projection(&loaded)?.clone();
                let Some(VerifierExecutionStateV1::PublicationObserved {
                    replay_plan_digest,
                    transcript,
                    transcript_digest,
                    bundle,
                    bundle_record_digest,
                    evidence_current,
                    observed_at,
                }) = next.verifier.clone()
                else {
                    return Err(EngineerVerifierLoopError::ProjectionConflict);
                };
                let at = self.clock.now();
                let transition_trigger = if next.cancellation.is_some() {
                    transition_state(
                        &mut next,
                        EngineerVerifierPhaseV1::Cancelled,
                        EngineerVerifierTriggerV1::CancellationAccepted,
                        at,
                    )?;
                    EngineerVerifierTriggerV1::CancellationAccepted
                } else {
                    next.verifier = Some(VerifierExecutionStateV1::Admitted {
                        replay_plan_digest,
                        transcript,
                        transcript_digest,
                        bundle,
                        bundle_record_digest,
                        evidence_current,
                        observed_at,
                        admitted_at: at,
                    });
                    transition_state(
                        &mut next,
                        EngineerVerifierPhaseV1::Reviewing,
                        EngineerVerifierTriggerV1::VerificationEvidenceAccepted,
                        at,
                    )?;
                    EngineerVerifierTriggerV1::VerificationEvidenceAccepted
                };
                attach_pending_projection(
                    &self.log,
                    &mut next,
                    EngineerVerifierPhaseV1::Verifying,
                    transition_trigger,
                )?;
                cas_replace(&self.execution, loaded.clone(), next)
            });
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(EngineerVerifierLoopError::ProjectionConflict) => {
                return self.fail_with_cleanup(
                    broker,
                    &lease,
                    loaded,
                    EngineerVerifierFailureReason::RecoveryConflict,
                )
            }
            Err(error) => return Err(error),
        };
        let admitted = reconcile_pending(&self.log, &self.execution, admitted)?;
        broker.close_lease(
            &lease,
            if projection(&admitted)?.phase == EngineerVerifierPhaseV1::Cancelled {
                CleanupReason::Cancelled
            } else {
                CleanupReason::Completed
            },
        )?;
        let mut next = projection(&admitted)?.clone();
        close_durable_workspace(&mut next);
        let admitted = cas_replace(&self.execution, admitted, next)?;
        let state = projection(&admitted)?;
        if state.phase == EngineerVerifierPhaseV1::Cancelled {
            return Ok(EngineerVerifierLoopOutcome::Cancelled {
                state_digest: state.state_digest.clone(),
            });
        }
        let bundle = admitted_bundle(state).ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        Ok(EngineerVerifierLoopOutcome::Reviewing {
            state_digest: state.state_digest.clone(),
            bundle_id: bundle.bundle_id.clone(),
        })
    }

    fn transition_with_event(
        &self,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        to: EngineerVerifierPhaseV1,
        trigger: EngineerVerifierTriggerV1,
    ) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
        let mut next = projection(&loaded)?.clone();
        let from = next.phase;
        transition_state(&mut next, to, trigger, self.clock.now())?;
        attach_pending_projection(&self.log, &mut next, from, trigger)?;
        let loaded = cas_replace(&self.execution, loaded, next)?;
        reconcile_pending(&self.log, &self.execution, loaded)
    }

    fn fail_with_cleanup(
        &self,
        broker: &mut WorkspaceCapabilityBroker,
        lease: &TrustedWorkspaceLease,
        loaded: ovca_runtime_core::LoadedExecutionRun,
        reason: EngineerVerifierFailureReason,
    ) -> Result<EngineerVerifierLoopOutcome, EngineerVerifierLoopError> {
        broker.close_lease(lease, CleanupReason::Failed)?;
        let mut next = projection(&loaded)?.clone();
        close_durable_workspace(&mut next);
        let loaded = cas_replace(&self.execution, loaded, next)?;
        let failed = self.transition_with_event(
            loaded,
            EngineerVerifierPhaseV1::Failed,
            EngineerVerifierTriggerV1::FailureRecorded,
        )?;
        Ok(EngineerVerifierLoopOutcome::Failed {
            state_digest: projection(&failed)?.state_digest.clone(),
            reason,
        })
    }
}

fn projection(
    loaded: &ovca_runtime_core::LoadedExecutionRun,
) -> Result<&EngineerVerifierStateV1, EngineerVerifierLoopError> {
    loaded
        .envelope
        .engineer_verifier
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)
}

fn expect_applied(
    outcome: EngineerVerifierCasOutcome,
) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
    match outcome {
        EngineerVerifierCasOutcome::Applied(value) => Ok(value),
        EngineerVerifierCasOutcome::Unchanged(_) | EngineerVerifierCasOutcome::Conflict(_) => {
            Err(EngineerVerifierLoopError::ProjectionConflict)
        }
    }
}

fn cas_replace(
    authority: &DurableExecutionAuthority,
    loaded: ovca_runtime_core::LoadedExecutionRun,
    next: EngineerVerifierStateV1,
) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
    let expected = projection(&loaded)?.state_digest.clone();
    let run_id = next.run_id.clone();
    expect_applied(authority.compare_and_swap_engineer_verifier(
        &run_id,
        loaded.revision,
        Some(&expected),
        next,
    )?)
}

fn transition_state(
    state: &mut EngineerVerifierStateV1,
    to: EngineerVerifierPhaseV1,
    trigger: EngineerVerifierTriggerV1,
    at: DateTime<Utc>,
) -> Result<(), EngineerVerifierLoopError> {
    if !ovca_runtime_core::transition_allowed(state.phase, trigger, to) {
        return Err(EngineerVerifierLoopError::Kernel(
            EngineerVerifierError::InvalidTransition,
        ));
    }
    state.phase = to;
    state.phase_revision = state
        .phase_revision
        .checked_add(1)
        .ok_or(EngineerVerifierError::Overflow)?;
    state.controller_time = at;
    state.refresh_digest()?;
    Ok(())
}

fn close_durable_workspace(state: &mut EngineerVerifierStateV1) {
    if let Some(workspace) = &mut state.workspace {
        workspace.closed = true;
        workspace.cleanup_required = false;
    }
}

fn build_grant(
    execution: &RoleExecutionRequest,
    lease: &TrustedWorkspaceLease,
    input: &EngineerWorkspaceInput,
) -> Result<CapabilityGrantV1, EngineerVerifierLoopError> {
    let grant = CapabilityGrantV1 {
        contract_version: TOOL_BOUNDARY_CONTRACT_VERSION,
        grant_id: input.grant_id.clone(),
        invocation_id: execution.invocation.invocation_id.clone(),
        invocation_digest: execution
            .invocation
            .canonical_digest()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        attempt: execution.attempt,
        issuer: execution.invocation.invoker.clone(),
        grantee: execution.invocation.target.clone(),
        scope: execution.invocation.scope.clone(),
        grant_authority: input.grant_authority.clone(),
        grant_authority_digest: canonical_authority_digest(&input.grant_authority)
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        lease_id: lease.observation().lease_id.clone(),
        lease_digest: lease.digest().to_owned(),
        workspace_id: lease.observation().workspace_id.clone(),
        snapshot_digest: lease.initial_snapshot().snapshot_digest.clone(),
        read_paths: input.read_paths.clone(),
        write_paths: input.write_paths.clone(),
        max_read_bytes: input.max_read_bytes,
        max_write_bytes: input.max_write_bytes,
        command_policy: CapabilityPolicyV1::Denied,
        environment_policy: CapabilityPolicyV1::Denied,
        network_policy: CapabilityPolicyV1::Denied,
        valid_from: input.grant_valid_from,
        valid_until: input.grant_valid_until,
    };
    grant
        .validate()
        .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
    Ok(grant)
}

fn validate_payload_set(
    plan: &EngineerLogicalPlanV1,
    payloads: &BTreeMap<String, &[u8]>,
) -> Result<(), EngineerVerifierLoopError> {
    let expected = plan
        .ordered_effects
        .iter()
        .filter(|effect| matches!(effect.operation, ToolOperationV1::WriteFile { .. }))
        .map(|effect| effect.effect_id.as_str())
        .collect::<BTreeSet<_>>();
    if payloads.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(EngineerVerifierLoopError::InvalidInput);
    }
    for effect in &plan.ordered_effects {
        effect.validate_payload(payloads.get(&effect.effect_id).copied())?;
    }
    Ok(())
}

fn prepare_write(
    state: &EngineerVerifierStateV1,
    template: &ovca_runtime_core::PlannedToolEffectTemplateV1,
    request: ToolRequestV1,
    broker: &WorkspaceCapabilityBroker,
    prepared_at: DateTime<Utc>,
) -> Result<PreparedWriteEffectV1, EngineerVerifierLoopError> {
    let workspace = state
        .workspace
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    let ToolOperationV1::WriteFile {
        logical_path,
        content_sha256,
        byte_length,
    } = &template.operation
    else {
        return Err(EngineerVerifierLoopError::InvalidInput);
    };
    let before = workspace.current_snapshot.clone();
    let before_file = before
        .files
        .iter()
        .find(|file| file.logical_path == *logical_path)
        .cloned();
    let intended_file = WorkspaceFileV1 {
        logical_path: logical_path.clone(),
        sha256: content_sha256.clone(),
        byte_length: *byte_length,
    };
    let mut files = before.files.clone();
    if let Some(index) = files
        .iter()
        .position(|file| file.logical_path == *logical_path)
    {
        files[index] = intended_file.clone();
    } else {
        files.push(intended_file.clone());
        files.sort_by(|left, right| {
            left.logical_path
                .as_bytes()
                .cmp(right.logical_path.as_bytes())
        });
    }
    let generation = before
        .generation
        .checked_add(1)
        .ok_or(EngineerVerifierError::Overflow)?;
    let after = WorkspaceSnapshotV1::try_new(
        before.workspace_id.clone(),
        before.lease_id.clone(),
        generation,
        files,
    )
    .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
    let prepared = PreparedWriteEffectV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        ordinal: template.ordinal,
        effect_id: template.effect_id.clone(),
        request_digest: request
            .canonical_digest()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        payload_sha256: template.payload_sha256.clone(),
        lease_digest: workspace.lease_digest.clone(),
        grant_digest: workspace.grant_digest.clone(),
        expected_before_snapshot: before,
        expected_before_file: before_file,
        intended_after_snapshot: after,
        intended_after_file: intended_file,
        reserved_sequence: broker.next_receipt_sequence(),
        prepared_at,
        request,
    };
    prepared.validate()?;
    Ok(prepared)
}

#[derive(Debug, Clone)]
struct VerifierInputIdentity {
    behavior_sha256: String,
    capabilities_sha256: String,
    selection_sha256: String,
    source_manifest_sha256: String,
    failure_identities_sha256: String,
    executable_profiles_identity_sha256: String,
    environment_names: Vec<String>,
    environment_digest: String,
    source_manifest_fingerprint: String,
    command_set_digest: String,
    capability_set_digest: String,
    policy_digest: String,
}

impl VerifierInputIdentity {
    fn compute(input: &VerifierReplayInputs<'_>) -> Result<Self, EngineerVerifierLoopError> {
        input
            .behavior
            .validate()
            .and_then(|_| input.selection.validate())
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        if input.capabilities.is_empty()
            || input.implementation_actor == input.verifier_actor
            || !input.limits.is_valid()
            || input.created_at.timestamp_subsec_nanos() % 1_000_000 != 0
        {
            return Err(EngineerVerifierLoopError::InvalidInput);
        }
        for capability in input.capabilities {
            capability
                .validate_non_command_fields()
                .and_then(|_| capability.validate_commands())
                .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        }
        if input
            .capabilities
            .windows(2)
            .any(|pair| pair[0].capability_id.as_bytes() >= pair[1].capability_id.as_bytes())
        {
            return Err(EngineerVerifierLoopError::InvalidInput);
        }
        input
            .source_manifest
            .validate()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let command_count = input
            .capabilities
            .iter()
            .try_fold(0_usize, |count, capability| {
                count.checked_add(capability.commands.len())
            })
            .ok_or(EngineerVerifierLoopError::InvalidInput)?;
        if !validate_failure_identity_map(
            input.failure_identities,
            command_count,
            &input.created_at,
        ) {
            return Err(EngineerVerifierLoopError::InvalidInput);
        }

        let behavior_sha256 = verification_sha256_hex(
            &input
                .behavior
                .canonical_json_bytes()
                .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        );
        let capabilities_sha256 = verification_sha256_hex(
            &serde_json::to_vec(input.capabilities)
                .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        );
        let selection_sha256 = verification_sha256_hex(
            &targeted_rerun_selection_canonical_json_bytes(input.selection)?,
        );
        let source_manifest_bytes = input
            .source_manifest
            .canonical_json_bytes()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let source_manifest_sha256 = verification_sha256_hex(&source_manifest_bytes);
        let source_manifest_fingerprint = input
            .source_manifest
            .fingerprint()
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let failure_identities_sha256 = failure_identity_digest(input.failure_identities)?;
        let (executable_profiles_identity_sha256, environment_names) =
            executable_profile_identity(input.capabilities, input.executable_registry)?;
        let names_set = environment_names.iter().cloned().collect::<BTreeSet<_>>();
        if input.environment_bindings.digest_for(&names_set).as_deref()
            != Some(input.environment_digest)
        {
            return Err(EngineerVerifierLoopError::InvalidInput);
        }
        let command_set_digest = verification_command_set_digest(input.capabilities)
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let capability_set_digest = verification_capability_set_digest(input.selection)
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let policy_digest = verification_policy_digest(input.capabilities)
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        if source_manifest_fingerprint != input.selection.source_fingerprint
            || policy_digest != input.selection.policy_digest
        {
            return Err(EngineerVerifierLoopError::InvalidInput);
        }
        Ok(Self {
            behavior_sha256,
            capabilities_sha256,
            selection_sha256,
            source_manifest_sha256,
            failure_identities_sha256,
            executable_profiles_identity_sha256,
            environment_names,
            environment_digest: input.environment_digest.to_owned(),
            source_manifest_fingerprint,
            command_set_digest,
            capability_set_digest,
            policy_digest,
        })
    }
}

#[derive(Serialize)]
struct FailureIdentityRecord<'a> {
    failure_code: &'static str,
    command_sequence: Option<u32>,
    failure_id: &'a str,
}

fn targeted_rerun_selection_canonical_json_bytes(
    selection: &ovca_types::TargetedRerunSelection,
) -> Result<Vec<u8>, EngineerVerifierLoopError> {
    selection
        .validate()
        .map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
    serde_json::to_vec(selection).map_err(|_| EngineerVerifierLoopError::InvalidInput)
}

fn failure_identity_digest(
    identities: &FailureIdentityMap,
) -> Result<String, EngineerVerifierLoopError> {
    let records = identities
        .iter()
        .map(|(key, failure_id)| FailureIdentityRecord {
            failure_code: failure_code_name(key.failure_code),
            command_sequence: key.command_sequence,
            failure_id,
        })
        .collect::<Vec<_>>();
    Ok(verification_sha256_hex(
        &serde_json::to_vec(&records).map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
    ))
}

fn failure_code_name(code: FailureCode) -> &'static str {
    match code {
        FailureCode::TestFailedUnclassified => "test_failed_unclassified",
        FailureCode::PolicyBlock => "policy_block",
        FailureCode::EnvironmentBlock => "environment_block",
        FailureCode::ExecutableUnavailable => "executable_unavailable",
        FailureCode::ExecutableTamper => "executable_tamper",
        FailureCode::CommandTimeout => "command_timeout",
        FailureCode::OutputLimit => "output_limit",
        FailureCode::SourceDrift => "source_drift",
        FailureCode::SnapshotTamper => "snapshot_tamper",
    }
}

#[derive(Serialize)]
struct ExecutableProfileIdentityV1<'a> {
    executable_id: &'a str,
    sha256: &'a str,
    enabled: bool,
    approved: bool,
    reviewed_offline: bool,
    allowed_environment_names: Vec<&'a str>,
}

fn executable_profile_identity(
    capabilities: &[CapabilityDefinition],
    registry: &ExecutableRegistry,
) -> Result<(String, Vec<String>), EngineerVerifierLoopError> {
    if !registry.validate_structure() {
        return Err(EngineerVerifierLoopError::InvalidInput);
    }
    let referenced = capabilities
        .iter()
        .flat_map(|capability| capability.commands.iter())
        .map(|command| command.executable_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut profiles = Vec::with_capacity(referenced.len());
    for executable_id in referenced {
        let profile = registry
            .profiles
            .get(executable_id)
            .ok_or(EngineerVerifierLoopError::InvalidInput)?;
        profiles.push(ExecutableProfileIdentityV1 {
            executable_id: &profile.executable_id,
            sha256: &profile.sha256,
            enabled: profile.enabled,
            approved: profile.approved,
            reviewed_offline: profile.reviewed_offline,
            allowed_environment_names: profile
                .allowed_environment_names
                .iter()
                .map(String::as_str)
                .collect(),
        });
    }
    let environment_names = capabilities
        .iter()
        .flat_map(|capability| capability.commands.iter())
        .flat_map(|command| command.environment_names.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok((
        verification_sha256_hex(
            &serde_json::to_vec(&profiles).map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
        ),
        environment_names,
    ))
}

fn validate_source_manifest(
    snapshot: &WorkspaceSnapshotV1,
    manifest: &SourceManifest,
) -> Result<(), EngineerVerifierLoopError> {
    let expected = snapshot
        .files
        .iter()
        .map(|file| SourceFile {
            logical_path: file.logical_path.clone(),
            sha256: file.sha256.clone(),
        })
        .collect::<Vec<_>>();
    if manifest.files != expected {
        return Err(EngineerVerifierLoopError::InvalidInput);
    }
    Ok(())
}

fn build_workspace_bridge(
    state: &EngineerVerifierStateV1,
    sealed: &TrustedSealedWorkspace,
    identity: &VerifierInputIdentity,
) -> Result<WorkspaceDiffBridgeV1, EngineerVerifierLoopError> {
    let workspace = state
        .workspace
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    if sealed.snapshot() != &workspace.current_snapshot {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let before = &workspace.initial_snapshot;
    let after = &workspace.current_snapshot;
    let before_map = before
        .files
        .iter()
        .map(|file| (file.logical_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let after_map = after
        .files
        .iter()
        .map(|file| (file.logical_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let changed_paths = before_map
        .keys()
        .chain(after_map.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| before_map.get(path) != after_map.get(path))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let before_file_identities = changed_paths
        .iter()
        .map(|path| WorkspaceDiffPathIdentityV1 {
            logical_path: path.clone(),
            file: before_map.get(path.as_str()).map(|value| (*value).clone()),
        })
        .collect();
    let after_file_identities = changed_paths
        .iter()
        .map(|path| WorkspaceDiffPathIdentityV1 {
            logical_path: path.clone(),
            file: after_map.get(path.as_str()).map(|value| (*value).clone()),
        })
        .collect();
    let mut bridge = WorkspaceDiffBridgeV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        run_id: state.run_id.clone(),
        goal_id: state.goal_id.clone(),
        task_id: state.task_id.clone(),
        attempt: state.attempt,
        broker_before_snapshot_digest: before.snapshot_digest.clone(),
        broker_after_snapshot_digest: after.snapshot_digest.clone(),
        changed_paths,
        before_file_identities,
        after_file_identities,
        verifier_source_manifest_fingerprint: identity.source_manifest_fingerprint.clone(),
        source_copy_digest: sealed.source_copy_digest().to_owned(),
        snapshot_copy_digest: sealed.snapshot_copy_digest().to_owned(),
        invocation_digest: state.plan.invocation_digest.clone(),
        engineer_result_digest: state
            .engineer_result_digest
            .clone()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?,
        command_set_digest: identity.command_set_digest.clone(),
        capability_set_digest: identity.capability_set_digest.clone(),
        policy_digest: identity.policy_digest.clone(),
        environment_digest: identity.environment_digest.clone(),
        canonical_diff_digest: String::new(),
    };
    bridge.canonical_diff_digest = bridge.computed_digest()?;
    bridge.validate()?;
    Ok(bridge)
}

fn build_replay_plan(
    state: &EngineerVerifierStateV1,
    bridge: &WorkspaceDiffBridgeV1,
    identity: &VerifierInputIdentity,
    input: &VerifierReplayInputs<'_>,
) -> Result<VerifierReplayPlanV1, EngineerVerifierLoopError> {
    if input.implementation_actor.as_str() != state.plan.invocation.target.principal_id.as_str()
        || input.selection.run_id != state.run_id
        || input.selection.goal_id != state.goal_id
        || input.selection.task_id != state.task_id
    {
        return Err(EngineerVerifierLoopError::InvalidInput);
    }
    let mut plan = VerifierReplayPlanV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        evidence_key: EvidenceKey {
            run_id: state.run_id.clone(),
            goal_id: state.goal_id.clone(),
            task_id: state.task_id.clone(),
        },
        attempt: state.attempt,
        created_at: input.created_at,
        implementation_actor: input.implementation_actor.clone(),
        verifier_actor: input.verifier_actor.clone(),
        limits: VerifierExecutionLimitsV1 {
            timeout_millis: input.limits.timeout_millis,
            stdout_cap_bytes: input.limits.stdout_cap_bytes,
            stderr_cap_bytes: input.limits.stderr_cap_bytes,
        },
        behavior_sha256: identity.behavior_sha256.clone(),
        capabilities_sha256: identity.capabilities_sha256.clone(),
        selection_sha256: identity.selection_sha256.clone(),
        source_manifest_sha256: identity.source_manifest_sha256.clone(),
        failure_identities_sha256: identity.failure_identities_sha256.clone(),
        executable_profiles_identity_sha256: identity.executable_profiles_identity_sha256.clone(),
        environment_names: identity.environment_names.clone(),
        environment_digest: identity.environment_digest.clone(),
        sealed_workspace_snapshot_digest: state
            .workspace
            .as_ref()
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
            .current_snapshot
            .snapshot_digest
            .clone(),
        source_manifest_fingerprint: identity.source_manifest_fingerprint.clone(),
        workspace_bridge_digest: bridge.canonical_diff_digest.clone(),
        expected_initial_projection: ovca_runtime_core::ExpectedInitialProjectionV1::Absent,
        replay_plan_digest: String::new(),
    };
    plan.replay_plan_digest = plan.computed_digest()?;
    plan.validate()?;
    Ok(plan)
}

fn validate_replay_resupply(
    state: &EngineerVerifierStateV1,
    identity: &VerifierInputIdentity,
    input: &VerifierReplayInputs<'_>,
) -> Result<(), EngineerVerifierLoopError> {
    let plan = state
        .verifier_replay_plan
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    let bridge = state
        .workspace_bridge
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    let workspace = state
        .workspace
        .as_ref()
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    plan.validate()?;
    if plan.evidence_key.run_id != state.run_id
        || plan.evidence_key.goal_id != state.goal_id
        || plan.evidence_key.task_id != state.task_id
        || plan.attempt != state.attempt
        || plan.created_at != input.created_at
        || plan.implementation_actor != input.implementation_actor
        || plan.verifier_actor != input.verifier_actor
        || plan.implementation_actor.as_str() != state.plan.invocation.target.principal_id.as_str()
        || input.selection.run_id != state.run_id
        || input.selection.goal_id != state.goal_id
        || input.selection.task_id != state.task_id
        || plan.limits.timeout_millis != input.limits.timeout_millis
        || plan.limits.stdout_cap_bytes != input.limits.stdout_cap_bytes
        || plan.limits.stderr_cap_bytes != input.limits.stderr_cap_bytes
        || plan.behavior_sha256 != identity.behavior_sha256
        || plan.capabilities_sha256 != identity.capabilities_sha256
        || plan.selection_sha256 != identity.selection_sha256
        || plan.source_manifest_sha256 != identity.source_manifest_sha256
        || plan.failure_identities_sha256 != identity.failure_identities_sha256
        || plan.executable_profiles_identity_sha256 != identity.executable_profiles_identity_sha256
        || plan.environment_names != identity.environment_names
        || plan.environment_digest != identity.environment_digest
        || plan.sealed_workspace_snapshot_digest != workspace.current_snapshot.snapshot_digest
        || plan.source_manifest_fingerprint != identity.source_manifest_fingerprint
        || plan.workspace_bridge_digest != bridge.canonical_diff_digest
        || bridge.command_set_digest != identity.command_set_digest
        || bridge.capability_set_digest != identity.capability_set_digest
        || bridge.policy_digest != identity.policy_digest
        || bridge.environment_digest != identity.environment_digest
        || plan.expected_initial_projection
            != ovca_runtime_core::ExpectedInitialProjectionV1::Absent
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    Ok(())
}

fn validate_verifier_publication_binding(
    plan: &VerifierReplayPlanV1,
    bridge: &WorkspaceDiffBridgeV1,
    published: &PublishedVerification,
) -> Result<(), EngineerVerifierLoopError> {
    let bundle = &published.bundle;
    bundle
        .validate()
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    if bundle.run_id != plan.evidence_key.run_id
        || bundle.goal_id != plan.evidence_key.goal_id
        || bundle.task_id != plan.evidence_key.task_id
        || bundle.implementation_actor != plan.implementation_actor
        || bundle.verifier_actor != plan.verifier_actor
        || bundle.created_at != plan.created_at
        || bundle.fingerprints.source_pre != plan.source_manifest_fingerprint
        || bundle.fingerprints.source_post != plan.source_manifest_fingerprint
        || bundle.fingerprints.behavior_contract != plan.behavior_sha256
        || bundle.fingerprints.capability_set != bridge.capability_set_digest
        || bundle.fingerprints.command != bridge.command_set_digest
        || bundle.fingerprints.policy != bridge.policy_digest
        || bundle.fingerprints.environment != bridge.environment_digest
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    Ok(())
}

fn verifier_request<'a>(
    input: &'a VerifierReplayInputs<'a>,
    sealed: &'a TrustedSealedWorkspace,
) -> VerifierRequest<'a> {
    VerifierRequest {
        behavior: input.behavior,
        capabilities: input.capabilities,
        selection: input.selection,
        source_manifest: input.source_manifest,
        source_root: sealed.source_root(),
        snapshot_root: sealed.snapshot_root(),
        executable_registry: input.executable_registry,
        environment_bindings: input.environment_bindings,
        environment_digest: input.environment_digest,
        limits: input.limits,
        implementation_actor: input.implementation_actor.clone(),
        verifier_actor: input.verifier_actor.clone(),
        created_at: input.created_at,
        failure_identities: input.failure_identities,
    }
}

fn authoritative_publication(
    bank: &EvidenceBank,
    published: &PublishedVerification,
) -> Result<(BundleRecord, EvidenceCurrent), EngineerVerifierLoopError> {
    let record = match &published.storage.publication {
        PublishOutcome::Inserted(record) | PublishOutcome::ExistingIdentical(record) => record,
    };
    let current = match &published.storage.projection {
        CasOutcome::Applied(current) | CasOutcome::Unchanged(current) => current,
        CasOutcome::Conflict(_) => return Err(EngineerVerifierLoopError::ProjectionConflict),
    };
    let loaded_current = bank
        .load_current(&current.key)?
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    let loaded_record = bank
        .load_bundle(&loaded_current.record_digest)?
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    if &loaded_record != record || loaded_current != *current {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    Ok((loaded_record, loaded_current))
}

fn validate_admission_snapshot(
    snapshot: &CompletionAdmissionSnapshot,
    expected_record: &BundleRecord,
    expected_current: &EvidenceCurrent,
    replay_plan: &VerifierReplayPlanV1,
    bridge: &WorkspaceDiffBridgeV1,
    verifier: &VerifierReplayInputs<'_>,
) -> Result<(), EngineerVerifierLoopError> {
    if snapshot.bundles.len() != 1
        || snapshot.bundles[0].record != *expected_record
        || snapshot.bundles[0].current != *expected_current
        || expected_record.bundle.verdict != VerificationVerdict::Pass
        || expected_record.bundle.implementation_actor == expected_record.bundle.verifier_actor
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let registry_rows = snapshot
        .capabilities
        .iter()
        .map(|capability| ovca_types::CapabilityRegistryRow {
            definition: capability.record.definition.clone(),
            record_digest: capability.current.record_digest.clone(),
            generation: capability.current.token.generation,
            state_digest: capability.current.token.state_digest.clone(),
        })
        .collect::<Vec<_>>();
    let registry = ovca_types::CapabilityRegistrySnapshot::new(registry_rows)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    if verifier.selection.registry_snapshot_digest != registry.registry_snapshot_digest
        || verifier.capabilities.len() != verifier.selection.capabilities.len()
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let current_capabilities = snapshot
        .capabilities
        .iter()
        .map(|capability| (capability.current.capability_id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    for (definition, selected) in verifier
        .capabilities
        .iter()
        .zip(&verifier.selection.capabilities)
    {
        let current = current_capabilities
            .get(selected.capability_id.as_str())
            .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
        if current.current.revision != selected.revision
            || current.current.record_digest != selected.record_digest
            || current.record.digest != selected.record_digest
            || current.record.definition != *definition
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
    }
    let capabilities_sha256 = verification_sha256_hex(
        &serde_json::to_vec(verifier.capabilities)
            .map_err(|_| EngineerVerifierLoopError::InvalidInput)?,
    );
    let capability_set_digest = verification_capability_set_digest(verifier.selection)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    let command_set_digest = verification_command_set_digest(verifier.capabilities)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    let policy_digest = verification_policy_digest(verifier.capabilities)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    if capabilities_sha256 != replay_plan.capabilities_sha256
        || capability_set_digest != expected_record.bundle.fingerprints.capability_set
        || capability_set_digest != bridge.capability_set_digest
        || command_set_digest != expected_record.bundle.fingerprints.command
        || command_set_digest != bridge.command_set_digest
        || policy_digest != expected_record.bundle.fingerprints.policy
        || policy_digest != bridge.policy_digest
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    Ok(())
}

fn admitted_bundle(state: &EngineerVerifierStateV1) -> Option<&VerificationBundle> {
    match state.verifier.as_ref()? {
        VerifierExecutionStateV1::Admitted { bundle, .. } => Some(bundle),
        _ => None,
    }
}

fn attach_pending_projection(
    log: &RunEventLog,
    state: &mut EngineerVerifierStateV1,
    from: EngineerVerifierPhaseV1,
    trigger: EngineerVerifierTriggerV1,
) -> Result<(), EngineerVerifierLoopError> {
    if state.pending_projection.is_some() {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let projection = EngineerVerifierPhaseProjectionV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        run_id: state.run_id.clone(),
        goal_id: state.goal_id.clone(),
        task_id: state.task_id.clone(),
        from,
        to: state.phase,
        trigger,
        phase_revision: state.phase_revision,
        attempt: state.attempt,
        execution_binding_digest: state.execution_binding.execution_binding_digest.clone(),
        logical_plan_digest: state.plan.logical_plan_digest.clone(),
        state_digest: state.state_digest.clone(),
        resolved_effect_ledger_digest: state.ledger.resolved_effect_ledger_digest.clone(),
        engineer_result_digest: state.engineer_result_digest.clone(),
        verifier_transcript_digest: state
            .verifier
            .as_ref()
            .and_then(VerifierExecutionStateV1::transcript_digest)
            .map(str::to_owned),
        controller_time: state.controller_time,
    };
    projection.validate()?;
    let event_id = derive_phase_event_id(&projection)?;
    let expected_cursor = current_run_cursor(log, &state.run_id)?;
    let stored_cursor = state
        .projected_sequence
        .zip(state.projected_event_id.clone());
    if expected_cursor != stored_cursor {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let sequence = stored_cursor
        .as_ref()
        .map_or(0, |value| value.0.saturating_add(1));
    if sequence == u64::MAX {
        return Err(EngineerVerifierLoopError::Kernel(
            EngineerVerifierError::Overflow,
        ));
    }
    let mut metadata = BTreeMap::new();
    metadata.insert(
        PHASE_METADATA_KEY.to_owned(),
        Value::String(
            String::from_utf8(projection.canonical_json_bytes()?)
                .map_err(|_| EngineerVerifierLoopError::Utf8)?,
        ),
    );
    let event = RunEvent {
        contract_version: ContractVersion::current(),
        id: EventId::from(event_id.clone()),
        run_id: state.run_id.clone(),
        sequence,
        previous_event_id: stored_cursor
            .as_ref()
            .map(|value| EventId::from(value.1.clone())),
        occurred_at: state.controller_time,
        producer_role: Role::Coordinator,
        payload: RunEventPayload::NoteRecorded {
            message: PHASE_NOTE.to_owned(),
        },
        metadata,
    };
    let event_bytes =
        serde_json::to_vec(&event).map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
    state.pending_projection = Some(PendingPhaseProjectionV1 {
        event_id,
        sequence,
        previous_event_id: stored_cursor.map(|value| value.1),
        event_digest: verification_sha256_hex(&event_bytes),
        event_bytes,
    });
    state.validate()?;
    Ok(())
}

fn reconcile_pending(
    log: &RunEventLog,
    execution: &DurableExecutionAuthority,
    loaded: ovca_runtime_core::LoadedExecutionRun,
) -> Result<ovca_runtime_core::LoadedExecutionRun, EngineerVerifierLoopError> {
    let state = projection(&loaded)?.clone();
    let Some(pending) = state.pending_projection.clone() else {
        let actual = current_run_cursor(log, &state.run_id)?;
        let expected = state
            .projected_sequence
            .zip(state.projected_event_id.clone());
        if actual != expected {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        return Ok(loaded);
    };
    pending.validate()?;
    let frozen_event: RunEvent = serde_json::from_slice(&pending.event_bytes)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    if serde_json::to_vec(&frozen_event)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?
        != pending.event_bytes
        || frozen_event.id.as_str() != pending.event_id
        || frozen_event.sequence != pending.sequence
        || frozen_event.run_id != state.run_id
        || frozen_event.previous_event_id.as_ref().map(EventId::as_str)
            != pending.previous_event_id.as_deref()
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let frozen_projection = validate_phase_event(&frozen_event)?
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?;
    if frozen_projection.run_id != state.run_id
        || frozen_projection.goal_id != state.goal_id
        || frozen_projection.task_id != state.task_id
        || frozen_projection.to != state.phase
        || frozen_projection.phase_revision != state.phase_revision
        || frozen_projection.attempt != state.attempt
        || frozen_projection.execution_binding_digest
            != state.execution_binding.execution_binding_digest
        || frozen_projection.logical_plan_digest != state.plan.logical_plan_digest
        || frozen_projection.state_digest != state.state_digest
        || frozen_projection.resolved_effect_ledger_digest
            != state.ledger.resolved_effect_ledger_digest
        || frozen_projection.engineer_result_digest != state.engineer_result_digest
        || frozen_projection.verifier_transcript_digest
            != state
                .verifier
                .as_ref()
                .and_then(VerifierExecutionStateV1::transcript_digest)
                .map(str::to_owned)
        || frozen_projection.controller_time != state.controller_time
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }

    let rows = raw_event_rows(log)?;
    let run_rows = rows
        .iter()
        .filter(|row| row.event.run_id == state.run_id)
        .collect::<Vec<_>>();
    validate_run_chain(&run_rows)?;
    let expected_base = state
        .projected_sequence
        .zip(state.projected_event_id.clone());
    if let Some(existing) = run_rows
        .iter()
        .find(|row| row.event.id.as_str() == pending.event_id)
    {
        if existing.bytes != pending.event_bytes
            || existing.event.sequence != pending.sequence
            || existing
                .event
                .previous_event_id
                .as_ref()
                .map(EventId::as_str)
                != pending.previous_event_id.as_deref()
            || run_rows.last().map(|row| row.event.id.as_str()) != Some(pending.event_id.as_str())
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
    } else {
        let actual = run_rows
            .last()
            .map(|row| (row.event.sequence, row.event.id.as_str().to_owned()));
        if actual != expected_base {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        log.append(&frozen_event)?;
        let appended_rows = raw_event_rows(log)?;
        let appended_run_rows = appended_rows
            .iter()
            .filter(|row| row.event.run_id == state.run_id)
            .collect::<Vec<_>>();
        validate_run_chain(&appended_run_rows)?;
        let Some(tail) = appended_run_rows.last() else {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        };
        if tail.bytes != pending.event_bytes
            || tail.event.id.as_str() != pending.event_id
            || tail.event.sequence != pending.sequence
            || tail.event.previous_event_id.as_ref().map(EventId::as_str)
                != pending.previous_event_id.as_deref()
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
    }

    let mut next = state;
    next.pending_projection = None;
    next.projected_sequence = Some(pending.sequence);
    next.projected_event_id = Some(pending.event_id);
    next.validate()?;
    cas_replace(execution, loaded, next)
}

#[derive(Debug)]
struct RawEventRow {
    event: RunEvent,
    bytes: Vec<u8>,
}

fn raw_event_rows(log: &RunEventLog) -> Result<Vec<RawEventRow>, EngineerVerifierLoopError> {
    let bytes = match fs::read(log.path()) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(EngineerVerifierLoopError::Io),
    };
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let mut rows = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let event: RunEvent = serde_json::from_slice(line)
            .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
        if serde_json::to_vec(&event).map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?
            != line
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
        validate_phase_event(&event)?;
        rows.push(RawEventRow {
            event,
            bytes: line.to_vec(),
        });
    }
    Ok(rows)
}

fn validate_phase_event(
    event: &RunEvent,
) -> Result<Option<EngineerVerifierPhaseProjectionV1>, EngineerVerifierLoopError> {
    let is_phase_note = matches!(
        &event.payload,
        RunEventPayload::NoteRecorded { message } if message == PHASE_NOTE
    );
    let has_phase_metadata = event.metadata.contains_key(PHASE_METADATA_KEY);
    if !is_phase_note && !has_phase_metadata {
        return Ok(None);
    }
    if !is_phase_note
        || event.contract_version != ContractVersion::current()
        || event.producer_role != Role::Coordinator
        || event.metadata.len() != 1
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    let Value::String(canonical_projection) = event
        .metadata
        .get(PHASE_METADATA_KEY)
        .ok_or(EngineerVerifierLoopError::ProjectionConflict)?
    else {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    };
    let projection: EngineerVerifierPhaseProjectionV1 = serde_json::from_str(canonical_projection)
        .map_err(|_| EngineerVerifierLoopError::ProjectionConflict)?;
    projection.validate()?;
    if String::from_utf8(projection.canonical_json_bytes()?)
        .map_err(|_| EngineerVerifierLoopError::Utf8)?
        != *canonical_projection
        || projection.run_id != event.run_id
        || projection.controller_time != event.occurred_at
        || derive_phase_event_id(&projection)? != event.id.as_str()
    {
        return Err(EngineerVerifierLoopError::ProjectionConflict);
    }
    Ok(Some(projection))
}

fn validate_run_chain(run: &[&RawEventRow]) -> Result<(), EngineerVerifierLoopError> {
    for (index, row) in run.iter().enumerate() {
        let sequence = u64::try_from(index).map_err(|_| EngineerVerifierLoopError::InvalidInput)?;
        let expected_previous = index
            .checked_sub(1)
            .map(|prior| run[prior].event.id.as_str());
        if row.event.sequence != sequence
            || row.event.previous_event_id.as_ref().map(EventId::as_str) != expected_previous
        {
            return Err(EngineerVerifierLoopError::ProjectionConflict);
        }
    }
    Ok(())
}

fn current_run_cursor(
    log: &RunEventLog,
    run_id: &ovca_types::RunId,
) -> Result<Option<(u64, String)>, EngineerVerifierLoopError> {
    let rows = raw_event_rows(log)?;
    let run = rows
        .iter()
        .filter(|row| &row.event.run_id == run_id)
        .collect::<Vec<_>>();
    validate_run_chain(&run)?;
    Ok(run
        .last()
        .map(|row| (row.event.sequence, row.event.id.as_str().to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedClock(DateTime<Utc>);

    impl EngineerVerifierClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[test]
    fn failure_code_spellings_are_closed() {
        assert_eq!(failure_code_name(FailureCode::PolicyBlock), "policy_block");
        assert_eq!(
            failure_code_name(FailureCode::TestFailedUnclassified),
            "test_failed_unclassified"
        );
    }

    #[test]
    fn system_clock_is_millisecond_precision() {
        let value = SystemEngineerVerifierClock.now();
        assert_eq!(value.timestamp_subsec_nanos() % 1_000_000, 0);
    }

    #[test]
    fn fixed_clock_is_injected_without_wire_state() {
        let value = Utc.with_ymd_and_hms(2026, 8, 17, 0, 0, 0).unwrap();
        assert_eq!(FixedClock(value).now(), value);
    }
}
