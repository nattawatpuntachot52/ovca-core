use chrono::{DateTime, Utc};
use ovca_observability::{
    evaluate_goal_runtime, guard_authority_projection, GoalRuntimeEvaluation,
    GoalRuntimeEvaluationError,
};
use ovca_runtime_core::{
    admit_local_verification_completion, completion_environment_names, completion_evidence_keys,
    replay_run, schedule_tasks, validate_local_verification_completion_contract,
    validate_persisted_completion_material, DurableApprovalError, DurableApprovalEvaluation,
    DurableApprovalRecord, DurableDecisionResult, DurableExecutionAuthority, DurableExecutionError,
    DurableGuardrailAuthority, GuardEvaluationContext, GuardedExecution, InitializeRunResult,
    LoadedExecutionRun, LocalVerificationCompletionContract, LocalVerificationCompletionError,
    LocalVerificationObservation, ReplayError, ReplayedRun, ScheduleError,
    VerifiedCompletionMaterial, DEFAULT_APPROVAL_CAS_RETRY_LIMIT,
};
use ovca_storage::{EvidenceBank, LocalVerificationStoreError, RunEventLog, RunEventLogError};
use ovca_types::{
    ApprovalDecisionRecord, ApprovalRequestId, CompletionAppendReconciliation, ContractVersion,
    EventId, ExecutionPlan, GoalContract, GoalId, GuardRequest, RetryBudget, Role, RunEvent,
    RunEventPayload, RunId, RunStatus, Task, TaskId, TaskStatus,
};
use ovca_verifier::execution::EnvironmentBindings;
use ovca_verifier::snapshot::{FrozenSnapshot, SnapshotError, SourceManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStamp {
    pub id: EventId,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRunStamps {
    pub run_created: EventStamp,
    pub accepted: EventStamp,
    pub plan_recorded: EventStamp,
    pub planned: EventStamp,
}

/// Evidence returned after the explicit JSONL-to-SQLite execution bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBootstrapResult {
    pub view: RuntimeView,
    /// True only when this call created the SQLite execution state.
    pub initialized: bool,
}

/// The independently authoritative orchestration and execution views of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeView {
    pub orchestration: ReplayedRun,
    pub execution: LoadedExecutionRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalRuntimeError {
    GoalContractVersionMismatch {
        expected: ContractVersion,
        found: ContractVersion,
    },
    PermissionProfileContractVersionMismatch {
        expected: ContractVersion,
        found: ContractVersion,
    },
    CompletionPreconditionContractVersionMismatch {
        expected: ContractVersion,
        found: ContractVersion,
    },
    TaskContractVersionMismatch {
        task_id: TaskId,
        expected: ContractVersion,
        found: ContractVersion,
    },
    TaskGoalMismatch {
        task_id: TaskId,
        expected_goal_id: GoalId,
        found_goal_id: GoalId,
    },
    TaskNotPending {
        task_id: TaskId,
        status: TaskStatus,
    },
    Schedule(ScheduleError),
    DuplicateStampId {
        event_id: EventId,
    },
    DecreasingStampTimestamp {
        previous_sequence: u64,
        previous_occurred_at: DateTime<Utc>,
        sequence: u64,
        occurred_at: DateTime<Utc>,
    },
    Replay(ReplayError),
    ReplayedStatusMismatch {
        expected: RunStatus,
        found: RunStatus,
    },
    ReplayedPlanMismatch {
        expected: ExecutionPlan,
        found: Option<ExecutionPlan>,
    },
}

impl fmt::Display for GoalRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GoalContractVersionMismatch { expected, found } => write!(
                formatter,
                "goal contract version {found:?} does not match current version {expected:?}"
            ),
            Self::PermissionProfileContractVersionMismatch { expected, found } => write!(
                formatter,
                "permission profile contract version {found:?} does not match current version {expected:?}"
            ),
            Self::CompletionPreconditionContractVersionMismatch { expected, found } => write!(
                formatter,
                "completion precondition contract version {found:?} does not match current version {expected:?}"
            ),
            Self::TaskContractVersionMismatch {
                task_id,
                expected,
                found,
            } => write!(
                formatter,
                "task {task_id} contract version {found:?} does not match current version {expected:?}"
            ),
            Self::TaskGoalMismatch {
                task_id,
                expected_goal_id,
                found_goal_id,
            } => write!(
                formatter,
                "task {task_id} belongs to goal {found_goal_id}, expected {expected_goal_id}"
            ),
            Self::TaskNotPending { task_id, status } => {
                write!(formatter, "task {task_id} has status {status:?}, expected Pending")
            }
            Self::Schedule(error) => write!(formatter, "task scheduling failed: {error}"),
            Self::DuplicateStampId { event_id } => {
                write!(formatter, "duplicate planned-run event stamp ID: {event_id}")
            }
            Self::DecreasingStampTimestamp {
                previous_sequence,
                previous_occurred_at,
                sequence,
                occurred_at,
            } => write!(
                formatter,
                "planned-run event timestamp decreased from sequence {previous_sequence} ({previous_occurred_at}) to sequence {sequence} ({occurred_at})"
            ),
            Self::Replay(error) => write!(formatter, "constructed run events failed replay: {error}"),
            Self::ReplayedStatusMismatch { expected, found } => write!(
                formatter,
                "constructed run replayed to status {found}, expected {expected}"
            ),
            Self::ReplayedPlanMismatch { .. } => {
                formatter.write_str("constructed run replayed with a different execution plan")
            }
        }
    }
}

impl std::error::Error for GoalRuntimeError {}

impl From<ScheduleError> for GoalRuntimeError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl From<ReplayError> for GoalRuntimeError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}

/// Failures produced by [`DurableGoalRuntime`].
#[derive(Debug)]
pub enum DurableGoalRuntimeError {
    Build {
        source: GoalRuntimeError,
    },
    Storage {
        source: RunEventLogError,
    },
    Replay {
        source: ReplayError,
    },
    Evaluation {
        source: GoalRuntimeEvaluationError,
    },
    RunAlreadyExists {
        run_id: RunId,
    },
    RunNotFound {
        run_id: RunId,
    },
    Execution {
        source: DurableExecutionError,
    },
    Guard {
        source: DurableApprovalError,
    },
    LocalVerificationStorage {
        source: LocalVerificationStoreError,
    },
    LocalVerificationAdmission {
        source: LocalVerificationCompletionError,
    },
    LocalVerificationSnapshot {
        source: SnapshotError,
    },
    LocalVerificationTemporarySnapshot,
    InvalidCompletionPolicy {
        detail: String,
    },
    CompletionPolicyMissing {
        goal_id: GoalId,
    },
    CompletionGoalContractMismatch {
        goal_id: GoalId,
    },
    CompletionTaskSetMismatch {
        goal_id: GoalId,
    },
    VerifiedCompletionRequired {
        goal_id: GoalId,
    },
    VerifiedCompletionNotRequired {
        goal_id: GoalId,
    },
    InvalidVerifiedCompletionEvent,
    CompletionAppendEventConflict {
        event_id: EventId,
    },
    CompletionEnvironmentUnavailable {
        task_id: TaskId,
    },
    BootstrapRunStatusMismatch {
        expected: RunStatus,
        found: RunStatus,
    },
    BootstrapGoalMismatch {
        expected: GoalId,
        found: Option<GoalId>,
    },
    BootstrapTaskSetMismatch {
        declared: BTreeSet<TaskId>,
        provided: BTreeSet<TaskId>,
    },
    BootstrapTaskStatusMismatch {
        task_id: TaskId,
        orchestration: TaskStatus,
        provided: TaskStatus,
    },
    BootstrapPlanMismatch {
        declared: Option<ExecutionPlan>,
        provided: ExecutionPlan,
    },
    ViewRunMismatch {
        expected: RunId,
        found: RunId,
    },
    ViewGoalMismatch {
        expected: GoalId,
        found: Option<GoalId>,
    },
    ViewTaskSetMismatch {
        orchestration: BTreeSet<TaskId>,
        execution: BTreeSet<TaskId>,
    },
}

impl fmt::Display for DurableGoalRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build { source } => write!(formatter, "failed to build planned run: {source}"),
            Self::Storage { source } => write!(formatter, "run-event storage failed: {source}"),
            Self::Replay { source } => write!(formatter, "run-event replay failed: {source}"),
            Self::Evaluation { source } => {
                write!(formatter, "run-event evaluation failed: {source}")
            }
            Self::RunAlreadyExists { run_id } => {
                write!(formatter, "run {run_id} already exists")
            }
            Self::RunNotFound { run_id } => write!(formatter, "run {run_id} was not found"),
            Self::Execution { source } => write!(formatter, "execution authority failed: {source}"),
            Self::Guard { source } => write!(formatter, "guard authority failed: {source}"),
            Self::LocalVerificationStorage { source } => {
                write!(formatter, "local-verification storage failed: {source}")
            }
            Self::LocalVerificationAdmission { source } => {
                write!(formatter, "local-verification admission failed: {source}")
            }
            Self::LocalVerificationSnapshot { source } => {
                write!(formatter, "local-verification source observation failed: {source}")
            }
            Self::LocalVerificationTemporarySnapshot => formatter
                .write_str("failed to create a private local-verification snapshot witness"),
            Self::InvalidCompletionPolicy { detail } => {
                write!(formatter, "invalid local-verification completion policy: {detail}")
            }
            Self::CompletionPolicyMissing { goal_id } => {
                write!(formatter, "completion policy is missing for persisted goal {goal_id}")
            }
            Self::CompletionGoalContractMismatch { goal_id } => write!(
                formatter,
                "caller goal contract differs from authoritative completion policy for {goal_id}"
            ),
            Self::CompletionTaskSetMismatch { goal_id } => write!(
                formatter,
                "persisted run task set differs from authoritative completion policy for {goal_id}"
            ),
            Self::VerifiedCompletionRequired { goal_id } => write!(
                formatter,
                "goal {goal_id} requires verifier-backed completion"
            ),
            Self::VerifiedCompletionNotRequired { goal_id } => write!(
                formatter,
                "goal {goal_id} does not require verifier-backed completion"
            ),
            Self::InvalidVerifiedCompletionEvent => formatter.write_str(
                "verified completion accepts only a final StatusTransition into Completed",
            ),
            Self::CompletionAppendEventConflict { event_id } => write!(
                formatter,
                "durable completion event identity {event_id} has conflicting bytes"
            ),
            Self::CompletionEnvironmentUnavailable { task_id } => write!(
                formatter,
                "declared environment bindings are unavailable for completion task {task_id}"
            ),
            Self::BootstrapRunStatusMismatch { expected, found } => write!(
                formatter,
                "execution bootstrap requires orchestration status {expected}, found {found}"
            ),
            Self::BootstrapGoalMismatch { expected, found } => write!(
                formatter,
                "execution bootstrap goal {found:?} does not match orchestration goal {expected}"
            ),
            Self::BootstrapTaskSetMismatch { .. } => formatter.write_str(
                "execution bootstrap task set does not match the declared orchestration task set",
            ),
            Self::BootstrapTaskStatusMismatch {
                task_id,
                orchestration,
                provided,
            } => write!(
                formatter,
                "execution bootstrap task {task_id} status {provided:?} does not match orchestration status {orchestration:?}"
            ),
            Self::BootstrapPlanMismatch { .. } => formatter.write_str(
                "execution bootstrap task definitions do not reproduce the declared execution plan",
            ),
            Self::ViewRunMismatch { expected, found } => write!(
                formatter,
                "execution view run {found} does not match orchestration run {expected}"
            ),
            Self::ViewGoalMismatch { expected, found } => write!(
                formatter,
                "execution view goal {found:?} does not match orchestration goal {expected}"
            ),
            Self::ViewTaskSetMismatch { .. } => formatter.write_str(
                "execution view task set does not match the orchestration task set",
            ),
        }
    }
}

impl std::error::Error for DurableGoalRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build { source } => Some(source),
            Self::Storage { source } => Some(source),
            Self::Replay { source } => Some(source),
            Self::Evaluation { source } => Some(source),
            Self::Execution { source } => Some(source),
            Self::Guard { source } => Some(source),
            Self::LocalVerificationStorage { source } => Some(source),
            Self::LocalVerificationAdmission { source } => Some(source),
            Self::LocalVerificationSnapshot { source } => Some(source),
            Self::RunAlreadyExists { .. }
            | Self::RunNotFound { .. }
            | Self::BootstrapRunStatusMismatch { .. }
            | Self::BootstrapGoalMismatch { .. }
            | Self::BootstrapTaskSetMismatch { .. }
            | Self::BootstrapTaskStatusMismatch { .. }
            | Self::BootstrapPlanMismatch { .. }
            | Self::ViewRunMismatch { .. }
            | Self::ViewGoalMismatch { .. }
            | Self::ViewTaskSetMismatch { .. }
            | Self::LocalVerificationTemporarySnapshot
            | Self::InvalidCompletionPolicy { .. }
            | Self::CompletionPolicyMissing { .. }
            | Self::CompletionGoalContractMismatch { .. }
            | Self::CompletionTaskSetMismatch { .. }
            | Self::VerifiedCompletionRequired { .. }
            | Self::VerifiedCompletionNotRequired { .. }
            | Self::InvalidVerifiedCompletionEvent
            | Self::CompletionAppendEventConflict { .. }
            | Self::CompletionEnvironmentUnavailable { .. } => None,
        }
    }
}

impl From<RunEventLogError> for DurableGoalRuntimeError {
    fn from(source: RunEventLogError) -> Self {
        Self::Storage { source }
    }
}

impl From<LocalVerificationStoreError> for DurableGoalRuntimeError {
    fn from(source: LocalVerificationStoreError) -> Self {
        Self::LocalVerificationStorage { source }
    }
}

impl From<LocalVerificationCompletionError> for DurableGoalRuntimeError {
    fn from(source: LocalVerificationCompletionError) -> Self {
        Self::LocalVerificationAdmission { source }
    }
}

impl From<SnapshotError> for DurableGoalRuntimeError {
    fn from(source: SnapshotError) -> Self {
        Self::LocalVerificationSnapshot { source }
    }
}

/// Owner-bound inputs for one verifier-enforced goal.
#[derive(Clone)]
pub struct EnforcedLocalVerificationGoal {
    pub completion: LocalVerificationCompletionContract,
    pub source_manifest: SourceManifest,
    pub source_root: PathBuf,
    pub environment_bindings: EnvironmentBindings,
}

impl fmt::Debug for EnforcedLocalVerificationGoal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnforcedLocalVerificationGoal")
            .field("goal_id", &self.completion.goal.id)
            .field("task_count", &self.completion.task_ids.len())
            .field("source_file_count", &self.source_manifest.files.len())
            .field("source_root", &"[redacted]")
            .field("environment_bindings", &"[redacted]")
            .finish()
    }
}

/// Closed completion enforcement selector. It is never inferred from the host
/// environment, a shadow report, a handoff claim, or a per-event boolean.
#[derive(Clone)]
pub enum LocalVerificationCompletionPolicy {
    Disabled,
    Enforced {
        goals: BTreeMap<GoalId, EnforcedLocalVerificationGoal>,
    },
}

impl fmt::Debug for LocalVerificationCompletionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Enforced { goals } => formatter
                .debug_struct("Enforced")
                .field("goal_ids", &goals.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

fn validate_completion_policy(
    policy: &LocalVerificationCompletionPolicy,
) -> Result<(), DurableGoalRuntimeError> {
    let LocalVerificationCompletionPolicy::Enforced { goals } = policy else {
        return Ok(());
    };
    if goals.is_empty() {
        return Err(DurableGoalRuntimeError::InvalidCompletionPolicy {
            detail: "enforced policy requires at least one authoritative goal".to_owned(),
        });
    }
    for (goal_id, authority) in goals {
        if goal_id != &authority.completion.goal.id {
            return Err(DurableGoalRuntimeError::InvalidCompletionPolicy {
                detail: format!("goal map key {goal_id} differs from the stored contract"),
            });
        }
        validate_local_verification_completion_contract(&authority.completion)?;
        authority.source_manifest.validate()?;
        if !is_local_absolute_source_root(&authority.source_root) {
            return Err(DurableGoalRuntimeError::InvalidCompletionPolicy {
                detail: format!(
                    "source root for {goal_id} must be an absolute local filesystem path"
                ),
            });
        }
    }
    Ok(())
}

fn is_local_absolute_source_root(root: &Path) -> bool {
    if !root.is_absolute() {
        return false;
    }
    let text = root.as_os_str().to_string_lossy();
    let lower = text.to_ascii_lowercase();
    !text.starts_with("\\\\")
        && !text.starts_with("//")
        && !lower.starts_with("file:")
        && !lower.contains("://")
}

/// Durable orchestration, execution, and guardrail wrapper for validated goal runs.
///
/// JSONL create, append, and transition methods remain caller-serialized or
/// single-writer per run. Claim, lease, CAS, and concurrency guarantees are
/// provided only through the SQLite execution authority methods. Execution and
/// approval records use separate entity namespaces in the same SQLite
/// versioned-state database. The three logical authorities span two durable
/// media: JSONL and SQLite. Current APIs expose no combined execution-plus-
/// approval transaction, and JSONL/SQLite do not form one transaction. Public
/// assignment and event-producer identities remain the role-only [`Role`] surface.
#[derive(Debug, Clone)]
pub struct DurableGoalRuntime {
    log: RunEventLog,
    execution: DurableExecutionAuthority,
    guardrails: DurableGuardrailAuthority,
    completion_policy: LocalVerificationCompletionPolicy,
    evidence_bank: Option<EvidenceBank>,
}

impl DurableGoalRuntime {
    /// Creates a runtime rooted at the caller-supplied external path without
    /// touching the filesystem.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            log: RunEventLog::new(root),
            execution: DurableExecutionAuthority::new(root),
            guardrails: DurableGuardrailAuthority::new(root, DEFAULT_APPROVAL_CAS_RETRY_LIMIT),
            completion_policy: LocalVerificationCompletionPolicy::Disabled,
            evidence_bank: None,
        }
    }

    /// Creates a runtime with an explicit closed completion policy.
    ///
    /// Construction remains side-effect free. An enforced runtime binds its
    /// EvidenceBank to the same caller-provided durable root as the event log.
    pub fn try_new_with_completion_policy(
        root: impl AsRef<Path>,
        completion_policy: LocalVerificationCompletionPolicy,
    ) -> Result<Self, DurableGoalRuntimeError> {
        validate_completion_policy(&completion_policy)?;
        let root = root.as_ref();
        let evidence_bank = match &completion_policy {
            LocalVerificationCompletionPolicy::Disabled => None,
            LocalVerificationCompletionPolicy::Enforced { .. } => {
                Some(EvidenceBank::try_new(root)?)
            }
        };
        Ok(Self {
            log: RunEventLog::new(root),
            execution: DurableExecutionAuthority::new(root),
            guardrails: DurableGuardrailAuthority::new(root, DEFAULT_APPROVAL_CAS_RETRY_LIMIT),
            completion_policy,
            evidence_bank,
        })
    }

    /// Returns the fixed JSONL path used by this runtime.
    pub fn log_path(&self) -> &Path {
        self.log.path()
    }

    /// Returns the durable SQLite execution authority without opening it.
    pub fn execution_authority(&self) -> &DurableExecutionAuthority {
        &self.execution
    }

    /// Returns the fixed SQLite path used by the execution authority.
    pub fn execution_database_path(&self) -> std::path::PathBuf {
        self.execution.database_path()
    }

    /// Returns the durable guardrail authority without opening the shared SQLite database.
    ///
    /// Execution and approval use separate entity namespaces in the same SQLite
    /// versioned-state database. Current APIs expose no combined transaction for
    /// those logical authorities, and JSONL/SQLite have no cross-medium transaction.
    pub fn guardrail_authority(&self) -> &DurableGuardrailAuthority {
        &self.guardrails
    }

    /// Evaluates a guard request and durably records an R2 pause when required.
    pub fn evaluate_guard_and_record(
        &self,
        request: &GuardRequest,
        context: &GuardEvaluationContext,
    ) -> Result<DurableApprovalEvaluation, DurableApprovalError> {
        self.guardrails.evaluate_and_record(request, context)
    }

    /// Evaluates P3 policy and appends its redacted result to an existing run.
    ///
    /// Approval-ledger persistence and JSONL append are separate operations and
    /// do not form a cross-medium transaction.
    pub fn evaluate_run_guard_and_record(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
        request: &GuardRequest,
        context: &GuardEvaluationContext,
        stamp: EventStamp,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        let current = self.load_run(run_id, goal)?;
        let evaluation = self
            .guardrails
            .evaluate_and_record(request, context)
            .map_err(|source| DurableGoalRuntimeError::Guard { source })?;
        let projection = guard_authority_projection(&evaluation);
        let event = RunEvent {
            contract_version: ContractVersion::current(),
            id: stamp.id,
            run_id: run_id.clone(),
            sequence: current.run_record.event_count,
            previous_event_id: current.run_record.last_event_id,
            occurred_at: stamp.occurred_at,
            producer_role: Role::Coordinator,
            payload: RunEventPayload::GuardOutcomeRecorded {
                projection: projection.clone(),
            },
            metadata: BTreeMap::new(),
        };
        self.append_event(event, goal)
    }

    /// Executes an allowed effect, records an R2 pause, or returns an R3 denial.
    pub fn execute_guarded<T, E, F>(
        &self,
        request: &GuardRequest,
        context: &GuardEvaluationContext,
        effect: F,
    ) -> Result<GuardedExecution<T, E>, DurableApprovalError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        self.guardrails.execute_guarded(request, context, effect)
    }

    /// Records a typed caller-supplied owner decision for one exact request.
    ///
    /// `ApprovalAuthority::ExplicitOwner` is a caller assertion. This library
    /// does not authenticate an identity, credential, tenant, or session.
    pub fn record_approval_decision(
        &self,
        decision: ApprovalDecisionRecord,
    ) -> Result<DurableDecisionResult, DurableApprovalError> {
        self.guardrails.record_decision(decision)
    }

    /// Strictly loads and validates one durable approval record.
    pub fn load_approval(
        &self,
        approval_request_id: &ApprovalRequestId,
    ) -> Result<DurableApprovalRecord, DurableApprovalError> {
        self.guardrails.load(approval_request_id)
    }

    /// Consumes an exact approved request before invoking its effect closure.
    ///
    /// Consumption and an external effect are not one transaction. Failure or
    /// panic after consumption is at-most-once/no-retry and may leave no effect.
    /// Reviewer and Auditor requirements are returned for downstream P4
    /// completion enforcement; P3 does not satisfy those requirements.
    pub fn resume_approved<T, E, F>(
        &self,
        approval_request_id: &ApprovalRequestId,
        request: &GuardRequest,
        effect: F,
    ) -> Result<GuardedExecution<T, E>, DurableApprovalError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        self.guardrails
            .resume_approved(approval_request_id, request, effect)
    }

    /// Validates and durably creates a planned run from exactly four bootstrap
    /// events, then strictly reloads and replays the persisted stream.
    pub fn create_run(
        &self,
        run_id: RunId,
        goal: &GoalContract,
        tasks: &[Task],
        stamps: PlannedRunStamps,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        let (_, events) = build_planned_run(run_id.clone(), goal, tasks, stamps)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;

        if !self.log.load_run(&run_id)?.is_empty() {
            return Err(DurableGoalRuntimeError::RunAlreadyExists { run_id });
        }

        for event in &events {
            self.log.append(event)?;
        }

        self.load_run(&run_id, goal)
    }

    /// Validates an existing planned JSONL run, then idempotently bootstraps its
    /// independent SQLite execution authority.
    ///
    /// JSONL validation completes before the first possible SQLite write. The
    /// two durable media do not form one transaction.
    pub fn initialize_execution(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
        tasks: &[Task],
        retry_budget: RetryBudget,
    ) -> Result<ExecutionBootstrapResult, DurableGoalRuntimeError> {
        let orchestration = self.load_bootstrap_run(run_id, goal)?;
        validate_execution_bootstrap(&orchestration, goal, tasks)?;

        let InitializeRunResult { state, initialized } = self
            .execution
            .initialize_run(run_id.clone(), tasks.to_vec(), retry_budget)
            .map_err(|source| DurableGoalRuntimeError::Execution { source })?;
        let view = validate_runtime_view(orchestration, state)?;
        Ok(ExecutionBootstrapResult { view, initialized })
    }

    fn load_bootstrap_run(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        let events = self.log.load_run(run_id)?;
        if events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound {
                run_id: run_id.clone(),
            });
        }

        let unbound = replay_run(&events, None)
            .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;
        if unbound.run_record.goal_id != goal.id {
            return Err(DurableGoalRuntimeError::BootstrapGoalMismatch {
                expected: unbound.run_record.goal_id,
                found: Some(goal.id.clone()),
            });
        }

        replay_run(&events, Some(goal)).map_err(|source| DurableGoalRuntimeError::Replay { source })
    }

    /// Loads both durable stores and validates their shared identity boundary.
    ///
    /// Task statuses are intentionally not reconciled: JSONL remains the P1
    /// orchestration authority and SQLite is the P2 execution authority.
    pub fn load_runtime_view(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
    ) -> Result<RuntimeView, DurableGoalRuntimeError> {
        let orchestration = self.load_run(run_id, goal)?;
        let execution = self
            .execution
            .load(run_id)
            .map_err(|source| DurableGoalRuntimeError::Execution { source })?;
        validate_runtime_view(orchestration, execution)
    }

    fn authoritative_completion_goal<'a>(
        &'a self,
        events: &[RunEvent],
        caller_goal: &GoalContract,
    ) -> Result<Option<&'a EnforcedLocalVerificationGoal>, DurableGoalRuntimeError> {
        let LocalVerificationCompletionPolicy::Enforced { goals } = &self.completion_policy else {
            return Ok(None);
        };
        let (goal_id, persisted_task_ids) = match events.first().map(|event| &event.payload) {
            Some(RunEventPayload::RunCreated {
                goal_id, task_ids, ..
            }) => (goal_id, task_ids),
            _ => {
                // Preserve the canonical replay error for malformed or missing
                // run creation. A completed stream cannot be replayed unbound,
                // so its closed identity is resolved from the creation event and
                // every caller performs the full authoritative replay next.
                replay_run(events, None)
                    .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
                unreachable!("successful replay requires a run-created event")
            }
        };
        let authority =
            goals
                .get(goal_id)
                .ok_or_else(|| DurableGoalRuntimeError::CompletionPolicyMissing {
                    goal_id: goal_id.clone(),
                })?;
        if &authority.completion.goal != caller_goal {
            return Err(DurableGoalRuntimeError::CompletionGoalContractMismatch {
                goal_id: goal_id.clone(),
            });
        }
        if persisted_task_ids != &authority.completion.task_ids {
            return Err(DurableGoalRuntimeError::CompletionTaskSetMismatch {
                goal_id: goal_id.clone(),
            });
        }
        Ok(Some(authority))
    }

    fn fresh_completion_material(
        &self,
        authority: &EnforcedLocalVerificationGoal,
        run_id: &RunId,
        declared_task_ids: &[TaskId],
        snapshot: &ovca_storage::CompletionAdmissionSnapshot,
    ) -> Result<VerifiedCompletionMaterial, DurableGoalRuntimeError> {
        let snapshot_root = tempfile::tempdir()
            .map_err(|_| DurableGoalRuntimeError::LocalVerificationTemporarySnapshot)?;
        let frozen = FrozenSnapshot::materialize(
            &authority.source_root,
            snapshot_root.path(),
            &authority.source_manifest,
        )?;
        let source_pre_digest = frozen.source_pre_fingerprint().to_owned();
        let source_post_digest = frozen.source_post_fingerprint()?;

        let mut observations = Vec::with_capacity(authority.completion.tasks.len());
        for task in &authority.completion.tasks {
            let environment_names = completion_environment_names(task)?;
            let environment_digest = authority
                .environment_bindings
                .digest_for(&environment_names)
                .ok_or_else(
                    || DurableGoalRuntimeError::CompletionEnvironmentUnavailable {
                        task_id: task.selection.task_id.clone(),
                    },
                )?;
            observations.push(LocalVerificationObservation {
                task_id: task.selection.task_id.clone(),
                source_pre_digest: source_pre_digest.clone(),
                source_post_digest: source_post_digest.clone(),
                environment_digest,
            });
        }

        admit_local_verification_completion(
            &authority.completion,
            run_id,
            declared_task_ids,
            snapshot,
            &observations,
        )
        .map_err(Into::into)
    }

    /// Prepares authoritative evidence material without appending any event.
    ///
    /// The result is intentionally provisional: final completion always opens a
    /// fresh EvidenceBank lease and recomputes all live observations again.
    pub fn prepare_local_verification_completion(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
    ) -> Result<VerifiedCompletionMaterial, DurableGoalRuntimeError> {
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;
        let events = self.log.load_run(run_id)?;
        if events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound {
                run_id: run_id.clone(),
            });
        }
        let authority = self
            .authoritative_completion_goal(&events, goal)?
            .ok_or_else(|| DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: goal.id.clone(),
            })?;
        if !requires_local_verification(&authority.completion.goal) {
            return Err(DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: authority.completion.goal.id.clone(),
            });
        }
        let keys = completion_evidence_keys(&authority.completion, run_id)?;
        let evidence_bank = self.evidence_bank.as_ref().ok_or_else(|| {
            DurableGoalRuntimeError::CompletionPolicyMissing {
                goal_id: authority.completion.goal.id.clone(),
            }
        })?;
        evidence_bank.with_completion_admission_lease(&keys, |snapshot| {
            let current_events = self.log.load_run(run_id)?;
            let current_authority = self
                .authoritative_completion_goal(&current_events, goal)?
                .ok_or_else(|| DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                    goal_id: goal.id.clone(),
                })?;
            let replayed = replay_run(&current_events, Some(&current_authority.completion.goal))
                .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
            self.fresh_completion_material(
                current_authority,
                run_id,
                &replayed.run_record.task_ids,
                snapshot,
            )
        })
    }

    /// Revalidates current local evidence and appends only a final synced
    /// `StatusTransition` into `Completed` while the EvidenceBank writer
    /// reservation remains held.
    ///
    /// SQLite and JSONL are not one atomic transaction. A return error after
    /// the JSONL `sync_all` boundary can therefore be ambiguous; V5 recovery
    /// must reload/replay and check the exact event ID before any retry.
    pub fn append_verified_completion(
        &self,
        event: RunEvent,
        goal: &GoalContract,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        if !is_completed_transition(&event.payload) {
            return Err(DurableGoalRuntimeError::InvalidVerifiedCompletionEvent);
        }
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;
        let run_id = event.run_id.clone();
        let events = self.log.load_run(&run_id)?;
        if events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound { run_id });
        }
        let authority = self
            .authoritative_completion_goal(&events, goal)?
            .ok_or_else(|| DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: goal.id.clone(),
            })?;
        if !requires_local_verification(&authority.completion.goal) {
            return Err(DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: authority.completion.goal.id.clone(),
            });
        }
        let keys = completion_evidence_keys(&authority.completion, &event.run_id)?;
        let evidence_bank = self.evidence_bank.as_ref().ok_or_else(|| {
            DurableGoalRuntimeError::CompletionPolicyMissing {
                goal_id: authority.completion.goal.id.clone(),
            }
        })?;

        evidence_bank.with_completion_admission_lease(&keys, |snapshot| {
            let mut current_events = self.log.load_run(&event.run_id)?;
            if current_events.is_empty() {
                return Err(DurableGoalRuntimeError::RunNotFound {
                    run_id: event.run_id.clone(),
                });
            }
            let current_authority = self
                .authoritative_completion_goal(&current_events, goal)?
                .ok_or_else(|| DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                    goal_id: goal.id.clone(),
                })?;
            let current = replay_run(&current_events, Some(&current_authority.completion.goal))
                .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
            let material = self.fresh_completion_material(
                current_authority,
                &event.run_id,
                &current.run_record.task_ids,
                snapshot,
            )?;
            validate_persisted_completion_material(
                &material,
                &current.evidence_references,
                current.completion_evidence.as_ref(),
            )?;

            current_events.push(event.clone());
            replay_run(&current_events, Some(&current_authority.completion.goal))
                .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
            self.log.append(&event)?;
            Ok(())
        })?;

        self.load_run(&event.run_id, goal)
    }

    /// Reconciles an ambiguous completion append without appending or retrying.
    ///
    /// The durable JSONL is reloaded and strictly replayed first. An exact event
    /// already present is `AlreadyCommitted`. A valid absent event is
    /// `RetryRequired`, leaving the retry decision to the caller. Reused event
    /// identities with different bytes, alternate sequence/previous-event links,
    /// malformed JSONL, and conflicting completion state all fail closed.
    pub fn reconcile_verified_completion_append(
        &self,
        event: &RunEvent,
        goal: &GoalContract,
    ) -> Result<CompletionAppendReconciliation, DurableGoalRuntimeError> {
        if !is_completed_transition(&event.payload) {
            return Err(DurableGoalRuntimeError::InvalidVerifiedCompletionEvent);
        }
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;
        let events = self.log.load_run(&event.run_id)?;
        if events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound {
                run_id: event.run_id.clone(),
            });
        }
        let authority = self
            .authoritative_completion_goal(&events, goal)?
            .ok_or_else(|| DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: goal.id.clone(),
            })?;
        if !requires_local_verification(&authority.completion.goal) {
            return Err(DurableGoalRuntimeError::VerifiedCompletionNotRequired {
                goal_id: authority.completion.goal.id.clone(),
            });
        }
        replay_run(&events, Some(&authority.completion.goal))
            .map_err(|source| DurableGoalRuntimeError::Replay { source })?;

        if let Some(committed) = events.iter().find(|value| value.id == event.id) {
            if committed == event {
                return Ok(CompletionAppendReconciliation::AlreadyCommitted);
            }
            return Err(DurableGoalRuntimeError::CompletionAppendEventConflict {
                event_id: event.id.clone(),
            });
        }

        let mut prospective = events;
        prospective.push(event.clone());
        replay_run(&prospective, Some(&authority.completion.goal))
            .map_err(|source| DurableGoalRuntimeError::Replay { source })?;
        Ok(CompletionAppendReconciliation::RetryRequired)
    }

    /// Prospectively validates a caller-supplied complete event before
    /// persisting it, then strictly reloads and replays the run.
    ///
    /// P1 requires a single writer per run. This method does not provide a
    /// claim, lease, CAS, or other concurrency protocol.
    pub fn append_event(
        &self,
        event: RunEvent,
        goal: &GoalContract,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;

        let run_id = event.run_id.clone();
        let mut prospective = self.log.load_run(&run_id)?;
        if prospective.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound { run_id });
        }

        if is_completed_transition(&event.payload) {
            if let Some(authority) = self.authoritative_completion_goal(&prospective, goal)? {
                if requires_local_verification(&authority.completion.goal) {
                    return Err(DurableGoalRuntimeError::VerifiedCompletionRequired {
                        goal_id: authority.completion.goal.id.clone(),
                    });
                }
            }
        }

        prospective.push(event.clone());
        replay_run(&prospective, Some(goal))
            .map_err(|source| DurableGoalRuntimeError::Replay { source })?;

        self.log.append(&event)?;
        self.load_run(&run_id, goal)
    }

    /// Strictly loads and replays an existing run.
    pub fn load_run(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;

        let events = self.log.load_run(run_id)?;
        if events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound {
                run_id: run_id.clone(),
            });
        }

        replay_run(&events, Some(goal)).map_err(|source| DurableGoalRuntimeError::Replay { source })
    }

    /// Loads the durable event stream twice and evaluates canonical replay parity
    /// without appending JSONL, opening SQLite, or changing execution state.
    pub fn evaluate_run(
        &self,
        run_id: &RunId,
        goal: &GoalContract,
    ) -> Result<GoalRuntimeEvaluation, DurableGoalRuntimeError> {
        validate_goal_contract_versions(goal)
            .map_err(|source| DurableGoalRuntimeError::Build { source })?;

        let persisted_events = self.log.load_run(run_id)?;
        if persisted_events.is_empty() {
            return Err(DurableGoalRuntimeError::RunNotFound {
                run_id: run_id.clone(),
            });
        }
        let reloaded_events = self.log.load_run(run_id)?;
        evaluate_goal_runtime(&persisted_events, &reloaded_events, goal)
            .map_err(|source| DurableGoalRuntimeError::Evaluation { source })
    }
}

fn is_completed_transition(payload: &RunEventPayload) -> bool {
    matches!(
        payload,
        RunEventPayload::StatusTransition {
            to: RunStatus::Completed,
            ..
        }
    )
}

fn requires_local_verification(goal: &GoalContract) -> bool {
    goal.completion_precondition
        .require_all_verification_criteria
        && !goal.verification_criteria.is_empty()
}

fn validate_execution_bootstrap(
    orchestration: &ReplayedRun,
    goal: &GoalContract,
    tasks: &[Task],
) -> Result<(), DurableGoalRuntimeError> {
    if orchestration.run_record.status != RunStatus::Planned {
        return Err(DurableGoalRuntimeError::BootstrapRunStatusMismatch {
            expected: RunStatus::Planned,
            found: orchestration.run_record.status,
        });
    }

    let provided_goal = tasks.first().map(|task| task.goal_id.clone());
    if provided_goal.as_ref() != Some(&goal.id) || tasks.iter().any(|task| task.goal_id != goal.id)
    {
        return Err(DurableGoalRuntimeError::BootstrapGoalMismatch {
            expected: goal.id.clone(),
            found: provided_goal,
        });
    }

    let declared = orchestration
        .run_record
        .task_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let provided = tasks
        .iter()
        .map(|task| task.id.clone())
        .collect::<BTreeSet<_>>();
    if declared != provided || provided.len() != tasks.len() {
        return Err(DurableGoalRuntimeError::BootstrapTaskSetMismatch { declared, provided });
    }

    for task in tasks {
        let orchestration_status = orchestration.task_statuses[&task.id];
        if task.status != orchestration_status {
            return Err(DurableGoalRuntimeError::BootstrapTaskStatusMismatch {
                task_id: task.id.clone(),
                orchestration: orchestration_status,
                provided: task.status,
            });
        }
    }

    let provided_plan = schedule_tasks(tasks).map_err(|source| DurableGoalRuntimeError::Build {
        source: GoalRuntimeError::Schedule(source),
    })?;
    if orchestration.execution_plan.as_ref() != Some(&provided_plan) {
        return Err(DurableGoalRuntimeError::BootstrapPlanMismatch {
            declared: orchestration.execution_plan.clone(),
            provided: provided_plan,
        });
    }
    Ok(())
}

fn validate_runtime_view(
    orchestration: ReplayedRun,
    execution: LoadedExecutionRun,
) -> Result<RuntimeView, DurableGoalRuntimeError> {
    if execution.envelope.run_id != orchestration.run_record.id {
        return Err(DurableGoalRuntimeError::ViewRunMismatch {
            expected: orchestration.run_record.id.clone(),
            found: execution.envelope.run_id.clone(),
        });
    }
    if execution.envelope.snapshot.goal_id.as_ref() != Some(&orchestration.run_record.goal_id) {
        return Err(DurableGoalRuntimeError::ViewGoalMismatch {
            expected: orchestration.run_record.goal_id.clone(),
            found: execution.envelope.snapshot.goal_id.clone(),
        });
    }

    let orchestration_tasks = orchestration
        .run_record
        .task_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let execution_tasks = execution
        .envelope
        .tasks
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if orchestration_tasks != execution_tasks {
        return Err(DurableGoalRuntimeError::ViewTaskSetMismatch {
            orchestration: orchestration_tasks,
            execution: execution_tasks,
        });
    }

    Ok(RuntimeView {
        orchestration,
        execution,
    })
}

pub fn build_planned_run(
    run_id: RunId,
    goal: &GoalContract,
    tasks: &[Task],
    stamps: PlannedRunStamps,
) -> Result<(ExecutionPlan, Vec<RunEvent>), GoalRuntimeError> {
    validate_goal_contract_versions(goal)?;

    let expected_contract_version = ContractVersion::current();
    let mut ordered_tasks = tasks.iter().collect::<Vec<_>>();
    ordered_tasks.sort_by(|left, right| left.id.cmp(&right.id));

    for task in ordered_tasks {
        if task.contract_version != expected_contract_version {
            return Err(GoalRuntimeError::TaskContractVersionMismatch {
                task_id: task.id.clone(),
                expected: expected_contract_version,
                found: task.contract_version,
            });
        }
        if task.goal_id != goal.id {
            return Err(GoalRuntimeError::TaskGoalMismatch {
                task_id: task.id.clone(),
                expected_goal_id: goal.id.clone(),
                found_goal_id: task.goal_id.clone(),
            });
        }
        if task.status != TaskStatus::Pending {
            return Err(GoalRuntimeError::TaskNotPending {
                task_id: task.id.clone(),
                status: task.status,
            });
        }
    }

    let plan = schedule_tasks(tasks)?;

    let mut task_ids = tasks.iter().map(|task| task.id.clone()).collect::<Vec<_>>();
    task_ids.sort();

    validate_stamps(&stamps)?;

    let PlannedRunStamps {
        run_created,
        accepted,
        plan_recorded,
        planned,
    } = stamps;
    let contract_version = ContractVersion::current();

    let events = vec![
        RunEvent {
            contract_version,
            id: run_created.id.clone(),
            run_id: run_id.clone(),
            sequence: 0,
            previous_event_id: None,
            occurred_at: run_created.occurred_at,
            producer_role: Role::Coordinator,
            payload: RunEventPayload::RunCreated {
                project_id: goal.project_id.clone(),
                goal_id: goal.id.clone(),
                task_ids,
                status: RunStatus::Draft,
                created_at: run_created.occurred_at,
                updated_at: run_created.occurred_at,
                started_at: None,
                finished_at: None,
            },
            metadata: BTreeMap::new(),
        },
        RunEvent {
            contract_version,
            id: accepted.id.clone(),
            run_id: run_id.clone(),
            sequence: 1,
            previous_event_id: Some(run_created.id),
            occurred_at: accepted.occurred_at,
            producer_role: Role::Coordinator,
            payload: RunEventPayload::StatusTransition {
                from: RunStatus::Draft,
                to: RunStatus::Accepted,
            },
            metadata: BTreeMap::new(),
        },
        RunEvent {
            contract_version,
            id: plan_recorded.id.clone(),
            run_id: run_id.clone(),
            sequence: 2,
            previous_event_id: Some(accepted.id),
            occurred_at: plan_recorded.occurred_at,
            producer_role: Role::Coordinator,
            payload: RunEventPayload::ExecutionPlanRecorded { plan: plan.clone() },
            metadata: BTreeMap::new(),
        },
        RunEvent {
            contract_version,
            id: planned.id,
            run_id,
            sequence: 3,
            previous_event_id: Some(plan_recorded.id),
            occurred_at: planned.occurred_at,
            producer_role: Role::Coordinator,
            payload: RunEventPayload::StatusTransition {
                from: RunStatus::Accepted,
                to: RunStatus::Planned,
            },
            metadata: BTreeMap::new(),
        },
    ];

    let replayed = replay_run(&events, Some(goal))?;
    if replayed.run_record.status != RunStatus::Planned {
        return Err(GoalRuntimeError::ReplayedStatusMismatch {
            expected: RunStatus::Planned,
            found: replayed.run_record.status,
        });
    }
    if replayed.execution_plan.as_ref() != Some(&plan) {
        return Err(GoalRuntimeError::ReplayedPlanMismatch {
            expected: plan,
            found: replayed.execution_plan,
        });
    }

    Ok((plan, events))
}

fn validate_goal_contract_versions(goal: &GoalContract) -> Result<(), GoalRuntimeError> {
    let expected_contract_version = ContractVersion::current();
    if goal.contract_version != expected_contract_version {
        return Err(GoalRuntimeError::GoalContractVersionMismatch {
            expected: expected_contract_version,
            found: goal.contract_version,
        });
    }
    if goal.permission_profile.contract_version != expected_contract_version {
        return Err(GoalRuntimeError::PermissionProfileContractVersionMismatch {
            expected: expected_contract_version,
            found: goal.permission_profile.contract_version,
        });
    }
    if goal.completion_precondition.contract_version != expected_contract_version {
        return Err(
            GoalRuntimeError::CompletionPreconditionContractVersionMismatch {
                expected: expected_contract_version,
                found: goal.completion_precondition.contract_version,
            },
        );
    }

    Ok(())
}

fn validate_stamps(stamps: &PlannedRunStamps) -> Result<(), GoalRuntimeError> {
    let ordered_stamps = [
        &stamps.run_created,
        &stamps.accepted,
        &stamps.plan_recorded,
        &stamps.planned,
    ];
    let mut event_ids = BTreeSet::new();

    for stamp in ordered_stamps {
        if !event_ids.insert(stamp.id.clone()) {
            return Err(GoalRuntimeError::DuplicateStampId {
                event_id: stamp.id.clone(),
            });
        }
    }

    for (index, pair) in ordered_stamps.windows(2).enumerate() {
        let previous = pair[0];
        let current = pair[1];
        if current.occurred_at < previous.occurred_at {
            return Err(GoalRuntimeError::DecreasingStampTimestamp {
                previous_sequence: index as u64,
                previous_occurred_at: previous.occurred_at,
                sequence: index as u64 + 1,
                occurred_at: current.occurred_at,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ovca_observability::GoalRuntimeEvaluationOutcome;
    use ovca_runtime_core::ClaimRequest;
    use ovca_storage::{
        AuthoritativeProjectionSelection, CasOutcome, EvidenceKey, LocalVerificationStore,
        ProjectionExpectation, ProjectionRebuildIntent, PublishOutcome, StaleCause,
        VERSIONED_STATE_DB_RELATIVE_PATH,
    };
    use ovca_types::{
        select_targeted_rerun, verification_behavior_digest, verification_capability_set_digest,
        verification_command_set_digest, verification_policy_digest, verification_sha256_hex,
    };
    use ovca_types::{
        ApprovalAuthority, ApprovalDisposition, ApprovalState, AuditDecision, AuditDecisionId,
        BehaviorBinding, BehaviorCriterion, BehaviorKind, BehavioralAcceptanceContract,
        CapabilityDefinition, ChangedPathEntry, ChangedPathKind, ChangedPathManifest,
        ChangedPathSelector, CompletionEvidence, CompletionPrecondition, CoordinatorFinalResponse,
        CriterionAssessment, CriterionAssessmentVerdict, CriterionKind, CriterionResult,
        CriterionResultVerdict, DeniedAccess, DigestAlgorithm, EvidenceId, EvidenceKind,
        EvidenceRef, ExecutionMode, FailureConfirmation, GuardDenyReason, GuardRequestId,
        GuardRequirement, GuardSurface, LeaseId, LocalMachinePolicy, PathSelectorKind,
        PermissionProfile, ProjectId, ReviewAuditRequirements, ReviewAuditResolution,
        ReviewDecision, ReviewDecisionId, ReviewVerdict, RiskTier, RunGuardDecision, ShellPolicy,
        SideEffectClass, SpecialistOutput, TargetedRerunOutcome, TargetedRerunRequest,
        UnknownPathPolicy, VerificationBundle, VerificationCommand, VerificationFailure,
        VerificationFailureCategory, VerificationFingerprints, VerificationVerdict, WorkerId,
        WorkingDirectory, LOCAL_VERIFICATION_CONTRACT_VERSION,
    };
    use ovca_verifier::snapshot::SourceFile;
    use std::ffi::OsString;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    fn timestamp(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 0, 0, second)
            .single()
            .expect("fixed test timestamp should be valid")
    }

    fn goal() -> GoalContract {
        GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from("goal-1"),
            project_id: ProjectId::from("project-1"),
            objective: "build a deterministic planned run".to_owned(),
            constraints: Vec::new(),
            acceptance_criteria: Vec::new(),
            verification_criteria: Vec::new(),
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R0,
                resource_keys: Vec::new(),
                write_keys: Vec::new(),
                approval_required: false,
                review_required: false,
                audit_required: false,
            },
            definition_of_done: Vec::new(),
            completion_precondition: CompletionPrecondition::default(),
            created_at: timestamp(0),
            updated_at: timestamp(0),
        }
    }

    fn task(id: &str, dependencies: &[&str]) -> Task {
        Task {
            contract_version: ContractVersion::current(),
            id: TaskId::from(id),
            goal_id: GoalId::from("goal-1"),
            outcome: format!("finish {id}"),
            dependencies: dependencies.iter().copied().map(TaskId::from).collect(),
            assigned_role: Role::Engineer,
            resource_keys: Vec::new(),
            write_keys: vec![format!("write-{id}")],
            status: TaskStatus::Pending,
            created_at: timestamp(0),
            updated_at: timestamp(0),
        }
    }

    fn stamps() -> PlannedRunStamps {
        PlannedRunStamps {
            run_created: EventStamp {
                id: EventId::from("event-0"),
                occurred_at: timestamp(0),
            },
            accepted: EventStamp {
                id: EventId::from("event-1"),
                occurred_at: timestamp(1),
            },
            plan_recorded: EventStamp {
                id: EventId::from("event-2"),
                occurred_at: timestamp(2),
            },
            planned: EventStamp {
                id: EventId::from("event-3"),
                occurred_at: timestamp(3),
            },
        }
    }

    fn appended_event(
        event_id: &str,
        sequence: u64,
        previous_event_id: &str,
        producer_role: Role,
        payload: RunEventPayload,
    ) -> RunEvent {
        RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from(event_id),
            run_id: RunId::from("run-1"),
            sequence,
            previous_event_id: Some(EventId::from(previous_event_id)),
            occurred_at: timestamp(sequence as u32),
            producer_role,
            payload,
            metadata: BTreeMap::new(),
        }
    }

    fn append_runtime_event(
        runtime: &DurableGoalRuntime,
        goal: &GoalContract,
        sequence: u64,
        producer_role: Role,
        payload: RunEventPayload,
    ) -> Result<ReplayedRun, DurableGoalRuntimeError> {
        let event_id = format!("event-{sequence}");
        let previous_event_id = format!("event-{}", sequence - 1);
        runtime.append_event(
            appended_event(
                &event_id,
                sequence,
                &previous_event_id,
                producer_role,
                payload,
            ),
            goal,
        )
    }

    struct V4cFixture {
        _durable: TempDir,
        _source: TempDir,
        runtime: DurableGoalRuntime,
        goal: GoalContract,
    }

    const V4C_ENVIRONMENT_NAME: &str = "OVCA_V4C_TEST_BINDING";
    const V4C_ENVIRONMENT_VALUE: &str = "v4c-environment-value-must-not-be-serialized";

    fn inserted<T>(outcome: PublishOutcome<T>) -> T {
        match outcome {
            PublishOutcome::Inserted(value) | PublishOutcome::ExistingIdentical(value) => value,
        }
    }

    fn v4c_fixture() -> V4cFixture {
        let durable = TempDir::new().unwrap();
        let source = TempDir::new().unwrap();
        let source_bytes = b"verified completion source\n";
        fs::write(source.path().join("input.txt"), source_bytes).unwrap();
        let source_manifest = SourceManifest {
            files: vec![SourceFile {
                logical_path: "input.txt".to_owned(),
                sha256: verification_sha256_hex(source_bytes),
            }],
        };
        let source_fingerprint = source_manifest.fingerprint().unwrap();

        let mut goal = goal();
        goal.objective = "complete from current local verification only".to_owned();
        goal.verification_criteria = vec!["verified".to_owned(), "verified second".to_owned()];
        goal.completion_precondition = CompletionPrecondition {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        };

        let capability = CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "capability.v4c".to_owned(),
            revision: 1,
            criterion_ids: vec![
                "criterion.verify".to_owned(),
                "criterion.verify.second".to_owned(),
            ],
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
                allowed_executable_ids: BTreeSet::from(["cargo".to_owned()]),
                allowed_environment_names: BTreeSet::from([V4C_ENVIRONMENT_NAME.to_owned()]),
            },
            commands: vec![VerificationCommand {
                command_id: "command.v4c".to_owned(),
                executable_id: "cargo".to_owned(),
                argv: vec!["test".to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: BTreeSet::from([V4C_ENVIRONMENT_NAME.to_owned()]),
            }],
        };
        let behavior = BehavioralAcceptanceContract {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            contract_id: "behavior.v4c".to_owned(),
            binding: BehaviorBinding::Bound {
                goal_id: goal.id.clone(),
                task_id: TaskId::from("task-a"),
            },
            criteria: vec![
                BehaviorCriterion {
                    criterion_id: "criterion.verify".to_owned(),
                    order: 0,
                    kind: BehaviorKind::Verification,
                    text: "verified".to_owned(),
                    required: true,
                    capability_ids: vec![capability.capability_id.clone()],
                },
                BehaviorCriterion {
                    criterion_id: "criterion.verify.second".to_owned(),
                    order: 1,
                    kind: BehaviorKind::Verification,
                    text: "verified second".to_owned(),
                    required: true,
                    capability_ids: vec![capability.capability_id.clone()],
                },
            ],
        };

        let store = LocalVerificationStore::try_new(durable.path()).unwrap();
        let registry = store.capability_registry();
        let capability_record = inserted(registry.publish(&capability).unwrap());
        registry
            .compare_and_swap_current(
                &capability.capability_id,
                capability.revision,
                &capability_record.digest,
                &ProjectionExpectation::Absent,
            )
            .unwrap();
        let registry_snapshot = registry.load_current_snapshot().unwrap();
        let policy_digest = verification_policy_digest(std::slice::from_ref(&capability)).unwrap();
        let selection_request = TargetedRerunRequest {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            run_id: RunId::from("run-1"),
            goal_id: goal.id.clone(),
            task_id: TaskId::from("task-a"),
            source_fingerprint: source_fingerprint.clone(),
            policy_digest: policy_digest.clone(),
            changed_paths: ChangedPathManifest {
                entries: vec![ChangedPathEntry {
                    kind: ChangedPathKind::Modified,
                    path: "input.txt".to_owned(),
                    previous_path: None,
                }],
            },
            unknown_path_policy: UnknownPathPolicy::Blocked,
        };
        let selection = match select_targeted_rerun(&selection_request, &registry_snapshot) {
            TargetedRerunOutcome::Selected { selection } => *selection,
            other => panic!("unexpected selection: {other:?}"),
        };
        let environment_bindings = EnvironmentBindings {
            values: BTreeMap::from([(
                V4C_ENVIRONMENT_NAME.to_owned(),
                OsString::from(V4C_ENVIRONMENT_VALUE),
            )]),
        };
        let environment_digest = environment_bindings
            .digest_for(&BTreeSet::from([V4C_ENVIRONMENT_NAME.to_owned()]))
            .unwrap();
        let bundle = VerificationBundle {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            bundle_id: "bundle.v4c".to_owned(),
            run_id: RunId::from("run-1"),
            goal_id: goal.id.clone(),
            task_id: TaskId::from("task-a"),
            behavior_contract_id: behavior.contract_id.clone(),
            capability_ids: vec![capability.capability_id.clone()],
            implementation_actor: WorkerId::from("engineer.v4c"),
            verifier_actor: WorkerId::from("reviewer.v4c"),
            fingerprints: VerificationFingerprints {
                source_pre: source_fingerprint.clone(),
                source_post: source_fingerprint,
                behavior_contract: verification_behavior_digest(&behavior).unwrap(),
                capability_set: verification_capability_set_digest(&selection).unwrap(),
                command: verification_command_set_digest(std::slice::from_ref(&capability))
                    .unwrap(),
                policy: policy_digest,
                environment: environment_digest,
            },
            criterion_results: vec![
                CriterionResult {
                    criterion_id: "criterion.verify".to_owned(),
                    order: 0,
                    kind: BehaviorKind::Verification,
                    text: "verified".to_owned(),
                    verdict: CriterionResultVerdict::Pass,
                },
                CriterionResult {
                    criterion_id: "criterion.verify.second".to_owned(),
                    order: 1,
                    kind: BehaviorKind::Verification,
                    text: "verified second".to_owned(),
                    verdict: CriterionResultVerdict::Pass,
                },
            ],
            failures: Vec::new(),
            verdict: VerificationVerdict::Pass,
            created_at: timestamp(5),
        };
        store
            .evidence_bank()
            .publish_bundle_and_cas(&bundle, &ProjectionExpectation::Absent)
            .unwrap();

        let completion = LocalVerificationCompletionContract {
            goal: goal.clone(),
            task_ids: vec![TaskId::from("task-a")],
            tasks: vec![ovca_runtime_core::LocalVerificationCompletionTask {
                behavior,
                selection,
                capabilities: vec![capability],
            }],
        };
        let authority = EnforcedLocalVerificationGoal {
            completion,
            source_manifest,
            source_root: source.path().to_path_buf(),
            environment_bindings,
        };
        let runtime = DurableGoalRuntime::try_new_with_completion_policy(
            durable.path(),
            LocalVerificationCompletionPolicy::Enforced {
                goals: BTreeMap::from([(goal.id.clone(), authority)]),
            },
        )
        .unwrap();
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();

        V4cFixture {
            _durable: durable,
            _source: source,
            runtime,
            goal,
        }
    }

    fn v4c_authority(fixture: &V4cFixture) -> EnforcedLocalVerificationGoal {
        let LocalVerificationCompletionPolicy::Enforced { goals } =
            &fixture.runtime.completion_policy
        else {
            panic!("V4c fixture must use enforced completion");
        };
        goals.get(&fixture.goal.id).unwrap().clone()
    }

    fn record_v4c_material(fixture: &V4cFixture) -> VerifiedCompletionMaterial {
        let material = fixture
            .runtime
            .prepare_local_verification_completion(&RunId::from("run-1"), &fixture.goal)
            .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            5,
            Role::Coordinator,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: material.evidence_references[0].clone(),
            },
        )
        .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            6,
            Role::Coordinator,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: material.completion_evidence.clone(),
            },
        )
        .unwrap();
        material
    }

    fn v4c_final_event() -> RunEvent {
        appended_event(
            "event-7",
            7,
            "event-6",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        )
    }

    fn v4c_evidence_key(fixture: &V4cFixture) -> EvidenceKey {
        EvidenceKey {
            run_id: RunId::from("run-1"),
            goal_id: fixture.goal.id.clone(),
            task_id: TaskId::from("task-a"),
        }
    }

    fn replace_v4c_bundle(fixture: &V4cFixture, mutate: impl FnOnce(&mut VerificationBundle)) {
        let store = LocalVerificationStore::try_new(fixture._durable.path()).unwrap();
        let bank = store.evidence_bank();
        let current = bank
            .load_current(&v4c_evidence_key(fixture))
            .unwrap()
            .unwrap();
        let mut bundle = bank
            .load_bundle(&current.record_digest)
            .unwrap()
            .unwrap()
            .bundle;
        mutate(&mut bundle);
        assert!(matches!(
            bank.publish_bundle_and_cas(&bundle, &ProjectionExpectation::Token(current.token),)
                .unwrap()
                .projection,
            CasOutcome::Applied(_)
        ));
    }

    fn review_audit_goal() -> GoalContract {
        let mut goal = goal();
        goal.objective = "complete only after evidence-backed review and audit".to_owned();
        goal.acceptance_criteria = vec!["accepted".to_owned()];
        goal.verification_criteria = vec!["verified".to_owned()];
        goal.definition_of_done = vec!["done".to_owned()];
        goal.completion_precondition = CompletionPrecondition {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        };
        goal
    }

    fn review_audit_evidence() -> EvidenceRef {
        EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from("evidence-1"),
            kind: EvidenceKind::TestResult,
            reference: "memory://evidence/evidence-1".to_owned(),
            producer_role: Role::Engineer,
            integrity: None,
            produced_at: timestamp(5),
        }
    }

    fn completion_evidence() -> CompletionEvidence {
        CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
            satisfied_acceptance_criteria: vec!["accepted".to_owned()],
            satisfied_verification_criteria: vec!["verified".to_owned()],
            satisfied_definition_of_done: vec!["done".to_owned()],
        }
    }

    fn passing_assessments() -> Vec<CriterionAssessment> {
        [
            (CriterionKind::Acceptance, "accepted"),
            (CriterionKind::Verification, "verified"),
            (CriterionKind::DefinitionOfDone, "done"),
        ]
        .into_iter()
        .map(|(kind, criterion)| CriterionAssessment {
            contract_version: ContractVersion::current(),
            kind,
            criterion: criterion.to_owned(),
            verdict: CriterionAssessmentVerdict::Satisfied,
            evidence_refs: vec![EvidenceId::from("evidence-1")],
            rationale: "the recorded evidence satisfies the exact criterion".to_owned(),
        })
        .collect()
    }

    fn review_decision() -> ReviewDecision {
        ReviewDecision {
            contract_version: ContractVersion::current(),
            id: ReviewDecisionId::from("review-1"),
            run_id: RunId::from("run-1"),
            goal_id: GoalId::from("goal-1"),
            producer_role: Role::Reviewer,
            verdict: ReviewVerdict::Pass,
            assessments: passing_assessments(),
            summary: "review passed".to_owned(),
            decided_at: timestamp(9),
        }
    }

    fn audit_decision(verdict: ReviewVerdict) -> AuditDecision {
        let mut assessments = passing_assessments();
        if verdict == ReviewVerdict::Fail {
            assessments[0].verdict = CriterionAssessmentVerdict::Unsatisfied;
            assessments[0].rationale = "the independent countercheck failed".to_owned();
        }
        AuditDecision {
            contract_version: ContractVersion::current(),
            id: AuditDecisionId::from("audit-1"),
            run_id: RunId::from("run-1"),
            goal_id: GoalId::from("goal-1"),
            review_decision_id: ReviewDecisionId::from("review-1"),
            producer_role: Role::Auditor,
            verdict,
            assessments,
            summary: "audit completed".to_owned(),
            decided_at: timestamp(11),
        }
    }

    fn append_review_audit_prerequisites(
        runtime: &DurableGoalRuntime,
        goal: &GoalContract,
        guard_requirements: BTreeSet<GuardRequirement>,
    ) {
        append_runtime_event(
            runtime,
            goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();
        append_runtime_event(
            runtime,
            goal,
            5,
            Role::Engineer,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: review_audit_evidence(),
            },
        )
        .unwrap();
        append_runtime_event(
            runtime,
            goal,
            6,
            Role::Engineer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: completion_evidence(),
            },
        )
        .unwrap();
        append_runtime_event(
            runtime,
            goal,
            7,
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded {
                requirements: ReviewAuditRequirements {
                    contract_version: ContractVersion::current(),
                    guard_requirements,
                },
            },
        )
        .unwrap();
        append_runtime_event(
            runtime,
            goal,
            8,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        )
        .unwrap();
    }

    fn append_pass_review_and_enter_auditing(runtime: &DurableGoalRuntime, goal: &GoalContract) {
        append_runtime_event(
            runtime,
            goal,
            9,
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        )
        .unwrap();
        append_runtime_event(
            runtime,
            goal,
            10,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Auditing,
            },
        )
        .unwrap();
    }

    fn guard_context(id: impl Into<String>) -> GuardEvaluationContext {
        GuardEvaluationContext {
            approval_request_id: ApprovalRequestId::new(id),
            requested_at: timestamp(20),
        }
    }

    fn guard_request(
        id: impl Into<String>,
        surface: GuardSurface,
        side_effect: SideEffectClass,
    ) -> GuardRequest {
        let risk_tier = match side_effect {
            SideEffectClass::ReadOnly => RiskTier::R0,
            SideEffectClass::ReversibleLocalWrite => RiskTier::R1,
            SideEffectClass::RepositoryWrite
            | SideEffectClass::NetworkAction
            | SideEffectClass::Publication
            | SideEffectClass::ExternalSideEffect => RiskTier::R2,
            SideEffectClass::Destructive
            | SideEffectClass::SecretBearing
            | SideEffectClass::Irreversible
            | SideEffectClass::Privileged => RiskTier::R3,
        };
        let write_keys = if side_effect == SideEffectClass::ReadOnly {
            Vec::new()
        } else {
            vec!["write:runtime".to_owned()]
        };
        let audit_required = risk_tier == RiskTier::R2
            && matches!(
                side_effect,
                SideEffectClass::NetworkAction
                    | SideEffectClass::Publication
                    | SideEffectClass::ExternalSideEffect
            );
        GuardRequest {
            contract_version: ContractVersion::current(),
            id: GuardRequestId::new(id),
            surface,
            side_effect,
            operation_label: "guarded runtime operation".to_owned(),
            resource_keys: vec!["resource:runtime".to_owned()],
            write_keys: write_keys.clone(),
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier,
                resource_keys: vec!["resource:runtime".to_owned()],
                write_keys,
                approval_required: risk_tier == RiskTier::R2,
                review_required: matches!(risk_tier, RiskTier::R1 | RiskTier::R2),
                audit_required,
            },
        }
    }

    fn owner_decision(
        approval_request_id: &ApprovalRequestId,
        request: &GuardRequest,
    ) -> ApprovalDecisionRecord {
        ApprovalDecisionRecord {
            contract_version: ContractVersion::current(),
            approval_request_id: approval_request_id.clone(),
            guard_request_id: request.id.clone(),
            authority: ApprovalAuthority::ExplicitOwner,
            disposition: ApprovalDisposition::Approved,
            decided_at: timestamp(21),
        }
    }

    #[test]
    fn shuffled_task_input_produces_identical_plan_and_events_with_sorted_task_ids() {
        let goal = goal();
        let first_tasks = vec![task("task-b", &[]), task("task-a", &[])];
        let shuffled_tasks = vec![task("task-a", &[]), task("task-b", &[])];

        let first = build_planned_run(RunId::from("run-1"), &goal, &first_tasks, stamps())
            .expect("first input order should build");
        let shuffled = build_planned_run(RunId::from("run-1"), &goal, &shuffled_tasks, stamps())
            .expect("shuffled input order should build");

        assert_eq!(first, shuffled);
        let RunEventPayload::RunCreated { task_ids, .. } = &first.1[0].payload else {
            panic!("first event should be RunCreated");
        };
        assert_eq!(task_ids, &[TaskId::from("task-a"), TaskId::from("task-b")]);
    }

    #[test]
    fn independent_tasks_are_parallel_and_dependency_chain_is_sequential() {
        let goal = goal();
        let independent = vec![task("task-b", &[]), task("task-a", &[])];
        let chain = vec![task("task-b", &["task-a"]), task("task-a", &[])];

        let (parallel_plan, _) =
            build_planned_run(RunId::from("run-parallel"), &goal, &independent, stamps())
                .expect("independent tasks should build");
        let (sequential_plan, _) =
            build_planned_run(RunId::from("run-sequential"), &goal, &chain, stamps())
                .expect("dependency chain should build");

        assert_eq!(parallel_plan.waves.len(), 1);
        assert_eq!(parallel_plan.waves[0].mode, ExecutionMode::Parallel);
        assert_eq!(
            parallel_plan.waves[0].task_ids,
            vec![TaskId::from("task-a"), TaskId::from("task-b")]
        );
        assert_eq!(sequential_plan.waves.len(), 2);
        assert!(sequential_plan
            .waves
            .iter()
            .all(|wave| wave.mode == ExecutionMode::Sequential));
        assert_eq!(
            sequential_plan
                .waves
                .iter()
                .flat_map(|wave| wave.task_ids.iter().cloned())
                .collect::<Vec<_>>(),
            vec![TaskId::from("task-a"), TaskId::from("task-b")]
        );
    }

    #[test]
    fn task_goal_mismatch_is_rejected() {
        let goal = goal();
        let mut mismatched = task("task-a", &[]);
        mismatched.goal_id = GoalId::from("goal-2");

        assert_eq!(
            build_planned_run(RunId::from("run-1"), &goal, &[mismatched], stamps()),
            Err(GoalRuntimeError::TaskGoalMismatch {
                task_id: TaskId::from("task-a"),
                expected_goal_id: GoalId::from("goal-1"),
                found_goal_id: GoalId::from("goal-2"),
            })
        );
    }

    #[test]
    fn top_level_goal_contract_version_mismatch_is_rejected() {
        let mut goal = goal();
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        goal.contract_version = unsupported;

        assert_eq!(
            build_planned_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            ),
            Err(GoalRuntimeError::GoalContractVersionMismatch {
                expected: ContractVersion::current(),
                found: unsupported,
            })
        );
    }

    #[test]
    fn permission_profile_contract_version_mismatch_is_rejected() {
        let mut goal = goal();
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        goal.permission_profile.contract_version = unsupported;

        assert_eq!(
            build_planned_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            ),
            Err(GoalRuntimeError::PermissionProfileContractVersionMismatch {
                expected: ContractVersion::current(),
                found: unsupported,
            })
        );
    }

    #[test]
    fn completion_precondition_contract_version_mismatch_is_rejected() {
        let mut goal = goal();
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        goal.completion_precondition.contract_version = unsupported;

        assert_eq!(
            build_planned_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            ),
            Err(
                GoalRuntimeError::CompletionPreconditionContractVersionMismatch {
                    expected: ContractVersion::current(),
                    found: unsupported,
                }
            )
        );
    }

    #[test]
    fn task_contract_version_mismatch_is_rejected() {
        let goal = goal();
        let mut mismatched = task("task-a", &[]);
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        mismatched.contract_version = unsupported;

        assert_eq!(
            build_planned_run(RunId::from("run-1"), &goal, &[mismatched], stamps(),),
            Err(GoalRuntimeError::TaskContractVersionMismatch {
                task_id: TaskId::from("task-a"),
                expected: ContractVersion::current(),
                found: unsupported,
            })
        );
    }

    #[test]
    fn non_pending_task_is_rejected() {
        let goal = goal();
        let mut ready = task("task-a", &[]);
        ready.status = TaskStatus::Ready;

        assert_eq!(
            build_planned_run(RunId::from("run-1"), &goal, &[ready], stamps()),
            Err(GoalRuntimeError::TaskNotPending {
                task_id: TaskId::from("task-a"),
                status: TaskStatus::Ready,
            })
        );
    }

    #[test]
    fn duplicate_stamp_ids_are_rejected() {
        let goal = goal();
        let mut duplicate = stamps();
        duplicate.plan_recorded.id = duplicate.accepted.id.clone();

        assert_eq!(
            build_planned_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                duplicate,
            ),
            Err(GoalRuntimeError::DuplicateStampId {
                event_id: EventId::from("event-1"),
            })
        );
    }

    #[test]
    fn decreasing_stamp_timestamps_are_rejected() {
        let goal = goal();
        let mut decreasing = stamps();
        decreasing.plan_recorded.occurred_at = timestamp(0);

        assert_eq!(
            build_planned_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                decreasing,
            ),
            Err(GoalRuntimeError::DecreasingStampTimestamp {
                previous_sequence: 1,
                previous_occurred_at: timestamp(1),
                sequence: 2,
                occurred_at: timestamp(0),
            })
        );
    }

    #[test]
    fn built_events_replay_to_the_exact_planned_state() {
        let goal = goal();
        let (plan, events) = build_planned_run(
            RunId::from("run-1"),
            &goal,
            &[task("task-b", &["task-a"]), task("task-a", &[])],
            stamps(),
        )
        .expect("planned run should build");

        assert_eq!(events.len(), 4);
        for (sequence, event) in events.iter().enumerate() {
            assert_eq!(event.sequence, sequence as u64);
            assert_eq!(event.producer_role, Role::Coordinator);
            assert_eq!(
                event.previous_event_id.as_ref(),
                sequence.checked_sub(1).map(|previous| &events[previous].id)
            );
        }
        assert!(matches!(
            events[0].payload,
            RunEventPayload::RunCreated {
                status: RunStatus::Draft,
                ..
            }
        ));
        assert!(matches!(
            events[1].payload,
            RunEventPayload::StatusTransition {
                from: RunStatus::Draft,
                to: RunStatus::Accepted,
            }
        ));
        assert!(matches!(
            events[2].payload,
            RunEventPayload::ExecutionPlanRecorded { .. }
        ));
        assert!(matches!(
            events[3].payload,
            RunEventPayload::StatusTransition {
                from: RunStatus::Accepted,
                to: RunStatus::Planned,
            }
        ));

        let replayed = replay_run(&events, Some(&goal)).expect("built events should replay");
        assert_eq!(replayed.run_record.status, RunStatus::Planned);
        assert_eq!(replayed.execution_plan, Some(plan));
    }

    #[test]
    fn durable_create_persists_planned_state_and_fresh_instance_loads_exact_state() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());

        let created = runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .expect("valid bootstrap should persist");

        assert_eq!(created.run_record.status, RunStatus::Planned);
        assert_eq!(created.run_record.event_count, 4);
        drop(runtime);

        let reopened = DurableGoalRuntime::new(dir.path());
        let loaded = reopened
            .load_run(&RunId::from("run-1"), &goal)
            .expect("fresh runtime should load the persisted run");
        assert_eq!(loaded, created);
    }

    #[test]
    fn durable_constructor_is_side_effect_free_for_all_authorities_and_media() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("runtime-root");
        let runtime = DurableGoalRuntime::new(&root);

        assert!(!root.exists());
        assert!(!runtime.log_path().exists());
        assert!(!runtime.execution_database_path().exists());
        assert!(!root.join(VERSIONED_STATE_DB_RELATIVE_PATH).exists());
        let _ = runtime.guardrail_authority();
    }

    #[test]
    fn r0_executes_once_without_creating_approval_state() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("runtime-root");
        let runtime = DurableGoalRuntime::new(&root);
        let calls = AtomicUsize::new(0);
        let result = runtime
            .execute_guarded(
                &guard_request("guard-r0", GuardSurface::Input, SideEffectClass::ReadOnly),
                &guard_context("approval-r0"),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>("executed")
                },
            )
            .unwrap();

        assert!(matches!(
            result,
            GuardedExecution::Executed {
                output: "executed",
                ..
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!root.exists());
        assert!(!root.join(VERSIONED_STATE_DB_RELATIVE_PATH).exists());
    }

    #[test]
    fn every_r2_surface_and_side_effect_pauses_before_execution() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        let calls = AtomicUsize::new(0);
        let mut paused = 0;

        for surface in [
            GuardSurface::Input,
            GuardSurface::Output,
            GuardSurface::Tool,
        ] {
            for side_effect in [
                SideEffectClass::RepositoryWrite,
                SideEffectClass::NetworkAction,
                SideEffectClass::Publication,
                SideEffectClass::ExternalSideEffect,
            ] {
                let suffix = format!("{surface:?}-{side_effect:?}");
                let result = runtime
                    .execute_guarded(
                        &guard_request(format!("guard-{suffix}"), surface, side_effect),
                        &guard_context(format!("approval-{suffix}")),
                        || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert!(matches!(result, GuardedExecution::PausedForApproval { .. }));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                paused += 1;
            }
        }

        assert_eq!(paused, 12);
    }

    #[test]
    fn every_r3_surface_denies_before_execution() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        let calls = AtomicUsize::new(0);
        let mut denied = 0;

        for surface in [
            GuardSurface::Input,
            GuardSurface::Output,
            GuardSurface::Tool,
        ] {
            for side_effect in [
                SideEffectClass::Destructive,
                SideEffectClass::SecretBearing,
                SideEffectClass::Irreversible,
                SideEffectClass::Privileged,
            ] {
                let suffix = format!("{surface:?}-{side_effect:?}");
                let result = runtime
                    .execute_guarded(
                        &guard_request(format!("guard-{suffix}"), surface, side_effect),
                        &guard_context(format!("approval-{suffix}")),
                        || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert!(matches!(result, GuardedExecution::DeniedByPolicy { .. }));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                denied += 1;
            }
        }

        assert_eq!(denied, 12);
        assert!(!dir.path().join(VERSIONED_STATE_DB_RELATIVE_PATH).exists());
    }

    #[test]
    fn pending_approval_reopens_and_concurrent_exact_resume_executes_once() {
        let dir = TempDir::new().unwrap();
        let request = guard_request(
            "guard-r2",
            GuardSurface::Tool,
            SideEffectClass::NetworkAction,
        );
        let approval_id = ApprovalRequestId::from("approval-r2");
        let runtime = DurableGoalRuntime::new(dir.path());
        let paused = runtime
            .execute_guarded(&request, &guard_context(approval_id.0.clone()), || {
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(paused, GuardedExecution::PausedForApproval { .. }));
        drop(runtime);

        let reopened = DurableGoalRuntime::new(dir.path());
        assert_eq!(
            reopened.load_approval(&approval_id).unwrap().envelope.state,
            ApprovalState::Pending
        );
        reopened
            .record_approval_decision(owner_decision(&approval_id, &request))
            .unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = dir.path().to_path_buf();
            let request = request.clone();
            let approval_id = approval_id.clone();
            let calls = Arc::clone(&calls);
            handles.push(thread::spawn(move || {
                DurableGoalRuntime::new(root)
                    .resume_approved(&approval_id, &request, || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(())
                    })
                    .unwrap()
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, GuardedExecution::Executed { .. }))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, GuardedExecution::AlreadyConsumed { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn request_and_permission_mismatches_cannot_resume_or_consume() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        let request = guard_request(
            "guard-r2",
            GuardSurface::Tool,
            SideEffectClass::RepositoryWrite,
        );
        let approval_id = ApprovalRequestId::from("approval-r2");
        runtime
            .evaluate_guard_and_record(&request, &guard_context(approval_id.0.clone()))
            .unwrap();
        runtime
            .record_approval_decision(owner_decision(&approval_id, &request))
            .unwrap();

        let calls = AtomicUsize::new(0);
        let mut changed_request = request.clone();
        changed_request.operation_label = "different operation".to_owned();
        let mut changed_permission = request.clone();
        changed_permission
            .permission_profile
            .write_keys
            .push("write:other".to_owned());
        for mismatch in [&changed_request, &changed_permission] {
            assert!(matches!(
                runtime.resume_approved(&approval_id, mismatch, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(())
                }),
                Err(DurableApprovalError::RequestMismatch { .. })
            ));
        }

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            runtime.load_approval(&approval_id).unwrap().envelope.state,
            ApprovalState::Approved
        );
    }

    #[test]
    fn logical_authority_states_remain_independent() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[])];
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
            .unwrap();
        runtime
            .initialize_execution(
                &RunId::from("run-1"),
                &goal,
                &tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();
        let guarded = guard_request(
            "guard-r2",
            GuardSurface::Tool,
            SideEffectClass::RepositoryWrite,
        );
        let approval_id = ApprovalRequestId::from("approval-r2");
        runtime
            .evaluate_guard_and_record(&guarded, &guard_context(approval_id.0.clone()))
            .unwrap();
        runtime
            .execution_authority()
            .claim(
                &RunId::from("run-1"),
                ClaimRequest {
                    task_id: TaskId::from("task-a"),
                    worker_id: WorkerId::from("worker-1"),
                    worker_role: Role::Engineer,
                    lease_id: LeaseId::from("lease-1"),
                    now: timestamp(4),
                    expires_at: timestamp(5),
                },
            )
            .unwrap();

        let view = runtime
            .load_runtime_view(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(view.orchestration.run_record.status, RunStatus::Planned);
        assert_eq!(
            view.orchestration.task_statuses[&TaskId::from("task-a")],
            TaskStatus::Pending
        );
        assert_eq!(
            view.execution.envelope.snapshot.tasks[&TaskId::from("task-a")].status,
            TaskStatus::Running
        );
        assert_eq!(
            runtime.load_approval(&approval_id).unwrap().envelope.state,
            ApprovalState::Pending
        );
        assert!(runtime.log_path().exists());
        assert!(runtime.execution_database_path().exists());
        assert!(dir.path().join(VERSIONED_STATE_DB_RELATIVE_PATH).exists());
    }

    #[test]
    fn create_run_writes_only_jsonl_and_leaves_execution_uninitialized() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal(),
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();

        assert!(runtime.log_path().exists());
        assert!(!runtime.execution_database_path().exists());
        assert!(matches!(
            runtime
                .load_runtime_view(&RunId::from("run-1"), &goal())
                .unwrap_err(),
            DurableGoalRuntimeError::Execution {
                source: DurableExecutionError::RunNotFound { .. }
            }
        ));
    }

    #[test]
    fn initialize_execution_requires_existing_planned_run_before_sqlite_write() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        let database_path = runtime.execution_database_path();

        let error = runtime
            .initialize_execution(
                &RunId::from("run-1"),
                &goal(),
                &[task("task-a", &[])],
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap_err();

        assert!(matches!(error, DurableGoalRuntimeError::RunNotFound { .. }));
        assert!(!database_path.exists());
    }

    #[test]
    fn planned_run_initializes_and_reopens_an_exact_combined_view() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[]), task("task-b", &["task-a"])];
        let runtime = DurableGoalRuntime::new(dir.path());
        let planned = runtime
            .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
            .unwrap();
        let initialized = runtime
            .initialize_execution(
                &RunId::from("run-1"),
                &goal,
                &tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 3,
                },
            )
            .unwrap();

        assert!(initialized.initialized);
        assert_eq!(initialized.view.orchestration, planned);
        assert_eq!(initialized.view.execution.revision, 0);
        drop(runtime);

        let reopened = DurableGoalRuntime::new(dir.path())
            .load_runtime_view(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(reopened, initialized.view);
    }

    #[test]
    fn shuffled_identical_execution_bootstrap_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let first_tasks = vec![task("task-a", &[]), task("task-b", &["task-a"])];
        let shuffled_tasks = vec![first_tasks[1].clone(), first_tasks[0].clone()];
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(RunId::from("run-1"), &goal, &first_tasks, stamps())
            .unwrap();
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };

        let first = runtime
            .initialize_execution(&RunId::from("run-1"), &goal, &first_tasks, budget)
            .unwrap();
        let retry = runtime
            .initialize_execution(&RunId::from("run-1"), &goal, &shuffled_tasks, budget)
            .unwrap();

        assert!(first.initialized);
        assert!(!retry.initialized);
        assert_eq!(retry.view, first.view);
    }

    #[test]
    fn bootstrap_mismatches_reject_before_sqlite_mutation() {
        fn planned_runtime() -> (TempDir, DurableGoalRuntime, GoalContract, Vec<Task>) {
            let dir = TempDir::new().unwrap();
            let goal = goal();
            let tasks = vec![task("task-a", &[]), task("task-b", &["task-a"])];
            let runtime = DurableGoalRuntime::new(dir.path());
            runtime
                .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
                .unwrap();
            (dir, runtime, goal, tasks)
        }
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };

        let (_dir, runtime, goal, mut tasks) = planned_runtime();
        let mut mismatched_goal = goal.clone();
        mismatched_goal.id = GoalId::from("different-goal");
        assert!(matches!(
            runtime
                .initialize_execution(&RunId::from("run-1"), &mismatched_goal, &tasks, budget,)
                .unwrap_err(),
            DurableGoalRuntimeError::BootstrapGoalMismatch { .. }
        ));
        assert!(!runtime.execution_database_path().exists());

        tasks[0].goal_id = GoalId::from("different-goal");
        assert!(matches!(
            runtime
                .initialize_execution(&RunId::from("run-1"), &goal, &tasks, budget)
                .unwrap_err(),
            DurableGoalRuntimeError::BootstrapGoalMismatch { .. }
        ));
        assert!(!runtime.execution_database_path().exists());

        let (_dir, runtime, goal, mut tasks) = planned_runtime();
        tasks.pop();
        assert!(matches!(
            runtime
                .initialize_execution(&RunId::from("run-1"), &goal, &tasks, budget)
                .unwrap_err(),
            DurableGoalRuntimeError::BootstrapTaskSetMismatch { .. }
        ));
        assert!(!runtime.execution_database_path().exists());

        let (_dir, runtime, goal, mut tasks) = planned_runtime();
        tasks[0].status = TaskStatus::Ready;
        assert!(matches!(
            runtime
                .initialize_execution(&RunId::from("run-1"), &goal, &tasks, budget)
                .unwrap_err(),
            DurableGoalRuntimeError::BootstrapTaskStatusMismatch { .. }
        ));
        assert!(!runtime.execution_database_path().exists());
    }

    #[test]
    fn create_to_initialize_crash_gap_is_recoverable_after_reopen() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[])];
        DurableGoalRuntime::new(dir.path())
            .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
            .unwrap();

        let reopened = DurableGoalRuntime::new(dir.path());
        assert!(matches!(
            reopened
                .load_runtime_view(&RunId::from("run-1"), &goal)
                .unwrap_err(),
            DurableGoalRuntimeError::Execution {
                source: DurableExecutionError::RunNotFound { .. }
            }
        ));
        let recovered = reopened
            .initialize_execution(
                &RunId::from("run-1"),
                &goal,
                &tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();
        assert!(recovered.initialized);
    }

    #[test]
    fn combined_view_exposes_independent_orchestration_and_execution_statuses() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[])];
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
            .unwrap();
        runtime
            .initialize_execution(
                &RunId::from("run-1"),
                &goal,
                &tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();
        runtime
            .execution_authority()
            .claim(
                &RunId::from("run-1"),
                ClaimRequest {
                    task_id: TaskId::from("task-a"),
                    worker_id: WorkerId::from("worker-1"),
                    worker_role: Role::Engineer,
                    lease_id: LeaseId::from("lease-1"),
                    now: timestamp(4),
                    expires_at: timestamp(5),
                },
            )
            .unwrap();

        let view = runtime
            .load_runtime_view(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(
            view.orchestration.task_statuses[&TaskId::from("task-a")],
            TaskStatus::Pending
        );
        assert_eq!(
            view.execution.envelope.snapshot.tasks[&TaskId::from("task-a")].status,
            TaskStatus::Running
        );
    }

    #[test]
    fn combined_view_reports_structured_identity_mismatch() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[])];
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(RunId::from("run-1"), &goal, &tasks, stamps())
            .unwrap();
        let mut mismatched_tasks = tasks;
        mismatched_tasks[0].goal_id = GoalId::from("different-goal");
        runtime
            .execution_authority()
            .initialize_run(
                RunId::from("run-1"),
                mismatched_tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();

        assert!(matches!(
            runtime
                .load_runtime_view(&RunId::from("run-1"), &goal)
                .unwrap_err(),
            DurableGoalRuntimeError::ViewGoalMismatch {
                expected,
                found: Some(found),
            } if expected == GoalId::from("goal-1") && found == GoalId::from("different-goal")
        ));
    }

    #[test]
    fn traversal_like_run_ids_remain_data_across_both_stores() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let tasks = vec![task("task-a", &[])];
        let runtime = DurableGoalRuntime::new(dir.path());
        let run_id = RunId::from("../outside/run");
        let expected_log_path = runtime.log_path().to_path_buf();
        let expected_database_path = runtime.execution_database_path();

        runtime
            .create_run(run_id.clone(), &goal, &tasks, stamps())
            .unwrap();
        runtime
            .initialize_execution(
                &run_id,
                &goal,
                &tasks,
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();

        assert_eq!(runtime.log_path(), expected_log_path);
        assert_eq!(runtime.execution_database_path(), expected_database_path);
        assert_eq!(
            runtime
                .load_runtime_view(&run_id, &goal)
                .unwrap()
                .execution
                .envelope
                .run_id,
            run_id
        );
        assert!(!dir.path().join("outside").exists());
    }

    #[test]
    fn durable_r0_completion_without_review_events_remains_compatible() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            5,
            Role::Engineer,
            RunEventPayload::EvidenceAttached {
                evidence_id: EvidenceId::from("evidence-1"),
            },
        )
        .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            6,
            Role::Engineer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: CompletionEvidence {
                    contract_version: ContractVersion::current(),
                    evidence_refs: vec![EvidenceId::from("evidence-1")],
                    satisfied_acceptance_criteria: Vec::new(),
                    satisfied_verification_criteria: Vec::new(),
                    satisfied_definition_of_done: Vec::new(),
                },
            },
        )
        .unwrap();

        let completed = append_runtime_event(
            &runtime,
            &goal,
            7,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        )
        .expect("R0 completion should remain compatible without review events");

        assert_eq!(completed.run_record.status, RunStatus::Completed);
        assert_eq!(completed.review_audit_requirements, None);
        assert!(completed.review_decisions.is_empty());
        assert!(completed.audit_decisions.is_empty());
        let before_evaluation = fs::read(runtime.log_path()).unwrap();
        let database_path = runtime.execution_database_path();
        assert!(!database_path.exists());
        let evaluation = runtime.evaluate_run(&RunId::from("run-1"), &goal).unwrap();
        assert!(evaluation.passes);
        assert_eq!(evaluation.completeness.score, 1.0);
        assert!(evaluation.replay_parity.canonical_match);
        assert_eq!(
            evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::SuccessfulCompletion
        );
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before_evaluation);
        assert!(!database_path.exists());
        let reopened = DurableGoalRuntime::new(dir.path());
        assert_eq!(
            reopened.load_run(&RunId::from("run-1"), &goal).unwrap(),
            completed
        );
    }

    #[test]
    fn enforced_completion_blocks_generic_bypass_and_appends_only_verified_final_event() {
        let fixture = v4c_fixture();
        let material = fixture
            .runtime
            .prepare_local_verification_completion(&RunId::from("run-1"), &fixture.goal)
            .unwrap();
        assert_eq!(
            fixture
                .runtime
                .log
                .load_run(&RunId::from("run-1"))
                .unwrap()
                .len(),
            5
        );

        let final_event = appended_event(
            "event-7",
            7,
            "event-6",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );
        let before_bypass = fs::read(fixture.runtime.log_path()).unwrap();
        assert!(matches!(
            fixture
                .runtime
                .append_event(final_event.clone(), &fixture.goal),
            Err(DurableGoalRuntimeError::VerifiedCompletionRequired { .. })
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before_bypass);

        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            5,
            Role::Coordinator,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: material.evidence_references[0].clone(),
            },
        )
        .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            6,
            Role::Coordinator,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: material.completion_evidence,
            },
        )
        .unwrap();
        let before_verified = fixture.runtime.log.load_run(&RunId::from("run-1")).unwrap();
        let completed = fixture
            .runtime
            .append_verified_completion(final_event, &fixture.goal)
            .unwrap();
        let after_verified = fixture.runtime.log.load_run(&RunId::from("run-1")).unwrap();
        assert_eq!(after_verified.len(), before_verified.len() + 1);
        assert_eq!(completed.run_record.status, RunStatus::Completed);

        let persisted = fs::read_to_string(fixture.runtime.log_path()).unwrap();
        assert!(!persisted.contains(&fixture._source.path().display().to_string()));
        assert!(!persisted.contains(V4C_ENVIRONMENT_VALUE));
    }

    #[test]
    fn enforced_completion_resolves_persisted_goal_before_caller_contract_branch() {
        let fixture = v4c_fixture();
        let mut forged = fixture.goal.clone();
        forged.objective.push_str(" caller drift");
        let before = fs::read(fixture.runtime.log_path()).unwrap();
        let error = fixture
            .runtime
            .append_event(
                appended_event(
                    "event-5",
                    5,
                    "event-4",
                    Role::Coordinator,
                    RunEventPayload::StatusTransition {
                        from: RunStatus::Running,
                        to: RunStatus::Completed,
                    },
                ),
                &forged,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DurableGoalRuntimeError::CompletionGoalContractMismatch { .. }
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
        assert!(matches!(
            fixture
                .runtime
                .reconcile_verified_completion_append(&v4c_final_event(), &forged),
            Err(DurableGoalRuntimeError::CompletionGoalContractMismatch { .. })
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
    }

    #[test]
    fn enforced_completion_rejects_missing_policy_and_persisted_task_set_mismatch_without_append() {
        let fixture = v4c_fixture();
        let before = fs::read(fixture.runtime.log_path()).unwrap();
        let missing = DurableGoalRuntime {
            log: fixture.runtime.log.clone(),
            execution: fixture.runtime.execution.clone(),
            guardrails: fixture.runtime.guardrails.clone(),
            completion_policy: LocalVerificationCompletionPolicy::Enforced {
                goals: BTreeMap::new(),
            },
            evidence_bank: fixture.runtime.evidence_bank.clone(),
        };
        assert!(matches!(
            missing
                .append_event(v4c_final_event(), &fixture.goal)
                .unwrap_err(),
            DurableGoalRuntimeError::CompletionPolicyMissing { .. }
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
        assert!(matches!(
            missing.reconcile_verified_completion_append(&v4c_final_event(), &fixture.goal),
            Err(DurableGoalRuntimeError::CompletionPolicyMissing { .. })
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);

        let mut authority = v4c_authority(&fixture);
        authority.completion.task_ids = vec![TaskId::from("task-b")];
        authority.completion.tasks[0].selection.task_id = TaskId::from("task-b");
        authority.completion.tasks[0].behavior.binding = BehaviorBinding::Bound {
            goal_id: fixture.goal.id.clone(),
            task_id: TaskId::from("task-b"),
        };
        let mismatch = DurableGoalRuntime {
            log: fixture.runtime.log.clone(),
            execution: fixture.runtime.execution.clone(),
            guardrails: fixture.runtime.guardrails.clone(),
            completion_policy: LocalVerificationCompletionPolicy::Enforced {
                goals: BTreeMap::from([(fixture.goal.id.clone(), authority)]),
            },
            evidence_bank: fixture.runtime.evidence_bank.clone(),
        };
        let error = mismatch
            .append_event(v4c_final_event(), &fixture.goal)
            .unwrap_err();
        assert!(matches!(
            error,
            DurableGoalRuntimeError::CompletionTaskSetMismatch { .. }
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
        assert!(matches!(
            mismatch.reconcile_verified_completion_append(&v4c_final_event(), &fixture.goal),
            Err(DurableGoalRuntimeError::CompletionTaskSetMismatch { .. })
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
    }

    #[test]
    fn completion_policy_rejects_network_like_source_roots_before_filesystem_access() {
        let fixture = v4c_fixture();
        let authority = v4c_authority(&fixture);
        assert!(!is_local_absolute_source_root(Path::new("file:///remote")));
        assert!(!is_local_absolute_source_root(Path::new(
            "https://example.invalid/source"
        )));
        for root in [
            PathBuf::from(r"\\server\share"),
            PathBuf::from("//server/share"),
        ] {
            let mut rejected = authority.clone();
            rejected.source_root = root;
            assert!(matches!(
                DurableGoalRuntime::try_new_with_completion_policy(
                    fixture._durable.path(),
                    LocalVerificationCompletionPolicy::Enforced {
                        goals: BTreeMap::from([(fixture.goal.id.clone(), rejected)]),
                    },
                ),
                Err(DurableGoalRuntimeError::InvalidCompletionPolicy { .. })
            ));
        }
    }

    #[test]
    fn verified_completion_rejects_wrong_recorded_material_without_append() {
        let fixture = v4c_fixture();
        let wrong_reference = EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from("wrong-evidence"),
            kind: EvidenceKind::TestResult,
            reference: "evidence/wrong".to_owned(),
            producer_role: Role::Coordinator,
            integrity: None,
            produced_at: timestamp(5),
        };
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            5,
            Role::Coordinator,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: wrong_reference,
            },
        )
        .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            6,
            Role::Coordinator,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: CompletionEvidence {
                    contract_version: ContractVersion::current(),
                    evidence_refs: vec![EvidenceId::from("wrong-evidence")],
                    satisfied_acceptance_criteria: Vec::new(),
                    satisfied_verification_criteria: vec!["verified".to_owned()],
                    satisfied_definition_of_done: Vec::new(),
                },
            },
        )
        .unwrap();
        let before = fs::read(fixture.runtime.log_path()).unwrap();
        let error = fixture
            .runtime
            .append_verified_completion(
                appended_event(
                    "event-7",
                    7,
                    "event-6",
                    Role::Coordinator,
                    RunEventPayload::StatusTransition {
                        from: RunStatus::Running,
                        to: RunStatus::Completed,
                    },
                ),
                &fixture.goal,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DurableGoalRuntimeError::LocalVerificationAdmission { .. }
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
    }

    #[test]
    fn verified_completion_rechecks_live_source_and_appends_nothing_on_drift() {
        let fixture = v4c_fixture();
        let material = fixture
            .runtime
            .prepare_local_verification_completion(&RunId::from("run-1"), &fixture.goal)
            .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            5,
            Role::Coordinator,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: material.evidence_references[0].clone(),
            },
        )
        .unwrap();
        append_runtime_event(
            &fixture.runtime,
            &fixture.goal,
            6,
            Role::Coordinator,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: material.completion_evidence,
            },
        )
        .unwrap();
        fs::write(
            fixture._source.path().join("input.txt"),
            b"changed after preparation\n",
        )
        .unwrap();
        let before = fs::read(fixture.runtime.log_path()).unwrap();
        assert!(matches!(
            fixture.runtime.append_verified_completion(
                appended_event(
                    "event-7",
                    7,
                    "event-6",
                    Role::Coordinator,
                    RunEventPayload::StatusTransition {
                        from: RunStatus::Running,
                        to: RunStatus::Completed,
                    },
                ),
                &fixture.goal,
            ),
            Err(DurableGoalRuntimeError::LocalVerificationSnapshot { .. })
        ));
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
    }

    #[test]
    fn verified_completion_rejects_stale_and_nonpass_current_bundles_without_append() {
        let stale = v4c_fixture();
        record_v4c_material(&stale);
        let stale_store = LocalVerificationStore::try_new(stale._durable.path()).unwrap();
        let stale_bank = stale_store.evidence_bank();
        let stale_key = v4c_evidence_key(&stale);
        let stale_current = stale_bank.load_current(&stale_key).unwrap().unwrap();
        assert!(matches!(
            stale_bank
                .mark_stale(
                    &stale_key,
                    &stale_current.token,
                    BTreeSet::from([StaleCause::Environment]),
                )
                .unwrap(),
            CasOutcome::Applied(_)
        ));
        let before_stale = fs::read(stale.runtime.log_path()).unwrap();
        assert!(stale
            .runtime
            .append_verified_completion(v4c_final_event(), &stale.goal)
            .is_err());
        assert_eq!(fs::read(stale.runtime.log_path()).unwrap(), before_stale);

        let nonpass = v4c_fixture();
        record_v4c_material(&nonpass);
        replace_v4c_bundle(&nonpass, |bundle| {
            bundle.bundle_id = "bundle.v4c.nonpass".to_owned();
            bundle.verdict = VerificationVerdict::Fail;
            bundle.criterion_results[0].verdict = CriterionResultVerdict::Fail;
            bundle.failures = vec![VerificationFailure {
                contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
                failure_id: "failure.v4c.nonpass".to_owned(),
                category: VerificationFailureCategory::ProductBug,
                confirmation: FailureConfirmation::Provisional,
                supersedes_failure_id: None,
                criterion_id: Some("criterion.verify".to_owned()),
                summary: "bounded non-pass regression".to_owned(),
                recorded_at: timestamp(5),
            }];
        });
        let before_nonpass = fs::read(nonpass.runtime.log_path()).unwrap();
        assert!(nonpass
            .runtime
            .append_verified_completion(v4c_final_event(), &nonpass.goal)
            .is_err());
        assert_eq!(
            fs::read(nonpass.runtime.log_path()).unwrap(),
            before_nonpass
        );
    }

    #[test]
    fn verified_completion_rejects_fingerprint_and_incomplete_coverage_without_append() {
        let fingerprint = v4c_fixture();
        record_v4c_material(&fingerprint);
        replace_v4c_bundle(&fingerprint, |bundle| {
            bundle.bundle_id = "bundle.v4c.environment-drift".to_owned();
            bundle.fingerprints.environment = verification_sha256_hex(b"different environment");
        });
        let before_fingerprint = fs::read(fingerprint.runtime.log_path()).unwrap();
        assert!(fingerprint
            .runtime
            .append_verified_completion(v4c_final_event(), &fingerprint.goal)
            .is_err());
        assert_eq!(
            fs::read(fingerprint.runtime.log_path()).unwrap(),
            before_fingerprint
        );

        let incomplete = v4c_fixture();
        record_v4c_material(&incomplete);
        replace_v4c_bundle(&incomplete, |bundle| {
            bundle.bundle_id = "bundle.v4c.incomplete".to_owned();
            bundle.criterion_results.pop();
        });
        let before_incomplete = fs::read(incomplete.runtime.log_path()).unwrap();
        assert!(incomplete
            .runtime
            .append_verified_completion(v4c_final_event(), &incomplete.goal)
            .is_err());
        assert_eq!(
            fs::read(incomplete.runtime.log_path()).unwrap(),
            before_incomplete
        );
    }

    #[test]
    fn verified_completion_rejects_partial_mixed_task_projection_without_append() {
        let fixture = v4c_fixture();
        record_v4c_material(&fixture);
        let store = LocalVerificationStore::try_new(fixture._durable.path()).unwrap();
        let registry = store.capability_registry();
        let bank = store.evidence_bank();
        let current = bank
            .load_current(&v4c_evidence_key(&fixture))
            .unwrap()
            .unwrap();
        let mut mixed = bank
            .load_bundle(&current.record_digest)
            .unwrap()
            .unwrap()
            .bundle;
        mixed.bundle_id = "bundle.v4c.mixed-task".to_owned();
        mixed.task_id = TaskId::from("task-b");
        let mixed_current = match bank
            .publish_bundle_and_cas(&mixed, &ProjectionExpectation::Absent)
            .unwrap()
            .projection
        {
            CasOutcome::Applied(current) => current,
            other => panic!("unexpected mixed projection: {other:?}"),
        };
        let capability_current = registry.load_current("capability.v4c").unwrap().unwrap();
        let projection = AuthoritativeProjectionSelection::new(
            ProjectionRebuildIntent::Replace,
            vec![capability_current],
            vec![mixed_current],
        )
        .unwrap();
        store.rebuild_projections(&projection).unwrap();

        let before = fs::read(fixture.runtime.log_path()).unwrap();
        assert!(fixture
            .runtime
            .append_verified_completion(v4c_final_event(), &fixture.goal)
            .is_err());
        assert_eq!(fs::read(fixture.runtime.log_path()).unwrap(), before);
    }

    #[test]
    fn durable_missing_required_review_rejects_without_changing_jsonl() {
        let dir = TempDir::new().unwrap();
        let goal = review_audit_goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_review_audit_prerequisites(
            &runtime,
            &goal,
            BTreeSet::from([GuardRequirement::Reviewer]),
        );
        let before = fs::read(runtime.log_path()).unwrap();

        let error = append_runtime_event(
            &runtime,
            &goal,
            9,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Completed,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::ReviewAuditResolutionRejected {
                    sequence: 9,
                    resolution: ReviewAuditResolution::AwaitingReview,
                }
            }
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        let evaluation = runtime.evaluate_run(&RunId::from("run-1"), &goal).unwrap();
        assert!(!evaluation.passes);
        assert_eq!(
            evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::AwaitingReview
        );
        assert_eq!(evaluation.trace.spans.len(), 9);
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .status,
            RunStatus::Reviewing
        );
    }

    #[test]
    fn durable_missing_required_audit_rejects_without_changing_jsonl() {
        let dir = TempDir::new().unwrap();
        let goal = review_audit_goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_review_audit_prerequisites(
            &runtime,
            &goal,
            BTreeSet::from([GuardRequirement::Reviewer, GuardRequirement::Auditor]),
        );
        append_pass_review_and_enter_auditing(&runtime, &goal);
        let before = fs::read(runtime.log_path()).unwrap();

        let error = append_runtime_event(
            &runtime,
            &goal,
            11,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::ReviewAuditResolutionRejected {
                    sequence: 11,
                    resolution: ReviewAuditResolution::AwaitingAudit {
                        review_decision_id,
                    },
                }
            } if review_decision_id == ReviewDecisionId::from("review-1")
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        let evaluation = runtime.evaluate_run(&RunId::from("run-1"), &goal).unwrap();
        assert!(!evaluation.passes);
        assert_eq!(
            evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::AwaitingAudit
        );
        assert_eq!(evaluation.trace.spans.len(), 11);
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .status,
            RunStatus::Auditing
        );
    }

    #[test]
    fn durable_review_audit_disagreement_preserves_owner_escalation_and_jsonl() {
        let dir = TempDir::new().unwrap();
        let goal = review_audit_goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_review_audit_prerequisites(
            &runtime,
            &goal,
            BTreeSet::from([GuardRequirement::Reviewer, GuardRequirement::Auditor]),
        );
        append_pass_review_and_enter_auditing(&runtime, &goal);
        append_runtime_event(
            &runtime,
            &goal,
            11,
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision(ReviewVerdict::Fail),
            },
        )
        .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();

        let error = append_runtime_event(
            &runtime,
            &goal,
            12,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::ReviewAuditResolutionRejected {
                    sequence: 12,
                    resolution: ReviewAuditResolution::OwnerEscalation {
                        review_decision_id,
                        audit_decision_id,
                        reviewer_verdict: ReviewVerdict::Pass,
                        auditor_verdict: ReviewVerdict::Fail,
                    },
                }
            } if review_decision_id == ReviewDecisionId::from("review-1")
                && audit_decision_id == AuditDecisionId::from("audit-1")
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        let evaluation = runtime.evaluate_run(&RunId::from("run-1"), &goal).unwrap();
        assert!(!evaluation.passes);
        assert_eq!(
            evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::OwnerEscalation
        );
        assert_eq!(evaluation.trace.spans.len(), 12);
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .status,
            RunStatus::Auditing
        );
    }

    #[test]
    fn durable_run_guard_projection_preserves_pause_and_deny_after_reload() {
        let pause_dir = TempDir::new().unwrap();
        let goal = goal();
        let pause_runtime = DurableGoalRuntime::new(pause_dir.path());
        pause_runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &pause_runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();

        let pause = pause_runtime
            .evaluate_run_guard_and_record(
                &RunId::from("run-1"),
                &goal,
                &guard_request(
                    "guard-sensitive-pause",
                    GuardSurface::Tool,
                    SideEffectClass::NetworkAction,
                ),
                &guard_context("approval-sensitive-pause"),
                EventStamp {
                    id: EventId::from("event-5"),
                    occurred_at: timestamp(21),
                },
            )
            .unwrap();
        assert!(matches!(
            &pause.guard_outcomes.last().unwrap().outcome,
            RunGuardDecision::Pause { .. }
        ));
        let pause_bytes = fs::read(pause_runtime.log_path()).unwrap();
        let pause_jsonl = String::from_utf8(pause_bytes.clone()).unwrap();
        for excluded in [
            "guard-sensitive-pause",
            "approval-sensitive-pause",
            "guarded runtime operation",
            "resource:runtime",
            "write:runtime",
        ] {
            assert!(!pause_jsonl.contains(excluded));
        }
        let pause_reloaded = DurableGoalRuntime::new(pause_dir.path())
            .load_run(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(pause_reloaded, pause);
        let pause_evaluation = DurableGoalRuntime::new(pause_dir.path())
            .evaluate_run(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(
            pause_evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::AwaitingApproval
        );
        assert!(!pause_evaluation.passes);
        assert_eq!(fs::read(pause_runtime.log_path()).unwrap(), pause_bytes);

        let deny_dir = TempDir::new().unwrap();
        let deny_runtime = DurableGoalRuntime::new(deny_dir.path());
        deny_runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &deny_runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();

        let deny = deny_runtime
            .evaluate_run_guard_and_record(
                &RunId::from("run-1"),
                &goal,
                &guard_request(
                    "guard-sensitive-deny",
                    GuardSurface::Tool,
                    SideEffectClass::Destructive,
                ),
                &guard_context("approval-sensitive-deny"),
                EventStamp {
                    id: EventId::from("event-5"),
                    occurred_at: timestamp(21),
                },
            )
            .unwrap();
        assert!(matches!(
            &deny.guard_outcomes.last().unwrap().outcome,
            RunGuardDecision::Deny { reasons }
                if reasons.contains(&GuardDenyReason::R3DenyByDefault)
        ));
        let deny_bytes = fs::read(deny_runtime.log_path()).unwrap();
        let deny_reloaded = DurableGoalRuntime::new(deny_dir.path())
            .load_run(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(deny_reloaded, deny);
        let deny_evaluation = DurableGoalRuntime::new(deny_dir.path())
            .evaluate_run(&RunId::from("run-1"), &goal)
            .unwrap();
        assert_eq!(
            deny_evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::PolicyDenied
        );
        assert!(!deny_evaluation.passes);
        assert_eq!(fs::read(deny_runtime.log_path()).unwrap(), deny_bytes);
    }

    #[test]
    fn durable_evaluation_keeps_approval_pause_non_successful_and_read_only() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            5,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::AwaitingApproval,
            },
        )
        .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();

        let evaluation = runtime.evaluate_run(&RunId::from("run-1"), &goal).unwrap();

        assert!(!evaluation.passes);
        assert_eq!(
            evaluation.invariants.outcome,
            GoalRuntimeEvaluationOutcome::AwaitingApproval
        );
        assert_eq!(evaluation.trace.spans.len(), 6);
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert!(!runtime.execution_database_path().exists());
    }

    #[test]
    fn durable_exact_required_pass_decisions_complete_and_reload_equally() {
        let dir = TempDir::new().unwrap();
        let goal = review_audit_goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let requirements = BTreeSet::from([GuardRequirement::Reviewer, GuardRequirement::Auditor]);
        append_review_audit_prerequisites(&runtime, &goal, requirements.clone());
        append_pass_review_and_enter_auditing(&runtime, &goal);
        append_runtime_event(
            &runtime,
            &goal,
            11,
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision(ReviewVerdict::Pass),
            },
        )
        .unwrap();

        let completed = append_runtime_event(
            &runtime,
            &goal,
            12,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        )
        .expect("exact required Pass decisions should permit completion");

        assert_eq!(completed.run_record.status, RunStatus::Completed);
        assert_eq!(
            completed
                .review_audit_requirements
                .as_ref()
                .map(|recorded| &recorded.guard_requirements),
            Some(&requirements)
        );
        assert_eq!(completed.review_decisions, vec![review_decision()]);
        assert_eq!(
            completed.audit_decisions,
            vec![audit_decision(ReviewVerdict::Pass)]
        );
        let reopened = DurableGoalRuntime::new(dir.path());
        let reloaded = reopened.load_run(&RunId::from("run-1"), &goal).unwrap();
        assert_eq!(reloaded, completed);
        assert_eq!(reloaded.run_record.status, RunStatus::Completed);
    }

    #[test]
    fn durable_load_rejects_unsupported_goal_version_without_mutation() {
        let dir = TempDir::new().unwrap();
        let valid_goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        let persisted = runtime
            .create_run(
                RunId::from("run-1"),
                &valid_goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();
        let mut unsupported_goal = goal();
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        unsupported_goal.contract_version = unsupported;

        let error = runtime
            .load_run(&RunId::from("run-1"), &unsupported_goal)
            .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Build {
                source: GoalRuntimeError::GoalContractVersionMismatch {
                    expected,
                    found,
                }
            } if expected == ContractVersion::current() && found == unsupported
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        let reloaded = runtime
            .load_run(&RunId::from("run-1"), &valid_goal)
            .unwrap();
        assert_eq!(reloaded, persisted);
        assert_eq!(reloaded.run_record.event_count, 4);
    }

    #[test]
    fn durable_append_rejects_unsupported_nested_goal_version_without_mutation() {
        let dir = TempDir::new().unwrap();
        let valid_goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        let persisted = runtime
            .create_run(
                RunId::from("run-1"),
                &valid_goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();
        let mut unsupported_goal = goal();
        let unsupported = ContractVersion(ContractVersion::current().0 + 1);
        unsupported_goal.permission_profile.contract_version = unsupported;

        let error = runtime
            .append_event(
                appended_event(
                    "event-4",
                    4,
                    "event-3",
                    Role::Engineer,
                    RunEventPayload::NoteRecorded {
                        message: "rejected before persistence".to_owned(),
                    },
                ),
                &unsupported_goal,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Build {
                source: GoalRuntimeError::PermissionProfileContractVersionMismatch {
                    expected,
                    found,
                }
            } if expected == ContractVersion::current() && found == unsupported
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        let reloaded = runtime
            .load_run(&RunId::from("run-1"), &valid_goal)
            .unwrap();
        assert_eq!(reloaded, persisted);
        assert_eq!(reloaded.run_record.event_count, 4);
    }

    #[test]
    fn invalid_bootstrap_creates_no_event_log_file_or_bytes() {
        let dir = TempDir::new().unwrap();
        let runtime = DurableGoalRuntime::new(dir.path());
        let log_path = runtime.log_path().to_path_buf();
        let mut invalid_stamps = stamps();
        invalid_stamps.planned.id = invalid_stamps.accepted.id.clone();

        let error = runtime
            .create_run(
                RunId::from("run-1"),
                &goal(),
                &[task("task-a", &[])],
                invalid_stamps,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Build {
                source: GoalRuntimeError::DuplicateStampId { .. }
            }
        ));
        assert!(!log_path.exists());
        assert!(fs::read(log_path).unwrap_or_default().is_empty());
    }

    #[test]
    fn existing_run_is_rejected_without_mutation() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();

        let error = runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::RunAlreadyExists { run_id }
                if run_id == RunId::from("run-1")
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .event_count,
            4
        );
    }

    #[test]
    fn missing_run_load_and_append_are_rejected_without_writes() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());

        let load_error = runtime.load_run(&RunId::from("run-1"), &goal).unwrap_err();
        assert!(matches!(
            load_error,
            DurableGoalRuntimeError::RunNotFound { run_id }
                if run_id == RunId::from("run-1")
        ));

        let append_error = runtime
            .append_event(
                appended_event(
                    "event-4",
                    4,
                    "event-3",
                    Role::Engineer,
                    RunEventPayload::NoteRecorded {
                        message: "missing run".to_owned(),
                    },
                ),
                &goal,
            )
            .unwrap_err();
        assert!(matches!(
            append_error,
            DurableGoalRuntimeError::RunNotFound { run_id }
                if run_id == RunId::from("run-1")
        ));
        assert!(!runtime.log_path().exists());
    }

    #[test]
    fn invalid_sequence_and_previous_link_leave_count_and_bytes_unchanged() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();

        let sequence_error = runtime
            .append_event(
                appended_event(
                    "event-5",
                    5,
                    "event-3",
                    Role::Engineer,
                    RunEventPayload::NoteRecorded {
                        message: "skipped sequence".to_owned(),
                    },
                ),
                &goal,
            )
            .unwrap_err();
        assert!(matches!(
            sequence_error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::SequenceMismatch {
                    expected: 4,
                    found: 5,
                    ..
                }
            }
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);

        let previous_link_error = runtime
            .append_event(
                appended_event(
                    "event-4",
                    4,
                    "wrong-previous",
                    Role::Engineer,
                    RunEventPayload::NoteRecorded {
                        message: "bad previous link".to_owned(),
                    },
                ),
                &goal,
            )
            .unwrap_err();
        assert!(matches!(
            previous_link_error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::PreviousEventIdMismatch { sequence: 4, .. }
            }
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .event_count,
            4
        );
    }

    #[test]
    fn engineer_coordinator_final_response_is_rejected_without_mutation() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        let before = fs::read(runtime.log_path()).unwrap();

        let error = runtime
            .append_event(
                appended_event(
                    "event-4",
                    4,
                    "event-3",
                    Role::Engineer,
                    RunEventPayload::CoordinatorFinalResponseRecorded {
                        response: CoordinatorFinalResponse {
                            contract_version: ContractVersion::current(),
                            response: "engineer cannot finalize".to_owned(),
                            evidence_refs: Vec::new(),
                        },
                    },
                ),
                &goal,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            DurableGoalRuntimeError::Replay {
                source: ReplayError::UnauthorizedCoordinatorFinalResponse {
                    sequence: 4,
                    producer_role: Role::Engineer,
                }
            }
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
        assert_eq!(
            runtime
                .load_run(&RunId::from("run-1"), &goal)
                .unwrap()
                .run_record
                .event_count,
            4
        );
    }

    #[test]
    fn valid_specialist_output_then_coordinator_final_response_persists_and_replays() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();

        let output = SpecialistOutput {
            contract_version: ContractVersion::current(),
            task_id: TaskId::from("task-a"),
            specialist_role: Role::Engineer,
            summary: "implemented the bounded slice".to_owned(),
            evidence_refs: Vec::new(),
        };
        let after_output = runtime
            .append_event(
                appended_event(
                    "event-4",
                    4,
                    "event-3",
                    Role::Engineer,
                    RunEventPayload::SpecialistOutputRecorded {
                        output: output.clone(),
                    },
                ),
                &goal,
            )
            .expect("valid Engineer output should persist");
        assert_eq!(after_output.specialist_outputs, vec![output.clone()]);

        let response = CoordinatorFinalResponse {
            contract_version: ContractVersion::current(),
            response: "bounded P1 result".to_owned(),
            evidence_refs: Vec::new(),
        };
        let finalized = runtime
            .append_event(
                appended_event(
                    "event-5",
                    5,
                    "event-4",
                    Role::Coordinator,
                    RunEventPayload::CoordinatorFinalResponseRecorded {
                        response: response.clone(),
                    },
                ),
                &goal,
            )
            .expect("valid Coordinator response should persist");

        assert_eq!(finalized.run_record.event_count, 6);
        assert_eq!(finalized.specialist_outputs, vec![output]);
        assert_eq!(finalized.coordinator_final_response, Some(response));
        let reopened = DurableGoalRuntime::new(dir.path());
        assert_eq!(
            reopened.load_run(&RunId::from("run-1"), &goal).unwrap(),
            finalized
        );
    }

    #[test]
    fn completion_append_reconciliation_rejects_disabled_policy_without_mutation() {
        let dir = TempDir::new().unwrap();
        let goal = goal();
        let runtime = DurableGoalRuntime::new(dir.path());
        runtime
            .create_run(
                RunId::from("run-1"),
                &goal,
                &[task("task-a", &[])],
                stamps(),
            )
            .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            4,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        )
        .unwrap();
        let evidence = EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from("evidence-v5"),
            kind: EvidenceKind::TestResult,
            reference: "evidence/v5".to_owned(),
            producer_role: Role::Coordinator,
            integrity: None,
            produced_at: timestamp(5),
        };
        append_runtime_event(
            &runtime,
            &goal,
            5,
            Role::Coordinator,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: evidence.clone(),
            },
        )
        .unwrap();
        append_runtime_event(
            &runtime,
            &goal,
            6,
            Role::Coordinator,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: CompletionEvidence {
                    contract_version: ContractVersion::current(),
                    evidence_refs: vec![evidence.id],
                    satisfied_acceptance_criteria: vec![],
                    satisfied_verification_criteria: vec![],
                    satisfied_definition_of_done: vec![],
                },
            },
        )
        .unwrap();
        let completion = appended_event(
            "event-7",
            7,
            "event-6",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );
        let before = fs::read(runtime.log_path()).unwrap();
        assert!(matches!(
            runtime.reconcile_verified_completion_append(&completion, &goal),
            Err(DurableGoalRuntimeError::VerifiedCompletionNotRequired { .. })
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);

        let mut altered_goal = goal.clone();
        altered_goal.objective = "same identity, different authority".to_owned();
        assert!(matches!(
            runtime.reconcile_verified_completion_append(&completion, &altered_goal),
            Err(DurableGoalRuntimeError::VerifiedCompletionNotRequired { .. })
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
    }
}
