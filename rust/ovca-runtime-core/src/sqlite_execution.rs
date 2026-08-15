//! Durable execution lifecycle authority backed by the versioned state store.

use crate::execution_lifecycle::{
    CancellationRequest, ClaimRequest, CompletionRequest, ExecutionLifecycleError,
    ExecutionLifecycleKernel, ExecutionLifecycleRestoreError, ExecutionLifecycleSnapshot,
    FailureRequest, HeartbeatRequest,
};
use ovca_storage::{
    CompareAndSwapOutcome, InitializeOutcome, VersionedState, VersionedStateError,
    VersionedStateStore,
};
use ovca_types::{
    ContractVersion, RetryBudget, RunId, Task, TaskId, TaskLease, TaskStatus, TaskTerminalRecord,
    GOAL_RUNTIME_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

pub const DEFAULT_EXECUTION_CAS_RETRY_LIMIT: usize = 16;
const EXECUTION_ENTITY_PREFIX: &str = "execution_run:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRunEnvelope {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub tasks: BTreeMap<TaskId, Task>,
    pub retry_budget: RetryBudget,
    pub snapshot: ExecutionLifecycleSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedExecutionRun {
    pub envelope: ExecutionRunEnvelope,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeRunResult {
    pub state: LoadedExecutionRun,
    pub initialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCommandResult<T> {
    pub output: T,
    pub snapshot: ExecutionLifecycleSnapshot,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStateCorruption {
    UnsupportedEnvelopeVersion {
        expected: ContractVersion,
        actual: ContractVersion,
    },
    EnvelopeRunMismatch {
        expected: RunId,
        actual: RunId,
    },
    Lifecycle(ExecutionLifecycleRestoreError),
}

impl fmt::Display for ExecutionStateCorruption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ExecutionStateCorruption {}

#[derive(Debug)]
pub enum DurableExecutionError {
    RunNotFound {
        run_id: RunId,
    },
    DefinitionConflict {
        run_id: RunId,
        existing_revision: u64,
    },
    Lifecycle(ExecutionLifecycleError),
    Storage(VersionedStateError),
    Serialization(serde_json::Error),
    CorruptState {
        run_id: RunId,
        source: ExecutionStateCorruption,
    },
    ContentionExhausted {
        run_id: RunId,
        retry_limit: usize,
        current_revision: u64,
    },
}

impl fmt::Display for DurableExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound { run_id } => write!(formatter, "execution run {run_id} not found"),
            Self::DefinitionConflict {
                run_id,
                existing_revision,
            } => write!(
                formatter,
                "execution run {run_id} already has a different definition at revision {existing_revision}"
            ),
            Self::Lifecycle(source) => write!(formatter, "lifecycle command rejected: {source}"),
            Self::Storage(source) => write!(formatter, "execution storage failed: {source}"),
            Self::Serialization(source) => {
                write!(formatter, "execution envelope serialization failed: {source}")
            }
            Self::CorruptState { run_id, source } => {
                write!(formatter, "execution run {run_id} contains corrupt state: {source}")
            }
            Self::ContentionExhausted {
                run_id,
                retry_limit,
                current_revision,
            } => write!(
                formatter,
                "execution run {run_id} exceeded {retry_limit} CAS retries at revision {current_revision}"
            ),
        }
    }
}

impl std::error::Error for DurableExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(source) => Some(source),
            Self::Storage(source) => Some(source),
            Self::Serialization(source) => Some(source),
            Self::CorruptState { source, .. } => Some(source),
            Self::RunNotFound { .. }
            | Self::DefinitionConflict { .. }
            | Self::ContentionExhausted { .. } => None,
        }
    }
}

impl From<VersionedStateError> for DurableExecutionError {
    fn from(source: VersionedStateError) -> Self {
        Self::Storage(source)
    }
}

impl From<serde_json::Error> for DurableExecutionError {
    fn from(source: serde_json::Error) -> Self {
        Self::Serialization(source)
    }
}

#[derive(Clone, Debug)]
pub struct DurableExecutionAuthority {
    store: VersionedStateStore,
    cas_retry_limit: usize,
}

impl DurableExecutionAuthority {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            store: VersionedStateStore::new(root),
            cas_retry_limit: DEFAULT_EXECUTION_CAS_RETRY_LIMIT,
        }
    }

    pub fn with_retry_limit(root: impl Into<PathBuf>, cas_retry_limit: usize) -> Self {
        Self {
            store: VersionedStateStore::new(root),
            cas_retry_limit,
        }
    }

    pub fn database_path(&self) -> PathBuf {
        self.store.database_path()
    }

    pub fn initialize_run(
        &self,
        run_id: RunId,
        tasks: Vec<Task>,
        retry_budget: RetryBudget,
    ) -> Result<InitializeRunResult, DurableExecutionError> {
        let kernel = ExecutionLifecycleKernel::new(run_id.clone(), tasks.clone(), retry_budget)
            .map_err(DurableExecutionError::Lifecycle)?;
        let envelope = ExecutionRunEnvelope {
            contract_version: GOAL_RUNTIME_CONTRACT_VERSION,
            run_id: run_id.clone(),
            tasks: tasks
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
            retry_budget,
            snapshot: kernel.snapshot(),
        };
        restore_kernel(&run_id, &envelope)?;
        let payload = serde_json::to_vec(&envelope)?;
        let outcome = self.store.initialize(&entity_key(&run_id), payload)?;
        let (state, initialized) = match outcome {
            InitializeOutcome::Initialized(state) => (state, true),
            InitializeOutcome::Existing(state) => (state, false),
        };
        let loaded = decode_and_restore(&run_id, state)?;
        if !same_definition(&loaded.envelope, &envelope) {
            return Err(DurableExecutionError::DefinitionConflict {
                run_id,
                existing_revision: loaded.revision,
            });
        }
        Ok(InitializeRunResult {
            state: loaded,
            initialized,
        })
    }

    pub fn load(&self, run_id: &RunId) -> Result<LoadedExecutionRun, DurableExecutionError> {
        let state = self.store.load(&entity_key(run_id))?.ok_or_else(|| {
            DurableExecutionError::RunNotFound {
                run_id: run_id.clone(),
            }
        })?;
        decode_and_restore(run_id, state)
    }

    pub fn claim(
        &self,
        run_id: &RunId,
        request: ClaimRequest,
    ) -> Result<DurableCommandResult<TaskLease>, DurableExecutionError> {
        self.apply(run_id, request, ExecutionLifecycleKernel::claim)
    }

    pub fn heartbeat(
        &self,
        run_id: &RunId,
        request: HeartbeatRequest,
    ) -> Result<DurableCommandResult<TaskLease>, DurableExecutionError> {
        self.apply(run_id, request, ExecutionLifecycleKernel::heartbeat)
    }

    pub fn fail(
        &self,
        run_id: &RunId,
        request: FailureRequest,
    ) -> Result<DurableCommandResult<TaskStatus>, DurableExecutionError> {
        self.apply(run_id, request, ExecutionLifecycleKernel::fail)
    }

    pub fn complete(
        &self,
        run_id: &RunId,
        request: CompletionRequest,
    ) -> Result<DurableCommandResult<TaskTerminalRecord>, DurableExecutionError> {
        self.apply(run_id, request, ExecutionLifecycleKernel::complete)
    }

    pub fn cancel(
        &self,
        run_id: &RunId,
        request: CancellationRequest,
    ) -> Result<DurableCommandResult<TaskTerminalRecord>, DurableExecutionError> {
        self.apply(run_id, request, ExecutionLifecycleKernel::cancel)
    }

    fn apply<Request, Output>(
        &self,
        run_id: &RunId,
        request: Request,
        operation: fn(
            &mut ExecutionLifecycleKernel,
            Request,
        ) -> Result<Output, ExecutionLifecycleError>,
    ) -> Result<DurableCommandResult<Output>, DurableExecutionError>
    where
        Request: Clone,
    {
        let mut current = self.store.load(&entity_key(run_id))?.ok_or_else(|| {
            DurableExecutionError::RunNotFound {
                run_id: run_id.clone(),
            }
        })?;
        let mut conflicts = 0;
        loop {
            let loaded = decode_and_restore(run_id, current)?;
            let mut kernel = restore_kernel(run_id, &loaded.envelope)?;
            let before = kernel.snapshot();
            let output = operation(&mut kernel, request.clone())
                .map_err(DurableExecutionError::Lifecycle)?;
            let snapshot = kernel.snapshot();
            if snapshot == before {
                return Ok(DurableCommandResult {
                    output,
                    snapshot,
                    revision: loaded.revision,
                });
            }

            let mut next_envelope = loaded.envelope;
            next_envelope.snapshot = snapshot.clone();
            restore_kernel(run_id, &next_envelope)?;
            let payload = serde_json::to_vec(&next_envelope)?;
            match self
                .store
                .compare_and_swap(&entity_key(run_id), loaded.revision, payload)?
            {
                CompareAndSwapOutcome::Applied(state) => {
                    return Ok(DurableCommandResult {
                        output,
                        snapshot,
                        revision: state.revision,
                    });
                }
                CompareAndSwapOutcome::Conflict(state) => {
                    if conflicts >= self.cas_retry_limit {
                        return Err(DurableExecutionError::ContentionExhausted {
                            run_id: run_id.clone(),
                            retry_limit: self.cas_retry_limit,
                            current_revision: state.revision,
                        });
                    }
                    conflicts += 1;
                    current = state;
                }
            }
        }
    }
}

fn entity_key(run_id: &RunId) -> String {
    format!("{EXECUTION_ENTITY_PREFIX}{}", run_id.as_str())
}

fn same_definition(left: &ExecutionRunEnvelope, right: &ExecutionRunEnvelope) -> bool {
    left.contract_version == right.contract_version
        && left.run_id == right.run_id
        && left.tasks == right.tasks
        && left.retry_budget == right.retry_budget
}

fn decode_and_restore(
    expected_run_id: &RunId,
    state: VersionedState,
) -> Result<LoadedExecutionRun, DurableExecutionError> {
    let envelope: ExecutionRunEnvelope = serde_json::from_slice(&state.payload)?;
    restore_kernel(expected_run_id, &envelope)?;
    Ok(LoadedExecutionRun {
        envelope,
        revision: state.revision,
    })
}

fn restore_kernel(
    expected_run_id: &RunId,
    envelope: &ExecutionRunEnvelope,
) -> Result<ExecutionLifecycleKernel, DurableExecutionError> {
    if envelope.contract_version != GOAL_RUNTIME_CONTRACT_VERSION {
        return Err(corrupt(
            expected_run_id,
            ExecutionStateCorruption::UnsupportedEnvelopeVersion {
                expected: GOAL_RUNTIME_CONTRACT_VERSION,
                actual: envelope.contract_version,
            },
        ));
    }
    if envelope.run_id != *expected_run_id {
        return Err(corrupt(
            expected_run_id,
            ExecutionStateCorruption::EnvelopeRunMismatch {
                expected: expected_run_id.clone(),
                actual: envelope.run_id.clone(),
            },
        ));
    }
    ExecutionLifecycleKernel::restore(
        envelope.run_id.clone(),
        envelope.tasks.values().cloned().collect(),
        envelope.retry_budget,
        envelope.snapshot.clone(),
    )
    .map_err(|source| corrupt(expected_run_id, ExecutionStateCorruption::Lifecycle(source)))
}

fn corrupt(run_id: &RunId, source: ExecutionStateCorruption) -> DurableExecutionError {
    DurableExecutionError::CorruptState {
        run_id: run_id.clone(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use ovca_types::{GoalId, IdempotencyKey, LeaseId, Role, TaskStatus, WorkerId};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 18, 0, 0, second).unwrap()
    }

    fn task(id: &str, write_keys: &[&str]) -> Task {
        Task {
            contract_version: ContractVersion::current(),
            id: TaskId::from(id),
            goal_id: GoalId::from("goal-1"),
            outcome: format!("finish {id}"),
            dependencies: vec![],
            assigned_role: Role::Engineer,
            resource_keys: vec![],
            write_keys: write_keys.iter().map(|key| (*key).to_owned()).collect(),
            status: TaskStatus::Ready,
            created_at: at(0),
            updated_at: at(0),
        }
    }

    fn budget(max_attempts: u32) -> RetryBudget {
        RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts,
        }
    }

    fn run_id() -> RunId {
        RunId::from("run-1")
    }

    fn claim_for(
        task_id: &str,
        worker_id: &str,
        lease_id: &str,
        now: u32,
        expires_at: u32,
    ) -> ClaimRequest {
        ClaimRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from(worker_id),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            now: at(now),
            expires_at: at(expires_at),
        }
    }

    fn heartbeat_for(expires_at: u32) -> HeartbeatRequest {
        HeartbeatRequest {
            task_id: TaskId::from("a"),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from("lease-1"),
            now: at(2),
            expires_at: at(expires_at),
        }
    }

    fn failure_for(task_id: &str, lease_id: &str, now: u32) -> FailureRequest {
        FailureRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            now: at(now),
            reason: "failed attempt".to_owned(),
        }
    }

    fn completion_for(key: &str, occurred_at: u32) -> CompletionRequest {
        CompletionRequest {
            task_id: TaskId::from("a"),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from("lease-1"),
            idempotency_key: IdempotencyKey::from(key),
            occurred_at: at(occurred_at),
        }
    }

    fn cancellation_for(key: &str, occurred_at: u32) -> CancellationRequest {
        CancellationRequest {
            task_id: TaskId::from("a"),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from("lease-1"),
            idempotency_key: IdempotencyKey::from(key),
            occurred_at: at(occurred_at),
            reason: Some("owner cancelled".to_owned()),
        }
    }

    fn initialized(temp: &TempDir, max_attempts: u32) -> DurableExecutionAuthority {
        let authority = DurableExecutionAuthority::new(temp.path());
        authority
            .initialize_run(run_id(), vec![task("a", &["shared"])], budget(max_attempts))
            .unwrap();
        authority
    }

    #[test]
    fn constructor_is_side_effect_free_and_initialize_reopens_revision_zero() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("missing");
        let authority = DurableExecutionAuthority::new(&root);
        assert!(!root.exists());

        let initialized = authority
            .initialize_run(run_id(), vec![task("a", &[])], budget(2))
            .unwrap();
        assert!(initialized.initialized);
        assert_eq!(initialized.state.revision, 0);
        let expected = initialized.state.envelope.snapshot.clone();

        let reopened = DurableExecutionAuthority::new(&root)
            .load(&run_id())
            .unwrap();
        assert_eq!(reopened.revision, 0);
        assert_eq!(reopened.envelope.snapshot, expected);
    }

    #[test]
    fn shuffled_initialize_is_idempotent_and_changed_definition_does_not_mutate() {
        let temp = TempDir::new().unwrap();
        let authority = DurableExecutionAuthority::new(temp.path());
        let a = task("a", &[]);
        let b = task("b", &[]);
        authority
            .initialize_run(run_id(), vec![a.clone(), b.clone()], budget(2))
            .unwrap();

        let equivalent = authority
            .initialize_run(run_id(), vec![b, a], budget(2))
            .unwrap();
        assert!(!equivalent.initialized);
        assert_eq!(equivalent.state.revision, 0);
        let before = authority.load(&run_id()).unwrap();

        assert!(matches!(
            authority.initialize_run(run_id(), vec![task("a", &[])], budget(2)),
            Err(DurableExecutionError::DefinitionConflict { .. })
        ));
        assert!(matches!(
            authority.initialize_run(run_id(), vec![task("a", &[]), task("b", &[])], budget(3),),
            Err(DurableExecutionError::DefinitionConflict { .. })
        ));
        assert_eq!(authority.load(&run_id()).unwrap(), before);
    }

    #[test]
    fn corrupt_snapshot_is_rejected_before_commands() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 2);
        let loaded = authority.load(&run_id()).unwrap();
        let mut corrupt_envelope = loaded.envelope;
        corrupt_envelope
            .snapshot
            .tasks
            .get_mut(&TaskId::from("a"))
            .unwrap()
            .attempts = 3;
        let raw = VersionedStateStore::new(temp.path());
        raw.compare_and_swap(
            &entity_key(&run_id()),
            loaded.revision,
            serde_json::to_vec(&corrupt_envelope).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            authority.load(&run_id()),
            Err(DurableExecutionError::CorruptState {
                source: ExecutionStateCorruption::Lifecycle(
                    ExecutionLifecycleRestoreError::AttemptsExceedBudget { .. }
                ),
                ..
            })
        ));
        assert!(matches!(
            authority.claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10)),
            Err(DurableExecutionError::CorruptState { .. })
        ));
    }

    #[test]
    fn unreachable_status_attempt_corruption_preserves_stored_payload_and_revision() {
        let cases = [
            (TaskStatus::Pending, 1),
            (TaskStatus::Ready, 2),
            (TaskStatus::Running, 0),
            (TaskStatus::Completed, 0),
            (TaskStatus::Cancelled, 0),
            (TaskStatus::Failed, 1),
        ];

        for (status, attempts) in cases {
            let temp = TempDir::new().unwrap();
            let authority = initialized(&temp, 2);
            let loaded = authority.load(&run_id()).unwrap();
            let mut corrupt_envelope = loaded.envelope;
            let state = corrupt_envelope
                .snapshot
                .tasks
                .get_mut(&TaskId::from("a"))
                .unwrap();
            state.status = status;
            state.attempts = attempts;

            let raw = VersionedStateStore::new(temp.path());
            raw.compare_and_swap(
                &entity_key(&run_id()),
                loaded.revision,
                serde_json::to_vec(&corrupt_envelope).unwrap(),
            )
            .unwrap();
            let before_rejection = raw.load(&entity_key(&run_id())).unwrap().unwrap();

            assert!(matches!(
                authority.load(&run_id()),
                Err(DurableExecutionError::CorruptState {
                    source: ExecutionStateCorruption::Lifecycle(
                        ExecutionLifecycleRestoreError::InvalidStatusAttempts {
                            status: actual_status,
                            attempts: actual_attempts,
                            ..
                        }
                    ),
                    ..
                }) if actual_status == status && actual_attempts == attempts
            ));
            assert!(matches!(
                authority.claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10)),
                Err(DurableExecutionError::CorruptState { .. })
            ));
            assert_eq!(
                raw.load(&entity_key(&run_id())).unwrap().unwrap(),
                before_rejection
            );
        }
    }

    #[test]
    fn heartbeat_persists_across_reopen() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 2);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();
        let heartbeat = authority.heartbeat(&run_id(), heartbeat_for(20)).unwrap();
        assert_eq!(heartbeat.revision, 2);

        let reopened = DurableExecutionAuthority::new(temp.path())
            .load(&run_id())
            .unwrap();
        let lease = reopened.envelope.snapshot.tasks[&TaskId::from("a")]
            .current_lease
            .as_ref()
            .unwrap();
        assert_eq!(lease.heartbeat_at, at(2));
        assert_eq!(lease.expires_at, at(20));
        assert_eq!(
            reopened.envelope.snapshot.write_key_owners["shared"].expires_at,
            at(20)
        );
    }

    #[test]
    fn expiry_equality_reclaim_increments_attempt() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 2);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();

        let reclaimed = authority
            .claim(&run_id(), claim_for("a", "worker-2", "lease-2", 10, 20))
            .unwrap();
        assert_eq!(reclaimed.output.attempt, 2);
        assert_eq!(reclaimed.revision, 2);
        assert_eq!(
            reclaimed.snapshot.write_key_owners["shared"].worker_id,
            WorkerId::from("worker-2")
        );
    }

    #[test]
    fn failure_retry_releases_owner_and_terminal_failure_persists() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 2);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();
        let first = authority
            .fail(&run_id(), failure_for("a", "lease-1", 2))
            .unwrap();
        assert_eq!(first.output, TaskStatus::Ready);
        assert!(first.snapshot.write_key_owners.is_empty());

        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-2", 3, 10))
            .unwrap();
        let failed = authority
            .fail(&run_id(), failure_for("a", "lease-2", 4))
            .unwrap();
        assert_eq!(failed.output, TaskStatus::Failed);
        assert!(failed.snapshot.write_key_owners.is_empty());
        assert_eq!(
            DurableExecutionAuthority::new(temp.path())
                .load(&run_id())
                .unwrap()
                .envelope
                .snapshot
                .tasks[&TaskId::from("a")]
                .status,
            TaskStatus::Failed
        );
    }

    #[test]
    fn duplicate_completion_after_reopen_returns_original_without_revision_change() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 1);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();
        let completed = authority
            .complete(&run_id(), completion_for("complete-a", 2))
            .unwrap();
        assert_eq!(completed.revision, 2);

        let duplicate = DurableExecutionAuthority::new(temp.path())
            .complete(&run_id(), completion_for("complete-a", 3))
            .unwrap();
        assert_eq!(duplicate.output, completed.output);
        assert_eq!(duplicate.snapshot, completed.snapshot);
        assert_eq!(duplicate.revision, completed.revision);
    }

    #[test]
    fn cancellation_persists_and_terminal_outcome_is_first_writer() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 1);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();
        let cancelled = authority
            .cancel(&run_id(), cancellation_for("terminal", 2))
            .unwrap();
        assert_eq!(
            cancelled.snapshot.tasks[&TaskId::from("a")].status,
            TaskStatus::Cancelled
        );
        assert!(matches!(
            DurableExecutionAuthority::new(temp.path())
                .complete(&run_id(), completion_for("terminal", 3)),
            Err(DurableExecutionError::Lifecycle(
                ExecutionLifecycleError::IdempotencyKeyConflict { .. }
            ))
        ));
        assert_eq!(
            authority.load(&run_id()).unwrap().revision,
            cancelled.revision
        );
    }

    #[test]
    fn independent_authorities_claiming_same_task_have_one_winner() {
        let temp = TempDir::new().unwrap();
        initialized(&temp, 2);
        let root = temp.path().to_owned();
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [("worker-1", "lease-1"), ("worker-2", "lease-2")]
            .into_iter()
            .map(|(worker, lease)| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let authority = DurableExecutionAuthority::new(root);
                    barrier.wait();
                    authority.claim(&run_id(), claim_for("a", worker, lease, 1, 10))
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(DurableExecutionError::Lifecycle(
                        ExecutionLifecycleError::ActiveTaskLease { .. }
                    ))
                ))
                .count(),
            1
        );
    }

    #[test]
    fn independent_authorities_with_shared_write_key_have_one_winner() {
        let temp = TempDir::new().unwrap();
        let authority = DurableExecutionAuthority::new(temp.path());
        authority
            .initialize_run(
                run_id(),
                vec![task("a", &["shared"]), task("b", &["shared"])],
                budget(1),
            )
            .unwrap();
        let root = temp.path().to_owned();
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [("a", "worker-1", "lease-1"), ("b", "worker-2", "lease-2")]
            .into_iter()
            .map(|(task_id, worker, lease)| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let authority = DurableExecutionAuthority::new(root);
                    barrier.wait();
                    authority.claim(&run_id(), claim_for(task_id, worker, lease, 1, 10))
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(DurableExecutionError::Lifecycle(
                        ExecutionLifecycleError::WriteKeyConflict { .. }
                    ))
                ))
                .count(),
            1
        );
    }

    #[test]
    fn rejected_command_preserves_snapshot_and_revision_and_missing_run_is_explicit() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 1);
        let before = authority.load(&run_id()).unwrap();
        assert!(matches!(
            authority.heartbeat(&run_id(), heartbeat_for(20)),
            Err(DurableExecutionError::Lifecycle(
                ExecutionLifecycleError::NoCurrentLease { .. }
            ))
        ));
        assert_eq!(authority.load(&run_id()).unwrap(), before);
        assert!(matches!(
            authority.load(&RunId::from("missing")),
            Err(DurableExecutionError::RunNotFound { .. })
        ));
    }

    #[test]
    fn command_cannot_persist_a_snapshot_that_fails_strict_restore() {
        let temp = TempDir::new().unwrap();
        let authority = initialized(&temp, 1);
        authority
            .claim(&run_id(), claim_for("a", "worker-1", "lease-1", 1, 10))
            .unwrap();
        let before = authority.load(&run_id()).unwrap();
        let mut invalid = heartbeat_for(20);
        invalid.now = at(0);

        assert!(matches!(
            authority.heartbeat(&run_id(), invalid),
            Err(DurableExecutionError::CorruptState {
                source: ExecutionStateCorruption::Lifecycle(
                    ExecutionLifecycleRestoreError::InvalidLeaseTimestamps { .. }
                ),
                ..
            })
        ));
        assert_eq!(authority.load(&run_id()).unwrap(), before);
    }

    #[test]
    fn source_contains_no_process_global_mutex() {
        let source = include_str!("sqlite_execution.rs");
        for forbidden in [
            ["static ", "Mutex"].concat(),
            ["OnceLock<", "Mutex"].concat(),
            ["rusq", "lite"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }
}
