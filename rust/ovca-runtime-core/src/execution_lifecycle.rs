//! Pure task execution lease lifecycle and write ownership.

use chrono::{DateTime, Utc};
use ovca_types::{
    ContractVersion, GoalId, IdempotencyKey, LeaseId, RetryBudget, Role, RunId, Task, TaskId,
    TaskLease, TaskStatus, TaskTerminalOutcome, TaskTerminalRecord, WorkerId,
    GOAL_RUNTIME_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskExecutionSnapshot {
    pub status: TaskStatus,
    pub attempts: u32,
    pub current_lease: Option<TaskLease>,
    pub terminal_record: Option<TaskTerminalRecord>,
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteKeyOwner {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub lease_id: LeaseId,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLifecycleSnapshot {
    pub run_id: RunId,
    pub goal_id: Option<GoalId>,
    pub max_attempts: u32,
    pub tasks: BTreeMap<TaskId, TaskExecutionSnapshot>,
    pub write_key_owners: BTreeMap<String, WriteKeyOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRequest {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRequest {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    pub now: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionRequest {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    pub idempotency_key: IdempotencyKey,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationRequest {
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    pub idempotency_key: IdempotencyKey,
    pub occurred_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ExecutionLifecycleError {
    UnsupportedContractVersion {
        contract: String,
        expected: ContractVersion,
        actual: ContractVersion,
    },
    InvalidMaxAttempts,
    DuplicateTaskId {
        task_id: TaskId,
    },
    GoalMismatch {
        task_id: TaskId,
        expected_goal_id: GoalId,
        actual_goal_id: GoalId,
    },
    UnknownDependency {
        task_id: TaskId,
        dependency_id: TaskId,
    },
    InvalidAssignedRole {
        task_id: TaskId,
        role: Role,
    },
    InvalidInitialTaskStatus {
        task_id: TaskId,
        status: TaskStatus,
    },
    UnknownTask {
        task_id: TaskId,
    },
    DependencyIncomplete {
        task_id: TaskId,
        dependency_id: TaskId,
        status: TaskStatus,
    },
    CoordinatorRejected {
        task_id: TaskId,
    },
    RoleMismatch {
        task_id: TaskId,
        expected: Role,
        actual: Role,
    },
    TaskNotClaimable {
        task_id: TaskId,
        status: TaskStatus,
    },
    InvalidLeaseExpiry {
        task_id: TaskId,
    },
    ActiveTaskLease {
        task_id: TaskId,
        lease_id: LeaseId,
    },
    WriteKeyConflict {
        write_key: String,
        owner_task_id: TaskId,
    },
    RetryExhausted {
        task_id: TaskId,
        max_attempts: u32,
    },
    NoCurrentLease {
        task_id: TaskId,
    },
    WorkerMismatch {
        task_id: TaskId,
    },
    LeaseMismatch {
        task_id: TaskId,
    },
    StaleHeartbeat {
        task_id: TaskId,
    },
    LeaseExpired {
        task_id: TaskId,
    },
    NonExtendingHeartbeat {
        task_id: TaskId,
    },
    TerminalRetryIdentityMismatch {
        task_id: TaskId,
    },
    IdempotencyKeyConflict {
        task_id: TaskId,
        existing: IdempotencyKey,
        requested: IdempotencyKey,
    },
}

impl fmt::Display for ExecutionLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ExecutionLifecycleError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ExecutionLifecycleRestoreError {
    InvalidDefinition {
        source: ExecutionLifecycleError,
    },
    RunIdMismatch {
        expected: RunId,
        actual: RunId,
    },
    GoalIdMismatch {
        expected: Option<GoalId>,
        actual: Option<GoalId>,
    },
    MaxAttemptsMismatch {
        expected: u32,
        actual: u32,
    },
    TaskSetMismatch {
        expected: BTreeSet<TaskId>,
        actual: BTreeSet<TaskId>,
    },
    AttemptsExceedBudget {
        task_id: TaskId,
        attempts: u32,
        max_attempts: u32,
    },
    InvalidStatusAttempts {
        task_id: TaskId,
        status: TaskStatus,
        attempts: u32,
        max_attempts: u32,
    },
    UnsupportedTaskStatus {
        task_id: TaskId,
        status: TaskStatus,
    },
    LastFailureWithoutAttempt {
        task_id: TaskId,
    },
    RunningLeaseMismatch {
        task_id: TaskId,
        status: TaskStatus,
        has_current_lease: bool,
    },
    TerminalRecordMismatch {
        task_id: TaskId,
        status: TaskStatus,
        outcome: Option<TaskTerminalOutcome>,
    },
    InvalidLeaseContract {
        task_id: TaskId,
        actual: ContractVersion,
    },
    LeaseRunMismatch {
        task_id: TaskId,
        actual: RunId,
    },
    LeaseTaskMismatch {
        task_id: TaskId,
        actual: TaskId,
    },
    LeaseRoleMismatch {
        task_id: TaskId,
        expected: Role,
        actual: Role,
    },
    LeaseWriteKeysMismatch {
        task_id: TaskId,
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
    LeaseAttemptMismatch {
        task_id: TaskId,
        expected: u32,
        actual: u32,
    },
    LeaseMaxAttemptsMismatch {
        task_id: TaskId,
        expected: u32,
        actual: u32,
    },
    InvalidLeaseTimestamps {
        task_id: TaskId,
    },
    InvalidTerminalContract {
        task_id: TaskId,
        actual: ContractVersion,
    },
    TerminalRunMismatch {
        task_id: TaskId,
        actual: RunId,
    },
    TerminalTaskMismatch {
        task_id: TaskId,
        actual: TaskId,
    },
    TerminalWithoutAttempt {
        task_id: TaskId,
    },
    DuplicateWriteKeyOwner {
        write_key: String,
        first_task_id: TaskId,
        second_task_id: TaskId,
    },
    WriteKeyOwnersMismatch {
        expected: BTreeMap<String, WriteKeyOwner>,
        actual: BTreeMap<String, WriteKeyOwner>,
    },
}

impl fmt::Display for ExecutionLifecycleRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ExecutionLifecycleRestoreError {}

#[derive(Debug, Clone)]
pub struct ExecutionLifecycleKernel {
    run_id: RunId,
    goal_id: Option<GoalId>,
    retry_budget: RetryBudget,
    tasks: BTreeMap<TaskId, Task>,
    state: BTreeMap<TaskId, TaskExecutionSnapshot>,
    write_key_owners: BTreeMap<String, WriteKeyOwner>,
}

impl ExecutionLifecycleKernel {
    pub fn new(
        run_id: RunId,
        tasks: Vec<Task>,
        retry_budget: RetryBudget,
    ) -> Result<Self, ExecutionLifecycleError> {
        validate_version("retry_budget", retry_budget.contract_version)?;
        if retry_budget.max_attempts == 0 {
            return Err(ExecutionLifecycleError::InvalidMaxAttempts);
        }

        let mut task_counts = BTreeMap::<TaskId, usize>::new();
        for task in &tasks {
            *task_counts.entry(task.id.clone()).or_default() += 1;
        }
        if let Some(task_id) = task_counts
            .iter()
            .find_map(|(task_id, count)| (*count > 1).then(|| task_id.clone()))
        {
            return Err(ExecutionLifecycleError::DuplicateTaskId { task_id });
        }

        let task_map = tasks
            .into_iter()
            .map(|task| (task.id.clone(), task))
            .collect::<BTreeMap<_, _>>();
        for (task_id, task) in &task_map {
            validate_version(&format!("task:{task_id}"), task.contract_version)?;
            if !matches!(
                task.assigned_role,
                Role::Engineer | Role::Reviewer | Role::Auditor
            ) {
                return Err(ExecutionLifecycleError::InvalidAssignedRole {
                    task_id: task.id.clone(),
                    role: task.assigned_role,
                });
            }
            if !matches!(task.status, TaskStatus::Pending | TaskStatus::Ready) {
                return Err(ExecutionLifecycleError::InvalidInitialTaskStatus {
                    task_id: task.id.clone(),
                    status: task.status,
                });
            }
        }

        let goal_id = task_map
            .first_key_value()
            .map(|(_, task)| task.goal_id.clone());
        if let Some(expected_goal_id) = &goal_id {
            if let Some((task_id, task)) = task_map
                .iter()
                .find(|(_, task)| task.goal_id != *expected_goal_id)
            {
                return Err(ExecutionLifecycleError::GoalMismatch {
                    task_id: task_id.clone(),
                    expected_goal_id: expected_goal_id.clone(),
                    actual_goal_id: task.goal_id.clone(),
                });
            }
        }

        for task in task_map.values() {
            for dependency_id in task.dependencies.iter().collect::<BTreeSet<_>>() {
                if !task_map.contains_key(dependency_id) {
                    return Err(ExecutionLifecycleError::UnknownDependency {
                        task_id: task.id.clone(),
                        dependency_id: dependency_id.clone(),
                    });
                }
            }
        }
        let state = task_map
            .iter()
            .map(|(id, task)| {
                (
                    id.clone(),
                    TaskExecutionSnapshot {
                        status: task.status,
                        attempts: 0,
                        current_lease: None,
                        terminal_record: None,
                        last_failure_reason: None,
                    },
                )
            })
            .collect();
        Ok(Self {
            run_id,
            goal_id,
            retry_budget,
            tasks: task_map,
            state,
            write_key_owners: BTreeMap::new(),
        })
    }

    pub fn restore(
        run_id: RunId,
        tasks: Vec<Task>,
        retry_budget: RetryBudget,
        snapshot: ExecutionLifecycleSnapshot,
    ) -> Result<Self, ExecutionLifecycleRestoreError> {
        let mut kernel = Self::new(run_id.clone(), tasks, retry_budget)
            .map_err(|source| ExecutionLifecycleRestoreError::InvalidDefinition { source })?;
        if snapshot.run_id != run_id {
            return Err(ExecutionLifecycleRestoreError::RunIdMismatch {
                expected: run_id,
                actual: snapshot.run_id,
            });
        }
        if snapshot.goal_id != kernel.goal_id {
            return Err(ExecutionLifecycleRestoreError::GoalIdMismatch {
                expected: kernel.goal_id.clone(),
                actual: snapshot.goal_id,
            });
        }
        if snapshot.max_attempts != retry_budget.max_attempts {
            return Err(ExecutionLifecycleRestoreError::MaxAttemptsMismatch {
                expected: retry_budget.max_attempts,
                actual: snapshot.max_attempts,
            });
        }
        let expected_tasks = kernel.tasks.keys().cloned().collect::<BTreeSet<_>>();
        let actual_tasks = snapshot.tasks.keys().cloned().collect::<BTreeSet<_>>();
        if actual_tasks != expected_tasks {
            return Err(ExecutionLifecycleRestoreError::TaskSetMismatch {
                expected: expected_tasks,
                actual: actual_tasks,
            });
        }

        let mut expected_owners = BTreeMap::new();
        for (task_id, state) in &snapshot.tasks {
            if state.attempts > retry_budget.max_attempts {
                return Err(ExecutionLifecycleRestoreError::AttemptsExceedBudget {
                    task_id: task_id.clone(),
                    attempts: state.attempts,
                    max_attempts: retry_budget.max_attempts,
                });
            }
            if matches!(
                state.status,
                TaskStatus::AwaitingApproval | TaskStatus::Reviewing
            ) {
                return Err(ExecutionLifecycleRestoreError::UnsupportedTaskStatus {
                    task_id: task_id.clone(),
                    status: state.status,
                });
            }
            let valid_attempts = match state.status {
                TaskStatus::Pending => state.attempts == 0,
                TaskStatus::Ready => state.attempts < retry_budget.max_attempts,
                TaskStatus::Running | TaskStatus::Completed | TaskStatus::Cancelled => {
                    state.attempts >= 1
                }
                TaskStatus::Failed => state.attempts == retry_budget.max_attempts,
                TaskStatus::AwaitingApproval | TaskStatus::Reviewing => unreachable!(),
            };
            if !valid_attempts {
                return Err(ExecutionLifecycleRestoreError::InvalidStatusAttempts {
                    task_id: task_id.clone(),
                    status: state.status,
                    attempts: state.attempts,
                    max_attempts: retry_budget.max_attempts,
                });
            }
            if state.attempts == 0 && state.last_failure_reason.is_some() {
                return Err(ExecutionLifecycleRestoreError::LastFailureWithoutAttempt {
                    task_id: task_id.clone(),
                });
            }
            let has_current_lease = state.current_lease.is_some();
            if (state.status == TaskStatus::Running) != has_current_lease {
                return Err(ExecutionLifecycleRestoreError::RunningLeaseMismatch {
                    task_id: task_id.clone(),
                    status: state.status,
                    has_current_lease,
                });
            }
            let expected_outcome = match state.status {
                TaskStatus::Completed => Some(TaskTerminalOutcome::Completed),
                TaskStatus::Cancelled => Some(TaskTerminalOutcome::Cancelled),
                _ => None,
            };
            let actual_outcome = state.terminal_record.as_ref().map(|record| record.outcome);
            if actual_outcome != expected_outcome {
                return Err(ExecutionLifecycleRestoreError::TerminalRecordMismatch {
                    task_id: task_id.clone(),
                    status: state.status,
                    outcome: actual_outcome,
                });
            }

            let task = &kernel.tasks[task_id];
            if let Some(lease) = &state.current_lease {
                if lease.contract_version != GOAL_RUNTIME_CONTRACT_VERSION {
                    return Err(ExecutionLifecycleRestoreError::InvalidLeaseContract {
                        task_id: task_id.clone(),
                        actual: lease.contract_version,
                    });
                }
                if lease.run_id != kernel.run_id {
                    return Err(ExecutionLifecycleRestoreError::LeaseRunMismatch {
                        task_id: task_id.clone(),
                        actual: lease.run_id.clone(),
                    });
                }
                if lease.task_id != *task_id {
                    return Err(ExecutionLifecycleRestoreError::LeaseTaskMismatch {
                        task_id: task_id.clone(),
                        actual: lease.task_id.clone(),
                    });
                }
                if lease.worker_role != task.assigned_role {
                    return Err(ExecutionLifecycleRestoreError::LeaseRoleMismatch {
                        task_id: task_id.clone(),
                        expected: task.assigned_role,
                        actual: lease.worker_role,
                    });
                }
                let expected_write_keys = task.write_keys.iter().cloned().collect();
                if lease.write_keys != expected_write_keys {
                    return Err(ExecutionLifecycleRestoreError::LeaseWriteKeysMismatch {
                        task_id: task_id.clone(),
                        expected: expected_write_keys,
                        actual: lease.write_keys.clone(),
                    });
                }
                if lease.attempt == 0 || lease.attempt != state.attempts {
                    return Err(ExecutionLifecycleRestoreError::LeaseAttemptMismatch {
                        task_id: task_id.clone(),
                        expected: state.attempts,
                        actual: lease.attempt,
                    });
                }
                if lease.max_attempts != retry_budget.max_attempts {
                    return Err(ExecutionLifecycleRestoreError::LeaseMaxAttemptsMismatch {
                        task_id: task_id.clone(),
                        expected: retry_budget.max_attempts,
                        actual: lease.max_attempts,
                    });
                }
                if lease.claimed_at > lease.heartbeat_at || lease.heartbeat_at >= lease.expires_at {
                    return Err(ExecutionLifecycleRestoreError::InvalidLeaseTimestamps {
                        task_id: task_id.clone(),
                    });
                }
                for write_key in &lease.write_keys {
                    let owner = WriteKeyOwner {
                        task_id: task_id.clone(),
                        worker_id: lease.worker_id.clone(),
                        lease_id: lease.lease_id.clone(),
                        expires_at: lease.expires_at,
                    };
                    if let Some(first) = expected_owners.insert(write_key.clone(), owner) {
                        return Err(ExecutionLifecycleRestoreError::DuplicateWriteKeyOwner {
                            write_key: write_key.clone(),
                            first_task_id: first.task_id,
                            second_task_id: task_id.clone(),
                        });
                    }
                }
            }
            if let Some(record) = &state.terminal_record {
                if state.attempts == 0 {
                    return Err(ExecutionLifecycleRestoreError::TerminalWithoutAttempt {
                        task_id: task_id.clone(),
                    });
                }
                if record.contract_version != GOAL_RUNTIME_CONTRACT_VERSION {
                    return Err(ExecutionLifecycleRestoreError::InvalidTerminalContract {
                        task_id: task_id.clone(),
                        actual: record.contract_version,
                    });
                }
                if record.run_id != kernel.run_id {
                    return Err(ExecutionLifecycleRestoreError::TerminalRunMismatch {
                        task_id: task_id.clone(),
                        actual: record.run_id.clone(),
                    });
                }
                if record.task_id != *task_id {
                    return Err(ExecutionLifecycleRestoreError::TerminalTaskMismatch {
                        task_id: task_id.clone(),
                        actual: record.task_id.clone(),
                    });
                }
            }
        }
        if snapshot.write_key_owners != expected_owners {
            return Err(ExecutionLifecycleRestoreError::WriteKeyOwnersMismatch {
                expected: expected_owners,
                actual: snapshot.write_key_owners,
            });
        }

        kernel.state = snapshot.tasks;
        kernel.write_key_owners = snapshot.write_key_owners;
        Ok(kernel)
    }

    pub fn snapshot(&self) -> ExecutionLifecycleSnapshot {
        ExecutionLifecycleSnapshot {
            run_id: self.run_id.clone(),
            goal_id: self.goal_id.clone(),
            max_attempts: self.retry_budget.max_attempts,
            tasks: self.state.clone(),
            write_key_owners: self.write_key_owners.clone(),
        }
    }

    pub fn task_status(&self, task_id: &TaskId) -> Option<TaskStatus> {
        self.state.get(task_id).map(|state| state.status)
    }

    pub fn attempts(&self, task_id: &TaskId) -> Option<u32> {
        self.state.get(task_id).map(|state| state.attempts)
    }

    pub fn lease(&self, task_id: &TaskId) -> Option<&TaskLease> {
        self.state
            .get(task_id)
            .and_then(|state| state.current_lease.as_ref())
    }

    pub fn active_lease(&self, task_id: &TaskId, now: DateTime<Utc>) -> Option<&TaskLease> {
        self.lease(task_id).filter(|lease| lease.expires_at > now)
    }

    pub fn terminal_record(&self, task_id: &TaskId) -> Option<&TaskTerminalRecord> {
        self.state
            .get(task_id)
            .and_then(|state| state.terminal_record.as_ref())
    }

    pub fn write_key_owners(&self) -> &BTreeMap<String, WriteKeyOwner> {
        &self.write_key_owners
    }

    pub fn active_write_key_owners(&self, now: DateTime<Utc>) -> BTreeMap<String, WriteKeyOwner> {
        self.write_key_owners
            .iter()
            .filter(|(_, owner)| owner.expires_at > now)
            .map(|(write_key, owner)| (write_key.clone(), owner.clone()))
            .collect()
    }

    pub fn claim(&mut self, request: ClaimRequest) -> Result<TaskLease, ExecutionLifecycleError> {
        let mut next = self.clone();
        let lease = next.apply_claim(request)?;
        *self = next;
        Ok(lease)
    }

    pub fn heartbeat(
        &mut self,
        request: HeartbeatRequest,
    ) -> Result<TaskLease, ExecutionLifecycleError> {
        let mut next = self.clone();
        let lease = next.apply_heartbeat(request)?;
        *self = next;
        Ok(lease)
    }

    pub fn complete(
        &mut self,
        request: CompletionRequest,
    ) -> Result<TaskTerminalRecord, ExecutionLifecycleError> {
        let mut next = self.clone();
        let terminal = next.apply_completion(request)?;
        *self = next;
        Ok(terminal)
    }

    pub fn cancel(
        &mut self,
        request: CancellationRequest,
    ) -> Result<TaskTerminalRecord, ExecutionLifecycleError> {
        let mut next = self.clone();
        let terminal = next.apply_cancellation(request)?;
        *self = next;
        Ok(terminal)
    }

    pub fn fail(&mut self, request: FailureRequest) -> Result<TaskStatus, ExecutionLifecycleError> {
        let mut next = self.clone();
        let status = next.apply_failure(request)?;
        *self = next;
        Ok(status)
    }

    fn apply_claim(&mut self, request: ClaimRequest) -> Result<TaskLease, ExecutionLifecycleError> {
        let task = self.tasks.get(&request.task_id).ok_or_else(|| {
            ExecutionLifecycleError::UnknownTask {
                task_id: request.task_id.clone(),
            }
        })?;
        validate_role(&request.task_id, task.assigned_role, request.worker_role)?;
        if request.expires_at <= request.now {
            return Err(ExecutionLifecycleError::InvalidLeaseExpiry {
                task_id: request.task_id,
            });
        }
        let current = &self.state[&request.task_id];
        match current.status {
            TaskStatus::Pending | TaskStatus::Ready => {}
            TaskStatus::Running => match &current.current_lease {
                Some(lease) if lease.expires_at > request.now => {
                    return Err(ExecutionLifecycleError::ActiveTaskLease {
                        task_id: request.task_id,
                        lease_id: lease.lease_id.clone(),
                    });
                }
                Some(_) => {}
                None => {
                    return Err(ExecutionLifecycleError::TaskNotClaimable {
                        task_id: request.task_id,
                        status: current.status,
                    });
                }
            },
            _ => {
                return Err(ExecutionLifecycleError::TaskNotClaimable {
                    task_id: request.task_id,
                    status: current.status,
                });
            }
        }
        for dependency_id in &task.dependencies {
            let status = self.state[dependency_id].status;
            if status != TaskStatus::Completed {
                return Err(ExecutionLifecycleError::DependencyIncomplete {
                    task_id: request.task_id.clone(),
                    dependency_id: dependency_id.clone(),
                    status,
                });
            }
        }
        let attempt = current.attempts + 1;
        if attempt > self.retry_budget.max_attempts {
            return Err(ExecutionLifecycleError::RetryExhausted {
                task_id: request.task_id,
                max_attempts: self.retry_budget.max_attempts,
            });
        }
        let last_failure_reason = current.last_failure_reason.clone();
        for write_key in BTreeSet::<String>::from_iter(task.write_keys.iter().cloned()) {
            if let Some(owner) = self.write_key_owners.get(&write_key) {
                if owner.expires_at > request.now && owner.task_id != request.task_id {
                    return Err(ExecutionLifecycleError::WriteKeyConflict {
                        write_key,
                        owner_task_id: owner.task_id.clone(),
                    });
                }
            }
        }

        self.write_key_owners
            .retain(|_, owner| owner.expires_at > request.now);
        let write_keys = BTreeSet::from_iter(task.write_keys.iter().cloned());
        let lease = TaskLease {
            contract_version: GOAL_RUNTIME_CONTRACT_VERSION,
            run_id: self.run_id.clone(),
            task_id: request.task_id.clone(),
            worker_id: request.worker_id.clone(),
            worker_role: request.worker_role,
            lease_id: request.lease_id.clone(),
            write_keys: write_keys.clone(),
            attempt,
            max_attempts: self.retry_budget.max_attempts,
            claimed_at: request.now,
            heartbeat_at: request.now,
            expires_at: request.expires_at,
        };
        for write_key in write_keys {
            self.write_key_owners.insert(
                write_key,
                WriteKeyOwner {
                    task_id: request.task_id.clone(),
                    worker_id: request.worker_id.clone(),
                    lease_id: request.lease_id.clone(),
                    expires_at: request.expires_at,
                },
            );
        }
        self.state.insert(
            request.task_id,
            TaskExecutionSnapshot {
                status: TaskStatus::Running,
                attempts: attempt,
                current_lease: Some(lease.clone()),
                terminal_record: None,
                last_failure_reason,
            },
        );
        Ok(lease)
    }

    fn apply_heartbeat(
        &mut self,
        request: HeartbeatRequest,
    ) -> Result<TaskLease, ExecutionLifecycleError> {
        let task = self.tasks.get(&request.task_id).ok_or_else(|| {
            ExecutionLifecycleError::UnknownTask {
                task_id: request.task_id.clone(),
            }
        })?;
        validate_role(&request.task_id, task.assigned_role, request.worker_role)?;
        let state = self
            .state
            .get_mut(&request.task_id)
            .expect("task state exists");
        let lease = state.current_lease.as_mut().ok_or_else(|| {
            ExecutionLifecycleError::NoCurrentLease {
                task_id: request.task_id.clone(),
            }
        })?;
        if lease.worker_id != request.worker_id {
            return Err(ExecutionLifecycleError::WorkerMismatch {
                task_id: request.task_id,
            });
        }
        if lease.lease_id != request.lease_id {
            return Err(ExecutionLifecycleError::LeaseMismatch {
                task_id: request.task_id,
            });
        }
        if request.now >= lease.expires_at {
            return Err(ExecutionLifecycleError::StaleHeartbeat {
                task_id: request.task_id,
            });
        }
        if request.expires_at <= lease.expires_at {
            return Err(ExecutionLifecycleError::NonExtendingHeartbeat {
                task_id: request.task_id,
            });
        }
        lease.heartbeat_at = request.now;
        lease.expires_at = request.expires_at;
        for write_key in &lease.write_keys {
            let owner = self
                .write_key_owners
                .get_mut(write_key)
                .expect("lease owns write key");
            owner.expires_at = request.expires_at;
        }
        Ok(lease.clone())
    }

    fn apply_completion(
        &mut self,
        request: CompletionRequest,
    ) -> Result<TaskTerminalRecord, ExecutionLifecycleError> {
        self.apply_terminal(
            request.task_id,
            request.worker_id,
            request.worker_role,
            request.lease_id,
            request.idempotency_key,
            request.occurred_at,
            TaskTerminalOutcome::Completed,
            None,
        )
    }

    fn apply_cancellation(
        &mut self,
        request: CancellationRequest,
    ) -> Result<TaskTerminalRecord, ExecutionLifecycleError> {
        self.apply_terminal(
            request.task_id,
            request.worker_id,
            request.worker_role,
            request.lease_id,
            request.idempotency_key,
            request.occurred_at,
            TaskTerminalOutcome::Cancelled,
            request.reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_terminal(
        &mut self,
        task_id: TaskId,
        worker_id: WorkerId,
        worker_role: Role,
        lease_id: LeaseId,
        idempotency_key: IdempotencyKey,
        occurred_at: DateTime<Utc>,
        outcome: TaskTerminalOutcome,
        reason: Option<String>,
    ) -> Result<TaskTerminalRecord, ExecutionLifecycleError> {
        let task =
            self.tasks
                .get(&task_id)
                .ok_or_else(|| ExecutionLifecycleError::UnknownTask {
                    task_id: task_id.clone(),
                })?;
        validate_role(&task_id, task.assigned_role, worker_role)?;

        let state = &self.state[&task_id];
        if let Some(existing) = &state.terminal_record {
            if existing.idempotency_key == idempotency_key && existing.outcome == outcome {
                if existing.worker_id != worker_id || existing.lease_id != lease_id {
                    return Err(ExecutionLifecycleError::TerminalRetryIdentityMismatch { task_id });
                }
                return Ok(existing.clone());
            }
            return Err(ExecutionLifecycleError::IdempotencyKeyConflict {
                task_id,
                existing: existing.idempotency_key.clone(),
                requested: idempotency_key,
            });
        }
        if matches!(
            state.status,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            return Err(ExecutionLifecycleError::TaskNotClaimable {
                task_id,
                status: state.status,
            });
        }

        self.require_active_owner(&task_id, &worker_id, worker_role, &lease_id, occurred_at)?;
        let record = TaskTerminalRecord {
            contract_version: GOAL_RUNTIME_CONTRACT_VERSION,
            run_id: self.run_id.clone(),
            task_id: task_id.clone(),
            worker_id,
            lease_id,
            idempotency_key,
            outcome,
            occurred_at,
            reason,
        };
        self.release_current_lease(&task_id);
        let state = self.state.get_mut(&task_id).expect("task state exists");
        state.status = match outcome {
            TaskTerminalOutcome::Completed => TaskStatus::Completed,
            TaskTerminalOutcome::Cancelled => TaskStatus::Cancelled,
        };
        state.terminal_record = Some(record.clone());
        Ok(record)
    }

    fn apply_failure(
        &mut self,
        request: FailureRequest,
    ) -> Result<TaskStatus, ExecutionLifecycleError> {
        self.require_active_owner(
            &request.task_id,
            &request.worker_id,
            request.worker_role,
            &request.lease_id,
            request.now,
        )?;
        self.release_current_lease(&request.task_id);
        let state = self
            .state
            .get_mut(&request.task_id)
            .expect("task state exists");
        state.last_failure_reason = Some(request.reason);
        state.status = if state.attempts >= self.retry_budget.max_attempts {
            TaskStatus::Failed
        } else {
            TaskStatus::Ready
        };
        Ok(state.status)
    }

    fn require_active_owner(
        &self,
        task_id: &TaskId,
        worker_id: &WorkerId,
        worker_role: Role,
        lease_id: &LeaseId,
        now: DateTime<Utc>,
    ) -> Result<TaskLease, ExecutionLifecycleError> {
        let task = self
            .tasks
            .get(task_id)
            .ok_or_else(|| ExecutionLifecycleError::UnknownTask {
                task_id: task_id.clone(),
            })?;
        validate_role(task_id, task.assigned_role, worker_role)?;
        let state = &self.state[task_id];
        if state.status != TaskStatus::Running {
            return Err(ExecutionLifecycleError::TaskNotClaimable {
                task_id: task_id.clone(),
                status: state.status,
            });
        }
        let lease = state.current_lease.as_ref().ok_or_else(|| {
            ExecutionLifecycleError::NoCurrentLease {
                task_id: task_id.clone(),
            }
        })?;
        if lease.worker_role != worker_role {
            return Err(ExecutionLifecycleError::RoleMismatch {
                task_id: task_id.clone(),
                expected: lease.worker_role,
                actual: worker_role,
            });
        }
        if lease.worker_id != *worker_id {
            return Err(ExecutionLifecycleError::WorkerMismatch {
                task_id: task_id.clone(),
            });
        }
        if lease.lease_id != *lease_id {
            return Err(ExecutionLifecycleError::LeaseMismatch {
                task_id: task_id.clone(),
            });
        }
        if lease.expires_at <= now {
            return Err(ExecutionLifecycleError::LeaseExpired {
                task_id: task_id.clone(),
            });
        }
        Ok(lease.clone())
    }

    fn release_current_lease(&mut self, task_id: &TaskId) {
        let lease = self
            .state
            .get_mut(task_id)
            .and_then(|state| state.current_lease.take());
        if let Some(lease) = lease {
            self.write_key_owners.retain(|write_key, owner| {
                !lease.write_keys.contains(write_key)
                    || owner.task_id != *task_id
                    || owner.lease_id != lease.lease_id
            });
        }
    }
}

fn validate_version(
    contract: &str,
    actual: ContractVersion,
) -> Result<(), ExecutionLifecycleError> {
    if actual == GOAL_RUNTIME_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ExecutionLifecycleError::UnsupportedContractVersion {
            contract: contract.to_owned(),
            expected: GOAL_RUNTIME_CONTRACT_VERSION,
            actual,
        })
    }
}

fn validate_role(
    task_id: &TaskId,
    expected: Role,
    actual: Role,
) -> Result<(), ExecutionLifecycleError> {
    if actual == Role::Coordinator {
        Err(ExecutionLifecycleError::CoordinatorRejected {
            task_id: task_id.clone(),
        })
    } else if actual != expected {
        Err(ExecutionLifecycleError::RoleMismatch {
            task_id: task_id.clone(),
            expected,
            actual,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ovca_types::GoalId;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 18, 0, 0, second).unwrap()
    }

    fn task(id: &str, dependencies: &[&str], write_keys: &[&str], status: TaskStatus) -> Task {
        Task {
            contract_version: ContractVersion::current(),
            id: TaskId::from(id),
            goal_id: GoalId::from("goal-1"),
            outcome: id.to_owned(),
            dependencies: dependencies.iter().copied().map(TaskId::from).collect(),
            assigned_role: Role::Engineer,
            resource_keys: vec![],
            write_keys: write_keys.iter().map(|key| (*key).to_owned()).collect(),
            status,
            created_at: at(0),
            updated_at: at(0),
        }
    }

    fn kernel(tasks: Vec<Task>, max_attempts: u32) -> ExecutionLifecycleKernel {
        ExecutionLifecycleKernel::new(
            RunId::from("run-1"),
            tasks,
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts,
            },
        )
        .unwrap()
    }

    fn claim(task_id: &str, lease_id: &str, now: u32, expires: u32) -> ClaimRequest {
        ClaimRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            now: at(now),
            expires_at: at(expires),
        }
    }

    fn heartbeat(task_id: &str, lease_id: &str, now: u32, expires: u32) -> HeartbeatRequest {
        HeartbeatRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            now: at(now),
            expires_at: at(expires),
        }
    }

    fn failure(task_id: &str, worker_id: &str, lease_id: &str, now: u32) -> FailureRequest {
        FailureRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from(worker_id),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            now: at(now),
            reason: "attempt failed".to_owned(),
        }
    }

    fn completion(
        task_id: &str,
        worker_id: &str,
        lease_id: &str,
        key: &str,
        occurred_at: u32,
    ) -> CompletionRequest {
        CompletionRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from(worker_id),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            idempotency_key: IdempotencyKey::from(key),
            occurred_at: at(occurred_at),
        }
    }

    fn cancellation(
        task_id: &str,
        worker_id: &str,
        lease_id: &str,
        key: &str,
        occurred_at: u32,
    ) -> CancellationRequest {
        CancellationRequest {
            task_id: TaskId::from(task_id),
            worker_id: WorkerId::from(worker_id),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from(lease_id),
            idempotency_key: IdempotencyKey::from(key),
            occurred_at: at(occurred_at),
            reason: Some("owner cancelled".to_owned()),
        }
    }

    fn claimed_kernel(max_attempts: u32) -> ExecutionLifecycleKernel {
        let mut kernel = kernel(
            vec![task("a", &[], &["key"], TaskStatus::Ready)],
            max_attempts,
        );
        kernel.claim(claim("a", "lease-1", 1, 10)).unwrap();
        kernel
    }

    fn assert_rejected_unchanged<T>(
        kernel: &mut ExecutionLifecycleKernel,
        operation: impl FnOnce(&mut ExecutionLifecycleKernel) -> Result<T, ExecutionLifecycleError>,
    ) -> ExecutionLifecycleError {
        let before = kernel.snapshot();
        let error = match operation(kernel) {
            Ok(_) => panic!("operation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(kernel.snapshot(), before);
        error
    }

    #[test]
    fn valid_claim_and_heartbeat_update_only_lease_timing_and_owner_expiry() {
        let mut kernel = kernel(vec![task("a", &[], &["key"], TaskStatus::Ready)], 2);
        let lease = kernel.claim(claim("a", "lease-1", 1, 10)).unwrap();
        assert_eq!(lease.attempt, 1);
        let before = kernel.snapshot();
        let lease = kernel.heartbeat(heartbeat("a", "lease-1", 2, 20)).unwrap();
        assert_eq!(lease.heartbeat_at, at(2));
        assert_eq!(lease.expires_at, at(20));
        let after = kernel.snapshot();
        assert_eq!(after.tasks[&TaskId::from("a")].attempts, 1);
        assert_eq!(after.write_key_owners["key"].expires_at, at(20));
        assert_eq!(
            before.tasks[&TaskId::from("a")].status,
            after.tasks[&TaskId::from("a")].status
        );
    }

    #[test]
    fn dependency_must_be_completed() {
        let mut kernel = kernel(
            vec![
                task("a", &[], &[], TaskStatus::Ready),
                task("b", &["a"], &[], TaskStatus::Ready),
            ],
            1,
        );
        assert!(matches!(
            kernel.claim(claim("b", "l", 1, 2)),
            Err(ExecutionLifecycleError::DependencyIncomplete { .. })
        ));
    }

    #[test]
    fn active_same_task_conflicts() {
        let mut kernel = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 2);
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        assert!(matches!(
            kernel.claim(claim("a", "l2", 2, 11)),
            Err(ExecutionLifecycleError::ActiveTaskLease { .. })
        ));
    }

    #[test]
    fn shared_active_write_key_conflicts() {
        let mut kernel = kernel(
            vec![
                task("a", &[], &["key"], TaskStatus::Ready),
                task("b", &[], &["key"], TaskStatus::Ready),
            ],
            2,
        );
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        assert!(matches!(
            kernel.claim(claim("b", "l2", 2, 11)),
            Err(ExecutionLifecycleError::WriteKeyConflict { .. })
        ));
    }

    #[test]
    fn expiry_equality_reclaims_and_increments_attempt() {
        let mut kernel = kernel(vec![task("a", &[], &["key"], TaskStatus::Ready)], 2);
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        let lease = kernel.claim(claim("a", "l2", 10, 20)).unwrap();
        assert_eq!(lease.attempt, 2);
        assert_eq!(
            kernel.snapshot().write_key_owners["key"].lease_id,
            LeaseId::from("l2")
        );
    }

    #[test]
    fn invalid_initial_statuses_are_rejected_deterministically() {
        for status in [
            TaskStatus::Running,
            TaskStatus::AwaitingApproval,
            TaskStatus::Reviewing,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Cancelled,
        ] {
            assert_eq!(
                ExecutionLifecycleKernel::new(
                    RunId::from("run-1"),
                    vec![task("a", &[], &["key"], status)],
                    RetryBudget {
                        contract_version: ContractVersion::current(),
                        max_attempts: 2,
                    },
                )
                .unwrap_err(),
                ExecutionLifecycleError::InvalidInitialTaskStatus {
                    task_id: TaskId::from("a"),
                    status,
                }
            );
        }
    }

    #[test]
    fn retry_exhaustion_preserves_snapshot() {
        let mut kernel = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 1);
        kernel.claim(claim("a", "l1", 1, 2)).unwrap();
        let before = kernel.snapshot();
        assert!(matches!(
            kernel.claim(claim("a", "l2", 2, 3)),
            Err(ExecutionLifecycleError::RetryExhausted { .. })
        ));
        assert_eq!(kernel.snapshot(), before);
    }

    #[test]
    fn wrong_worker_role_and_lease_are_rejected() {
        let mut kernel = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 1);
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        let mut request = heartbeat("a", "l1", 2, 11);
        request.worker_id = WorkerId::from("wrong");
        assert!(matches!(
            kernel.heartbeat(request),
            Err(ExecutionLifecycleError::WorkerMismatch { .. })
        ));
        let mut request = heartbeat("a", "l1", 2, 11);
        request.worker_role = Role::Reviewer;
        assert!(matches!(
            kernel.heartbeat(request),
            Err(ExecutionLifecycleError::RoleMismatch { .. })
        ));
        assert!(matches!(
            kernel.heartbeat(heartbeat("a", "wrong", 2, 11)),
            Err(ExecutionLifecycleError::LeaseMismatch { .. })
        ));
    }

    #[test]
    fn coordinator_is_rejected() {
        let mut kernel = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 1);
        let mut request = claim("a", "l", 1, 2);
        request.worker_role = Role::Coordinator;
        assert!(matches!(
            kernel.claim(request),
            Err(ExecutionLifecycleError::CoordinatorRejected { .. })
        ));
    }

    #[test]
    fn stale_and_nonextending_heartbeats_are_rejected_without_mutation() {
        let mut kernel = kernel(vec![task("a", &[], &["key"], TaskStatus::Ready)], 1);
        kernel.claim(claim("a", "l", 1, 10)).unwrap();
        let before = kernel.snapshot();
        assert!(matches!(
            kernel.heartbeat(heartbeat("a", "l", 10, 20)),
            Err(ExecutionLifecycleError::StaleHeartbeat { .. })
        ));
        assert_eq!(kernel.snapshot(), before);
        assert!(matches!(
            kernel.heartbeat(heartbeat("a", "l", 2, 10)),
            Err(ExecutionLifecycleError::NonExtendingHeartbeat { .. })
        ));
        assert_eq!(kernel.snapshot(), before);
    }

    #[test]
    fn rejected_claim_keeps_exact_snapshot() {
        let mut kernel = kernel(
            vec![
                task("a", &[], &["key"], TaskStatus::Ready),
                task("b", &[], &["key"], TaskStatus::Ready),
            ],
            1,
        );
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        let before = kernel.snapshot();
        let _ = kernel.claim(claim("b", "l2", 2, 11));
        assert_eq!(kernel.snapshot(), before);
    }

    #[test]
    fn chain_claim_heartbeat_complete_then_unblocks_dependency() {
        let mut kernel = kernel(
            vec![
                task("b", &["a"], &["result"], TaskStatus::Pending),
                task("a", &[], &["source"], TaskStatus::Ready),
            ],
            2,
        );
        let initial = kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        let heartbeat = kernel.heartbeat(heartbeat("a", "l1", 2, 20)).unwrap();
        assert_eq!(heartbeat.claimed_at, initial.claimed_at);
        assert_eq!(heartbeat.heartbeat_at, at(2));
        assert_eq!(heartbeat.expires_at, at(20));

        let completed = kernel
            .complete(completion("a", "worker-1", "l1", "complete-a", 3))
            .unwrap();
        assert_eq!(completed.outcome, TaskTerminalOutcome::Completed);
        assert_eq!(
            kernel.task_status(&TaskId::from("a")),
            Some(TaskStatus::Completed)
        );
        assert!(kernel.lease(&TaskId::from("a")).is_none());
        assert!(kernel.write_key_owners().is_empty());

        let dependent = kernel.claim(claim("b", "l2", 4, 14)).unwrap();
        assert_eq!(dependent.attempt, 1);
    }

    #[test]
    fn failure_releases_writes_retries_and_terminally_fails_when_exhausted() {
        let mut kernel = kernel(vec![task("a", &[], &["key"], TaskStatus::Ready)], 2);
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        assert_eq!(
            kernel.fail(failure("a", "worker-1", "l1", 2)).unwrap(),
            TaskStatus::Ready
        );
        assert!(kernel.write_key_owners().is_empty());
        assert!(kernel.lease(&TaskId::from("a")).is_none());
        assert_eq!(
            kernel.snapshot().tasks[&TaskId::from("a")].last_failure_reason,
            Some("attempt failed".to_owned())
        );

        let second = kernel.claim(claim("a", "l2", 3, 12)).unwrap();
        assert_eq!(second.attempt, 2);
        assert_eq!(
            kernel.fail(failure("a", "worker-1", "l2", 4)).unwrap(),
            TaskStatus::Failed
        );
        assert_eq!(
            kernel.task_status(&TaskId::from("a")),
            Some(TaskStatus::Failed)
        );
        assert!(kernel.lease(&TaskId::from("a")).is_none());
        assert!(kernel.write_key_owners().is_empty());
        assert!(matches!(
            kernel.claim(claim("a", "l3", 5, 15)),
            Err(ExecutionLifecycleError::TaskNotClaimable {
                status: TaskStatus::Failed,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_completion_is_idempotent_only_for_same_key() {
        let mut kernel = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 1);
        kernel.claim(claim("a", "l1", 1, 10)).unwrap();
        let original = kernel
            .complete(completion("a", "worker-1", "l1", "complete-a", 2))
            .unwrap();

        let before_retry = kernel.snapshot();
        let retry = completion("a", "worker-1", "l1", "complete-a", 3);
        assert_eq!(kernel.complete(retry).unwrap(), original);
        assert_eq!(kernel.snapshot(), before_retry);

        let wrong_worker = completion("a", "wrong-worker", "l1", "complete-a", 3);
        assert!(matches!(
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.complete(wrong_worker)),
            ExecutionLifecycleError::TerminalRetryIdentityMismatch { .. }
        ));
        let wrong_lease = completion("a", "worker-1", "wrong-lease", "complete-a", 3);
        assert!(matches!(
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.complete(wrong_lease)),
            ExecutionLifecycleError::TerminalRetryIdentityMismatch { .. }
        ));

        let replacement = completion("a", "worker-1", "l1", "complete-b", 3);
        assert!(matches!(
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.complete(replacement)),
            ExecutionLifecycleError::IdempotencyKeyConflict { .. }
        ));
        assert_eq!(kernel.terminal_record(&TaskId::from("a")), Some(&original));
    }

    #[test]
    fn cancellation_is_idempotent_and_complete_cancel_races_are_rejected() {
        let mut cancelled = kernel(vec![task("a", &[], &[], TaskStatus::Ready)], 1);
        cancelled.claim(claim("a", "l1", 1, 10)).unwrap();
        let original = cancelled
            .cancel(cancellation("a", "worker-1", "l1", "cancel-a", 2))
            .unwrap();
        let before_retry = cancelled.snapshot();
        let mut retry = cancellation("a", "worker-1", "l1", "cancel-a", 3);
        retry.reason = Some("replacement reason".to_owned());
        assert_eq!(cancelled.cancel(retry).unwrap(), original);
        assert_eq!(cancelled.snapshot(), before_retry);

        let wrong_worker = cancellation("a", "wrong-worker", "l1", "cancel-a", 3);
        assert!(matches!(
            assert_rejected_unchanged(&mut cancelled, |kernel| kernel.cancel(wrong_worker)),
            ExecutionLifecycleError::TerminalRetryIdentityMismatch { .. }
        ));
        let wrong_lease = cancellation("a", "worker-1", "wrong-lease", "cancel-a", 3);
        assert!(matches!(
            assert_rejected_unchanged(&mut cancelled, |kernel| kernel.cancel(wrong_lease)),
            ExecutionLifecycleError::TerminalRetryIdentityMismatch { .. }
        ));

        assert!(matches!(
            assert_rejected_unchanged(&mut cancelled, |kernel| {
                kernel.cancel(cancellation("a", "worker-1", "l1", "cancel-b", 3))
            }),
            ExecutionLifecycleError::IdempotencyKeyConflict { .. }
        ));
        assert_eq!(
            cancelled.terminal_record(&TaskId::from("a")),
            Some(&original)
        );

        let mut completed = kernel(vec![task("b", &[], &[], TaskStatus::Ready)], 1);
        completed.claim(claim("b", "l2", 1, 10)).unwrap();
        completed
            .complete(completion("b", "worker-1", "l2", "complete-b", 2))
            .unwrap();
        assert!(matches!(
            completed.cancel(cancellation("b", "worker-1", "l2", "cancel-b", 3)),
            Err(ExecutionLifecycleError::IdempotencyKeyConflict { .. })
        ));
    }

    #[test]
    fn rejected_completion_owners_and_expiry_preserve_exact_snapshot() {
        let requests = [
            {
                let mut request = completion("a", "worker-1", "lease-1", "key", 2);
                request.worker_id = WorkerId::from("wrong-worker");
                request
            },
            {
                let mut request = completion("a", "worker-1", "lease-1", "key", 2);
                request.worker_role = Role::Reviewer;
                request
            },
            completion("a", "worker-1", "wrong-lease", "key", 2),
            completion("a", "worker-1", "lease-1", "key", 10),
        ];
        for request in requests {
            let mut kernel = claimed_kernel(1);
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.complete(request));
        }
    }

    #[test]
    fn rejected_cancellation_owners_and_expiry_preserve_exact_snapshot() {
        let requests = [
            {
                let mut request = cancellation("a", "worker-1", "lease-1", "key", 2);
                request.worker_id = WorkerId::from("wrong-worker");
                request
            },
            {
                let mut request = cancellation("a", "worker-1", "lease-1", "key", 2);
                request.worker_role = Role::Reviewer;
                request
            },
            cancellation("a", "worker-1", "wrong-lease", "key", 2),
            cancellation("a", "worker-1", "lease-1", "key", 10),
        ];
        for request in requests {
            let mut kernel = claimed_kernel(1);
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.cancel(request));
        }
    }

    #[test]
    fn rejected_failure_owners_and_expiry_preserve_exact_snapshot() {
        let requests = [
            failure("a", "wrong-worker", "lease-1", 2),
            {
                let mut request = failure("a", "worker-1", "lease-1", 2);
                request.worker_role = Role::Reviewer;
                request
            },
            failure("a", "worker-1", "wrong-lease", 2),
            failure("a", "worker-1", "lease-1", 10),
        ];
        for request in requests {
            let mut kernel = claimed_kernel(1);
            assert_rejected_unchanged(&mut kernel, |kernel| kernel.fail(request));
        }
    }

    #[test]
    fn same_key_completion_cancellation_races_preserve_first_terminal_record() {
        let mut completed = claimed_kernel(1);
        let completed_record = completed
            .complete(completion("a", "worker-1", "lease-1", "same-key", 2))
            .unwrap();
        let completed_snapshot = completed.snapshot();
        assert_rejected_unchanged(&mut completed, |kernel| {
            kernel.cancel(cancellation("a", "worker-1", "lease-1", "same-key", 3))
        });
        assert_eq!(completed.snapshot(), completed_snapshot);
        assert_eq!(
            completed.terminal_record(&TaskId::from("a")),
            Some(&completed_record)
        );

        let mut cancelled = claimed_kernel(1);
        let cancelled_record = cancelled
            .cancel(cancellation("a", "worker-1", "lease-1", "same-key", 2))
            .unwrap();
        let cancelled_snapshot = cancelled.snapshot();
        assert_rejected_unchanged(&mut cancelled, |kernel| {
            kernel.complete(completion("a", "worker-1", "lease-1", "same-key", 3))
        });
        assert_eq!(cancelled.snapshot(), cancelled_snapshot);
        assert_eq!(
            cancelled.terminal_record(&TaskId::from("a")),
            Some(&cancelled_record)
        );
    }

    #[test]
    fn construction_validates_versions_budget_goal_role_and_dependencies() {
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 1,
        };
        assert!(matches!(
            ExecutionLifecycleKernel::new(
                RunId::from("run-1"),
                Vec::new(),
                RetryBudget {
                    max_attempts: 0,
                    ..budget
                },
            ),
            Err(ExecutionLifecycleError::InvalidMaxAttempts)
        ));

        let duplicate = task("a", &[], &[], TaskStatus::Ready);
        assert!(matches!(
            ExecutionLifecycleKernel::new(
                RunId::from("run-1"),
                vec![duplicate.clone(), duplicate],
                budget,
            ),
            Err(ExecutionLifecycleError::DuplicateTaskId { .. })
        ));

        let goal_a = task("a", &[], &[], TaskStatus::Ready);
        let mut goal_b = task("b", &[], &[], TaskStatus::Ready);
        goal_b.goal_id = GoalId::from("goal-2");
        assert!(matches!(
            ExecutionLifecycleKernel::new(RunId::from("run-1"), vec![goal_a, goal_b], budget,),
            Err(ExecutionLifecycleError::GoalMismatch { .. })
        ));

        let mut coordinator_task = task("a", &[], &[], TaskStatus::Ready);
        coordinator_task.assigned_role = Role::Coordinator;
        assert!(matches!(
            ExecutionLifecycleKernel::new(RunId::from("run-1"), vec![coordinator_task], budget,),
            Err(ExecutionLifecycleError::InvalidAssignedRole { .. })
        ));

        assert!(matches!(
            ExecutionLifecycleKernel::new(
                RunId::from("run-1"),
                vec![task("a", &["missing"], &[], TaskStatus::Ready)],
                budget,
            ),
            Err(ExecutionLifecycleError::UnknownDependency { .. })
        ));

        let mut wrong_version = task("a", &[], &[], TaskStatus::Ready);
        wrong_version.contract_version = ContractVersion(2);
        assert!(matches!(
            ExecutionLifecycleKernel::new(RunId::from("run-1"), vec![wrong_version], budget,),
            Err(ExecutionLifecycleError::UnsupportedContractVersion { .. })
        ));
    }

    #[test]
    fn shuffled_task_input_produces_identical_snapshot() {
        let a = task("a", &[], &["z"], TaskStatus::Ready);
        let b = task("b", &["a"], &["a"], TaskStatus::Pending);
        assert_eq!(
            kernel(vec![a.clone(), b.clone()], 2).snapshot(),
            kernel(vec![b, a], 2).snapshot()
        );

        let mut invalid_a = task("a", &[], &[], TaskStatus::Ready);
        invalid_a.assigned_role = Role::Coordinator;
        let mut invalid_b = task("b", &[], &[], TaskStatus::Ready);
        invalid_b.assigned_role = Role::Coordinator;
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };
        let ordered_error = ExecutionLifecycleKernel::new(
            RunId::from("run-1"),
            vec![invalid_a.clone(), invalid_b.clone()],
            budget,
        );
        let shuffled_error =
            ExecutionLifecycleKernel::new(RunId::from("run-1"), vec![invalid_b, invalid_a], budget);
        assert_eq!(
            ordered_error.as_ref().unwrap_err(),
            shuffled_error.as_ref().unwrap_err()
        );
        assert!(matches!(
            ordered_error,
            Err(ExecutionLifecycleError::InvalidAssignedRole { task_id, .. })
                if task_id == TaskId::from("a")
        ));
    }

    #[test]
    fn every_valid_initial_status_round_trips_with_shuffled_definitions() {
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };
        for (a_status, b_status) in [
            (TaskStatus::Pending, TaskStatus::Ready),
            (TaskStatus::Ready, TaskStatus::Pending),
        ] {
            let a = task("a", &[], &["z"], a_status);
            let b = task("b", &["a"], &["a"], b_status);
            let kernel = ExecutionLifecycleKernel::new(
                RunId::from("run-1"),
                vec![a.clone(), b.clone()],
                budget,
            )
            .unwrap();
            let snapshot = kernel.snapshot();

            let restored = ExecutionLifecycleKernel::restore(
                RunId::from("run-1"),
                vec![b, a],
                budget,
                snapshot.clone(),
            )
            .unwrap();

            assert_eq!(restored.snapshot(), snapshot);
        }
    }

    #[test]
    fn restore_rejects_unreachable_status_attempt_combinations() {
        let definitions = vec![task("a", &[], &[], TaskStatus::Ready)];
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };
        let base = kernel(definitions.clone(), budget.max_attempts).snapshot();
        let cases = [
            (TaskStatus::Pending, 1),
            (TaskStatus::Ready, 2),
            (TaskStatus::Running, 0),
            (TaskStatus::Completed, 0),
            (TaskStatus::Cancelled, 0),
            (TaskStatus::Failed, 1),
        ];

        for (status, attempts) in cases {
            let mut snapshot = base.clone();
            let state = snapshot.tasks.get_mut(&TaskId::from("a")).unwrap();
            state.status = status;
            state.attempts = attempts;

            assert_eq!(
                ExecutionLifecycleKernel::restore(
                    RunId::from("run-1"),
                    definitions.clone(),
                    budget,
                    snapshot,
                )
                .unwrap_err(),
                ExecutionLifecycleRestoreError::InvalidStatusAttempts {
                    task_id: TaskId::from("a"),
                    status,
                    attempts,
                    max_attempts: budget.max_attempts,
                }
            );
        }
    }

    #[test]
    fn restore_rejects_p2_unsupported_statuses_and_failure_without_attempt() {
        let definitions = vec![task("a", &[], &[], TaskStatus::Ready)];
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 2,
        };
        let base = kernel(definitions.clone(), budget.max_attempts).snapshot();

        for status in [TaskStatus::AwaitingApproval, TaskStatus::Reviewing] {
            let mut snapshot = base.clone();
            snapshot.tasks.get_mut(&TaskId::from("a")).unwrap().status = status;
            assert_eq!(
                ExecutionLifecycleKernel::restore(
                    RunId::from("run-1"),
                    definitions.clone(),
                    budget,
                    snapshot,
                )
                .unwrap_err(),
                ExecutionLifecycleRestoreError::UnsupportedTaskStatus {
                    task_id: TaskId::from("a"),
                    status,
                }
            );
        }

        let mut snapshot = base;
        snapshot
            .tasks
            .get_mut(&TaskId::from("a"))
            .unwrap()
            .last_failure_reason = Some("impossible".to_owned());
        assert_eq!(
            ExecutionLifecycleKernel::restore(RunId::from("run-1"), definitions, budget, snapshot,)
                .unwrap_err(),
            ExecutionLifecycleRestoreError::LastFailureWithoutAttempt {
                task_id: TaskId::from("a"),
            }
        );
    }
}
