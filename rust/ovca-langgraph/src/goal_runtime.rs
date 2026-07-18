use chrono::{DateTime, Utc};
use ovca_runtime_core::{replay_run, schedule_tasks, ReplayError, ReplayedRun, ScheduleError};
use ovca_storage::{RunEventLog, RunEventLogError};
use ovca_types::{
    ContractVersion, EventId, ExecutionPlan, GoalContract, GoalId, Role, RunEvent, RunEventPayload,
    RunId, RunStatus, Task, TaskId, TaskStatus,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

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
    Build { source: GoalRuntimeError },
    Storage { source: RunEventLogError },
    Replay { source: ReplayError },
    RunAlreadyExists { run_id: RunId },
    RunNotFound { run_id: RunId },
}

impl fmt::Display for DurableGoalRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build { source } => write!(formatter, "failed to build planned run: {source}"),
            Self::Storage { source } => write!(formatter, "run-event storage failed: {source}"),
            Self::Replay { source } => write!(formatter, "run-event replay failed: {source}"),
            Self::RunAlreadyExists { run_id } => {
                write!(formatter, "run {run_id} already exists")
            }
            Self::RunNotFound { run_id } => write!(formatter, "run {run_id} was not found"),
        }
    }
}

impl std::error::Error for DurableGoalRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build { source } => Some(source),
            Self::Storage { source } => Some(source),
            Self::Replay { source } => Some(source),
            Self::RunAlreadyExists { .. } | Self::RunNotFound { .. } => None,
        }
    }
}

impl From<RunEventLogError> for DurableGoalRuntimeError {
    fn from(source: RunEventLogError) -> Self {
        Self::Storage { source }
    }
}

/// Thin durable wrapper for validated goal-run events.
///
/// P1 supports one writer per run only. P2 adds claim, lease, CAS, and
/// concurrency semantics; callers must not infer those guarantees here.
#[derive(Debug, Clone)]
pub struct DurableGoalRuntime {
    log: RunEventLog,
}

impl DurableGoalRuntime {
    /// Creates a runtime rooted at the caller-supplied external path without
    /// touching the filesystem.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            log: RunEventLog::new(root),
        }
    }

    /// Returns the fixed JSONL path used by this runtime.
    pub fn log_path(&self) -> &Path {
        self.log.path()
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
    use ovca_types::{
        CompletionPrecondition, CoordinatorFinalResponse, ExecutionMode, PermissionProfile,
        ProjectId, RiskTier, SpecialistOutput,
    };
    use std::fs;
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
}
