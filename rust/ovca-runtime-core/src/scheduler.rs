use ovca_types::{ContractVersion, ExecutionMode, ExecutionPlan, ExecutionWave, Task, TaskId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Invalid task graphs rejected before an execution plan is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    DuplicateTaskId {
        task_id: TaskId,
    },
    SelfDependency {
        task_id: TaskId,
    },
    MissingDependency {
        task_id: TaskId,
        dependency_id: TaskId,
    },
    Cycle {
        task_ids: Vec<TaskId>,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTaskId { task_id } => {
                write!(f, "duplicate task ID: {task_id}")
            }
            Self::SelfDependency { task_id } => {
                write!(f, "task depends on itself: {task_id}")
            }
            Self::MissingDependency {
                task_id,
                dependency_id,
            } => write!(f, "task {task_id} depends on missing task {dependency_id}"),
            Self::Cycle { task_ids } => {
                let ids = task_ids
                    .iter()
                    .map(TaskId::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "task dependency cycle contains: {ids}")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

/// Builds a deterministic, provider-independent execution plan.
///
/// Every wave is computed from tasks whose dependencies were completed before
/// that wave began. Ready tasks are considered by task ID and co-scheduled only
/// when their declared write keys are disjoint.
pub fn schedule_tasks(tasks: &[Task]) -> Result<ExecutionPlan, ScheduleError> {
    let mut task_counts = BTreeMap::<TaskId, usize>::new();
    for task in tasks {
        *task_counts.entry(task.id.clone()).or_default() += 1;
    }
    if let Some((task_id, _)) = task_counts.iter().find(|(_, count)| **count > 1) {
        return Err(ScheduleError::DuplicateTaskId {
            task_id: task_id.clone(),
        });
    }

    let tasks_by_id = tasks
        .iter()
        .map(|task| (task.id.clone(), task))
        .collect::<BTreeMap<_, _>>();

    for (task_id, task) in &tasks_by_id {
        let dependencies = task.dependencies.iter().collect::<BTreeSet<_>>();
        if dependencies.contains(task_id) {
            return Err(ScheduleError::SelfDependency {
                task_id: task_id.clone(),
            });
        }
        if let Some(dependency_id) = dependencies
            .into_iter()
            .find(|dependency_id| !tasks_by_id.contains_key(*dependency_id))
        {
            return Err(ScheduleError::MissingDependency {
                task_id: task_id.clone(),
                dependency_id: dependency_id.clone(),
            });
        }
    }

    let mut completed = BTreeSet::<TaskId>::new();
    let mut remaining = tasks_by_id.keys().cloned().collect::<BTreeSet<_>>();
    let mut waves = Vec::new();

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .filter(|task_id| {
                tasks_by_id[*task_id]
                    .dependencies
                    .iter()
                    .all(|dependency_id| completed.contains(dependency_id))
            })
            .cloned()
            .collect::<Vec<_>>();

        if ready.is_empty() {
            return Err(ScheduleError::Cycle {
                task_ids: remaining.into_iter().collect(),
            });
        }

        let mut wave_task_ids = Vec::new();
        let mut wave_write_keys = BTreeSet::<String>::new();
        for task_id in ready {
            let task = tasks_by_id[&task_id];
            let conflicts = task
                .write_keys
                .iter()
                .any(|write_key| wave_write_keys.contains(write_key));
            if !conflicts {
                wave_write_keys.extend(task.write_keys.iter().cloned());
                wave_task_ids.push(task_id);
            }
        }

        for task_id in &wave_task_ids {
            remaining.remove(task_id);
            completed.insert(task_id.clone());
        }

        let mode = if wave_task_ids.len() == 1 {
            ExecutionMode::Sequential
        } else {
            ExecutionMode::Parallel
        };
        waves.push(ExecutionWave {
            index: u32::try_from(waves.len()).expect("execution wave count exceeds u32"),
            mode,
            task_ids: wave_task_ids,
        });
    }

    Ok(ExecutionPlan {
        contract_version: ContractVersion::current(),
        waves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ovca_types::{GoalId, Role, TaskStatus};

    fn task(id: &str, dependencies: &[&str], write_keys: &[&str]) -> Task {
        let now = Utc::now();
        Task {
            contract_version: ContractVersion::current(),
            id: TaskId::from(id),
            goal_id: GoalId::from("goal-1"),
            outcome: format!("complete {id}"),
            dependencies: dependencies.iter().copied().map(TaskId::from).collect(),
            assigned_role: Role::Engineer,
            resource_keys: Vec::new(),
            write_keys: write_keys.iter().map(|key| (*key).to_owned()).collect(),
            status: TaskStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    fn wave(index: u32, mode: ExecutionMode, task_ids: &[&str]) -> ExecutionWave {
        ExecutionWave {
            index,
            mode,
            task_ids: task_ids.iter().copied().map(TaskId::from).collect(),
        }
    }

    #[test]
    fn golden_sequential_chain() {
        let tasks = vec![
            task("task-c", &["task-b"], &[]),
            task("task-a", &[], &[]),
            task("task-b", &["task-a"], &[]),
        ];

        let plan = schedule_tasks(&tasks).expect("chain should schedule");

        assert_eq!(
            plan.waves,
            vec![
                wave(0, ExecutionMode::Sequential, &["task-a"]),
                wave(1, ExecutionMode::Sequential, &["task-b"]),
                wave(2, ExecutionMode::Sequential, &["task-c"]),
            ]
        );
    }

    #[test]
    fn golden_independent_tasks_share_parallel_wave() {
        let tasks = vec![
            task("task-b", &[], &["beta"]),
            task("task-a", &[], &["alpha"]),
        ];

        let plan = schedule_tasks(&tasks).expect("independent tasks should schedule");

        assert_eq!(
            plan.waves,
            vec![wave(0, ExecutionMode::Parallel, &["task-a", "task-b"])]
        );
    }

    #[test]
    fn golden_conflicting_writes_are_serialized_by_task_id() {
        let tasks = vec![
            task("task-b", &[], &["shared"]),
            task("task-c", &[], &["other"]),
            task("task-a", &[], &["shared"]),
        ];

        let plan = schedule_tasks(&tasks).expect("write conflicts should serialize");

        assert_eq!(
            plan.waves,
            vec![
                wave(0, ExecutionMode::Parallel, &["task-a", "task-c"]),
                wave(1, ExecutionMode::Sequential, &["task-b"]),
            ]
        );
    }

    #[test]
    fn golden_plan_is_stable_under_shuffled_input() {
        let ordered = vec![
            task("task-a", &[], &["shared"]),
            task("task-b", &[], &["shared"]),
            task("task-c", &["task-a"], &["result"]),
            task("task-d", &[], &["independent"]),
        ];
        let shuffled = vec![
            ordered[2].clone(),
            ordered[3].clone(),
            ordered[1].clone(),
            ordered[0].clone(),
        ];

        assert_eq!(
            schedule_tasks(&ordered),
            schedule_tasks(&shuffled),
            "input ordering must not affect the plan"
        );
    }

    #[test]
    fn golden_missing_dependency_is_rejected() {
        let error = schedule_tasks(&[task("task-a", &["missing"], &[])])
            .expect_err("missing dependency must fail");

        assert_eq!(
            error,
            ScheduleError::MissingDependency {
                task_id: TaskId::from("task-a"),
                dependency_id: TaskId::from("missing"),
            }
        );
    }

    #[test]
    fn golden_self_dependency_is_rejected() {
        let error = schedule_tasks(&[task("task-a", &["task-a"], &[])])
            .expect_err("self dependency must fail");

        assert_eq!(
            error,
            ScheduleError::SelfDependency {
                task_id: TaskId::from("task-a"),
            }
        );
    }

    #[test]
    fn golden_cycle_is_rejected_with_sorted_task_ids() {
        let tasks = vec![
            task("task-b", &["task-a"], &[]),
            task("task-a", &["task-b"], &[]),
        ];

        let error = schedule_tasks(&tasks).expect_err("cycle must fail");

        assert_eq!(
            error,
            ScheduleError::Cycle {
                task_ids: vec![TaskId::from("task-a"), TaskId::from("task-b")],
            }
        );
    }

    #[test]
    fn duplicate_task_ids_are_rejected() {
        let error = schedule_tasks(&[task("task-a", &[], &[]), task("task-a", &[], &[])])
            .expect_err("duplicate task IDs must fail");

        assert_eq!(
            error,
            ScheduleError::DuplicateTaskId {
                task_id: TaskId::from("task-a"),
            }
        );
    }
}
