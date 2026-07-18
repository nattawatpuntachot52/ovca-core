use ovca_types::{
    validate_run_transition, CompletionEvidence, ContractVersion, CoordinatorFinalResponse,
    EventId, EvidenceId, ExecutionPlan, GoalContract, GoalId, ProjectId, Role, RunEvent,
    RunEventPayload, RunId, RunRecord, RunStatus, RunTransitionError, SpecialistOutput, TaskId,
    TaskStatus,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Structural failures that prevent a run event stream from being replayed safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    EmptyStream,
    ContractVersionMismatch {
        sequence: u64,
        expected: ContractVersion,
        found: ContractVersion,
    },
    FirstEventNotRunCreated {
        event_id: EventId,
    },
    DuplicateRunCreated {
        sequence: u64,
        event_id: EventId,
    },
    RunIdMismatch {
        sequence: u64,
        expected: RunId,
        found: RunId,
    },
    SequenceMismatch {
        event_id: EventId,
        expected: u64,
        found: u64,
    },
    InitialPreviousEventIdPresent {
        event_id: EventId,
        found: EventId,
    },
    PreviousEventIdMismatch {
        sequence: u64,
        event_id: EventId,
        expected: EventId,
        found: Option<EventId>,
    },
    DuplicateEventId {
        event_id: EventId,
        first_sequence: u64,
        duplicate_sequence: u64,
    },
    InitialRunStatusMismatch {
        event_id: EventId,
        expected: RunStatus,
        found: RunStatus,
    },
    GoalContractIdMismatch {
        expected: GoalId,
        found: GoalId,
    },
    GoalContractProjectIdMismatch {
        expected: ProjectId,
        found: ProjectId,
    },
    NestedContractVersionMismatch {
        sequence: u64,
        contract: &'static str,
        expected: ContractVersion,
        found: ContractVersion,
    },
    DuplicateDeclaredTask {
        sequence: u64,
        task_id: TaskId,
    },
    DuplicateExecutionPlan {
        sequence: u64,
    },
    ExecutionPlanWaveIndexMismatch {
        sequence: u64,
        expected: u64,
        found: u32,
    },
    ExecutionPlanUnknownTask {
        sequence: u64,
        task_id: TaskId,
    },
    ExecutionPlanDuplicateTask {
        sequence: u64,
        task_id: TaskId,
    },
    ExecutionPlanMissingTask {
        sequence: u64,
        task_id: TaskId,
    },
    RunStatusFromMismatch {
        sequence: u64,
        expected: RunStatus,
        found: RunStatus,
    },
    RunTransitionRejected {
        sequence: u64,
        error: RunTransitionError,
    },
    UnknownTask {
        sequence: u64,
        task_id: TaskId,
    },
    TaskStatusFromMismatch {
        sequence: u64,
        task_id: TaskId,
        expected: TaskStatus,
        found: TaskStatus,
    },
    DuplicateCompletionEvidence {
        sequence: u64,
    },
    CompletionEvidenceNotAttached {
        sequence: u64,
        evidence_id: EvidenceId,
    },
    InvalidSpecialistRole {
        sequence: u64,
        role: Role,
    },
    SpecialistOutputRoleMismatch {
        sequence: u64,
        producer_role: Role,
        specialist_role: Role,
    },
    UnauthorizedCoordinatorFinalResponse {
        sequence: u64,
        producer_role: Role,
    },
    DuplicateCoordinatorFinalResponse {
        sequence: u64,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStream => f.write_str("run event stream is empty"),
            Self::ContractVersionMismatch {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "run event at sequence {sequence} has contract version {found}, expected {expected}"
            ),
            Self::FirstEventNotRunCreated { event_id } => {
                write!(f, "first run event {event_id} is not RunCreated")
            }
            Self::DuplicateRunCreated { sequence, event_id } => write!(
                f,
                "RunCreated appears more than once; duplicate event {event_id} is at sequence {sequence}"
            ),
            Self::RunIdMismatch {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "run event at sequence {sequence} has run ID {found}, expected {expected}"
            ),
            Self::SequenceMismatch {
                event_id,
                expected,
                found,
            } => write!(
                f,
                "run event {event_id} has sequence {found}, expected {expected}"
            ),
            Self::InitialPreviousEventIdPresent { event_id, found } => write!(
                f,
                "initial run event {event_id} references previous event {found}"
            ),
            Self::PreviousEventIdMismatch {
                sequence,
                event_id,
                expected,
                found,
            } => write!(
                f,
                "run event {event_id} at sequence {sequence} references previous event {found:?}, expected {expected}"
            ),
            Self::DuplicateEventId {
                event_id,
                first_sequence,
                duplicate_sequence,
            } => write!(
                f,
                "run event ID {event_id} is duplicated at sequence {duplicate_sequence}; first seen at sequence {first_sequence}"
            ),
            Self::InitialRunStatusMismatch {
                event_id,
                expected,
                found,
            } => write!(
                f,
                "initial RunCreated event {event_id} has status {found}, expected {expected}"
            ),
            Self::GoalContractIdMismatch { expected, found } => write!(
                f,
                "supplied goal contract ID {found} does not match run goal ID {expected}"
            ),
            Self::GoalContractProjectIdMismatch { expected, found } => write!(
                f,
                "supplied goal contract project ID {found} does not match run project ID {expected}"
            ),
            Self::NestedContractVersionMismatch {
                sequence,
                contract,
                expected,
                found,
            } => write!(
                f,
                "{contract} at sequence {sequence} has contract version {found}, expected {expected}"
            ),
            Self::DuplicateDeclaredTask { sequence, task_id } => write!(
                f,
                "RunCreated at sequence {sequence} declares task {task_id} more than once"
            ),
            Self::DuplicateExecutionPlan { sequence } => write!(
                f,
                "execution plan appears more than once; duplicate is at sequence {sequence}"
            ),
            Self::ExecutionPlanWaveIndexMismatch {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "execution plan at sequence {sequence} has wave index {found}, expected {expected}"
            ),
            Self::ExecutionPlanUnknownTask { sequence, task_id } => write!(
                f,
                "execution plan at sequence {sequence} references undeclared task {task_id}"
            ),
            Self::ExecutionPlanDuplicateTask { sequence, task_id } => write!(
                f,
                "execution plan at sequence {sequence} contains task {task_id} more than once"
            ),
            Self::ExecutionPlanMissingTask { sequence, task_id } => write!(
                f,
                "execution plan at sequence {sequence} omits declared task {task_id}"
            ),
            Self::RunStatusFromMismatch {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "run status transition at sequence {sequence} starts from {found}, replayed status is {expected}"
            ),
            Self::RunTransitionRejected { sequence, error } => {
                write!(f, "run status transition at sequence {sequence} was rejected: {error}")
            }
            Self::UnknownTask { sequence, task_id } => write!(
                f,
                "run event at sequence {sequence} references undeclared task {task_id}"
            ),
            Self::TaskStatusFromMismatch {
                sequence,
                task_id,
                expected,
                found,
            } => write!(
                f,
                "task {task_id} status change at sequence {sequence} starts from {found:?}, replayed status is {expected:?}"
            ),
            Self::DuplicateCompletionEvidence { sequence } => write!(
                f,
                "completion evidence appears more than once; duplicate is at sequence {sequence}"
            ),
            Self::CompletionEvidenceNotAttached {
                sequence,
                evidence_id,
            } => write!(
                f,
                "completion evidence at sequence {sequence} references unattached evidence {evidence_id}"
            ),
            Self::InvalidSpecialistRole { sequence, role } => write!(
                f,
                "specialist output at sequence {sequence} uses non-specialist role {role}"
            ),
            Self::SpecialistOutputRoleMismatch {
                sequence,
                producer_role,
                specialist_role,
            } => write!(
                f,
                "specialist output at sequence {sequence} declares role {specialist_role}, but event producer is {producer_role}"
            ),
            Self::UnauthorizedCoordinatorFinalResponse {
                sequence,
                producer_role,
            } => write!(
                f,
                "final response at sequence {sequence} was produced by unauthorized role {producer_role}"
            ),
            Self::DuplicateCoordinatorFinalResponse { sequence } => write!(
                f,
                "Coordinator final response appears more than once; duplicate is at sequence {sequence}"
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Deterministic runtime state reconstructed from one validated event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedRun {
    pub run_record: RunRecord,
    pub execution_plan: Option<ExecutionPlan>,
    pub task_statuses: BTreeMap<TaskId, TaskStatus>,
    pub completion_evidence: Option<CompletionEvidence>,
    pub specialist_outputs: Vec<SpecialistOutput>,
    pub coordinator_final_response: Option<CoordinatorFinalResponse>,
}

/// Reconstructs deterministic run state from one structurally valid event stream.
pub fn replay_run(
    events: &[RunEvent],
    goal: Option<&GoalContract>,
) -> Result<ReplayedRun, ReplayError> {
    validate_event_chain(events)?;

    let first = &events[0];
    let RunEventPayload::RunCreated {
        project_id,
        goal_id,
        task_ids,
        status,
        created_at,
        updated_at,
        started_at,
        finished_at,
    } = &first.payload
    else {
        unreachable!("validate_event_chain requires RunCreated first");
    };

    if *status != RunStatus::Draft {
        return Err(ReplayError::InitialRunStatusMismatch {
            event_id: first.id.clone(),
            expected: RunStatus::Draft,
            found: *status,
        });
    }

    if let Some(goal) = goal {
        if goal.id != *goal_id {
            return Err(ReplayError::GoalContractIdMismatch {
                expected: goal_id.clone(),
                found: goal.id.clone(),
            });
        }
        if goal.project_id != *project_id {
            return Err(ReplayError::GoalContractProjectIdMismatch {
                expected: project_id.clone(),
                found: goal.project_id.clone(),
            });
        }
    }

    let mut declared_tasks = BTreeSet::new();
    for task_id in task_ids {
        if !declared_tasks.insert(task_id.clone()) {
            return Err(ReplayError::DuplicateDeclaredTask {
                sequence: first.sequence,
                task_id: task_id.clone(),
            });
        }
    }

    let mut run_record = RunRecord {
        contract_version: first.contract_version,
        id: first.run_id.clone(),
        project_id: project_id.clone(),
        goal_id: goal_id.clone(),
        task_ids: task_ids.clone(),
        status: *status,
        event_count: 0,
        last_event_sequence: None,
        last_event_id: None,
        evidence_refs: Vec::new(),
        created_at: *created_at,
        updated_at: *updated_at,
        started_at: *started_at,
        finished_at: *finished_at,
    };
    let mut task_statuses = task_ids
        .iter()
        .cloned()
        .map(|task_id| (task_id, TaskStatus::Pending))
        .collect::<BTreeMap<_, _>>();
    let mut evidence_ids = BTreeSet::new();
    let mut execution_plan = None;
    let mut completion_evidence = None;
    let mut specialist_outputs = Vec::new();
    let mut coordinator_final_response = None;

    for event in events {
        match &event.payload {
            RunEventPayload::RunCreated { .. } | RunEventPayload::NoteRecorded { .. } => {}
            RunEventPayload::ExecutionPlanRecorded { plan } => {
                validate_nested_contract_version(
                    event.sequence,
                    "execution_plan",
                    plan.contract_version,
                )?;
                if execution_plan.is_some() {
                    return Err(ReplayError::DuplicateExecutionPlan {
                        sequence: event.sequence,
                    });
                }
                validate_execution_plan(event.sequence, plan, &declared_tasks)?;
                execution_plan = Some(plan.clone());
            }
            RunEventPayload::StatusTransition { from, to } => {
                if *from != run_record.status {
                    return Err(ReplayError::RunStatusFromMismatch {
                        sequence: event.sequence,
                        expected: run_record.status,
                        found: *from,
                    });
                }
                validate_run_transition(*from, *to, goal, completion_evidence.as_ref()).map_err(
                    |error| ReplayError::RunTransitionRejected {
                        sequence: event.sequence,
                        error,
                    },
                )?;
                if *to == RunStatus::Completed {
                    let evidence =
                        completion_evidence
                            .as_ref()
                            .ok_or(ReplayError::RunTransitionRejected {
                                sequence: event.sequence,
                                error: RunTransitionError::CompletionEvidenceMissing,
                            })?;
                    for evidence_id in &evidence.evidence_refs {
                        if !evidence_ids.contains(evidence_id) {
                            return Err(ReplayError::CompletionEvidenceNotAttached {
                                sequence: event.sequence,
                                evidence_id: evidence_id.clone(),
                            });
                        }
                    }
                }
                run_record.status = *to;
                if *to == RunStatus::Running && run_record.started_at.is_none() {
                    run_record.started_at = Some(event.occurred_at);
                }
                if to.is_terminal() && run_record.finished_at.is_none() {
                    run_record.finished_at = Some(event.occurred_at);
                }
            }
            RunEventPayload::TaskStatusChanged { task_id, from, to } => {
                let current =
                    task_statuses
                        .get_mut(task_id)
                        .ok_or_else(|| ReplayError::UnknownTask {
                            sequence: event.sequence,
                            task_id: task_id.clone(),
                        })?;
                if *from != *current {
                    return Err(ReplayError::TaskStatusFromMismatch {
                        sequence: event.sequence,
                        task_id: task_id.clone(),
                        expected: *current,
                        found: *from,
                    });
                }
                *current = *to;
            }
            RunEventPayload::EvidenceAttached { evidence_id } => {
                if evidence_ids.insert(evidence_id.clone()) {
                    run_record.evidence_refs.push(evidence_id.clone());
                }
            }
            RunEventPayload::CompletionEvidenceRecorded { evidence } => {
                validate_nested_contract_version(
                    event.sequence,
                    "completion_evidence",
                    evidence.contract_version,
                )?;
                if completion_evidence.is_some() {
                    return Err(ReplayError::DuplicateCompletionEvidence {
                        sequence: event.sequence,
                    });
                }
                completion_evidence = Some(evidence.clone());
            }
            RunEventPayload::SpecialistOutputRecorded { output } => {
                validate_nested_contract_version(
                    event.sequence,
                    "specialist_output",
                    output.contract_version,
                )?;
                if !declared_tasks.contains(&output.task_id) {
                    return Err(ReplayError::UnknownTask {
                        sequence: event.sequence,
                        task_id: output.task_id.clone(),
                    });
                }
                if !matches!(
                    output.specialist_role,
                    Role::Engineer | Role::Reviewer | Role::Auditor
                ) {
                    return Err(ReplayError::InvalidSpecialistRole {
                        sequence: event.sequence,
                        role: output.specialist_role,
                    });
                }
                if event.producer_role != output.specialist_role {
                    return Err(ReplayError::SpecialistOutputRoleMismatch {
                        sequence: event.sequence,
                        producer_role: event.producer_role,
                        specialist_role: output.specialist_role,
                    });
                }
                specialist_outputs.push(output.clone());
            }
            RunEventPayload::CoordinatorFinalResponseRecorded { response } => {
                validate_nested_contract_version(
                    event.sequence,
                    "coordinator_final_response",
                    response.contract_version,
                )?;
                if event.producer_role != Role::Coordinator {
                    return Err(ReplayError::UnauthorizedCoordinatorFinalResponse {
                        sequence: event.sequence,
                        producer_role: event.producer_role,
                    });
                }
                if coordinator_final_response.is_some() {
                    return Err(ReplayError::DuplicateCoordinatorFinalResponse {
                        sequence: event.sequence,
                    });
                }
                coordinator_final_response = Some(response.clone());
            }
        }

        run_record.event_count += 1;
        run_record.last_event_sequence = Some(event.sequence);
        run_record.last_event_id = Some(event.id.clone());
        if event.sequence > 0 {
            run_record.updated_at = event.occurred_at;
        }
    }

    Ok(ReplayedRun {
        run_record,
        execution_plan,
        task_statuses,
        completion_evidence,
        specialist_outputs,
        coordinator_final_response,
    })
}

fn validate_nested_contract_version(
    sequence: u64,
    contract: &'static str,
    found: ContractVersion,
) -> Result<(), ReplayError> {
    let expected = ContractVersion::current();
    if found == expected {
        Ok(())
    } else {
        Err(ReplayError::NestedContractVersionMismatch {
            sequence,
            contract,
            expected,
            found,
        })
    }
}

fn validate_execution_plan(
    sequence: u64,
    plan: &ExecutionPlan,
    declared_tasks: &BTreeSet<TaskId>,
) -> Result<(), ReplayError> {
    let mut planned_tasks = BTreeSet::new();
    for (expected_index, wave) in plan.waves.iter().enumerate() {
        if u64::from(wave.index) != expected_index as u64 {
            return Err(ReplayError::ExecutionPlanWaveIndexMismatch {
                sequence,
                expected: expected_index as u64,
                found: wave.index,
            });
        }
        for task_id in &wave.task_ids {
            if !declared_tasks.contains(task_id) {
                return Err(ReplayError::ExecutionPlanUnknownTask {
                    sequence,
                    task_id: task_id.clone(),
                });
            }
            if !planned_tasks.insert(task_id.clone()) {
                return Err(ReplayError::ExecutionPlanDuplicateTask {
                    sequence,
                    task_id: task_id.clone(),
                });
            }
        }
    }
    if let Some(task_id) = declared_tasks.difference(&planned_tasks).next() {
        return Err(ReplayError::ExecutionPlanMissingTask {
            sequence,
            task_id: task_id.clone(),
        });
    }
    Ok(())
}

/// Validates the durable structural invariants of one ordered run event stream.
///
/// This function does not apply event payloads or reconstruct runtime state. On
/// success it returns the single run identity shared by the validated events.
pub fn validate_event_chain(events: &[RunEvent]) -> Result<RunId, ReplayError> {
    let first = events.first().ok_or(ReplayError::EmptyStream)?;
    let expected_run_id = first.run_id.clone();
    let mut previous_event_id: Option<&EventId> = None;
    let mut seen_event_ids = BTreeMap::new();

    for (index, event) in events.iter().enumerate() {
        let expected_sequence = index as u64;

        if event.contract_version != ContractVersion::current() {
            return Err(ReplayError::ContractVersionMismatch {
                sequence: event.sequence,
                expected: ContractVersion::current(),
                found: event.contract_version,
            });
        }

        if index == 0 {
            if !matches!(event.payload, RunEventPayload::RunCreated { .. }) {
                return Err(ReplayError::FirstEventNotRunCreated {
                    event_id: event.id.clone(),
                });
            }
        } else if matches!(event.payload, RunEventPayload::RunCreated { .. }) {
            return Err(ReplayError::DuplicateRunCreated {
                sequence: event.sequence,
                event_id: event.id.clone(),
            });
        }

        if event.run_id != expected_run_id {
            return Err(ReplayError::RunIdMismatch {
                sequence: event.sequence,
                expected: expected_run_id.clone(),
                found: event.run_id.clone(),
            });
        }

        if event.sequence != expected_sequence {
            return Err(ReplayError::SequenceMismatch {
                event_id: event.id.clone(),
                expected: expected_sequence,
                found: event.sequence,
            });
        }

        if index == 0 {
            if let Some(found) = &event.previous_event_id {
                return Err(ReplayError::InitialPreviousEventIdPresent {
                    event_id: event.id.clone(),
                    found: found.clone(),
                });
            }
        } else {
            let expected = previous_event_id.expect("a non-initial event has a predecessor");
            if event.previous_event_id.as_ref() != Some(expected) {
                return Err(ReplayError::PreviousEventIdMismatch {
                    sequence: event.sequence,
                    event_id: event.id.clone(),
                    expected: expected.clone(),
                    found: event.previous_event_id.clone(),
                });
            }
        }

        if let Some(first_sequence) = seen_event_ids.insert(event.id.clone(), event.sequence) {
            return Err(ReplayError::DuplicateEventId {
                event_id: event.id.clone(),
                first_sequence,
                duplicate_sequence: event.sequence,
            });
        }

        previous_event_id = Some(&event.id);
    }

    Ok(expected_run_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};
    use ovca_storage::RunEventLog;
    use ovca_types::{
        CompletionPrecondition, EvidenceId, ExecutionMode, ExecutionWave, PermissionProfile,
        RiskTier,
    };
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn occurred_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .expect("fixed test timestamp should parse")
            .with_timezone(&Utc)
    }

    fn run_created() -> RunEventPayload {
        RunEventPayload::RunCreated {
            project_id: ProjectId::from("project-1"),
            goal_id: GoalId::from("goal-1"),
            task_ids: vec![],
            status: RunStatus::Draft,
            created_at: occurred_at(),
            updated_at: occurred_at(),
            started_at: None,
            finished_at: None,
        }
    }

    fn event(
        sequence: u64,
        id: &str,
        previous_event_id: Option<&str>,
        run_id: &str,
        payload: RunEventPayload,
    ) -> RunEvent {
        RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from(id),
            run_id: RunId::from(run_id),
            sequence,
            previous_event_id: previous_event_id.map(EventId::from),
            occurred_at: occurred_at(),
            producer_role: Role::Coordinator,
            payload,
            metadata: BTreeMap::new(),
        }
    }

    fn valid_chain() -> Vec<RunEvent> {
        vec![
            event(0, "event-0", None, "run-1", run_created()),
            event(
                1,
                "event-1",
                Some("event-0"),
                "run-1",
                RunEventPayload::NoteRecorded {
                    message: "deterministic note".to_owned(),
                },
            ),
        ]
    }

    fn run_created_with_tasks(status: RunStatus, task_ids: &[&str]) -> RunEventPayload {
        RunEventPayload::RunCreated {
            project_id: ProjectId::from("project-1"),
            goal_id: GoalId::from("goal-1"),
            task_ids: task_ids.iter().copied().map(TaskId::from).collect(),
            status,
            created_at: occurred_at(),
            updated_at: occurred_at(),
            started_at: None,
            finished_at: None,
        }
    }

    fn state_chain(status: RunStatus, task_ids: &[&str]) -> Vec<RunEvent> {
        let mut events = vec![event(
            0,
            "event-0",
            None,
            "run-1",
            run_created_with_tasks(RunStatus::Draft, task_ids),
        )];
        let transitions: &[(RunStatus, RunStatus)] = match status {
            RunStatus::Draft => &[],
            RunStatus::Accepted => &[(RunStatus::Draft, RunStatus::Accepted)],
            RunStatus::Planned => &[
                (RunStatus::Draft, RunStatus::Accepted),
                (RunStatus::Accepted, RunStatus::Planned),
            ],
            RunStatus::Running => &[
                (RunStatus::Draft, RunStatus::Accepted),
                (RunStatus::Accepted, RunStatus::Planned),
                (RunStatus::Planned, RunStatus::Running),
            ],
            unsupported => {
                panic!("state_chain does not support terminal/intermediate status {unsupported}")
            }
        };

        for (index, (from, to)) in transitions.iter().enumerate() {
            let id = format!("state-event-{}", index + 1);
            append_event(
                &mut events,
                &id,
                Role::Coordinator,
                RunEventPayload::StatusTransition {
                    from: *from,
                    to: *to,
                },
            );
        }

        events
    }

    fn append_event(
        events: &mut Vec<RunEvent>,
        id: &str,
        producer_role: Role,
        payload: RunEventPayload,
    ) {
        let sequence = events.len() as u64;
        let previous_event_id = events.last().map(|event| event.id.clone());
        events.push(RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from(id),
            run_id: RunId::from("run-1"),
            sequence,
            previous_event_id,
            occurred_at: occurred_at() + Duration::seconds(sequence as i64),
            producer_role,
            payload,
            metadata: BTreeMap::new(),
        });
    }

    fn goal_contract(id: &str) -> GoalContract {
        GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from(id),
            project_id: ProjectId::from("project-1"),
            objective: "replay the run".to_owned(),
            constraints: Vec::new(),
            acceptance_criteria: vec!["accepted".to_owned()],
            verification_criteria: vec!["verified".to_owned()],
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R0,
                resource_keys: Vec::new(),
                write_keys: Vec::new(),
                approval_required: false,
                review_required: false,
                audit_required: false,
            },
            definition_of_done: vec!["done".to_owned()],
            completion_precondition: CompletionPrecondition {
                contract_version: ContractVersion::current(),
                minimum_evidence_refs: 1,
                require_all_acceptance_criteria: true,
                require_all_verification_criteria: true,
            },
            created_at: occurred_at(),
            updated_at: occurred_at(),
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

    fn plan(task_ids: &[&str]) -> ExecutionPlan {
        ExecutionPlan {
            contract_version: ContractVersion::current(),
            waves: task_ids
                .iter()
                .enumerate()
                .map(|(index, task_id)| ExecutionWave {
                    index: index as u32,
                    mode: ExecutionMode::Sequential,
                    task_ids: vec![TaskId::from(*task_id)],
                })
                .collect(),
        }
    }

    fn specialist_output(task_id: &str, role: Role, summary: &str) -> SpecialistOutput {
        SpecialistOutput {
            contract_version: ContractVersion::current(),
            task_id: TaskId::from(task_id),
            specialist_role: role,
            summary: summary.to_owned(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
        }
    }

    fn final_response(response: &str) -> CoordinatorFinalResponse {
        CoordinatorFinalResponse {
            contract_version: ContractVersion::current(),
            response: response.to_owned(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
        }
    }

    #[test]
    fn valid_chain_returns_run_identity() {
        assert_eq!(
            validate_event_chain(&valid_chain()),
            Ok(RunId::from("run-1"))
        );
    }

    #[test]
    fn rejects_empty_stream() {
        assert_eq!(validate_event_chain(&[]), Err(ReplayError::EmptyStream));
    }

    #[test]
    fn rejects_non_current_contract_version() {
        let mut events = valid_chain();
        events[1].contract_version = ContractVersion(2);

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::ContractVersionMismatch {
                sequence: 1,
                expected: ContractVersion::current(),
                found: ContractVersion(2),
            })
        );
    }

    #[test]
    fn rejects_first_payload_other_than_run_created() {
        let mut events = valid_chain();
        events[0].payload = RunEventPayload::NoteRecorded {
            message: "not created".to_owned(),
        };

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::FirstEventNotRunCreated {
                event_id: EventId::from("event-0"),
            })
        );
    }

    #[test]
    fn rejects_duplicate_run_created() {
        let mut events = valid_chain();
        events[1].payload = run_created();

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::DuplicateRunCreated {
                sequence: 1,
                event_id: EventId::from("event-1"),
            })
        );
    }

    #[test]
    fn rejects_mismatched_run_id() {
        let mut events = valid_chain();
        events[1].run_id = RunId::from("run-2");

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::RunIdMismatch {
                sequence: 1,
                expected: RunId::from("run-1"),
                found: RunId::from("run-2"),
            })
        );
    }

    #[test]
    fn rejects_sequence_that_does_not_start_at_zero() {
        let mut events = valid_chain();
        events[0].sequence = 1;

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::SequenceMismatch {
                event_id: EventId::from("event-0"),
                expected: 0,
                found: 1,
            })
        );
    }

    #[test]
    fn rejects_non_contiguous_sequence() {
        let mut events = valid_chain();
        events[1].sequence = 2;

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::SequenceMismatch {
                event_id: EventId::from("event-1"),
                expected: 1,
                found: 2,
            })
        );
    }

    #[test]
    fn rejects_initial_previous_event_id() {
        let mut events = valid_chain();
        events[0].previous_event_id = Some(EventId::from("unexpected"));

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::InitialPreviousEventIdPresent {
                event_id: EventId::from("event-0"),
                found: EventId::from("unexpected"),
            })
        );
    }

    #[test]
    fn rejects_missing_previous_event_id_after_initial_event() {
        let mut events = valid_chain();
        events[1].previous_event_id = None;

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::PreviousEventIdMismatch {
                sequence: 1,
                event_id: EventId::from("event-1"),
                expected: EventId::from("event-0"),
                found: None,
            })
        );
    }

    #[test]
    fn rejects_wrong_previous_event_id_after_initial_event() {
        let mut events = valid_chain();
        events[1].previous_event_id = Some(EventId::from("wrong-event"));

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::PreviousEventIdMismatch {
                sequence: 1,
                event_id: EventId::from("event-1"),
                expected: EventId::from("event-0"),
                found: Some(EventId::from("wrong-event")),
            })
        );
    }

    #[test]
    fn rejects_duplicate_event_id() {
        let mut events = valid_chain();
        events[1].id = EventId::from("event-0");

        assert_eq!(
            validate_event_chain(&events),
            Err(ReplayError::DuplicateEventId {
                event_id: EventId::from("event-0"),
                first_sequence: 0,
                duplicate_sequence: 1,
            })
        );
    }

    #[test]
    fn replay_run_reconstructs_full_valid_state_exactly() {
        let created_at = occurred_at() - Duration::hours(1);
        let initial_updated_at = occurred_at() - Duration::minutes(30);
        let mut events = state_chain(RunStatus::Draft, &["task-1", "task-2"]);
        let RunEventPayload::RunCreated {
            created_at: payload_created_at,
            updated_at: payload_updated_at,
            ..
        } = &mut events[0].payload
        else {
            unreachable!("state_chain starts with RunCreated");
        };
        *payload_created_at = created_at;
        *payload_updated_at = initial_updated_at;

        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Draft,
                to: RunStatus::Accepted,
            },
        );
        let expected_plan = plan(&["task-1", "task-2"]);
        append_event(
            &mut events,
            "event-2",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded {
                plan: expected_plan.clone(),
            },
        );
        append_event(
            &mut events,
            "event-3",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Accepted,
                to: RunStatus::Planned,
            },
        );
        append_event(
            &mut events,
            "event-4",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        );
        append_event(
            &mut events,
            "event-5",
            Role::Engineer,
            RunEventPayload::TaskStatusChanged {
                task_id: TaskId::from("task-1"),
                from: TaskStatus::Pending,
                to: TaskStatus::Running,
            },
        );
        append_event(
            &mut events,
            "event-6",
            Role::Engineer,
            RunEventPayload::TaskStatusChanged {
                task_id: TaskId::from("task-1"),
                from: TaskStatus::Running,
                to: TaskStatus::Completed,
            },
        );
        append_event(
            &mut events,
            "event-7",
            Role::Reviewer,
            RunEventPayload::TaskStatusChanged {
                task_id: TaskId::from("task-2"),
                from: TaskStatus::Pending,
                to: TaskStatus::Ready,
            },
        );
        append_event(
            &mut events,
            "event-8",
            Role::Engineer,
            RunEventPayload::EvidenceAttached {
                evidence_id: EvidenceId::from("evidence-2"),
            },
        );
        append_event(
            &mut events,
            "event-9",
            Role::Engineer,
            RunEventPayload::EvidenceAttached {
                evidence_id: EvidenceId::from("evidence-1"),
            },
        );
        append_event(
            &mut events,
            "event-10",
            Role::Reviewer,
            RunEventPayload::EvidenceAttached {
                evidence_id: EvidenceId::from("evidence-2"),
            },
        );
        let expected_output = specialist_output("task-1", Role::Engineer, "implemented");
        append_event(
            &mut events,
            "event-11",
            Role::Engineer,
            RunEventPayload::SpecialistOutputRecorded {
                output: expected_output.clone(),
            },
        );
        let expected_completion_evidence = completion_evidence();
        append_event(
            &mut events,
            "event-12",
            Role::Reviewer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: expected_completion_evidence.clone(),
            },
        );
        let expected_final_response = final_response("goal completed");
        append_event(
            &mut events,
            "event-13",
            Role::Coordinator,
            RunEventPayload::CoordinatorFinalResponseRecorded {
                response: expected_final_response.clone(),
            },
        );
        append_event(
            &mut events,
            "event-14",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );

        let replayed = replay_run(&events, Some(&goal_contract("goal-1")))
            .expect("valid events should replay");

        assert_eq!(
            replayed.run_record,
            RunRecord {
                contract_version: ContractVersion::current(),
                id: RunId::from("run-1"),
                project_id: ProjectId::from("project-1"),
                goal_id: GoalId::from("goal-1"),
                task_ids: vec![TaskId::from("task-1"), TaskId::from("task-2")],
                status: RunStatus::Completed,
                event_count: 15,
                last_event_sequence: Some(14),
                last_event_id: Some(EventId::from("event-14")),
                evidence_refs: vec![
                    EvidenceId::from("evidence-2"),
                    EvidenceId::from("evidence-1"),
                ],
                created_at,
                updated_at: occurred_at() + Duration::seconds(14),
                started_at: Some(occurred_at() + Duration::seconds(4)),
                finished_at: Some(occurred_at() + Duration::seconds(14)),
            }
        );
        assert_eq!(replayed.execution_plan, Some(expected_plan));
        assert_eq!(
            replayed.task_statuses,
            BTreeMap::from([
                (TaskId::from("task-1"), TaskStatus::Completed),
                (TaskId::from("task-2"), TaskStatus::Ready),
            ])
        );
        assert_eq!(
            replayed.completion_evidence,
            Some(expected_completion_evidence)
        );
        assert_eq!(replayed.specialist_outputs, vec![expected_output]);
        assert_eq!(
            replayed.coordinator_final_response,
            Some(expected_final_response)
        );
    }

    #[test]
    fn replay_run_matches_after_durable_event_log_reopen() {
        let events = state_chain(RunStatus::Running, &["task-1"]);
        let goal = goal_contract("goal-1");
        let in_memory = replay_run(&events, Some(&goal)).expect("valid events should replay");
        let dir = TempDir::new().expect("temporary run-event root should be created");

        let log = RunEventLog::new(dir.path());
        for event in &events {
            log.append(event).expect("event append should succeed");
        }
        drop(log);

        let reopened = RunEventLog::new(dir.path());
        let reloaded = reopened
            .load_run(&RunId::from("run-1"))
            .expect("persisted run events should reload");
        let from_storage =
            replay_run(&reloaded, Some(&goal)).expect("reloaded events should replay");

        assert_eq!(from_storage, in_memory);
    }

    #[test]
    fn replay_run_preserves_run_created_updated_at_without_later_events() {
        let expected_updated_at = occurred_at() - Duration::minutes(30);
        let mut events = state_chain(RunStatus::Draft, &[]);
        let RunEventPayload::RunCreated { updated_at, .. } = &mut events[0].payload else {
            unreachable!("state_chain starts with RunCreated");
        };
        *updated_at = expected_updated_at;

        let replayed = replay_run(&events, None).expect("RunCreated should replay");

        assert_eq!(replayed.run_record.updated_at, expected_updated_at);
        assert_eq!(replayed.run_record.event_count, 1);
        assert_eq!(replayed.run_record.last_event_sequence, Some(0));
        assert_eq!(
            replayed.run_record.last_event_id,
            Some(EventId::from("event-0"))
        );
    }

    #[test]
    fn replay_run_rejects_initial_completed_status() {
        let events = vec![event(
            0,
            "event-0",
            None,
            "run-1",
            run_created_with_tasks(RunStatus::Completed, &[]),
        )];

        assert_eq!(
            replay_run(&events, Some(&goal_contract("goal-1"))),
            Err(ReplayError::InitialRunStatusMismatch {
                event_id: EventId::from("event-0"),
                expected: RunStatus::Draft,
                found: RunStatus::Completed,
            })
        );
    }

    #[test]
    fn replay_run_rejects_initial_running_status() {
        let events = vec![event(
            0,
            "event-0",
            None,
            "run-1",
            run_created_with_tasks(RunStatus::Running, &[]),
        )];

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::InitialRunStatusMismatch {
                event_id: EventId::from("event-0"),
                expected: RunStatus::Draft,
                found: RunStatus::Running,
            })
        );
    }

    #[test]
    fn replay_run_rejects_completion_missing_goal_contract() {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Engineer,
            RunEventPayload::EvidenceAttached {
                evidence_id: EvidenceId::from("evidence-1"),
            },
        );
        append_event(
            &mut events,
            "event-2",
            Role::Reviewer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: completion_evidence(),
            },
        );
        append_event(
            &mut events,
            "event-3",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::RunTransitionRejected {
                sequence: 6,
                error: RunTransitionError::CompletionContractMissing,
            })
        );
    }

    #[test]
    fn replay_run_rejects_completion_missing_completion_evidence() {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal_contract("goal-1"))),
            Err(ReplayError::RunTransitionRejected {
                sequence: 4,
                error: RunTransitionError::CompletionEvidenceMissing,
            })
        );
    }

    #[test]
    fn replay_run_rejects_completion_evidence_id_not_attached() {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Reviewer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: completion_evidence(),
            },
        );
        append_event(
            &mut events,
            "event-2",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal_contract("goal-1"))),
            Err(ReplayError::CompletionEvidenceNotAttached {
                sequence: 5,
                evidence_id: EvidenceId::from("evidence-1"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_run_status_from_mismatch() {
        let mut events = state_chain(RunStatus::Draft, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Accepted,
                to: RunStatus::Planned,
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::RunStatusFromMismatch {
                sequence: 1,
                expected: RunStatus::Draft,
                found: RunStatus::Accepted,
            })
        );
    }

    #[test]
    fn replay_run_rejects_unknown_task() {
        let mut events = state_chain(RunStatus::Running, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Engineer,
            RunEventPayload::TaskStatusChanged {
                task_id: TaskId::from("task-2"),
                from: TaskStatus::Pending,
                to: TaskStatus::Running,
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::UnknownTask {
                sequence: 4,
                task_id: TaskId::from("task-2"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_task_status_from_mismatch() {
        let mut events = state_chain(RunStatus::Running, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Engineer,
            RunEventPayload::TaskStatusChanged {
                task_id: TaskId::from("task-1"),
                from: TaskStatus::Running,
                to: TaskStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::TaskStatusFromMismatch {
                sequence: 4,
                task_id: TaskId::from("task-1"),
                expected: TaskStatus::Pending,
                found: TaskStatus::Running,
            })
        );
    }

    #[test]
    fn replay_run_rejects_duplicate_declared_task() {
        let events = state_chain(RunStatus::Draft, &["task-1", "task-1"]);

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::DuplicateDeclaredTask {
                sequence: 0,
                task_id: TaskId::from("task-1"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_duplicate_execution_plan() {
        let mut events = state_chain(RunStatus::Accepted, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded {
                plan: plan(&["task-1"]),
            },
        );
        append_event(
            &mut events,
            "event-2",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded {
                plan: plan(&["task-1"]),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::DuplicateExecutionPlan { sequence: 3 })
        );
    }

    #[test]
    fn replay_run_rejects_missing_declared_task_in_plan() {
        let mut events = state_chain(RunStatus::Accepted, &["task-1", "task-2"]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded {
                plan: plan(&["task-1"]),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::ExecutionPlanMissingTask {
                sequence: 2,
                task_id: TaskId::from("task-2"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_unknown_task_in_plan() {
        let mut events = state_chain(RunStatus::Accepted, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded {
                plan: plan(&["task-2"]),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::ExecutionPlanUnknownTask {
                sequence: 2,
                task_id: TaskId::from("task-2"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_coordinator_specialist_role() {
        let mut events = state_chain(RunStatus::Running, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::SpecialistOutputRecorded {
                output: specialist_output("task-1", Role::Coordinator, "invalid"),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::InvalidSpecialistRole {
                sequence: 4,
                role: Role::Coordinator,
            })
        );
    }

    #[test]
    fn replay_run_rejects_producer_output_specialist_role_mismatch() {
        let mut events = state_chain(RunStatus::Running, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Reviewer,
            RunEventPayload::SpecialistOutputRecorded {
                output: specialist_output("task-1", Role::Engineer, "mismatched"),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::SpecialistOutputRoleMismatch {
                sequence: 4,
                producer_role: Role::Reviewer,
                specialist_role: Role::Engineer,
            })
        );
    }

    #[test]
    fn replay_run_rejects_unauthorized_final_response() {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Engineer,
            RunEventPayload::CoordinatorFinalResponseRecorded {
                response: final_response("unauthorized"),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::UnauthorizedCoordinatorFinalResponse {
                sequence: 4,
                producer_role: Role::Engineer,
            })
        );
    }

    #[test]
    fn replay_run_rejects_duplicate_final_response() {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::CoordinatorFinalResponseRecorded {
                response: final_response("first"),
            },
        );
        append_event(
            &mut events,
            "event-2",
            Role::Coordinator,
            RunEventPayload::CoordinatorFinalResponseRecorded {
                response: final_response("second"),
            },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::DuplicateCoordinatorFinalResponse { sequence: 5 })
        );
    }

    #[test]
    fn replay_run_rejects_nested_contract_version_mismatch() {
        let mut invalid_plan = plan(&["task-1"]);
        invalid_plan.contract_version = ContractVersion(2);
        let mut events = state_chain(RunStatus::Accepted, &["task-1"]);
        append_event(
            &mut events,
            "event-1",
            Role::Coordinator,
            RunEventPayload::ExecutionPlanRecorded { plan: invalid_plan },
        );

        assert_eq!(
            replay_run(&events, None),
            Err(ReplayError::NestedContractVersionMismatch {
                sequence: 2,
                contract: "execution_plan",
                expected: ContractVersion::current(),
                found: ContractVersion(2),
            })
        );
    }

    #[test]
    fn replay_run_rejects_supplied_goal_contract_id_mismatch() {
        let events = state_chain(RunStatus::Draft, &[]);

        assert_eq!(
            replay_run(&events, Some(&goal_contract("goal-2"))),
            Err(ReplayError::GoalContractIdMismatch {
                expected: GoalId::from("goal-1"),
                found: GoalId::from("goal-2"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_supplied_goal_contract_project_id_mismatch() {
        let events = state_chain(RunStatus::Draft, &[]);
        let mut goal = goal_contract("goal-1");
        goal.project_id = ProjectId::from("project-2");

        assert_eq!(
            replay_run(&events, Some(&goal)),
            Err(ReplayError::GoalContractProjectIdMismatch {
                expected: ProjectId::from("project-1"),
                found: ProjectId::from("project-2"),
            })
        );
    }
}
