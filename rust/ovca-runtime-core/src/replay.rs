use crate::review_audit::{evaluate_review_audit, ReviewAuditError, ReviewAuditEvaluationContext};
use ovca_types::{
    validate_run_transition, validate_run_transition_with_guard_requirements, AuditDecision,
    AuditDecisionId, CompletionEvidence, ContractVersion, CoordinatorFinalResponse, EventId,
    EvidenceId, EvidenceRef, ExecutionPlan, GoalContract, GoalId, ProjectId,
    ReviewAuditRequirements, ReviewAuditResolution, ReviewDecision, ReviewDecisionId, Role,
    RunEvent, RunEventPayload, RunGuardProjection, RunId, RunRecord, RunStatus, RunTransitionError,
    SpecialistOutput, TaskId, TaskStatus,
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
    ReviewAuditEvaluationFailed {
        sequence: u64,
        error: ReviewAuditError,
    },
    ReviewAuditResolutionRejected {
        sequence: u64,
        resolution: ReviewAuditResolution,
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
    DuplicateEvidenceReference {
        sequence: u64,
        evidence_id: EvidenceId,
    },
    DuplicateReviewAuditRequirements {
        sequence: u64,
    },
    DecisionRunIdMismatch {
        sequence: u64,
        contract: &'static str,
        expected: RunId,
        found: RunId,
    },
    DecisionGoalIdMismatch {
        sequence: u64,
        contract: &'static str,
        expected: GoalId,
        found: GoalId,
    },
    DecisionProducerRoleMismatch {
        sequence: u64,
        contract: &'static str,
        expected: Role,
        event_role: Role,
        decision_role: Role,
    },
    DuplicateReviewDecision {
        sequence: u64,
        decision_id: ReviewDecisionId,
    },
    DuplicateAuditDecision {
        sequence: u64,
        decision_id: AuditDecisionId,
    },
    AuditReviewDecisionNotRecorded {
        sequence: u64,
        review_decision_id: ReviewDecisionId,
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
            Self::ReviewAuditEvaluationFailed { sequence, error } => write!(
                f,
                "completion review/audit evaluation at sequence {sequence} failed: {error}"
            ),
            Self::ReviewAuditResolutionRejected {
                sequence,
                resolution,
            } => write!(
                f,
                "completion review/audit resolution at sequence {sequence} was rejected: {resolution:?}"
            ),
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
            Self::DuplicateEvidenceReference {
                sequence,
                evidence_id,
            } => write!(
                f,
                "evidence reference {evidence_id} is duplicated at sequence {sequence}"
            ),
            Self::DuplicateReviewAuditRequirements { sequence } => write!(
                f,
                "review/audit requirements appear more than once; duplicate is at sequence {sequence}"
            ),
            Self::DecisionRunIdMismatch {
                sequence,
                contract,
                expected,
                found,
            } => write!(
                f,
                "{contract} at sequence {sequence} has run ID {found}, expected {expected}"
            ),
            Self::DecisionGoalIdMismatch {
                sequence,
                contract,
                expected,
                found,
            } => write!(
                f,
                "{contract} at sequence {sequence} has goal ID {found}, expected {expected}"
            ),
            Self::DecisionProducerRoleMismatch {
                sequence,
                contract,
                expected,
                event_role,
                decision_role,
            } => write!(
                f,
                "{contract} at sequence {sequence} requires event and decision role {expected}, found event role {event_role} and decision role {decision_role}"
            ),
            Self::DuplicateReviewDecision {
                sequence,
                decision_id,
            } => write!(
                f,
                "review decision {decision_id} is duplicated at sequence {sequence}"
            ),
            Self::DuplicateAuditDecision {
                sequence,
                decision_id,
            } => write!(
                f,
                "audit decision {decision_id} is duplicated at sequence {sequence}"
            ),
            Self::AuditReviewDecisionNotRecorded {
                sequence,
                review_decision_id,
            } => write!(
                f,
                "audit decision at sequence {sequence} references review decision {review_decision_id} before it was recorded"
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
    pub evidence_references: Vec<EvidenceRef>,
    pub guard_outcomes: Vec<RunGuardProjection>,
    pub review_audit_requirements: Option<ReviewAuditRequirements>,
    pub review_decisions: Vec<ReviewDecision>,
    pub audit_decisions: Vec<AuditDecision>,
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
    let mut evidence_references = Vec::new();
    let mut guard_outcomes = Vec::new();
    let mut review_audit_requirements = None;
    let mut review_decision_ids = BTreeSet::new();
    let mut review_decisions = Vec::new();
    let mut audit_decision_ids = BTreeSet::new();
    let mut audit_decisions = Vec::new();
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
                let empty_guard_requirements = BTreeSet::new();
                let guard_requirements = review_audit_requirements.as_ref().map_or(
                    &empty_guard_requirements,
                    |requirements: &ReviewAuditRequirements| &requirements.guard_requirements,
                );
                let transition_result = if *to == RunStatus::Completed {
                    validate_run_transition_with_guard_requirements(
                        *from,
                        *to,
                        goal,
                        completion_evidence.as_ref(),
                        guard_requirements,
                    )
                } else {
                    validate_run_transition(*from, *to, goal, completion_evidence.as_ref())
                };
                transition_result.map_err(|error| ReplayError::RunTransitionRejected {
                    sequence: event.sequence,
                    error,
                })?;
                if *to == RunStatus::Completed {
                    let goal = goal.ok_or(ReplayError::RunTransitionRejected {
                        sequence: event.sequence,
                        error: RunTransitionError::CompletionContractMissing,
                    })?;
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
                    let resolution = evaluate_review_audit(
                        &ReviewAuditEvaluationContext {
                            expected_run_id: &run_record.id,
                            goal_contract: goal,
                            completion_evidence: evidence,
                            evidence_catalog: &evidence_references,
                            guard_requirements,
                        },
                        review_decisions.first(),
                        audit_decisions.first(),
                    )
                    .map_err(|error| {
                        ReplayError::ReviewAuditEvaluationFailed {
                            sequence: event.sequence,
                            error,
                        }
                    })?;
                    if !matches!(&resolution, ReviewAuditResolution::Pass { .. }) {
                        return Err(ReplayError::ReviewAuditResolutionRejected {
                            sequence: event.sequence,
                            resolution,
                        });
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
            RunEventPayload::EvidenceReferenceRecorded { evidence } => {
                validate_nested_contract_version(
                    event.sequence,
                    "evidence_reference",
                    evidence.contract_version,
                )?;
                if let Some(integrity) = &evidence.integrity {
                    validate_nested_contract_version(
                        event.sequence,
                        "evidence_integrity",
                        integrity.contract_version,
                    )?;
                }
                if !evidence_ids.insert(evidence.id.clone()) {
                    return Err(ReplayError::DuplicateEvidenceReference {
                        sequence: event.sequence,
                        evidence_id: evidence.id.clone(),
                    });
                }
                run_record.evidence_refs.push(evidence.id.clone());
                evidence_references.push(evidence.clone());
            }
            RunEventPayload::GuardOutcomeRecorded { projection } => {
                validate_nested_contract_version(
                    event.sequence,
                    "run_guard_projection",
                    projection.contract_version,
                )?;
                guard_outcomes.push(projection.clone());
            }
            RunEventPayload::ReviewAuditRequirementsRecorded { requirements } => {
                validate_nested_contract_version(
                    event.sequence,
                    "review_audit_requirements",
                    requirements.contract_version,
                )?;
                if review_audit_requirements.is_some() {
                    return Err(ReplayError::DuplicateReviewAuditRequirements {
                        sequence: event.sequence,
                    });
                }
                review_audit_requirements = Some(requirements.clone());
            }
            RunEventPayload::ReviewDecisionRecorded { decision } => {
                validate_nested_contract_version(
                    event.sequence,
                    "review_decision",
                    decision.contract_version,
                )?;
                for assessment in &decision.assessments {
                    validate_nested_contract_version(
                        event.sequence,
                        "review_criterion_assessment",
                        assessment.contract_version,
                    )?;
                }
                validate_decision_binding(
                    event.sequence,
                    "review_decision",
                    &run_record,
                    &decision.run_id,
                    &decision.goal_id,
                )?;
                validate_decision_role(
                    event.sequence,
                    "review_decision",
                    Role::Reviewer,
                    event.producer_role,
                    decision.producer_role,
                )?;
                if !review_decisions.is_empty() || !review_decision_ids.insert(decision.id.clone())
                {
                    return Err(ReplayError::DuplicateReviewDecision {
                        sequence: event.sequence,
                        decision_id: decision.id.clone(),
                    });
                }
                review_decisions.push(decision.clone());
            }
            RunEventPayload::AuditDecisionRecorded { decision } => {
                validate_nested_contract_version(
                    event.sequence,
                    "audit_decision",
                    decision.contract_version,
                )?;
                for assessment in &decision.assessments {
                    validate_nested_contract_version(
                        event.sequence,
                        "audit_criterion_assessment",
                        assessment.contract_version,
                    )?;
                }
                validate_decision_binding(
                    event.sequence,
                    "audit_decision",
                    &run_record,
                    &decision.run_id,
                    &decision.goal_id,
                )?;
                validate_decision_role(
                    event.sequence,
                    "audit_decision",
                    Role::Auditor,
                    event.producer_role,
                    decision.producer_role,
                )?;
                if !audit_decisions.is_empty() || !audit_decision_ids.insert(decision.id.clone()) {
                    return Err(ReplayError::DuplicateAuditDecision {
                        sequence: event.sequence,
                        decision_id: decision.id.clone(),
                    });
                }
                if !review_decision_ids.contains(&decision.review_decision_id) {
                    return Err(ReplayError::AuditReviewDecisionNotRecorded {
                        sequence: event.sequence,
                        review_decision_id: decision.review_decision_id.clone(),
                    });
                }
                audit_decisions.push(decision.clone());
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
        evidence_references,
        guard_outcomes,
        review_audit_requirements,
        review_decisions,
        audit_decisions,
        completion_evidence,
        specialist_outputs,
        coordinator_final_response,
    })
}

fn validate_decision_binding(
    sequence: u64,
    contract: &'static str,
    run_record: &RunRecord,
    run_id: &RunId,
    goal_id: &GoalId,
) -> Result<(), ReplayError> {
    if *run_id != run_record.id {
        return Err(ReplayError::DecisionRunIdMismatch {
            sequence,
            contract,
            expected: run_record.id.clone(),
            found: run_id.clone(),
        });
    }
    if *goal_id != run_record.goal_id {
        return Err(ReplayError::DecisionGoalIdMismatch {
            sequence,
            contract,
            expected: run_record.goal_id.clone(),
            found: goal_id.clone(),
        });
    }
    Ok(())
}

fn validate_decision_role(
    sequence: u64,
    contract: &'static str,
    expected: Role,
    event_role: Role,
    decision_role: Role,
) -> Result<(), ReplayError> {
    if event_role != expected || decision_role != expected {
        return Err(ReplayError::DecisionProducerRoleMismatch {
            sequence,
            contract,
            expected,
            event_role,
            decision_role,
        });
    }
    Ok(())
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
        CompletionPrecondition, CriterionAssessment, CriterionAssessmentVerdict, CriterionKind,
        EvidenceId, EvidenceKind, ExecutionMode, ExecutionWave, GuardRequirement,
        PermissionProfile, ReviewVerdict, RiskTier,
    };
    use std::collections::{BTreeMap, BTreeSet};
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

    fn evidence_reference(id: &str) -> EvidenceRef {
        EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from(id),
            kind: EvidenceKind::TestResult,
            reference: format!("memory://evidence/{id}"),
            producer_role: Role::Engineer,
            integrity: None,
            produced_at: occurred_at(),
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
            rationale: "evidence supports the exact criterion".to_owned(),
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
            decided_at: occurred_at(),
        }
    }

    fn audit_decision() -> AuditDecision {
        audit_decision_with_verdict(ReviewVerdict::Pass)
    }

    fn audit_decision_with_verdict(verdict: ReviewVerdict) -> AuditDecision {
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
            decided_at: occurred_at() + Duration::seconds(1),
        }
    }

    fn completion_prerequisites(guard_requirements: BTreeSet<GuardRequirement>) -> Vec<RunEvent> {
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "evidence-event",
            Role::Engineer,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: evidence_reference("evidence-1"),
            },
        );
        append_event(
            &mut events,
            "completion-evidence-event",
            Role::Reviewer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: completion_evidence(),
            },
        );
        append_event(
            &mut events,
            "requirements-event",
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded {
                requirements: ReviewAuditRequirements {
                    contract_version: ContractVersion::current(),
                    guard_requirements,
                },
            },
        );
        events
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

    #[test]
    fn replay_run_reconstructs_review_and_audit_events() {
        let mut events = state_chain(RunStatus::Draft, &[]);
        let evidence = evidence_reference("evidence-1");
        let requirements = ReviewAuditRequirements {
            contract_version: ContractVersion::current(),
            guard_requirements: BTreeSet::from([
                GuardRequirement::Reviewer,
                GuardRequirement::Auditor,
            ]),
        };
        let review = review_decision();
        let audit = audit_decision();

        append_event(
            &mut events,
            "review-event-1",
            Role::Engineer,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: evidence.clone(),
            },
        );
        append_event(
            &mut events,
            "review-event-2",
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded {
                requirements: requirements.clone(),
            },
        );
        append_event(
            &mut events,
            "review-event-3",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review.clone(),
            },
        );
        append_event(
            &mut events,
            "review-event-4",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit.clone(),
            },
        );

        let replayed = replay_run(&events, Some(&goal_contract("goal-1")))
            .expect("ordered review and audit events should replay");

        assert_eq!(
            replayed.run_record.evidence_refs,
            vec![EvidenceId::from("evidence-1")]
        );
        assert_eq!(replayed.evidence_references, vec![evidence]);
        assert_eq!(replayed.review_audit_requirements, Some(requirements));
        assert_eq!(replayed.review_decisions, vec![review]);
        assert_eq!(replayed.audit_decisions, vec![audit]);
    }

    #[test]
    fn replay_run_rejects_invalid_review_audit_event_bindings_and_order() {
        let mut wrong_role = state_chain(RunStatus::Draft, &[]);
        append_event(
            &mut wrong_role,
            "review-event-1",
            Role::Engineer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        );
        assert!(matches!(
            replay_run(&wrong_role, Some(&goal_contract("goal-1"))),
            Err(ReplayError::DecisionProducerRoleMismatch {
                contract: "review_decision",
                ..
            })
        ));

        let mut wrong_run = state_chain(RunStatus::Draft, &[]);
        let mut mismatched_review = review_decision();
        mismatched_review.run_id = RunId::from("run-other");
        append_event(
            &mut wrong_run,
            "review-event-1",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: mismatched_review,
            },
        );
        assert!(matches!(
            replay_run(&wrong_run, Some(&goal_contract("goal-1"))),
            Err(ReplayError::DecisionRunIdMismatch {
                contract: "review_decision",
                ..
            })
        ));

        let mut duplicate_requirements = state_chain(RunStatus::Draft, &[]);
        let requirements = ReviewAuditRequirements {
            contract_version: ContractVersion::current(),
            guard_requirements: BTreeSet::new(),
        };
        append_event(
            &mut duplicate_requirements,
            "review-event-1",
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded {
                requirements: requirements.clone(),
            },
        );
        append_event(
            &mut duplicate_requirements,
            "review-event-2",
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded { requirements },
        );
        assert_eq!(
            replay_run(&duplicate_requirements, Some(&goal_contract("goal-1"))),
            Err(ReplayError::DuplicateReviewAuditRequirements { sequence: 2 })
        );

        let mut audit_before_review = state_chain(RunStatus::Draft, &[]);
        append_event(
            &mut audit_before_review,
            "review-event-1",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision(),
            },
        );
        assert_eq!(
            replay_run(&audit_before_review, Some(&goal_contract("goal-1"))),
            Err(ReplayError::AuditReviewDecisionNotRecorded {
                sequence: 1,
                review_decision_id: ReviewDecisionId::from("review-1"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_second_distinct_review_or_audit_decision() {
        let goal = goal_contract("goal-1");
        let mut duplicate_review = state_chain(RunStatus::Draft, &[]);
        append_event(
            &mut duplicate_review,
            "review-event-1",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        );
        let mut second_review = review_decision();
        second_review.id = ReviewDecisionId::from("review-2");
        append_event(
            &mut duplicate_review,
            "review-event-2",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: second_review,
            },
        );
        assert_eq!(
            replay_run(&duplicate_review, Some(&goal)),
            Err(ReplayError::DuplicateReviewDecision {
                sequence: 2,
                decision_id: ReviewDecisionId::from("review-2"),
            })
        );

        let mut duplicate_audit = state_chain(RunStatus::Draft, &[]);
        append_event(
            &mut duplicate_audit,
            "review-event-1",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        );
        append_event(
            &mut duplicate_audit,
            "audit-event-1",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision(),
            },
        );
        let mut second_audit = audit_decision();
        second_audit.id = AuditDecisionId::from("audit-2");
        append_event(
            &mut duplicate_audit,
            "audit-event-2",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: second_audit,
            },
        );
        assert_eq!(
            replay_run(&duplicate_audit, Some(&goal)),
            Err(ReplayError::DuplicateAuditDecision {
                sequence: 3,
                decision_id: AuditDecisionId::from("audit-2"),
            })
        );
    }

    #[test]
    fn replay_run_rejects_completion_missing_required_review() {
        let goal = goal_contract("goal-1");
        let mut events = completion_prerequisites(BTreeSet::from([GuardRequirement::Reviewer]));
        append_event(
            &mut events,
            "reviewing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal)),
            Err(ReplayError::ReviewAuditResolutionRejected {
                sequence: 8,
                resolution: ReviewAuditResolution::AwaitingReview,
            })
        );
    }

    #[test]
    fn replay_run_rejects_completion_missing_required_audit() {
        let goal = goal_contract("goal-1");
        let mut events = completion_prerequisites(BTreeSet::from([
            GuardRequirement::Reviewer,
            GuardRequirement::Auditor,
        ]));
        append_event(
            &mut events,
            "reviewing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        );
        append_event(
            &mut events,
            "review-event",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        );
        append_event(
            &mut events,
            "auditing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Auditing,
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal)),
            Err(ReplayError::ReviewAuditResolutionRejected {
                sequence: 10,
                resolution: ReviewAuditResolution::AwaitingAudit {
                    review_decision_id: ReviewDecisionId::from("review-1"),
                },
            })
        );
    }

    #[test]
    fn replay_run_rejects_review_audit_disagreement_with_owner_escalation() {
        let goal = goal_contract("goal-1");
        let mut events = completion_prerequisites(BTreeSet::from([
            GuardRequirement::Reviewer,
            GuardRequirement::Auditor,
        ]));
        append_event(
            &mut events,
            "reviewing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        );
        append_event(
            &mut events,
            "review-event",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision(),
            },
        );
        append_event(
            &mut events,
            "auditing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Auditing,
            },
        );
        append_event(
            &mut events,
            "audit-event",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision_with_verdict(ReviewVerdict::Fail),
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal)),
            Err(ReplayError::ReviewAuditResolutionRejected {
                sequence: 11,
                resolution: ReviewAuditResolution::OwnerEscalation {
                    review_decision_id: ReviewDecisionId::from("review-1"),
                    audit_decision_id: AuditDecisionId::from("audit-1"),
                    reviewer_verdict: ReviewVerdict::Pass,
                    auditor_verdict: ReviewVerdict::Fail,
                },
            })
        );
    }

    #[test]
    fn replay_run_completes_with_exact_required_pass_decisions() {
        let goal = goal_contract("goal-1");
        let guard_requirements =
            BTreeSet::from([GuardRequirement::Reviewer, GuardRequirement::Auditor]);
        let mut events = completion_prerequisites(guard_requirements.clone());
        let review = review_decision();
        let audit = audit_decision();
        append_event(
            &mut events,
            "reviewing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        );
        append_event(
            &mut events,
            "review-event",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: review.clone(),
            },
        );
        append_event(
            &mut events,
            "auditing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Auditing,
            },
        );
        append_event(
            &mut events,
            "audit-event",
            Role::Auditor,
            RunEventPayload::AuditDecisionRecorded {
                decision: audit.clone(),
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Auditing,
                to: RunStatus::Completed,
            },
        );

        let replayed = replay_run(&events, Some(&goal))
            .expect("exact required Pass decisions should permit completion");

        assert_eq!(replayed.run_record.status, RunStatus::Completed);
        assert_eq!(
            replayed.review_audit_requirements,
            Some(ReviewAuditRequirements {
                contract_version: ContractVersion::current(),
                guard_requirements,
            })
        );
        assert_eq!(replayed.review_decisions, vec![review]);
        assert_eq!(replayed.audit_decisions, vec![audit]);
    }

    #[test]
    fn replay_run_r0_no_requirements_event_completes_without_decisions() {
        let goal = goal_contract("goal-1");
        let mut events = state_chain(RunStatus::Running, &[]);
        append_event(
            &mut events,
            "evidence-event",
            Role::Engineer,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: evidence_reference("evidence-1"),
            },
        );
        append_event(
            &mut events,
            "completion-evidence-event",
            Role::Reviewer,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: completion_evidence(),
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        );

        let replayed = replay_run(&events, Some(&goal))
            .expect("R0 completion should remain compatible without review decisions");

        assert_eq!(replayed.run_record.status, RunStatus::Completed);
        assert_eq!(replayed.review_audit_requirements, None);
        assert!(replayed.review_decisions.is_empty());
        assert!(replayed.audit_decisions.is_empty());
    }

    #[test]
    fn replay_run_maps_malformed_review_to_structured_completion_error() {
        let goal = goal_contract("goal-1");
        let mut events = completion_prerequisites(BTreeSet::from([GuardRequirement::Reviewer]));
        let mut malformed_review = review_decision();
        malformed_review.assessments.truncate(1);
        append_event(
            &mut events,
            "review-event",
            Role::Reviewer,
            RunEventPayload::ReviewDecisionRecorded {
                decision: malformed_review,
            },
        );
        append_event(
            &mut events,
            "reviewing-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        );
        append_event(
            &mut events,
            "completed-event",
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Reviewing,
                to: RunStatus::Completed,
            },
        );

        assert_eq!(
            replay_run(&events, Some(&goal)),
            Err(ReplayError::ReviewAuditEvaluationFailed {
                sequence: 9,
                error: ReviewAuditError::MissingCriterionAssessment {
                    kind: CriterionKind::Verification,
                    criterion: "verified".to_owned(),
                },
            })
        );
    }
}
