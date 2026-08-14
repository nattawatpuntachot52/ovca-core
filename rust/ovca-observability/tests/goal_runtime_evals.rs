use chrono::{TimeZone, Utc};
use ovca_observability::{
    evaluate_goal_runtime, execution_authority_evidence, grade_replay_parity,
    grade_trace_completeness, guard_authority_projection, GoalRuntimeEvaluation,
    GoalRuntimeEvaluationOutcome, GoalRuntimeGuardEvidence,
};
use ovca_runtime_core::{
    replay_run, CancellationRequest, ClaimRequest, CompletionRequest, DurableApprovalEvaluation,
    DurableExecutionAuthority, DurableGuardrailAuthority, FailureRequest,
};
use ovca_storage::RunEventLog;
use ovca_types::{
    verification_sha256_hex, ApprovalRequestId, ApprovalState, ContractVersion, GoalContract,
    GuardDenyReason, GuardRequest, GuardRequestId, GuardSurface, IdempotencyKey, LeaseId,
    PermissionProfile, RetryBudget, RiskTier, Role, RunEvent, RunEventPayload, RunId,
    SideEffectClass, Task, TaskId, TaskStatus, TaskTerminalOutcome, WorkerId,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use tempfile::TempDir;

const FIXTURE: &str = include_str!("fixtures/goal_runtime_p5_golden_cases.json");
const FROZEN_FIXTURE_SHA256: &str =
    "e669918d7add262321f359ed9dd76727ef82310b519271d913dd7a2f79d5dde3";

#[derive(Debug, Deserialize)]
struct GoldenFixture {
    schema_version: u32,
    cases: Vec<GoldenCase>,
}

#[derive(Debug, Deserialize)]
struct GoldenCase {
    id: String,
    scenario: String,
    expected_outcome: GoalRuntimeEvaluationOutcome,
    expected_success: bool,
    expected_parity: bool,
    expected_completeness: f64,
    expected_span_count: usize,
    coverage: Vec<String>,
    mutation: Option<String>,
    semantic_assertion: Option<String>,
}

struct CaseInput {
    goal: GoalContract,
    persisted: Vec<RunEvent>,
    reloaded: Vec<RunEvent>,
    excluded_markers: Vec<&'static str>,
}

#[test]
fn golden_goal_runtime_regression_cases_remain_deterministic() {
    let fixture: GoldenFixture = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.cases.len(),
        41,
        "fixture must retain exactly 41 cases"
    );
    assert_eq!(
        verification_sha256_hex(FIXTURE.as_bytes()),
        FROZEN_FIXTURE_SHA256,
        "fixture bytes, case identities, and expected results are immutable"
    );

    let ids = fixture
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), fixture.cases.len(), "case IDs must be unique");
    assert_required_coverage(&fixture);
    assert_semantic_coverage(&fixture);

    for case in &fixture.cases {
        run_case(case);
    }
}

fn run_case(case: &GoldenCase) {
    let mut input = case_input(&case.scenario);
    if case.mutation.as_deref() == Some("shift_reload_time") {
        let shifted_time = serde_json::from_value(json!("2026-01-02T00:00:00Z")).unwrap();
        input.reloaded[0].occurred_at = shifted_time;
        if let ovca_types::RunEventPayload::RunCreated {
            created_at,
            updated_at,
            ..
        } = &mut input.reloaded[0].payload
        {
            *created_at = shifted_time;
            *updated_at = shifted_time;
        }
    }

    let evaluation = evaluate_goal_runtime(&input.persisted, &input.reloaded, &input.goal)
        .unwrap_or_else(|error| panic!("{} failed evaluation: {error}", case.id));
    if let Some(assertion) = case.semantic_assertion.as_deref() {
        run_semantic_assertion(assertion, &evaluation, &case.id);
    }
    let mut candidate = serde_json::to_value(&evaluation.trace).unwrap();

    match case.mutation.as_deref() {
        Some("remove_required_fields") => {
            let first = candidate["spans"][0].as_object_mut().unwrap();
            first.remove("decision_kind");
            first.remove("lifecycle_kind");
        }
        Some("assert_rejected_absent") => {
            let mut prospective = input.persisted.clone();
            prospective.push(event(
                5,
                "coordinator",
                json!({"type":"note_recorded","message":"rejected-marker"}),
            ));
            assert!(
                replay_run(&prospective, Some(&input.goal)).is_err(),
                "{} prospective stream unexpectedly replayed",
                case.id
            );
            assert_eq!(evaluation.trace.spans.len(), input.persisted.len());
        }
        Some("assert_unstructured_omitted") => {
            let serialized = serde_json::to_string(&evaluation.trace).unwrap();
            for marker in &input.excluded_markers {
                assert!(
                    !serialized.contains(marker),
                    "{} exposed excluded marker {marker}",
                    case.id
                );
            }
        }
        Some("shift_reload_time") | None => {}
        Some(other) => panic!("{} has unknown mutation {other}", case.id),
    }

    let completeness = grade_trace_completeness(&candidate, &input.persisted);
    let parity = grade_replay_parity(&candidate, &input.reloaded).unwrap();
    let actual_success = completeness.passes
        && parity.canonical_match
        && evaluation.invariants.contract_valid
        && evaluation.invariants.successful_completion;

    assert_eq!(
        evaluation.invariants.outcome, case.expected_outcome,
        "{} outcome",
        case.id
    );
    assert_eq!(
        evaluation.trace.spans.len(),
        case.expected_span_count,
        "{} span count",
        case.id
    );
    assert!(
        (completeness.score - case.expected_completeness).abs() < f64::EPSILON,
        "{} completeness: expected {}, found {}",
        case.id,
        case.expected_completeness,
        completeness.score
    );
    assert_eq!(
        parity.canonical_match, case.expected_parity,
        "{} parity",
        case.id
    );
    assert_eq!(actual_success, case.expected_success, "{} success", case.id);
}

fn run_semantic_assertion(assertion: &str, evaluation: &GoalRuntimeEvaluation, case_id: &str) {
    match assertion {
        "p2_claim_lease" => {
            let temp = TempDir::new().unwrap();
            let authority = initialized_execution(&temp, 2);
            let claimed = authority
                .claim(&execution_run_id(), claim_request("lease-1", 1, 10))
                .unwrap();
            let loaded = authority.load(&execution_run_id()).unwrap();
            let evidence = execution_authority_evidence(&loaded, &TaskId::from("task-a")).unwrap();

            assert_eq!(claimed.output.attempt, 1, "{case_id} claim attempt");
            assert_eq!(evidence.status, TaskStatus::Running, "{case_id} status");
            assert_eq!(evidence.attempts, 1, "{case_id} attempts");
            assert!(evidence.active_lease, "{case_id} active lease");
            assert_eq!(evidence.terminal_outcome, None, "{case_id} terminal");
        }
        "p2_retry" => {
            let temp = TempDir::new().unwrap();
            let authority = initialized_execution(&temp, 2);
            authority
                .claim(&execution_run_id(), claim_request("lease-1", 1, 10))
                .unwrap();
            let failed = authority
                .fail(&execution_run_id(), failure_request("lease-1", 2))
                .unwrap();
            let after_failure = authority.load(&execution_run_id()).unwrap();
            let retry_evidence =
                execution_authority_evidence(&after_failure, &TaskId::from("task-a")).unwrap();
            let reclaimed = authority
                .claim(&execution_run_id(), claim_request("lease-2", 3, 12))
                .unwrap();

            assert_eq!(failed.output, TaskStatus::Ready, "{case_id} retry state");
            assert_eq!(retry_evidence.status, TaskStatus::Ready);
            assert_eq!(retry_evidence.attempts, 1);
            assert!(!retry_evidence.active_lease);
            assert_eq!(reclaimed.output.attempt, 2, "{case_id} second attempt");
        }
        "p2_idempotency" => {
            let temp = TempDir::new().unwrap();
            let authority = initialized_execution(&temp, 1);
            authority
                .claim(&execution_run_id(), claim_request("lease-1", 1, 10))
                .unwrap();
            let first = authority
                .complete(&execution_run_id(), completion_request(2))
                .unwrap();
            let duplicate = DurableExecutionAuthority::new(temp.path())
                .complete(&execution_run_id(), completion_request(3))
                .unwrap();
            let loaded = authority.load(&execution_run_id()).unwrap();
            let evidence = execution_authority_evidence(&loaded, &TaskId::from("task-a")).unwrap();

            assert_eq!(duplicate.output, first.output, "{case_id} terminal record");
            assert_eq!(duplicate.snapshot, first.snapshot, "{case_id} snapshot");
            assert_eq!(duplicate.revision, first.revision, "{case_id} revision");
            assert_eq!(evidence.status, TaskStatus::Completed);
            assert_eq!(
                evidence.terminal_outcome,
                Some(TaskTerminalOutcome::Completed)
            );
        }
        "p2_cancellation" => {
            let temp = TempDir::new().unwrap();
            let authority = initialized_execution(&temp, 1);
            authority
                .claim(&execution_run_id(), claim_request("lease-1", 1, 10))
                .unwrap();
            authority
                .cancel(&execution_run_id(), cancellation_request(2))
                .unwrap();
            let loaded = authority.load(&execution_run_id()).unwrap();
            let evidence = execution_authority_evidence(&loaded, &TaskId::from("task-a")).unwrap();

            assert_eq!(evidence.status, TaskStatus::Cancelled, "{case_id} status");
            assert!(!evidence.active_lease, "{case_id} active lease");
            assert_eq!(
                evidence.terminal_outcome,
                Some(TaskTerminalOutcome::Cancelled)
            );
        }
        "p3_r0_allow" => {
            assert_eq!(
                evaluation.invariants.outcome,
                GoalRuntimeEvaluationOutcome::SuccessfulCompletion,
                "{case_id} guard outcome"
            );
            assert!(evaluation.passes, "{case_id} goal evaluation failed");
            assert_trace_guard_outcome(evaluation, GoalRuntimeGuardEvidence::Allow, case_id);
        }
        "p3_r2_pause" => {
            assert_eq!(
                evaluation.invariants.outcome,
                GoalRuntimeEvaluationOutcome::AwaitingApproval,
                "{case_id} guard outcome"
            );
            assert!(!evaluation.passes, "{case_id} goal evaluation passed");
            assert_trace_guard_outcome(evaluation, GoalRuntimeGuardEvidence::Pause, case_id);
        }
        "p3_r3_deny" => {
            assert_eq!(
                evaluation.invariants.outcome,
                GoalRuntimeEvaluationOutcome::PolicyDenied,
                "{case_id} guard outcome"
            );
            assert!(!evaluation.passes, "{case_id} goal evaluation passed");
            assert_trace_guard_outcome(evaluation, GoalRuntimeGuardEvidence::Deny, case_id);
        }
        other => panic!("{case_id} has unknown semantic assertion {other}"),
    }
}

fn assert_trace_guard_outcome(
    evaluation: &GoalRuntimeEvaluation,
    expected: GoalRuntimeGuardEvidence,
    case_id: &str,
) {
    let recorded = evaluation
        .trace
        .spans
        .iter()
        .filter_map(|span| span.facts.guard_outcome)
        .collect::<Vec<_>>();
    assert_eq!(recorded, vec![expected], "{case_id} trace guard outcome");
}

fn initialized_execution(temp: &TempDir, max_attempts: u32) -> DurableExecutionAuthority {
    let authority = DurableExecutionAuthority::new(temp.path());
    authority
        .initialize_run(
            execution_run_id(),
            vec![execution_task()],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts,
            },
        )
        .unwrap();
    authority
}

fn execution_task() -> Task {
    serde_json::from_value(json!({
        "contract_version":1,
        "id":"task-a",
        "goal_id":"goal-1",
        "outcome":"bounded execution",
        "dependencies":[],
        "assigned_role":"engineer",
        "resource_keys":[],
        "write_keys":["write:one"],
        "status":"ready",
        "created_at":"2026-01-01T00:00:00Z",
        "updated_at":"2026-01-01T00:00:00Z"
    }))
    .unwrap()
}

fn execution_run_id() -> RunId {
    RunId::from("run-1")
}

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, second)
        .single()
        .unwrap()
}

fn claim_request(lease_id: &str, now: u32, expires_at: u32) -> ClaimRequest {
    ClaimRequest {
        task_id: TaskId::from("task-a"),
        worker_id: WorkerId::from("worker-1"),
        worker_role: Role::Engineer,
        lease_id: LeaseId::from(lease_id),
        now: at(now),
        expires_at: at(expires_at),
    }
}

fn failure_request(lease_id: &str, now: u32) -> FailureRequest {
    FailureRequest {
        task_id: TaskId::from("task-a"),
        worker_id: WorkerId::from("worker-1"),
        worker_role: Role::Engineer,
        lease_id: LeaseId::from(lease_id),
        now: at(now),
        reason: "bounded failure".to_owned(),
    }
}

fn completion_request(occurred_at: u32) -> CompletionRequest {
    CompletionRequest {
        task_id: TaskId::from("task-a"),
        worker_id: WorkerId::from("worker-1"),
        worker_role: Role::Engineer,
        lease_id: LeaseId::from("lease-1"),
        idempotency_key: IdempotencyKey::from("completion-key"),
        occurred_at: at(occurred_at),
    }
}

fn cancellation_request(occurred_at: u32) -> CancellationRequest {
    CancellationRequest {
        task_id: TaskId::from("task-a"),
        worker_id: WorkerId::from("worker-1"),
        worker_role: Role::Engineer,
        lease_id: LeaseId::from("lease-1"),
        idempotency_key: IdempotencyKey::from("cancellation-key"),
        occurred_at: at(occurred_at),
        reason: Some("bounded cancellation".to_owned()),
    }
}

fn guard_context() -> ovca_runtime_core::GuardEvaluationContext {
    ovca_runtime_core::GuardEvaluationContext {
        approval_request_id: ApprovalRequestId::from("approval-1"),
        requested_at: at(10),
    }
}

fn guard_request(tier: RiskTier, side_effect: SideEffectClass) -> GuardRequest {
    let (approval_required, review_required, audit_required) = match tier {
        RiskTier::R0 => (false, false, false),
        RiskTier::R1 => (false, true, false),
        RiskTier::R2 | RiskTier::R3 => (true, true, true),
    };
    let write_keys = if side_effect == SideEffectClass::ReadOnly {
        Vec::new()
    } else {
        vec!["write:one".to_owned()]
    };
    GuardRequest {
        contract_version: ContractVersion::current(),
        id: GuardRequestId::from("guard-1"),
        surface: GuardSurface::Tool,
        side_effect,
        operation_label: "bounded operation".to_owned(),
        resource_keys: vec!["resource:one".to_owned()],
        write_keys: write_keys.clone(),
        permission_profile: PermissionProfile {
            contract_version: ContractVersion::current(),
            risk_tier: tier,
            resource_keys: vec!["resource:one".to_owned()],
            write_keys,
            approval_required,
            review_required,
            audit_required,
        },
    }
}

fn projected_guard_case(
    tier: RiskTier,
    side_effect: SideEffectClass,
    complete_after_allow: bool,
) -> CaseInput {
    let temp = TempDir::new().unwrap();
    let authority = DurableGuardrailAuthority::new(temp.path(), 8);
    let result = authority
        .evaluate_and_record(&guard_request(tier, side_effect), &guard_context())
        .unwrap();
    match &result {
        DurableApprovalEvaluation::Allow { .. } => {
            assert_eq!(tier, RiskTier::R0);
        }
        DurableApprovalEvaluation::Pending { record, .. } => {
            assert_eq!(tier, RiskTier::R2);
            assert_eq!(record.envelope.state, ApprovalState::Pending);
            assert_eq!(
                authority
                    .load(&ApprovalRequestId::from("approval-1"))
                    .unwrap(),
                **record
            );
        }
        DurableApprovalEvaluation::Deny { reasons } => {
            assert_eq!(tier, RiskTier::R3);
            assert!(reasons.contains(&GuardDenyReason::R3DenyByDefault));
        }
    }

    let projection = guard_authority_projection(&result);
    let mut events = running();
    events.push(event(
        5,
        "coordinator",
        serde_json::to_value(RunEventPayload::GuardOutcomeRecorded { projection }).unwrap(),
    ));
    if complete_after_allow {
        events.push(event(
            6,
            "engineer",
            json!({"type":"evidence_attached","evidence_id":"evidence-1"}),
        ));
        events.push(event(
            7,
            "engineer",
            json!({
                "type":"completion_evidence_recorded",
                "evidence":{
                    "contract_version":1,
                    "evidence_refs":["evidence-1"],
                    "satisfied_acceptance_criteria":[],
                    "satisfied_verification_criteria":[],
                    "satisfied_definition_of_done":[]
                }
            }),
        ));
        events.push(status(8, "running", "completed"));
    }

    let log = RunEventLog::new(temp.path());
    for event in &events {
        log.append(event).unwrap();
    }
    let before = fs::read(log.path()).unwrap();
    let persisted = log.load_run(&RunId::from("run-1")).unwrap();
    let reloaded = RunEventLog::new(temp.path())
        .load_run(&RunId::from("run-1"))
        .unwrap();
    assert_eq!(persisted, reloaded);
    assert_eq!(fs::read(log.path()).unwrap(), before);

    let jsonl = String::from_utf8(before).unwrap();
    for excluded in [
        "guard-1",
        "approval-1",
        "bounded operation",
        "resource:one",
        "write:one",
    ] {
        assert!(!jsonl.contains(excluded));
    }

    CaseInput {
        goal: goal(false, false),
        persisted,
        reloaded,
        excluded_markers: Vec::new(),
    }
}

fn case_input(scenario: &str) -> CaseInput {
    match scenario {
        "guard_r0_completed" => {
            return projected_guard_case(RiskTier::R0, SideEffectClass::ReadOnly, true);
        }
        "guard_r2_pause" => {
            return projected_guard_case(RiskTier::R2, SideEffectClass::NetworkAction, false);
        }
        "guard_r3_deny" => {
            return projected_guard_case(RiskTier::R3, SideEffectClass::Destructive, false);
        }
        "missing_review" => return review_flow(false, None, None),
        "completed_review" => return review_flow(false, Some("pass"), Some("complete")),
        "review_fail" => return review_flow(false, Some("fail"), None),
        "missing_audit" => return review_flow(true, Some("pass"), None),
        "completed_audit" => return review_flow(true, Some("pass"), Some("pass")),
        "audit_fail" => return review_flow(true, Some("fail"), Some("fail")),
        "disagreement" => return review_flow(true, Some("pass"), Some("fail")),
        "invalid_review_contract" => {
            let mut input = review_flow(false, Some("pass"), None);
            let ovca_types::RunEventPayload::ReviewDecisionRecorded { decision } =
                &mut input.persisted[9].payload
            else {
                unreachable!("review fixture records its decision at sequence 9");
            };
            decision.verdict = ovca_types::ReviewVerdict::Fail;
            input.reloaded = input.persisted.clone();
            return input;
        }
        _ => {}
    }

    let (goal, persisted, excluded_markers) = match scenario {
        "draft" => (goal(false, false), vec![run_created(&[])], Vec::new()),
        "accepted" => {
            let mut events = vec![run_created(&[])];
            events.push(status(1, "draft", "accepted"));
            (goal(false, false), events, Vec::new())
        }
        "planned_sequential" => (
            goal(false, false),
            planned(
                &["task-a"],
                json!([{"index":0,"mode":"sequential","task_ids":["task-a"]}]),
            ),
            Vec::new(),
        ),
        "planned_parallel" => (
            goal(false, false),
            planned(
                &["task-a", "task-b"],
                json!([{"index":0,"mode":"parallel","task_ids":["task-a","task-b"]}]),
            ),
            Vec::new(),
        ),
        "planned_routed" => (
            goal(false, false),
            planned(
                &["task-a", "task-b", "task-c"],
                json!([
                    {"index":0,"mode":"parallel","task_ids":["task-a","task-b"]},
                    {"index":1,"mode":"sequential","task_ids":["task-c"]}
                ]),
            ),
            Vec::new(),
        ),
        "running" => {
            let mut events = planned_one();
            events.push(status(4, "planned", "running"));
            (goal(false, false), events, Vec::new())
        }
        "failed" => {
            let mut events = running();
            events.push(status(5, "running", "failed"));
            (goal(false, false), events, Vec::new())
        }
        "cancelled" => {
            let mut events = planned_one();
            events.push(status(4, "planned", "cancelled"));
            (goal(false, false), events, Vec::new())
        }
        "task_ready" => (
            goal(false, false),
            task_progress(&[("pending", "ready")]),
            Vec::new(),
        ),
        "task_running" => (
            goal(false, false),
            task_progress(&[("pending", "ready"), ("ready", "running")]),
            Vec::new(),
        ),
        "task_completed" => (
            goal(false, false),
            task_progress(&[
                ("pending", "ready"),
                ("ready", "running"),
                ("running", "completed"),
            ]),
            Vec::new(),
        ),
        "task_cancelled" => (
            goal(false, false),
            task_progress(&[("pending", "cancelled")]),
            Vec::new(),
        ),
        "boundary_note" => {
            let mut events = planned_one();
            events.push(event_with_metadata(
                4,
                "engineer",
                json!({"type":"note_recorded","message":"unstructured-marker"}),
                json!({"external_state":"authority-marker"}),
            ));
            (
                goal(false, false),
                events,
                vec!["unstructured-marker", "authority-marker", "external_state"],
            )
        }
        "completed_r0" => (goal(false, false), completed_r0(), Vec::new()),
        "awaiting_approval" => {
            let mut events = running();
            events.push(status(5, "running", "awaiting_approval"));
            (goal(false, false), events, Vec::new())
        }
        "resumed_running" => {
            let mut events = running();
            events.push(status(5, "running", "awaiting_approval"));
            events.push(status(6, "awaiting_approval", "running"));
            (goal(false, false), events, Vec::new())
        }
        "sensitive_input" => {
            let events: Vec<RunEvent> = serde_json::from_value(json!([
                {
                    "contract_version":1,
                    "id":"opaque-input-event",
                    "run_id":"opaque-input-run",
                    "sequence":0,
                    "occurred_at":"2026-01-01T00:00:00Z",
                    "producer_role":"coordinator",
                    "payload":{
                        "type":"run_created",
                        "project_id":"project-1",
                        "goal_id":"goal-1",
                        "task_ids":[],
                        "status":"draft",
                        "created_at":"2026-01-01T00:00:00Z",
                        "updated_at":"2026-01-01T00:00:00Z"
                    },
                    "metadata":{"opaque_input":"opaque-input-metadata"}
                },
                {
                    "contract_version":1,
                    "id":"opaque-input-note",
                    "run_id":"opaque-input-run",
                    "sequence":1,
                    "previous_event_id":"opaque-input-event",
                    "occurred_at":"2026-01-01T00:00:01Z",
                    "producer_role":"engineer",
                    "payload":{"type":"note_recorded","message":"opaque-input-message"}
                }
            ]))
            .unwrap();
            (
                goal(false, false),
                events,
                vec![
                    "opaque-input-event",
                    "opaque-input-run",
                    "opaque-input-metadata",
                    "opaque-input-message",
                ],
            )
        }
        other => panic!("unknown scenario {other}"),
    };
    CaseInput {
        reloaded: persisted.clone(),
        goal,
        persisted,
        excluded_markers,
    }
}

fn goal(review_required: bool, audit_required: bool) -> GoalContract {
    let with_criteria = review_required || audit_required;
    serde_json::from_value(json!({
        "contract_version":1,
        "id":"goal-1",
        "project_id":"project-1",
        "objective":"verify deterministic runtime behavior",
        "constraints":[],
        "acceptance_criteria":if with_criteria { vec!["accepted"] } else { Vec::<&str>::new() },
        "verification_criteria":if with_criteria { vec!["verified"] } else { Vec::<&str>::new() },
        "permission_profile":{
            "contract_version":1,
            "risk_tier":"r0",
            "resource_keys":[],
            "write_keys":[],
            "approval_required":false,
            "review_required":review_required,
            "audit_required":audit_required
        },
        "definition_of_done":if with_criteria { vec!["done"] } else { Vec::<&str>::new() },
        "completion_precondition":{
            "contract_version":1,
            "minimum_evidence_refs":1,
            "require_all_acceptance_criteria":true,
            "require_all_verification_criteria":true
        },
        "created_at":"2026-01-01T00:00:00Z",
        "updated_at":"2026-01-01T00:00:00Z"
    }))
    .unwrap()
}

fn run_created(task_ids: &[&str]) -> RunEvent {
    event(
        0,
        "coordinator",
        json!({
            "type":"run_created",
            "project_id":"project-1",
            "goal_id":"goal-1",
            "task_ids":task_ids,
            "status":"draft",
            "created_at":"2026-01-01T00:00:00Z",
            "updated_at":"2026-01-01T00:00:00Z"
        }),
    )
}

fn planned_one() -> Vec<RunEvent> {
    planned(
        &["task-a"],
        json!([{"index":0,"mode":"sequential","task_ids":["task-a"]}]),
    )
}

fn planned(task_ids: &[&str], waves: Value) -> Vec<RunEvent> {
    vec![
        run_created(task_ids),
        status(1, "draft", "accepted"),
        event(
            2,
            "coordinator",
            json!({
                "type":"execution_plan_recorded",
                "plan":{"contract_version":1,"waves":waves}
            }),
        ),
        status(3, "accepted", "planned"),
    ]
}

fn running() -> Vec<RunEvent> {
    let mut events = planned_one();
    events.push(status(4, "planned", "running"));
    events
}

fn completed_r0() -> Vec<RunEvent> {
    let mut events = running();
    events.push(event(
        5,
        "engineer",
        json!({"type":"evidence_attached","evidence_id":"evidence-1"}),
    ));
    events.push(event(
        6,
        "engineer",
        json!({
            "type":"completion_evidence_recorded",
            "evidence":{
                "contract_version":1,
                "evidence_refs":["evidence-1"],
                "satisfied_acceptance_criteria":[],
                "satisfied_verification_criteria":[],
                "satisfied_definition_of_done":[]
            }
        }),
    ));
    events.push(status(7, "running", "completed"));
    events
}

fn task_progress(transitions: &[(&str, &str)]) -> Vec<RunEvent> {
    let mut events = running();
    for (index, (from, to)) in transitions.iter().enumerate() {
        events.push(event(
            5 + index as u64,
            "engineer",
            json!({
                "type":"task_status_changed",
                "task_id":"task-a",
                "from":from,
                "to":to
            }),
        ));
    }
    events
}

fn review_flow(
    audit_required: bool,
    review_verdict: Option<&str>,
    audit_action: Option<&str>,
) -> CaseInput {
    let mut events = running();
    let satisfied_acceptance = if review_verdict == Some("fail") {
        json!([])
    } else {
        json!(["accepted"])
    };
    events.push(event(
        5,
        "engineer",
        json!({
            "type":"evidence_reference_recorded",
            "evidence":{
                "contract_version":1,
                "id":"evidence-1",
                "kind":"test_result",
                "reference":"urn:evidence:one",
                "producer_role":"engineer",
                "produced_at":"2026-01-01T00:00:05Z"
            }
        }),
    ));
    events.push(event(
        6,
        "engineer",
        json!({
            "type":"completion_evidence_recorded",
            "evidence":{
                "contract_version":1,
                "evidence_refs":["evidence-1"],
                "satisfied_acceptance_criteria":satisfied_acceptance,
                "satisfied_verification_criteria":["verified"],
                "satisfied_definition_of_done":["done"]
            }
        }),
    ));
    let requirements = if audit_required {
        json!(["reviewer", "auditor"])
    } else {
        json!(["reviewer"])
    };
    events.push(event(
        7,
        "coordinator",
        json!({
            "type":"review_audit_requirements_recorded",
            "requirements":{"contract_version":1,"guard_requirements":requirements}
        }),
    ));
    events.push(status(8, "running", "reviewing"));

    if let Some(verdict) = review_verdict {
        events.push(event(9, "reviewer", review_decision(verdict)));
    }

    if audit_required && review_verdict.is_some() {
        events.push(status(10, "reviewing", "auditing"));
        if let Some(verdict) = audit_action {
            events.push(event(11, "auditor", audit_decision(verdict)));
            if verdict == "pass" && review_verdict == Some("pass") {
                events.push(status(12, "auditing", "completed"));
            }
        }
    } else if audit_action == Some("complete") {
        events.push(status(10, "reviewing", "completed"));
    }

    CaseInput {
        reloaded: events.clone(),
        goal: goal(true, audit_required),
        persisted: events,
        excluded_markers: Vec::new(),
    }
}

fn review_decision(verdict: &str) -> Value {
    json!({
        "type":"review_decision_recorded",
        "decision":{
            "contract_version":1,
            "id":"review-1",
            "run_id":"run-1",
            "goal_id":"goal-1",
            "producer_role":"reviewer",
            "verdict":verdict,
            "assessments":assessments(verdict),
            "summary":"bounded review result",
            "decided_at":"2026-01-01T00:00:09Z"
        }
    })
}

fn audit_decision(verdict: &str) -> Value {
    json!({
        "type":"audit_decision_recorded",
        "decision":{
            "contract_version":1,
            "id":"audit-1",
            "run_id":"run-1",
            "goal_id":"goal-1",
            "review_decision_id":"review-1",
            "producer_role":"auditor",
            "verdict":verdict,
            "assessments":assessments(verdict),
            "summary":"bounded audit result",
            "decided_at":"2026-01-01T00:00:11Z"
        }
    })
}

fn assessments(verdict: &str) -> Value {
    if verdict == "pass" {
        json!([
            {"contract_version":1,"kind":"acceptance","criterion":"accepted","verdict":"satisfied","evidence_refs":["evidence-1"],"rationale":"criterion result"},
            {"contract_version":1,"kind":"verification","criterion":"verified","verdict":"satisfied","evidence_refs":["evidence-1"],"rationale":"criterion result"},
            {"contract_version":1,"kind":"definition_of_done","criterion":"done","verdict":"satisfied","evidence_refs":["evidence-1"],"rationale":"criterion result"}
        ])
    } else {
        json!([
            {"contract_version":1,"kind":"acceptance","criterion":"accepted","verdict":"unsatisfied","evidence_refs":[],"rationale":"criterion result"},
            {"contract_version":1,"kind":"verification","criterion":"verified","verdict":"satisfied","evidence_refs":["evidence-1"],"rationale":"criterion result"},
            {"contract_version":1,"kind":"definition_of_done","criterion":"done","verdict":"satisfied","evidence_refs":["evidence-1"],"rationale":"criterion result"}
        ])
    }
}

fn status(sequence: u64, from: &str, to: &str) -> RunEvent {
    event(
        sequence,
        "coordinator",
        json!({"type":"status_transition","from":from,"to":to}),
    )
}

fn event(sequence: u64, producer_role: &str, payload: Value) -> RunEvent {
    event_with_metadata(sequence, producer_role, payload, json!({}))
}

fn event_with_metadata(
    sequence: u64,
    producer_role: &str,
    payload: Value,
    metadata: Value,
) -> RunEvent {
    serde_json::from_value(json!({
        "contract_version":1,
        "id":format!("event-{sequence}"),
        "run_id":"run-1",
        "sequence":sequence,
        "previous_event_id":if sequence == 0 { Value::Null } else { json!(format!("event-{}", sequence - 1)) },
        "occurred_at":format!("2026-01-01T00:00:{sequence:02}Z"),
        "producer_role":producer_role,
        "payload":payload,
        "metadata":metadata
    }))
    .unwrap()
}

fn assert_required_coverage(fixture: &GoldenFixture) {
    let actual = fixture
        .cases
        .iter()
        .flat_map(|case| case.coverage.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    for required in [
        "p0_contracts",
        "p0_transitions",
        "routing",
        "parallel",
        "sequential",
        "leases",
        "retries",
        "cancellation",
        "idempotency",
        "p3_r0",
        "p3_r2",
        "p3_r3",
        "p4_missing_review",
        "p4_review_pass",
        "p4_review_fail",
        "p4_missing_audit",
        "p4_audit_pass",
        "p4_audit_fail",
        "p4_disagreement",
        "durable_reload",
        "malformed_trace",
        "malformed_contract",
        "redaction",
        "rejected_prospective",
    ] {
        assert!(
            actual.contains(required),
            "missing coverage label {required}"
        );
    }
}

fn assert_semantic_coverage(fixture: &GoldenFixture) {
    for case in &fixture.cases {
        for coverage in &case.coverage {
            let expected_assertion = match (case.id.as_str(), coverage.as_str()) {
                (id, "leases") if id.starts_with("p2_") => Some("p2_claim_lease"),
                (id, "retries") if id.starts_with("p2_") => Some("p2_retry"),
                (id, "cancellation") if id.starts_with("p2_") => Some("p2_cancellation"),
                (id, "idempotency") if id.starts_with("p2_") => Some("p2_idempotency"),
                (id, "p3_r0") if id.starts_with("p3_") => Some("p3_r0_allow"),
                (id, "p3_r2") if id.starts_with("p3_") => Some("p3_r2_pause"),
                (id, "p3_r3") if id.starts_with("p3_") => Some("p3_r3_deny"),
                _ => None,
            };
            if let Some(expected_assertion) = expected_assertion {
                assert_eq!(
                    case.semantic_assertion.as_deref(),
                    Some(expected_assertion),
                    "{} coverage label {} requires semantic assertion {}",
                    case.id,
                    coverage,
                    expected_assertion
                );
            }
        }
    }
}
