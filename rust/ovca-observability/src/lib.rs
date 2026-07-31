use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use ovca_runtime_core::{
    evaluate_review_audit, replay_run, validate_event_chain, DurableApprovalEvaluation,
    LoadedExecutionRun, ReplayError, ReplayedRun, ReviewAuditEvaluationContext,
};
use ovca_types::{
    ContractVersion, ExecutionMode, GoalContract, GuardDenyReason, GuardRequirement,
    ReviewAuditResolution, ReviewVerdict, RunEvent, RunEventPayload, RunGuardDecision,
    RunGuardProjection, RunStatus, TaskId, TaskStatus, TaskTerminalOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;
use tracing_subscriber::EnvFilter;

const LATENCY_WINDOW: usize = 512;

/// Current schema version for provider-independent durable-run traces.
pub const GOAL_RUNTIME_TRACE_SCHEMA_VERSION: u32 = 1;

/// Required fields counted once for every authoritative event expected in a trace.
///
/// Nullable fields still have to be present. Extra and optional fields never add
/// to the completeness numerator or denominator.
pub const GOAL_RUNTIME_TRACE_REQUIRED_SPAN_FIELDS: &[&str] = &[
    "schema_version",
    "run_correlation",
    "event_identity",
    "sequence",
    "previous_event_identity",
    "occurred_at",
    "producer_role",
    "event_kind",
    "lifecycle_kind",
    "decision_kind",
    "facts",
    "facts.run_status_from",
    "facts.run_status_to",
    "facts.task_correlation",
    "facts.task_status_from",
    "facts.task_status_to",
    "facts.execution_modes",
    "facts.guard_requirements",
    "facts.guard_outcome",
    "facts.guard_deny_reasons",
    "facts.review_verdict",
    "facts.audit_verdict",
];

/// Canonical provider-independent trace reconstructed from durable run events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRuntimeTrace {
    pub schema_version: u32,
    pub run_correlation: String,
    pub spans: Vec<GoalRuntimeTraceSpan>,
}

/// One canonical span for one authoritative durable event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRuntimeTraceSpan {
    pub schema_version: u32,
    pub run_correlation: String,
    pub event_identity: String,
    pub sequence: u64,
    pub previous_event_identity: Option<String>,
    pub occurred_at: String,
    pub producer_role: ovca_types::Role,
    pub event_kind: GoalRuntimeEventKind,
    pub lifecycle_kind: GoalRuntimeLifecycleKind,
    pub decision_kind: GoalRuntimeDecisionKind,
    pub facts: GoalRuntimeTraceFacts,
}

/// Closed event vocabulary. No provider payload or free-form prose is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRuntimeEventKind {
    RunCreated,
    ExecutionPlanRecorded,
    StatusTransition,
    TaskStatusChanged,
    EvidenceAttached,
    EvidenceReferenceRecorded,
    GuardOutcomeRecorded,
    ReviewAuditRequirementsRecorded,
    ReviewDecisionRecorded,
    AuditDecisionRecorded,
    CompletionEvidenceRecorded,
    SpecialistOutputRecorded,
    CoordinatorFinalResponseRecorded,
    NoteRecorded,
}

/// Coarse lifecycle category mechanically selected from the event variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRuntimeLifecycleKind {
    Created,
    Planning,
    Transition,
    Task,
    Evidence,
    Decision,
    Output,
    Note,
}

/// Decision category mechanically selected from the event variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRuntimeDecisionKind {
    None,
    GuardRequirements,
    GuardOutcome,
    Review,
    Audit,
    CompletionEvidence,
}

/// Typed trace facts that are safe to expose and cannot contain caller prose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRuntimeTraceFacts {
    pub run_status_from: Option<RunStatus>,
    pub run_status_to: Option<RunStatus>,
    pub task_correlation: Option<String>,
    pub task_status_from: Option<TaskStatus>,
    pub task_status_to: Option<TaskStatus>,
    pub execution_modes: Vec<ExecutionMode>,
    pub guard_requirements: Vec<GuardRequirement>,
    pub guard_outcome: Option<GoalRuntimeGuardEvidence>,
    pub guard_deny_reasons: Vec<GuardDenyReason>,
    pub review_verdict: Option<ReviewVerdict>,
    pub audit_verdict: Option<ReviewVerdict>,
}

/// Deterministic required-field completeness grade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceCompletenessGrade {
    pub present_required_fields: usize,
    pub expected_required_fields: usize,
    pub score: f64,
    pub passes: bool,
    pub missing_fields: Vec<String>,
}

/// Exact canonical parity grade against a durable reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayParityGrade {
    pub canonical_match: bool,
}

/// Stable non-success outcomes retained by the invariant grader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRuntimeEvaluationOutcome {
    SuccessfulCompletion,
    ContractInvalid,
    Draft,
    InProgress,
    AwaitingApproval,
    PolicyDenied,
    AwaitingReview,
    AwaitingAudit,
    ReviewFailed,
    OwnerEscalation,
    Failed,
    Cancelled,
}

/// Contract and outcome grade derived from replayed state, never prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRuntimeInvariantGrade {
    pub contract_valid: bool,
    pub successful_completion: bool,
    pub outcome: GoalRuntimeEvaluationOutcome,
}

/// Read-only P2 task evidence extracted from authoritative durable execution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRuntimeExecutionEvidence {
    pub status: TaskStatus,
    pub attempts: u32,
    pub active_lease: bool,
    pub terminal_outcome: Option<TaskTerminalOutcome>,
}

/// Read-only P3 policy evidence reduced from an actual typed guard result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRuntimeGuardEvidence {
    Allow,
    Pause,
    Deny,
}

/// Complete deterministic result for one persisted and durably reloaded run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoalRuntimeEvaluation {
    pub trace: GoalRuntimeTrace,
    pub completeness: TraceCompletenessGrade,
    pub replay_parity: ReplayParityGrade,
    pub invariants: GoalRuntimeInvariantGrade,
    pub passes: bool,
}

/// Failures that prevent authoritative trace or evaluation construction.
#[derive(Debug)]
pub enum GoalRuntimeEvaluationError {
    Replay(ReplayError),
    Serialization(serde_json::Error),
}

impl fmt::Display for GoalRuntimeEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(error) => write!(formatter, "durable run replay failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "canonical trace serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for GoalRuntimeEvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replay(error) => Some(error),
            Self::Serialization(error) => Some(error),
        }
    }
}

impl From<ReplayError> for GoalRuntimeEvaluationError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}

impl From<serde_json::Error> for GoalRuntimeEvaluationError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

/// Builds a canonical trace from structurally valid authoritative events.
pub fn build_goal_runtime_trace(
    events: &[RunEvent],
) -> Result<GoalRuntimeTrace, GoalRuntimeEvaluationError> {
    validate_event_chain(events)?;
    let run_correlation = "run:0".to_owned();
    let task_correlations = match &events[0].payload {
        RunEventPayload::RunCreated { task_ids, .. } => task_ids
            .iter()
            .enumerate()
            .map(|(index, task_id)| (task_id.clone(), format!("task:{index}")))
            .collect::<BTreeMap<_, _>>(),
        _ => unreachable!("validated event chains begin with RunCreated"),
    };
    let spans = events
        .iter()
        .map(|event| trace_span(event, &run_correlation, &task_correlations))
        .collect();
    Ok(GoalRuntimeTrace {
        schema_version: GOAL_RUNTIME_TRACE_SCHEMA_VERSION,
        run_correlation,
        spans,
    })
}

/// Grades required-field presence against authoritative event count.
///
/// A missing entire span contributes every required span field to the
/// denominator. Extra spans and fields are ignored for completeness and are
/// rejected separately by canonical parity.
pub fn grade_trace_completeness(
    candidate: &Value,
    authoritative_events: &[RunEvent],
) -> TraceCompletenessGrade {
    let expected_required_fields =
        authoritative_events.len() * GOAL_RUNTIME_TRACE_REQUIRED_SPAN_FIELDS.len();
    let spans = candidate.get("spans").and_then(Value::as_array);
    let mut present_required_fields = 0;
    let mut missing_fields = Vec::new();

    for index in 0..authoritative_events.len() {
        let span = spans.and_then(|items| items.get(index));
        for field in GOAL_RUNTIME_TRACE_REQUIRED_SPAN_FIELDS {
            if span.is_some_and(|value| value_has_path(value, field)) {
                present_required_fields += 1;
            } else {
                missing_fields.push(format!("spans[{index}].{field}"));
            }
        }
    }

    let score = if expected_required_fields == 0 {
        0.0
    } else {
        present_required_fields as f64 / expected_required_fields as f64
    };
    TraceCompletenessGrade {
        present_required_fields,
        expected_required_fields,
        score,
        passes: score >= 0.99,
        missing_fields,
    }
}

/// Grades exact canonical parity against an independently reloaded event stream.
pub fn grade_replay_parity(
    candidate: &Value,
    reloaded_events: &[RunEvent],
) -> Result<ReplayParityGrade, GoalRuntimeEvaluationError> {
    let reloaded = serde_json::to_value(build_goal_runtime_trace(reloaded_events)?)?;
    Ok(ReplayParityGrade {
        canonical_match: *candidate == reloaded,
    })
}

/// Evaluates persisted events against an independently loaded copy.
pub fn evaluate_goal_runtime(
    persisted_events: &[RunEvent],
    reloaded_events: &[RunEvent],
    goal: &GoalContract,
) -> Result<GoalRuntimeEvaluation, GoalRuntimeEvaluationError> {
    let replayed = replay_run(persisted_events, Some(goal))?;
    replay_run(reloaded_events, Some(goal))?;

    let trace = build_goal_runtime_trace(persisted_events)?;
    let candidate = serde_json::to_value(&trace)?;
    let completeness = grade_trace_completeness(&candidate, persisted_events);
    let replay_parity = grade_replay_parity(&candidate, reloaded_events)?;
    let invariants = grade_goal_runtime_invariants(&replayed, goal);
    let passes = completeness.passes
        && replay_parity.canonical_match
        && invariants.contract_valid
        && invariants.successful_completion;

    Ok(GoalRuntimeEvaluation {
        trace,
        completeness,
        replay_parity,
        invariants,
        passes,
    })
}

/// Grades completion without allowing paused, denied, failed, or unresolved
/// review/audit paths to appear as successful.
pub fn grade_goal_runtime_invariants(
    replayed: &ReplayedRun,
    goal: &GoalContract,
) -> GoalRuntimeInvariantGrade {
    let resolution = replayed.completion_evidence.as_ref().map(|evidence| {
        let empty_requirements = Default::default();
        let guard_requirements = replayed
            .review_audit_requirements
            .as_ref()
            .map(|requirements| &requirements.guard_requirements)
            .unwrap_or(&empty_requirements);
        evaluate_review_audit(
            &ReviewAuditEvaluationContext {
                expected_run_id: &replayed.run_record.id,
                goal_contract: goal,
                completion_evidence: evidence,
                evidence_catalog: &replayed.evidence_references,
                guard_requirements,
            },
            replayed.review_decisions.first(),
            replayed.audit_decisions.first(),
        )
    });
    let contract_valid = !matches!(resolution, Some(Err(_)));
    let resolved = resolution.as_ref().and_then(|result| result.as_ref().ok());

    let has_policy_deny = replayed
        .guard_outcomes
        .iter()
        .any(|projection| matches!(&projection.outcome, RunGuardDecision::Deny { .. }));
    let has_policy_pause = replayed
        .guard_outcomes
        .iter()
        .any(|projection| matches!(&projection.outcome, RunGuardDecision::Pause { .. }));

    let outcome = if !contract_valid {
        GoalRuntimeEvaluationOutcome::ContractInvalid
    } else if has_policy_deny {
        GoalRuntimeEvaluationOutcome::PolicyDenied
    } else if has_policy_pause {
        GoalRuntimeEvaluationOutcome::AwaitingApproval
    } else {
        match replayed.run_record.status {
            RunStatus::Completed
                if matches!(resolved, Some(ReviewAuditResolution::Pass { .. })) =>
            {
                GoalRuntimeEvaluationOutcome::SuccessfulCompletion
            }
            RunStatus::Draft => GoalRuntimeEvaluationOutcome::Draft,
            RunStatus::AwaitingApproval => GoalRuntimeEvaluationOutcome::AwaitingApproval,
            RunStatus::Failed => GoalRuntimeEvaluationOutcome::Failed,
            RunStatus::Cancelled => GoalRuntimeEvaluationOutcome::Cancelled,
            _ => match resolved {
                Some(ReviewAuditResolution::AwaitingReview) => {
                    GoalRuntimeEvaluationOutcome::AwaitingReview
                }
                Some(ReviewAuditResolution::AwaitingAudit { .. }) => {
                    GoalRuntimeEvaluationOutcome::AwaitingAudit
                }
                Some(ReviewAuditResolution::Fail { .. }) => {
                    GoalRuntimeEvaluationOutcome::ReviewFailed
                }
                Some(ReviewAuditResolution::OwnerEscalation { .. }) => {
                    GoalRuntimeEvaluationOutcome::OwnerEscalation
                }
                _ => GoalRuntimeEvaluationOutcome::InProgress,
            },
        }
    };

    GoalRuntimeInvariantGrade {
        contract_valid,
        successful_completion: outcome == GoalRuntimeEvaluationOutcome::SuccessfulCompletion,
        outcome,
    }
}

/// Extracts a task-scoped, identifier-free P2 evidence view without mutation.
pub fn execution_authority_evidence(
    loaded: &LoadedExecutionRun,
    task_id: &TaskId,
) -> Option<GoalRuntimeExecutionEvidence> {
    loaded
        .envelope
        .snapshot
        .tasks
        .get(task_id)
        .map(|task| GoalRuntimeExecutionEvidence {
            status: task.status,
            attempts: task.attempts,
            active_lease: task.current_lease.is_some(),
            terminal_outcome: task.terminal_record.as_ref().map(|record| record.outcome),
        })
}

/// Reduces an actual P3 authority result to an identifier-free policy outcome.
pub fn guard_authority_evidence(
    evaluation: &DurableApprovalEvaluation,
) -> GoalRuntimeGuardEvidence {
    match guard_authority_projection(evaluation).outcome {
        RunGuardDecision::Allow { .. } => GoalRuntimeGuardEvidence::Allow,
        RunGuardDecision::Pause { .. } => GoalRuntimeGuardEvidence::Pause,
        RunGuardDecision::Deny { .. } => GoalRuntimeGuardEvidence::Deny,
    }
}

/// Reduces an actual P3 authority result to a closed, identifier-free run projection.
pub fn guard_authority_projection(evaluation: &DurableApprovalEvaluation) -> RunGuardProjection {
    let outcome = match evaluation {
        DurableApprovalEvaluation::Allow { required_gates } => RunGuardDecision::Allow {
            required_gates: required_gates.clone(),
        },
        DurableApprovalEvaluation::Pending { record, .. } => RunGuardDecision::Pause {
            required_gates: record.envelope.required_gates.clone(),
        },
        DurableApprovalEvaluation::Deny { reasons } => RunGuardDecision::Deny {
            reasons: reasons.clone(),
        },
    };
    RunGuardProjection {
        contract_version: ContractVersion::current(),
        outcome,
    }
}

fn trace_span(
    event: &RunEvent,
    run_correlation: &str,
    task_correlations: &BTreeMap<ovca_types::TaskId, String>,
) -> GoalRuntimeTraceSpan {
    let mut facts = GoalRuntimeTraceFacts::default();
    let (event_kind, lifecycle_kind, decision_kind) = match &event.payload {
        RunEventPayload::RunCreated { status, .. } => {
            facts.run_status_to = Some(*status);
            (
                GoalRuntimeEventKind::RunCreated,
                GoalRuntimeLifecycleKind::Created,
                GoalRuntimeDecisionKind::None,
            )
        }
        RunEventPayload::ExecutionPlanRecorded { plan } => {
            facts.execution_modes = plan.waves.iter().map(|wave| wave.mode).collect();
            (
                GoalRuntimeEventKind::ExecutionPlanRecorded,
                GoalRuntimeLifecycleKind::Planning,
                GoalRuntimeDecisionKind::None,
            )
        }
        RunEventPayload::StatusTransition { from, to } => {
            facts.run_status_from = Some(*from);
            facts.run_status_to = Some(*to);
            (
                GoalRuntimeEventKind::StatusTransition,
                GoalRuntimeLifecycleKind::Transition,
                GoalRuntimeDecisionKind::None,
            )
        }
        RunEventPayload::TaskStatusChanged { task_id, from, to } => {
            facts.task_correlation = task_correlations.get(task_id).cloned();
            facts.task_status_from = Some(*from);
            facts.task_status_to = Some(*to);
            (
                GoalRuntimeEventKind::TaskStatusChanged,
                GoalRuntimeLifecycleKind::Task,
                GoalRuntimeDecisionKind::None,
            )
        }
        RunEventPayload::EvidenceAttached { .. } => (
            GoalRuntimeEventKind::EvidenceAttached,
            GoalRuntimeLifecycleKind::Evidence,
            GoalRuntimeDecisionKind::None,
        ),
        RunEventPayload::EvidenceReferenceRecorded { .. } => (
            GoalRuntimeEventKind::EvidenceReferenceRecorded,
            GoalRuntimeLifecycleKind::Evidence,
            GoalRuntimeDecisionKind::None,
        ),
        RunEventPayload::GuardOutcomeRecorded { projection } => {
            match &projection.outcome {
                RunGuardDecision::Allow { required_gates } => {
                    facts.guard_outcome = Some(GoalRuntimeGuardEvidence::Allow);
                    facts.guard_requirements = required_gates.iter().copied().collect();
                }
                RunGuardDecision::Pause { required_gates } => {
                    facts.guard_outcome = Some(GoalRuntimeGuardEvidence::Pause);
                    facts.guard_requirements = required_gates.iter().copied().collect();
                }
                RunGuardDecision::Deny { reasons } => {
                    facts.guard_outcome = Some(GoalRuntimeGuardEvidence::Deny);
                    facts.guard_deny_reasons = reasons.iter().copied().collect();
                }
            }
            (
                GoalRuntimeEventKind::GuardOutcomeRecorded,
                GoalRuntimeLifecycleKind::Decision,
                GoalRuntimeDecisionKind::GuardOutcome,
            )
        }
        RunEventPayload::ReviewAuditRequirementsRecorded { requirements } => {
            facts.guard_requirements = requirements.guard_requirements.iter().copied().collect();
            (
                GoalRuntimeEventKind::ReviewAuditRequirementsRecorded,
                GoalRuntimeLifecycleKind::Decision,
                GoalRuntimeDecisionKind::GuardRequirements,
            )
        }
        RunEventPayload::ReviewDecisionRecorded { decision } => {
            facts.review_verdict = Some(decision.verdict);
            (
                GoalRuntimeEventKind::ReviewDecisionRecorded,
                GoalRuntimeLifecycleKind::Decision,
                GoalRuntimeDecisionKind::Review,
            )
        }
        RunEventPayload::AuditDecisionRecorded { decision } => {
            facts.audit_verdict = Some(decision.verdict);
            (
                GoalRuntimeEventKind::AuditDecisionRecorded,
                GoalRuntimeLifecycleKind::Decision,
                GoalRuntimeDecisionKind::Audit,
            )
        }
        RunEventPayload::CompletionEvidenceRecorded { .. } => (
            GoalRuntimeEventKind::CompletionEvidenceRecorded,
            GoalRuntimeLifecycleKind::Decision,
            GoalRuntimeDecisionKind::CompletionEvidence,
        ),
        RunEventPayload::SpecialistOutputRecorded { .. } => (
            GoalRuntimeEventKind::SpecialistOutputRecorded,
            GoalRuntimeLifecycleKind::Output,
            GoalRuntimeDecisionKind::None,
        ),
        RunEventPayload::CoordinatorFinalResponseRecorded { .. } => (
            GoalRuntimeEventKind::CoordinatorFinalResponseRecorded,
            GoalRuntimeLifecycleKind::Output,
            GoalRuntimeDecisionKind::None,
        ),
        RunEventPayload::NoteRecorded { .. } => (
            GoalRuntimeEventKind::NoteRecorded,
            GoalRuntimeLifecycleKind::Note,
            GoalRuntimeDecisionKind::None,
        ),
    };

    GoalRuntimeTraceSpan {
        schema_version: GOAL_RUNTIME_TRACE_SCHEMA_VERSION,
        run_correlation: run_correlation.to_owned(),
        event_identity: format!("event:{}", event.sequence),
        sequence: event.sequence,
        previous_event_identity: event
            .previous_event_id
            .as_ref()
            .map(|_| format!("event:{}", event.sequence - 1)),
        occurred_at: event.occurred_at.to_rfc3339(),
        producer_role: event.producer_role,
        event_kind,
        lifecycle_kind,
        decision_kind,
        facts,
    }
}

fn value_has_path(value: &Value, path: &str) -> bool {
    path.split('.')
        .try_fold(value, |current, key| current.as_object()?.get(key))
        .is_some()
}

#[derive(Debug)]
struct HttpMetricsInner {
    request_count: AtomicU64,
    error_count: AtomicU64,
    latencies_ms: Mutex<VecDeque<u64>>,
}

#[derive(Clone, Debug)]
pub struct HttpMetrics {
    service: Arc<str>,
    inner: Arc<HttpMetricsInner>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HttpMetricsSnapshot {
    pub ok: bool,
    pub service: String,
    pub request_count: u64,
    pub error_count: u64,
    pub request_latency_p99_ms: u64,
    pub latency_sample_size: usize,
}

impl HttpMetrics {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: Arc::<str>::from(service.into()),
            inner: Arc::new(HttpMetricsInner {
                request_count: AtomicU64::new(0),
                error_count: AtomicU64::new(0),
                latencies_ms: Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW)),
            }),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn record(&self, status_code: u16, duration_ms: u64) {
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        if status_code >= 400 {
            self.inner.error_count.fetch_add(1, Ordering::Relaxed);
        }

        let mut latencies = self.inner.latencies_ms.lock().unwrap();
        if latencies.len() >= LATENCY_WINDOW {
            latencies.pop_front();
        }
        latencies.push_back(duration_ms);
    }

    pub fn snapshot(&self) -> HttpMetricsSnapshot {
        let latencies = self.inner.latencies_ms.lock().unwrap();
        let p99 = percentile_99(&latencies);
        HttpMetricsSnapshot {
            ok: true,
            service: self.service.to_string(),
            request_count: self.inner.request_count.load(Ordering::Relaxed),
            error_count: self.inner.error_count.load(Ordering::Relaxed),
            request_latency_p99_ms: p99,
            latency_sample_size: latencies.len(),
        }
    }

    pub fn snapshot_json(&self) -> Value {
        serde_json::to_value(self.snapshot()).unwrap_or_else(|_| json!({"ok": false}))
    }
}

pub fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let format = std::env::var("ORACLE_LOG_FORMAT")
        .unwrap_or_else(|_| "json".to_string())
        .to_ascii_lowercase();

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    let _ = if format == "compact" {
        builder.compact().try_init()
    } else {
        builder
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .try_init()
    };
}

pub async fn track_http_metrics(
    State(metrics): State<HttpMetrics>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| req.uri().path())
        .to_string();
    let started_at = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let duration_ms = started_at.elapsed().as_millis() as u64;
    metrics.record(status, duration_ms);
    info!(
        service = %metrics.service(),
        method = %method,
        path = %path,
        status = status,
        duration_ms = duration_ms,
        "http request"
    );
    response
}

fn percentile_99(samples: &VecDeque<u64>) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut values = samples.iter().copied().collect::<Vec<_>>();
    values.sort_unstable();
    let idx = (((values.len() as f64) * 0.99).ceil() as usize).saturating_sub(1);
    values[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_events() -> Vec<RunEvent> {
        serde_json::from_value(json!([
            {
                "contract_version": 1,
                "id": "event-local-path",
                "run_id": "run-credential-value",
                "sequence": 0,
                "occurred_at": "2026-01-01T00:00:00Z",
                "producer_role": "coordinator",
                "payload": {
                    "type": "run_created",
                    "project_id": "project-1",
                    "goal_id": "goal-1",
                    "task_ids": [],
                    "status": "draft",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z"
                },
                "metadata": {
                    "raw_provider_payload": "must-not-appear"
                }
            },
            {
                "contract_version": 1,
                "id": "event-note",
                "run_id": "run-credential-value",
                "sequence": 1,
                "previous_event_id": "event-local-path",
                "occurred_at": "2026-01-01T00:00:01Z",
                "producer_role": "engineer",
                "payload": {
                    "type": "note_recorded",
                    "message": "password-value-must-not-appear"
                }
            }
        ]))
        .unwrap()
    }

    #[test]
    fn metrics_snapshot_tracks_counts_and_p99() {
        let metrics = HttpMetrics::new("test-service");
        for (status, duration) in [(200, 4), (200, 8), (500, 50), (200, 13)] {
            metrics.record(status, duration);
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.service, "test-service");
        assert_eq!(snapshot.request_count, 4);
        assert_eq!(snapshot.error_count, 1);
        assert_eq!(snapshot.request_latency_p99_ms, 50);
        assert_eq!(snapshot.latency_sample_size, 4);
    }

    #[test]
    fn durable_trace_is_deterministic_and_omits_unstructured_content() {
        let events = trace_events();
        let mut equivalent_events = events.clone();
        for event in &mut equivalent_events {
            event.run_id = "different-run-input".into();
        }
        equivalent_events[0].id = "different-event-zero".into();
        equivalent_events[1].id = "different-event-one".into();
        equivalent_events[1].previous_event_id = Some("different-event-zero".into());

        let first = build_goal_runtime_trace(&events).unwrap();
        let second = build_goal_runtime_trace(&events).unwrap();
        let equivalent = build_goal_runtime_trace(&equivalent_events).unwrap();
        let serialized = serde_json::to_string(&first).unwrap();

        assert_eq!(first, second);
        assert_eq!(first, equivalent);
        assert_eq!(first.run_correlation, "run:0");
        assert_eq!(first.spans[0].event_identity, "event:0");
        assert_eq!(first.spans.len(), events.len());
        assert_eq!(first.spans[0].sequence, 0);
        assert_eq!(
            first.spans[1].previous_event_identity,
            Some(first.spans[0].event_identity.clone())
        );
        for excluded in [
            "run-credential-value",
            "event-local-path",
            "raw_provider_payload",
            "must-not-appear",
            "password-value-must-not-appear",
        ] {
            assert!(
                !serialized.contains(excluded),
                "{excluded} leaked into trace"
            );
        }
    }

    #[test]
    fn guard_requirements_serialize_only_closed_public_variants() {
        assert_eq!(
            serde_json::to_value([
                GuardRequirement::OwnerApproval,
                GuardRequirement::Reviewer,
                GuardRequirement::Auditor,
            ])
            .unwrap(),
            json!(["owner_approval", "reviewer", "auditor"])
        );
    }

    #[test]
    fn completeness_uses_authoritative_span_count_and_fixed_required_fields() {
        let events = trace_events();
        let trace = build_goal_runtime_trace(&events).unwrap();
        let mut candidate = serde_json::to_value(trace).unwrap();
        candidate["spans"][0]
            .as_object_mut()
            .unwrap()
            .remove("decision_kind");
        candidate["spans"]
            .as_array_mut()
            .unwrap()
            .push(json!({"self_reported_required_fields": 10_000}));

        let grade = grade_trace_completeness(&candidate, &events);

        assert_eq!(
            grade.expected_required_fields,
            events.len() * GOAL_RUNTIME_TRACE_REQUIRED_SPAN_FIELDS.len()
        );
        assert_eq!(
            grade.present_required_fields,
            grade.expected_required_fields - 1
        );
        assert!(!grade.passes);
        assert_eq!(
            grade.missing_fields,
            vec!["spans[0].decision_kind".to_owned()]
        );
    }
}
