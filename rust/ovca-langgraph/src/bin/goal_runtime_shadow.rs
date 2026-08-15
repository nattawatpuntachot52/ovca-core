use chrono::{DateTime, TimeZone, Utc};
use ovca_langgraph::{DurableGoalRuntime, DurableGoalRuntimeError, EventStamp, PlannedRunStamps};
use ovca_observability::GoalRuntimeEvaluationOutcome;
use ovca_types::{
    CompletionEvidence, CompletionPrecondition, ContractVersion, EventId, EvidenceId, EvidenceKind,
    EvidenceRef, GoalContract, GoalId, GuardRequirement, PermissionProfile, ProjectId, RetryBudget,
    RiskTier, Role, RunEvent, RunEventPayload, RunId, RunStatus, Task, TaskId, TaskStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[path = "goal_runtime_shadow/v2.rs"]
mod v2;

const INPUT_SCHEMA_VERSION: u32 = 1;
const OUTPUT_SCHEMA_VERSION: u32 = 1;
const MAX_INPUT_BYTES: u64 = 8 * 1024;
const PROTECTED_WORKSPACE_ENV: &str = "OVCA_PROTECTED_WORKSPACE";

type ShadowResult<T> = Result<T, ShadowError>;

#[derive(Debug)]
struct ShadowError {
    code: &'static str,
    safety_prefix: Option<Vec<u8>>,
}

impl ShadowError {
    const fn new(code: &'static str) -> Self {
        Self {
            code,
            safety_prefix: None,
        }
    }

    fn with_safety_prefix(code: &'static str, safety_prefix: Vec<u8>) -> Self {
        Self {
            code,
            safety_prefix: Some(safety_prefix),
        }
    }
}

#[derive(Debug)]
struct CliArgs {
    durable_root: PathBuf,
    input_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaskKind {
    CodeChange,
    Analysis,
    General,
}

impl TaskKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CodeChange => "code_change",
            Self::Analysis => "analysis",
            Self::General => "general",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequiredGate {
    None,
    Reviewer,
    Auditor,
}

impl RequiredGate {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reviewer => "reviewer",
            Self::Auditor => "auditor",
        }
    }

    fn requirements(self) -> BTreeSet<GuardRequirement> {
        match self {
            Self::None => BTreeSet::new(),
            Self::Reviewer => BTreeSet::from([GuardRequirement::Reviewer]),
            Self::Auditor => {
                BTreeSet::from([GuardRequirement::Reviewer, GuardRequirement::Auditor])
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DispatchOutcome {
    Success,
    NonSuccess,
}

impl DispatchOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NonSuccess => "non_success",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowInput {
    schema_version: u32,
    request_correlation: String,
    task_kind: TaskKind,
    required_gate: RequiredGate,
    dispatch_outcome: DispatchOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum PublicRoleName {
    Coordinator,
    Engineer,
    Reviewer,
    Auditor,
}

#[derive(Debug, Serialize)]
struct ShadowOutput {
    schema_version: u32,
    shadow_only: bool,
    request_correlation: String,
    task_kind: TaskKind,
    required_gate: RequiredGate,
    dispatch_outcome: DispatchOutcome,
    roles_observed: Vec<PublicRoleName>,
    required_roles: Vec<PublicRoleName>,
    evaluation_outcome: GoalRuntimeEvaluationOutcome,
    successful: bool,
    trace_completeness: f64,
    replay_parity: bool,
    event_count: u64,
    storage_backends: [&'static str; 2],
    decision_evidence_recorded: bool,
    production_effect: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorOutput {
    schema_version: u32,
    shadow_only: bool,
    successful: bool,
    error_code: &'static str,
    production_effect: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RunOutput {
    V1(ShadowOutput),
    V2(v2::Output),
}

enum DurableRootRoute {
    Validated(PathBuf),
    V2Rejected(v2::Output),
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            print_json(&output);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_json(&ErrorOutput {
                schema_version: OUTPUT_SCHEMA_VERSION,
                shadow_only: true,
                successful: false,
                error_code: error.code,
                production_effect: "none",
            });
            ExitCode::from(2)
        }
    }
}

fn run() -> ShadowResult<RunOutput> {
    let args = parse_args(env::args_os().skip(1))?;
    let input_result = read_bounded_input(args.input_file.as_deref());
    let durable_root = match route_durable_root(
        &args.durable_root,
        args.input_file.is_some(),
        &input_result,
        validate_durable_root,
    )? {
        DurableRootRoute::Validated(value) => value,
        DurableRootRoute::V2Rejected(output) => return Ok(RunOutput::V2(output)),
    };
    let input_bytes = input_result?;
    if declares_schema_v2(&input_bytes) {
        return Ok(RunOutput::V2(v2::execute(
            Some(&durable_root),
            Some(&args.durable_root),
            args.input_file.is_some(),
            &input_bytes,
        )));
    }
    let input: ShadowInput =
        serde_json::from_slice(&input_bytes).map_err(|_| ShadowError::new("input_invalid"))?;
    validate_input(&input)?;
    execute_shadow(&durable_root, input).map(RunOutput::V1)
}

fn declares_schema_v2(bytes: &[u8]) -> bool {
    v2::schema_version(bytes) == Some(2) || has_frozen_leading_schema_v2_field(bytes)
}

fn has_frozen_leading_schema_v2_field(bytes: &[u8]) -> bool {
    const KEY: &[u8] = br#""schema_version""#;

    let mut cursor = 0;
    skip_json_whitespace(bytes, &mut cursor);
    if bytes.get(cursor) != Some(&b'{') {
        return false;
    }
    cursor += 1;
    skip_json_whitespace(bytes, &mut cursor);

    if bytes.get(cursor..cursor + KEY.len()) != Some(KEY) {
        return false;
    }
    cursor += KEY.len();
    skip_json_whitespace(bytes, &mut cursor);

    if bytes.get(cursor) != Some(&b':') {
        return false;
    }
    cursor += 1;
    skip_json_whitespace(bytes, &mut cursor);

    if bytes.get(cursor) != Some(&b'2') {
        return false;
    }
    cursor += 1;

    !matches!(bytes.get(cursor), Some(b'0'..=b'9'))
}

fn skip_json_whitespace(bytes: &[u8], cursor: &mut usize) {
    while matches!(bytes.get(*cursor), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        *cursor += 1;
    }
}

fn route_durable_root<F>(
    raw_root: &Path,
    input_file_was_used: bool,
    input_result: &ShadowResult<Vec<u8>>,
    validator: F,
) -> ShadowResult<DurableRootRoute>
where
    F: FnOnce(&Path) -> ShadowResult<PathBuf>,
{
    if let Some(input_bytes) = input_classification_bytes(input_result) {
        if declares_schema_v2(input_bytes) && !v2::raw_durable_root_allowed(raw_root) {
            return Ok(DurableRootRoute::V2Rejected(v2::execute(
                None,
                Some(raw_root),
                input_file_was_used,
                input_bytes,
            )));
        }
    }

    match validator(raw_root) {
        Ok(value) => Ok(DurableRootRoute::Validated(value)),
        Err(error) => {
            if let Some(input_bytes) = input_classification_bytes(input_result) {
                if declares_schema_v2(input_bytes) {
                    return Ok(DurableRootRoute::V2Rejected(v2::execute(
                        None,
                        Some(raw_root),
                        input_file_was_used,
                        input_bytes,
                    )));
                }
            }
            Err(error)
        }
    }
}

fn input_classification_bytes(input_result: &ShadowResult<Vec<u8>>) -> Option<&[u8]> {
    match input_result {
        Ok(bytes) => Some(bytes),
        Err(error) => error.safety_prefix.as_deref(),
    }
}

fn parse_args<I>(mut args: I) -> ShadowResult<CliArgs>
where
    I: Iterator<Item = OsString>,
{
    let mut durable_root = None;
    let mut input_file = None;

    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--durable-root") if durable_root.is_none() => {
                durable_root = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| ShadowError::new("arguments_invalid"))?,
                ));
            }
            Some("--input-file") if input_file.is_none() => {
                input_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| ShadowError::new("arguments_invalid"))?,
                ));
            }
            _ => return Err(ShadowError::new("arguments_invalid")),
        }
    }

    Ok(CliArgs {
        durable_root: durable_root.ok_or_else(|| ShadowError::new("durable_root_required"))?,
        input_file,
    })
}

fn validate_durable_root(root: &Path) -> ShadowResult<PathBuf> {
    if !root.is_absolute() {
        return Err(ShadowError::new("durable_root_not_absolute"));
    }
    if is_unc_path(root) {
        return Err(ShadowError::new("durable_root_unsupported"));
    }

    let protected = protected_workspace_from_env()?;
    let candidate = canonicalize_with_missing(&lexically_normalize(root)?)?;
    let candidate_key = windows_path_key(&candidate);
    let protected_key = windows_path_key(&protected);

    if candidate_key == protected_key
        || candidate_key
            .strip_prefix(&protected_key)
            .is_some_and(|suffix| suffix.starts_with('\\'))
    {
        return Err(ShadowError::new("protected_root"));
    }

    Ok(candidate)
}

fn protected_workspace_from_env() -> ShadowResult<PathBuf> {
    let raw = env::var_os(PROTECTED_WORKSPACE_ENV)
        .ok_or_else(|| ShadowError::new("protected_workspace_required"))?;
    let path = PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        return Err(ShadowError::new("protected_workspace_required"));
    }
    if !path.is_absolute() {
        return Err(ShadowError::new("protected_workspace_not_absolute"));
    }
    if is_unc_or_device_path(&path) {
        return Err(ShadowError::new("protected_workspace_unsupported"));
    }

    let normalized =
        lexically_normalize(&path).map_err(|_| ShadowError::new("protected_workspace_invalid"))?;
    let canonical = fs::canonicalize(normalized)
        .map_err(|_| ShadowError::new("protected_workspace_invalid"))?;
    if !canonical.is_dir() {
        return Err(ShadowError::new("protected_workspace_invalid"));
    }
    Ok(canonical)
}

fn is_unc_path(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('/', "\\");
    text.starts_with(r"\\") && !text.starts_with(r"\\?\")
}

fn is_unc_or_device_path(path: &Path) -> bool {
    path.to_string_lossy().replace('/', "\\").starts_with(r"\\")
}

fn lexically_normalize(path: &Path) -> ShadowResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(r"\")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(ShadowError::new("durable_root_invalid"));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn canonicalize_with_missing(path: &Path) -> ShadowResult<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::<OsString>::new();

    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| ShadowError::new("durable_root_invalid"))?;
        missing.push(name.to_os_string());
        if !existing.pop() {
            return Err(ShadowError::new("durable_root_invalid"));
        }
    }

    let mut resolved =
        fs::canonicalize(existing).map_err(|_| ShadowError::new("durable_root_invalid"))?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    lexically_normalize(&resolved)
}

fn windows_path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches('\\').to_lowercase()
}

fn read_bounded_input(input_file: Option<&Path>) -> ShadowResult<Vec<u8>> {
    let mut bytes = Vec::new();
    match input_file {
        Some(path) => {
            let file = fs::File::open(path).map_err(|_| ShadowError::new("input_unavailable"))?;
            file.take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ShadowError::new("input_unavailable"))?;
        }
        None => {
            io::stdin()
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ShadowError::new("input_unavailable"))?;
        }
    }
    finish_bounded_input(bytes)
}

fn finish_bounded_input(bytes: Vec<u8>) -> ShadowResult<Vec<u8>> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(ShadowError::with_safety_prefix("input_too_large", bytes));
    }
    Ok(bytes)
}

fn validate_input(input: &ShadowInput) -> ShadowResult<()> {
    if input.schema_version != INPUT_SCHEMA_VERSION {
        return Err(ShadowError::new("input_schema_unsupported"));
    }
    let Some(suffix) = input.request_correlation.strip_prefix("grs-") else {
        return Err(ShadowError::new("request_correlation_invalid"));
    };
    if suffix.len() != 16
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ShadowError::new("request_correlation_invalid"));
    }
    Ok(())
}

fn execute_shadow(root: &Path, input: ShadowInput) -> ShadowResult<ShadowOutput> {
    let scope = format!(
        "{}-{}-{}-{}",
        input.request_correlation,
        input.task_kind.as_str(),
        input.required_gate.as_str(),
        input.dispatch_outcome.as_str()
    );
    let runtime_root = root.join("goal-runtime-shadow").join(scope);
    fs::create_dir_all(&runtime_root).map_err(|_| ShadowError::new("persistence_unavailable"))?;

    let runtime = DurableGoalRuntime::new(&runtime_root);
    let goal = goal_contract(input.required_gate);
    let tasks = vec![shadow_task(&goal)];
    let run_id = RunId::from("run-shadow");

    match runtime.load_run(&run_id, &goal) {
        Ok(_) => {}
        Err(DurableGoalRuntimeError::RunNotFound { .. }) => {
            runtime
                .create_run(run_id.clone(), &goal, &tasks, planned_stamps())
                .map_err(|_| ShadowError::new("runtime_rejected"))?;
        }
        Err(_) => return Err(ShadowError::new("runtime_rejected")),
    }

    runtime
        .initialize_execution(
            &run_id,
            &goal,
            &tasks,
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 1,
            },
        )
        .map_err(|_| ShadowError::new("runtime_rejected"))?;

    let current = runtime
        .load_run(&run_id, &goal)
        .map_err(|_| ShadowError::new("runtime_rejected"))?;
    if current.run_record.event_count == 4 {
        append_shadow_events(&runtime, &run_id, &goal, &input)?;
    }

    let replayed = runtime
        .load_run(&run_id, &goal)
        .map_err(|_| ShadowError::new("runtime_rejected"))?;
    let expected_event_count = expected_event_count(&input);
    if replayed.run_record.event_count != expected_event_count {
        return Err(ShadowError::new("runtime_state_conflict"));
    }
    let evaluation = runtime
        .evaluate_run(&run_id, &goal)
        .map_err(|_| ShadowError::new("runtime_rejected"))?;

    Ok(ShadowOutput {
        schema_version: OUTPUT_SCHEMA_VERSION,
        shadow_only: true,
        request_correlation: input.request_correlation,
        task_kind: input.task_kind,
        required_gate: input.required_gate,
        dispatch_outcome: input.dispatch_outcome,
        roles_observed: vec![PublicRoleName::Coordinator, PublicRoleName::Engineer],
        required_roles: required_roles(input.required_gate),
        evaluation_outcome: evaluation.invariants.outcome,
        successful: evaluation.passes,
        trace_completeness: evaluation.completeness.score,
        replay_parity: evaluation.replay_parity.canonical_match,
        event_count: replayed.run_record.event_count,
        storage_backends: ["jsonl", "sqlite"],
        decision_evidence_recorded: false,
        production_effect: "none",
    })
}

fn goal_contract(required_gate: RequiredGate) -> GoalContract {
    let review_required = required_gate != RequiredGate::None;
    let audit_required = required_gate == RequiredGate::Auditor;
    GoalContract {
        contract_version: ContractVersion::current(),
        id: GoalId::from("goal-shadow"),
        project_id: ProjectId::from("project-shadow"),
        objective: "evaluate normalized shadow metadata".to_owned(),
        constraints: vec!["shadow_only".to_owned(), "provider_independent".to_owned()],
        acceptance_criteria: vec!["normalized_input_accepted".to_owned()],
        verification_criteria: vec!["durable_replay_matches".to_owned()],
        permission_profile: PermissionProfile {
            contract_version: ContractVersion::current(),
            risk_tier: RiskTier::R0,
            resource_keys: Vec::new(),
            write_keys: Vec::new(),
            approval_required: false,
            review_required,
            audit_required,
        },
        definition_of_done: vec!["shadow_observation_recorded".to_owned()],
        completion_precondition: CompletionPrecondition {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        },
        created_at: fixed_time(0),
        updated_at: fixed_time(0),
    }
}

fn shadow_task(goal: &GoalContract) -> Task {
    Task {
        contract_version: ContractVersion::current(),
        id: TaskId::from("task-shadow"),
        goal_id: goal.id.clone(),
        outcome: "observe normalized dispatch".to_owned(),
        dependencies: Vec::new(),
        assigned_role: Role::Engineer,
        resource_keys: Vec::new(),
        write_keys: Vec::new(),
        status: TaskStatus::Pending,
        created_at: fixed_time(0),
        updated_at: fixed_time(0),
    }
}

fn planned_stamps() -> PlannedRunStamps {
    PlannedRunStamps {
        run_created: EventStamp {
            id: EventId::from("event-0"),
            occurred_at: fixed_time(0),
        },
        accepted: EventStamp {
            id: EventId::from("event-1"),
            occurred_at: fixed_time(1),
        },
        plan_recorded: EventStamp {
            id: EventId::from("event-2"),
            occurred_at: fixed_time(2),
        },
        planned: EventStamp {
            id: EventId::from("event-3"),
            occurred_at: fixed_time(3),
        },
    }
}

fn append_shadow_events(
    runtime: &DurableGoalRuntime,
    run_id: &RunId,
    goal: &GoalContract,
    input: &ShadowInput,
) -> ShadowResult<()> {
    append_event(
        runtime,
        run_id,
        goal,
        Role::Coordinator,
        RunEventPayload::StatusTransition {
            from: RunStatus::Planned,
            to: RunStatus::Running,
        },
    )?;

    if input.dispatch_outcome == DispatchOutcome::NonSuccess {
        append_event(
            runtime,
            run_id,
            goal,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Failed,
            },
        )?;
        return Ok(());
    }

    append_event(
        runtime,
        run_id,
        goal,
        Role::Engineer,
        RunEventPayload::EvidenceReferenceRecorded {
            evidence: EvidenceRef {
                contract_version: ContractVersion::current(),
                id: EvidenceId::from("evidence-shadow"),
                kind: EvidenceKind::TestResult,
                reference: "shadow://evidence/recorded".to_owned(),
                producer_role: Role::Engineer,
                integrity: None,
                produced_at: fixed_time(5),
            },
        },
    )?;
    append_event(
        runtime,
        run_id,
        goal,
        Role::Engineer,
        RunEventPayload::CompletionEvidenceRecorded {
            evidence: CompletionEvidence {
                contract_version: ContractVersion::current(),
                evidence_refs: vec![EvidenceId::from("evidence-shadow")],
                satisfied_acceptance_criteria: vec!["normalized_input_accepted".to_owned()],
                satisfied_verification_criteria: vec!["durable_replay_matches".to_owned()],
                satisfied_definition_of_done: vec!["shadow_observation_recorded".to_owned()],
            },
        },
    )?;

    if input.required_gate == RequiredGate::None {
        append_event(
            runtime,
            run_id,
            goal,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Completed,
            },
        )?;
    } else {
        append_event(
            runtime,
            run_id,
            goal,
            Role::Coordinator,
            RunEventPayload::ReviewAuditRequirementsRecorded {
                requirements: ovca_types::ReviewAuditRequirements {
                    contract_version: ContractVersion::current(),
                    guard_requirements: input.required_gate.requirements(),
                },
            },
        )?;
        append_event(
            runtime,
            run_id,
            goal,
            Role::Coordinator,
            RunEventPayload::StatusTransition {
                from: RunStatus::Running,
                to: RunStatus::Reviewing,
            },
        )?;
    }
    Ok(())
}

fn append_event(
    runtime: &DurableGoalRuntime,
    run_id: &RunId,
    goal: &GoalContract,
    producer_role: Role,
    payload: RunEventPayload,
) -> ShadowResult<()> {
    let current = runtime
        .load_run(run_id, goal)
        .map_err(|_| ShadowError::new("runtime_rejected"))?;
    let sequence = current.run_record.event_count;
    let previous_event_id = current
        .run_record
        .last_event_id
        .ok_or_else(|| ShadowError::new("runtime_state_conflict"))?;
    runtime
        .append_event(
            RunEvent {
                contract_version: ContractVersion::current(),
                id: EventId::from(format!("event-{sequence}")),
                run_id: run_id.clone(),
                sequence,
                previous_event_id: Some(previous_event_id),
                occurred_at: fixed_time(sequence as u32),
                producer_role,
                payload,
                metadata: BTreeMap::new(),
            },
            goal,
        )
        .map_err(|_| ShadowError::new("runtime_rejected"))?;
    Ok(())
}

fn expected_event_count(input: &ShadowInput) -> u64 {
    match (input.dispatch_outcome, input.required_gate) {
        (DispatchOutcome::NonSuccess, _) => 6,
        (DispatchOutcome::Success, RequiredGate::None) => 8,
        (DispatchOutcome::Success, RequiredGate::Reviewer | RequiredGate::Auditor) => 9,
    }
}

fn required_roles(required_gate: RequiredGate) -> Vec<PublicRoleName> {
    match required_gate {
        RequiredGate::None => Vec::new(),
        RequiredGate::Reviewer => vec![PublicRoleName::Reviewer],
        RequiredGate::Auditor => vec![PublicRoleName::Reviewer, PublicRoleName::Auditor],
    }
}

fn fixed_time(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, second)
        .single()
        .expect("fixed shadow timestamp is valid")
}

fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(_) => println!(
            "{{\"schema_version\":1,\"shadow_only\":true,\"successful\":false,\"error_code\":\"output_unavailable\",\"production_effect\":\"none\"}}"
        ),
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use std::cell::Cell;

    #[cfg(windows)]
    #[test]
    fn schema_v2_extended_unc_is_rejected_before_legacy_root_io() {
        let input = Ok(br#"{"schema_version":2,"request_correlation":"grs-0123456789abcdef","task_kind":"code_change","required_gate":"auditor","dispatch_outcome":"success","verification_request_id":"vreq.sha256.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec());
        let validator_called = Cell::new(false);

        let route = route_durable_root(Path::new(r"\\?\UNC\server\share"), false, &input, |_| {
            validator_called.set(true);
            panic!("extended UNC reached legacy filesystem validation")
        })
        .unwrap();

        assert!(!validator_called.get());
        let DurableRootRoute::V2Rejected(output) = route else {
            panic!("extended UNC was not rejected by schema-v2 raw preflight");
        };
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["status"], "configuration_error");
        assert_eq!(value["verification_status"], "observer_error");
        assert_eq!(value["production_effect"], "none");
    }

    #[cfg(windows)]
    #[test]
    fn truncated_schema_v2_extended_unc_is_rejected_before_legacy_root_io() {
        let inputs = [
            br#"{"schema_version":2,"request_correlation":"grs-0123456789abcdef""#.as_slice(),
            br#" { "schema_version" : 2,"request_correlation":"grs-0123456789abcdef""#.as_slice(),
        ];

        for input_bytes in inputs {
            assert_eq!(v2::schema_version(input_bytes), None);
            assert!(declares_schema_v2(input_bytes));
            let input = Ok(input_bytes.to_vec());
            let validator_called = Cell::new(false);

            let route =
                route_durable_root(Path::new(r"\\?\UNC\server\share"), false, &input, |_| {
                    validator_called.set(true);
                    panic!("truncated schema-v2 input reached legacy filesystem validation")
                })
                .unwrap();

            assert!(!validator_called.get());
            let DurableRootRoute::V2Rejected(output) = route else {
                panic!("truncated schema-v2 input was not rejected before root I/O");
            };
            let value = serde_json::to_value(output).unwrap();
            assert_eq!(value["status"], "configuration_error");
            assert_eq!(value["verification_status"], "observer_error");
            assert_eq!(value["production_effect"], "none");
        }
    }

    #[cfg(windows)]
    #[test]
    fn oversized_leading_schema_v2_device_roots_never_reach_legacy_validator() {
        let mut bytes =
            br#" { "schema_version" : 2,"request_correlation":"grs-0123456789abcdef","padding":""#
                .to_vec();
        bytes.resize(MAX_INPUT_BYTES as usize + 1, b'x');
        let input = finish_bounded_input(bytes);
        let Err(error) = &input else {
            panic!("oversized input was accepted");
        };
        assert_eq!(error.code, "input_too_large");
        let safety_prefix = error
            .safety_prefix
            .as_deref()
            .expect("oversized input must retain a capped safety prefix");
        assert_eq!(safety_prefix.len(), MAX_INPUT_BYTES as usize + 1);
        assert_eq!(v2::schema_version(safety_prefix), None);
        assert!(declares_schema_v2(safety_prefix));

        for raw_root in [
            r"\\?\UNC\server\share\verification",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\verification",
        ] {
            let validator_calls = Cell::new(0_usize);
            let route = route_durable_root(Path::new(raw_root), false, &input, |_| {
                validator_calls.set(validator_calls.get() + 1);
                panic!("oversized schema-v2 input reached legacy filesystem validation")
            })
            .unwrap();

            assert_eq!(validator_calls.get(), 0, "{raw_root}");
            let DurableRootRoute::V2Rejected(output) = route else {
                panic!("{raw_root} was not rejected before root I/O");
            };
            let value = serde_json::to_value(output).unwrap();
            assert_eq!(value["status"], "configuration_error", "{raw_root}");
            assert_eq!(value["verification_status"], "observer_error", "{raw_root}");
            assert_eq!(value["production_effect"], "none", "{raw_root}");
        }
    }

    #[test]
    fn leading_schema_classifier_does_not_promote_other_versions() {
        assert!(declares_schema_v2(br#"{"schema_version":2"#));
        assert!(declares_schema_v2(br#" { "schema_version" : 2 "#));
        assert!(!declares_schema_v2(br#"{"schema_version":1"#));
        assert!(!declares_schema_v2(br#"{"schema_version":20"#));
        assert!(!declares_schema_v2(
            br#"{"request_correlation":"grs-0123456789abcdef","schema_version":2"#
        ));
    }

    #[test]
    fn oversized_non_v2_prefixes_keep_legacy_root_error_precedence() {
        let valid_v1 = br#"{"schema_version":1,"request_correlation":"grs-0123456789abcdef","task_kind":"code_change","required_gate":"none","dispatch_outcome":"success"}"#
            .as_slice();
        let version_twenty = br#"{"schema_version":20}"#.as_slice();
        let non_leading_truncated_v2 =
            br#"{"request_correlation":"grs-0123456789abcdef","schema_version":2,"padding":""#
                .as_slice();

        for prefix in [valid_v1, version_twenty, non_leading_truncated_v2] {
            let mut bytes = prefix.to_vec();
            bytes.resize(MAX_INPUT_BYTES as usize + 1, b' ');
            let input = finish_bounded_input(bytes);
            let Err(input_error) = &input else {
                panic!("oversized countercase was accepted");
            };
            assert_eq!(input_error.code, "input_too_large");
            assert!(!declares_schema_v2(
                input_error.safety_prefix.as_deref().unwrap()
            ));

            let validator_calls = Cell::new(0_usize);
            let error =
                match route_durable_root(Path::new("legacy-invalid-root"), false, &input, |_| {
                    validator_calls.set(validator_calls.get() + 1);
                    Err(ShadowError::new("legacy_root_error"))
                }) {
                    Err(error) => error,
                    Ok(_) => panic!("oversized non-v2 input bypassed legacy root handling"),
                };
            assert_eq!(validator_calls.get(), 1);
            assert_eq!(error.code, "legacy_root_error");
        }
    }

    #[test]
    fn schema_v1_keeps_legacy_invalid_root_error_precedence() {
        let v1_input = Ok(br#"{"schema_version":1,"request_correlation":"grs-0123456789abcdef","task_kind":"code_change","required_gate":"none","dispatch_outcome":"success"}"#.to_vec());
        let validator_called = Cell::new(false);
        let error =
            match route_durable_root(Path::new("legacy-invalid-root"), false, &v1_input, |_| {
                validator_called.set(true);
                Err(ShadowError::new("legacy_root_error"))
            }) {
                Err(error) => error,
                Ok(_) => panic!("schema v1 bypassed legacy invalid-root handling"),
            };
        assert!(validator_called.get());
        assert_eq!(error.code, "legacy_root_error");

        let input_error = Err(ShadowError::new("input_unavailable"));
        let error = match route_durable_root(
            Path::new("legacy-invalid-root"),
            false,
            &input_error,
            |_| Err(ShadowError::new("legacy_root_error")),
        ) {
            Err(error) => error,
            Ok(_) => panic!("input error displaced the legacy invalid-root error"),
        };
        assert_eq!(error.code, "legacy_root_error");

        let truncated_v1 =
            Ok(br#"{"schema_version":1,"request_correlation":"grs-0123456789abcdef""#.to_vec());
        let validator_called = Cell::new(false);
        let error = match route_durable_root(
            Path::new("legacy-invalid-root"),
            false,
            &truncated_v1,
            |_| {
                validator_called.set(true);
                Err(ShadowError::new("legacy_root_error"))
            },
        ) {
            Err(error) => error,
            Ok(_) => panic!("truncated schema v1 bypassed legacy invalid-root handling"),
        };
        assert!(validator_called.get());
        assert_eq!(error.code, "legacy_root_error");
    }
}
