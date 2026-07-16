use anyhow::Result;
use ovca_llm_client::{
    append_jsonl_value, load_jsonl_values, now_iso, parse_args, port_from_env, safe_json,
    McpHttpClient,
};
use ovca_mcp::init_tracing;
use ovca_mcp::server::{BoxFuture, McpServer};
use ovca_storage::write_json_atomic;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;
use uuid::Uuid;

const DEFAULT_PORT: u16 = 18780;
const SPECIALISTS: &[&str] = &["engineer", "reviewer", "auditor"];
const DIVERGENCE_VERSION: &str = "v0.1";

fn policy_path(root: &Path) -> PathBuf {
    root.join("memory").join("coordinator").join("policy.json")
}

fn owner_queue_path(root: &Path) -> PathBuf {
    root.join("logs")
        .join("coordinator_owner_action_queue.json")
}

fn decision_dir(root: &Path) -> PathBuf {
    root.join("memory").join("coordinator").join("decisions")
}

fn dispatch_queue_path(root: &Path) -> PathBuf {
    root.join("memory")
        .join("coordinator")
        .join("tasks")
        .join("dispatch_queue.jsonl")
}

fn signals_path(root: &Path) -> PathBuf {
    root.join("logs").join("agent_signals.jsonl")
}

fn last_report_path(root: &Path) -> PathBuf {
    root.join("logs").join("coordinator_last_report.json")
}

fn divergence_path(root: &Path, task_name: &str) -> PathBuf {
    root.join("tasks")
        .join("inbox")
        .join(task_name)
        .join("divergence.json")
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

fn classify_divergence_policy(
    text: &str,
    intent: &str,
    route_target: &str,
) -> (&'static str, &'static str) {
    let lowered = text.to_ascii_lowercase();

    let cross_domain_conflict = contains_any(
        &lowered,
        &[
            "cross-domain",
            "cross domain",
            "cross functional",
            "conflict between",
            "tradeoff between teams",
            "disagreement between",
            "multiple stakeholders disagree",
        ],
    );
    let root_cause_unknown = contains_any(
        &lowered,
        &[
            "root cause unknown",
            "unknown root cause",
            "ambiguous bug",
            "bug triage",
            "investigate bug",
            "triage this",
            "diagnose",
            "intermittent",
            "flaky",
            "not sure why",
        ],
    ) && contains_any(
        &lowered,
        &["bug", "error", "failure", "issue", "pipeline", "regression"],
    );
    let strategy_tradeoff = contains_any(
        &lowered,
        &[
            "tradeoff",
            "trade-off",
            "choose between",
            "which option",
            "prioritize",
            "priority order",
            "strategy recommendation",
            "recommend a strategy",
            "allocation decision",
            "multiple paths",
        ],
    );
    let new_design_required = contains_any(
        &lowered,
        &[
            "architecture",
            "architectural",
            "system design",
            "new workflow",
            "new process",
            "new policy",
            "new design",
            "design the workflow",
            "design this system",
            "operating model",
        ],
    );
    let ambiguous_problem = contains_any(
        &lowered,
        &[
            "ambiguous",
            "unclear",
            "open ended",
            "open-ended",
            "alternatives",
            "explore alternatives",
            "option space",
            "reframe",
            "not sure how",
            "problem framing",
        ],
    );

    if cross_domain_conflict {
        return ("required", "cross_domain_conflict");
    }
    if root_cause_unknown {
        return ("required", "root_cause_unknown");
    }
    if strategy_tradeoff {
        return ("required", "strategy_tradeoff");
    }
    if new_design_required {
        return ("required", "new_design");
    }
    if ambiguous_problem {
        return ("required", "ambiguous_problem");
    }

    let recommended_ui_ux = contains_any(
        &lowered,
        &["ui", "ux", "user experience", "concept", "concepting"],
    );
    let recommended_course = contains_any(
        &lowered,
        &[
            "course",
            "curriculum",
            "lesson plan",
            "content ideation",
            "brainstorm",
        ],
    );
    let recommended_story = contains_any(
        &lowered,
        &[
            "presentation",
            "story framing",
            "narrative",
            "slides",
            "messaging",
        ],
    );
    let recommended_roadmap =
        contains_any(&lowered, &["roadmap", "milestones", "sequencing options"]);

    if recommended_ui_ux || recommended_course {
        return ("recommended", "new_design");
    }
    if recommended_story {
        return ("recommended", "ambiguous_problem");
    }
    if recommended_roadmap {
        return ("recommended", "strategy_tradeoff");
    }

    let _ = (route_target, intent);
    ("exempt", "")
}

fn build_divergence_policy(mode: &str, reason: &str, artifact_path: &str) -> Value {
    let (min_options, min_families, required_lenses): (u64, u64, Vec<&str>) = match mode {
        "required" => (3, 2, vec!["default_challenge", "outside_view"]),
        "recommended" => (3, 2, vec!["default_challenge", "outside_view"]),
        _ => (0, 0, vec![]),
    };

    json!({
        "mode": mode,
        "reason": reason,
        "min_options": min_options,
        "min_families": min_families,
        "required_lenses": required_lenses,
        "artifact_path": artifact_path,
        "owner_override": false,
    })
}

fn validate_string_list(value: &Value) -> bool {
    value
        .as_array()
        .map(|items| items.iter().all(|item| item.as_str().is_some()))
        .unwrap_or(false)
}

fn collect_string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn validate_constraints_shape(constraints: &Value) -> bool {
    let Some(obj) = constraints.as_object() else {
        return false;
    };

    for key in ["must_preserve", "forbidden", "acceptance"] {
        if let Some(value) = obj.get(key) {
            if !validate_string_list(value) {
                return false;
            }
        }
    }

    for key in ["time_budget", "risk_budget"] {
        if let Some(value) = obj.get(key) {
            if value.as_str().is_none() {
                return false;
            }
        }
    }

    true
}

fn normalize_domain(domain: &str) -> &'static str {
    match domain.trim().to_ascii_lowercase().as_str() {
        "strategy" => "strategy",
        "research" => "research",
        "engineering" => "engineering",
        "product" => "product",
        "ops" => "ops",
        _ => "general",
    }
}

fn normalize_task_name(task_name: &str) -> Option<String> {
    let trimmed = task_name.trim();
    if trimmed.is_empty()
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn mode_minimums(mode: &str) -> (usize, usize, usize) {
    match mode {
        "quick" => (3, 1, 1),
        "standard" => (4, 2, 1),
        "deep" => (6, 3, 3),
        _ => (0, 0, 0),
    }
}

fn normalize_outside_view_role(role: &str) -> &'static str {
    match role.trim().to_ascii_lowercase().as_str() {
        "owner" | "coordinator" => "owner",
        "engineering" | "engineer" => "engineering",
        "ops" | "operations" | "auditor" => "ops",
        "user" => "user",
        _ => "user",
    }
}

fn build_outside_view(role: &str, objective: &str) -> Value {
    match role {
        "owner" => json!({
            "role": "owner",
            "point_of_view": format!("The owner wants {} to stay aligned with explicit constraints and a reversible decision path.", objective),
            "risk_seen": "A fast default path can hide a trade-off that becomes expensive to unwind later.",
        }),
        "engineering" => json!({
            "role": "engineering",
            "point_of_view": "Engineering optimizes for a path that is implementable, testable, and easy to roll back.",
            "risk_seen": "An option that looks simple on paper can still create hidden maintenance or integration debt.",
        }),
        "ops" => json!({
            "role": "ops",
            "point_of_view": "Ops cares about runtime stability, observability, and the cost of supporting the chosen path.",
            "risk_seen": "A novel option may shift complexity into deployment or incident response.",
        }),
        _ => json!({
            "role": "user",
            "point_of_view": "The user lens values a path that preserves clarity, speed, and predictable outcomes.",
            "risk_seen": "Internal optimization can degrade the external experience if success is measured only by implementation convenience.",
        }),
    }
}

fn build_diverge_error(error_code: &str, reason: &str) -> Value {
    json!({
        "ok": false,
        "tool": "oracle_diverge",
        "version": DIVERGENCE_VERSION,
        "error_code": error_code,
        "reason": reason,
    })
}

fn maybe_write_divergence_artifact(
    root: &Path,
    task_name: Option<&str>,
    policy_mode: &str,
    tool_output: &Value,
) -> std::result::Result<Option<String>, String> {
    let Some(task_name) = task_name else {
        return Ok(None);
    };
    let Some(task_name) = normalize_task_name(task_name) else {
        return Err("task_name must be a simple task folder name".to_string());
    };

    let artifact_path = divergence_path(root, &task_name);
    let mut artifact = tool_output.clone();
    let Some(obj) = artifact.as_object_mut() else {
        return Err("oracle_diverge output must be a JSON object".to_string());
    };
    obj.insert("task_name".to_string(), json!(task_name));
    obj.insert("created_at".to_string(), json!(now_iso()));
    obj.insert("policy_mode".to_string(), json!(policy_mode));
    obj.insert("chosen_option_id".to_string(), json!(""));
    obj.insert("source".to_string(), json!("oracle_diverge"));
    obj.insert("version".to_string(), json!(DIVERGENCE_VERSION));

    write_json_atomic(&artifact_path, &artifact).map_err(|error| error.to_string())?;
    Ok(Some(artifact_path.to_string_lossy().replace('\\', "/")))
}

fn oracle_diverge(root: &Path, args: Value) -> Value {
    let objective = args
        .get("objective")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if objective.is_empty() {
        return build_diverge_error("missing_objective", "objective is required");
    }

    let prompt = args
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if prompt.is_empty() {
        return build_diverge_error("invalid_input", "prompt is required");
    }

    let mode = args
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !matches!(mode.as_str(), "quick" | "standard" | "deep") {
        return build_diverge_error(
            "unsupported_mode",
            "mode must be one of quick, standard, or deep",
        );
    }

    let min_options = args.get("min_options").and_then(Value::as_u64).unwrap_or(0) as usize;
    if min_options < 2 {
        return build_diverge_error("invalid_input", "min_options must be at least 2");
    }

    if let Some(constraints) = args.get("constraints") {
        if !validate_constraints_shape(constraints) {
            return build_diverge_error("invalid_input", "constraints has an invalid shape");
        }
    }

    let domain = normalize_domain(
        args.get("domain")
            .and_then(Value::as_str)
            .unwrap_or("general"),
    );
    let task_name = args.get("task_name").and_then(Value::as_str);
    if let Some(raw_task_name) = task_name {
        if normalize_task_name(raw_task_name).is_none() {
            return build_diverge_error(
                "invalid_input",
                "task_name must not contain path separators or traversal",
            );
        }
    }

    let classification_text = format!("{objective}\n{prompt}");
    let intent = classify_intent(&classification_text);
    let route_target = match domain {
        "research" => "auditor",
        "engineering" => "engineer",
        _ => intent_to_agent(&intent),
    };
    let (policy_mode, policy_reason) =
        classify_divergence_policy(&classification_text, &intent, route_target);

    if policy_mode == "exempt" {
        let mut output = build_diverge_error(
            "deterministic_task_exempt",
            "task does not require divergent exploration",
        );
        if let Ok(Some(path)) =
            maybe_write_divergence_artifact(root, task_name, policy_mode, &output)
        {
            if let Some(obj) = output.as_object_mut() {
                obj.insert("artifact_path".to_string(), json!(path));
            }
        }
        return output;
    }

    let current_default = args
        .get("current_default")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let require_default_challenge = args
        .get("require_default_challenge")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let require_outside_view = args
        .get("require_outside_view")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let (mode_min_options, reframe_count, outside_view_target) = mode_minimums(&mode);
    let target_option_count = std::cmp::max(mode_min_options, min_options);

    let base_context = if current_default.is_empty() {
        objective.clone()
    } else {
        format!("{objective} (current default: {current_default})")
    };

    let mut default_assumptions = vec![json!({
        "assumption": if current_default.is_empty() {
            "The current/default path is good enough without exploring alternatives.".to_string()
        } else {
            format!("The current default path ({current_default}) is already the best baseline.")
        },
        "status": "challenged",
        "basis": "assumed",
        "note": "The divergence step exists to test at least one non-default path before converging.",
    })];

    if domain == "engineering"
        || contains_any(
            &prompt.to_ascii_lowercase(),
            &["bug", "error", "issue", "failure"],
        )
    {
        default_assumptions.push(json!({
            "assumption": "The root cause is already understood well enough to commit to one fix path.",
            "status": "challenged",
            "basis": "unknown",
            "note": "The request does not itself prove the root cause or that one fix family dominates the others.",
        }));
    }
    if mode != "quick" {
        default_assumptions.push(json!({
            "assumption": "Speed matters more than option quality for this decision.",
            "status": "retained",
            "basis": "inferred",
            "note": "A quick path can still be appropriate if the selected option stays reversible and bounded.",
        }));
    }
    if mode == "deep" {
        default_assumptions.push(json!({
            "assumption": "All stakeholders optimize for the same success metric.",
            "status": "challenged",
            "basis": "assumed",
            "note": "Deep mode should force multiple lenses before selecting one path.",
        }));
    }

    let reframe_blueprints = vec![
        (
            "Treat it as a reversibility problem",
            "This widens the option set toward safe, staged moves instead of a single all-in commitment.",
        ),
        (
            "Treat it as an evidence problem",
            "This favors options that collapse uncertainty fastest rather than options that merely feel familiar.",
        ),
        (
            "Treat it as a coordination problem",
            "This exposes whether the real blocker is a conflict between constraints, teams, or approval boundaries.",
        ),
        (
            "Treat it as a sequencing problem",
            "This separates what must happen now from what can wait until after the first learning loop.",
        ),
    ];
    let reframes: Vec<Value> = reframe_blueprints
        .into_iter()
        .take(reframe_count)
        .enumerate()
        .map(|(idx, (frame, why_it_changes_options))| {
            json!({
                "id": format!("R{}", idx + 1),
                "frame": frame,
                "why_it_changes_options": why_it_changes_options,
            })
        })
        .collect();

    let option_blueprints = vec![
        (
            "policy",
            "Constrain the decision rule first",
            format!("Define the explicit go/no-go boundaries for {base_context} before selecting a path."),
            "Reduces hidden trade-offs and makes later selection defensible.",
            "Adds upfront structure before execution begins.",
            vec!["Can feel slower if the task is already well-understood."],
            vec!["The owner needs a traceable choice under multiple constraints."],
            "inferred",
            0.82_f64,
            0.35_f64,
        ),
        (
            "process",
            "Run a reversible thin-slice",
            format!("Test the smallest safe slice of {base_context} before scaling the chosen path."),
            "Produces learning quickly while preserving rollback optionality.",
            "May under-represent long-tail integration costs.",
            vec!["The thin slice can miss complexity that appears only at full scale."],
            vec!["Rollback cost is low and learning speed matters."],
            "inferred",
            0.86_f64,
            0.51_f64,
        ),
        (
            "tooling",
            "Instrument before changing behavior",
            format!("Add the narrowest instrumentation around {base_context} so the next decision is evidence-backed."),
            "Turns the next iteration into an observed rather than assumed choice.",
            "Instrumentation itself adds some implementation overhead.",
            vec!["The signal collected may still be incomplete if the metric is too narrow."],
            vec!["The current blocker is weak evidence rather than weak effort."],
            "observed",
            0.79_f64,
            0.48_f64,
        ),
        (
            "people",
            "Escalate the unresolved trade-off",
            "Surface the decision boundary to the stakeholder best positioned to choose between competing objectives.".to_string(),
            "Prevents silent local optimization when the real issue is authority or alignment.",
            "Requires someone to own the trade-off explicitly.",
            vec!["Escalation can stall if the question is not framed crisply."],
            vec!["Success depends on approval, priorities, or conflicting stakeholder goals."],
            "inferred",
            0.68_f64,
            0.57_f64,
        ),
        (
            "fallback",
            "Keep the default path but add rollback",
            "Use the familiar path while recording a rollback trigger and the condition that would force a revisit.".to_string(),
            "Fastest path when the default is already good enough.",
            "Carries the risk of converging too early on a familiar answer.",
            vec!["The default path can anchor the team and suppress better alternatives."],
            vec!["The current default is already stable and the downside of waiting is high."],
            if current_default.is_empty() { "assumed" } else { "observed" },
            0.88_f64,
            0.22_f64,
        ),
        (
            "process",
            "Separate discovery from delivery",
            "Do one short discovery pass to compare option families, then only implement the option that survives.".to_string(),
            "Keeps divergence bounded instead of letting it turn into open-ended brainstorming.",
            "Introduces a deliberate planning checkpoint before delivery.",
            vec!["The discovery pass can drift if success criteria stay vague."],
            vec!["The task has multiple credible families but time is still constrained."],
            "inferred",
            0.74_f64,
            0.61_f64,
        ),
        (
            "tooling",
            "Prototype a parallel path in isolation",
            "Build or sketch one non-default option in parallel without committing the mainline to it yet.".to_string(),
            "Creates genuine contrast against the default path instead of hypothetical contrast only.",
            "Costs more effort than evaluating options on paper.",
            vec!["Parallel work can diverge from the mainline if the scope is not tightly bounded."],
            vec!["A meaningful alternative cannot be evaluated accurately without touching the real system."],
            "assumed",
            0.64_f64,
            0.79_f64,
        ),
    ];

    let mut options: Vec<Value> = option_blueprints
        .into_iter()
        .take(target_option_count)
        .enumerate()
        .map(
            |(
                idx,
                (
                    family,
                    title,
                    summary,
                    upside,
                    downside,
                    risks,
                    best_when,
                    basis,
                    feasibility_score,
                    novelty_score,
                ),
            )| {
                json!({
                    "id": format!("O{}", idx + 1),
                    "family": family,
                    "title": title,
                    "summary": summary,
                    "upside": upside,
                    "downside": downside,
                    "risks": risks,
                    "best_when": best_when,
                    "basis": basis,
                    "feasibility_score": feasibility_score,
                    "novelty_score": novelty_score,
                })
            },
        )
        .collect();

    options.dedup_by(|left, right| left["title"] == right["title"]);
    if options.len() < target_option_count {
        let mut output = build_diverge_error(
            "insufficient_option_diversity",
            "generated options did not meet the requested diversity threshold",
        );
        if let Ok(Some(path)) =
            maybe_write_divergence_artifact(root, task_name, policy_mode, &output)
        {
            if let Some(obj) = output.as_object_mut() {
                obj.insert("artifact_path".to_string(), json!(path));
            }
        }
        return output;
    }

    let stakeholder_roles = {
        let mut roles = collect_string_list(args.get("stakeholders"));
        if roles.is_empty() {
            roles = vec![
                "owner".to_string(),
                "engineering".to_string(),
                "ops".to_string(),
                "user".to_string(),
            ];
        }
        let mut seen = HashSet::new();
        roles
            .into_iter()
            .map(|role| normalize_outside_view_role(&role).to_string())
            .filter(|role| seen.insert(role.clone()))
            .collect::<Vec<_>>()
    };

    let outside_view_count = if require_outside_view {
        outside_view_target
    } else {
        std::cmp::min(1, outside_view_target)
    };
    let outside_views: Vec<Value> = stakeholder_roles
        .into_iter()
        .take(outside_view_count)
        .map(|role| build_outside_view(&role, &objective))
        .collect();
    let actual_outside_view_count = outside_views.len();

    let distinct_families = options
        .iter()
        .filter_map(|option| option.get("family").and_then(Value::as_str))
        .collect::<HashSet<_>>()
        .len();
    let default_challenged = default_assumptions.iter().any(|assumption| {
        assumption
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            == "challenged"
    });

    let convergence_ready = options.len() >= target_option_count
        && distinct_families >= 2
        && (!require_default_challenge || default_challenged)
        && (!require_outside_view || !outside_views.is_empty());

    let mut output = json!({
        "ok": true,
        "tool": "oracle_diverge",
        "version": DIVERGENCE_VERSION,
        "problem_frame": {
            "restated_problem": objective,
            "job_to_be_done": format!("Expand the option space for {} before converging on one execution path.", base_context),
            "why_now": args
                .get("constraints")
                .and_then(Value::as_object)
                .and_then(|constraints| constraints.get("time_budget"))
                .and_then(Value::as_str)
                .map(|budget| format!("A decision is needed within the stated time budget: {budget}."))
                .unwrap_or_else(|| "A decision is needed before execution hardens the default path.".to_string()),
        },
        "default_assumptions": default_assumptions,
        "reframes": reframes,
        "options": options,
        "outside_views": outside_views,
        "evidence_gaps": [
            "No comparative evidence was provided showing that the current default dominates the other option families.",
            "The request does not quantify which downside is unacceptable enough to eliminate an option immediately.",
        ],
        "next_questions": [
            "Which downside is unacceptable even if the option is faster to execute?",
            "What evidence would eliminate one option family immediately?",
            "Which option should become the chosen_option_id for execution, and what would trigger a revisit later?",
        ],
        "coverage": {
            "option_count": target_option_count,
            "distinct_families": distinct_families,
            "default_challenged": default_challenged,
            "outside_view_count": actual_outside_view_count,
        },
        "convergence_ready": convergence_ready,
        "divergence_policy": build_divergence_policy(policy_mode, policy_reason, ""),
    });

    if let Some(obj) = output.as_object_mut() {
        if let Some(options) = obj.get("options").and_then(Value::as_array) {
            obj.insert(
                "coverage".to_string(),
                json!({
                    "option_count": options.len(),
                    "distinct_families": distinct_families,
                    "default_challenged": default_challenged,
                    "outside_view_count": actual_outside_view_count,
                }),
            );
        }
    }

    match maybe_write_divergence_artifact(root, task_name, policy_mode, &output) {
        Ok(Some(path)) => {
            if let Some(obj) = output.as_object_mut() {
                obj.insert("artifact_path".to_string(), json!(path.clone()));
                obj.insert(
                    "divergence_policy".to_string(),
                    build_divergence_policy(policy_mode, policy_reason, &path),
                );
            }
        }
        Ok(None) => {}
        Err(error) => {
            return build_diverge_error("invalid_input", &error);
        }
    }

    output
}

fn tokenize(text: &str) -> HashSet<String> {
    let mut tokens = HashSet::new();
    let mut current = String::new();

    for ch in text.chars() {
        let is_token =
            ch.is_ascii_alphanumeric() || ch == '_' || ('\u{0E00}'..='\u{0E7F}').contains(&ch);
        if is_token {
            for lower in ch.to_lowercase() {
                current.push(lower);
            }
        } else if !current.is_empty() {
            tokens.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.insert(current);
    }

    tokens
}

fn intent_keywords() -> [(&'static str, &'static [&'static str]); 4] {
    [
        (
            "intel",
            &[
                "market",
                "macro",
                "geopolitics",
                "fed",
                "inflation",
                "rate",
                "regime",
                "stocks",
                "equity",
                "crypto",
                "gold",
                "oil",
            ],
        ),
        (
            "research",
            &[
                "hypothesis",
                "backtest",
                "strategy",
                "edge",
                "research",
                "statistical",
                "correlation",
                "robustness",
            ],
        ),
        (
            "trading",
            &[
                "trade",
                "position",
                "risk",
                "entry",
                "exit",
                "drawdown",
                "execution",
                "order",
                "stop",
                "hedge",
                "portfolio",
            ],
        ),
        (
            "engineering",
            &[
                "script", "code", "bug", "automate", "api", "python", "rust", "fix", "error",
                "pipeline",
            ],
        ),
    ]
}

fn classify_intent(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    let tokens = tokenize(&lowered);
    for (intent, keywords) in intent_keywords() {
        if keywords.iter().any(|keyword| {
            keyword
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
                && tokens.contains(*keyword)
                || lowered.contains(keyword)
        }) {
            return intent.to_string();
        }
    }
    "general".to_string()
}

fn intent_to_agent(intent: &str) -> &'static str {
    match intent {
        "intel" => "reviewer",
        "research" => "auditor",
        "trading" => "coordinator",
        "engineering" => "engineer",
        _ => "coordinator",
    }
}

fn resolve_requested_agent(raw: &str) -> String {
    let normalized = raw.trim().to_ascii_lowercase();
    if SPECIALISTS.contains(&normalized.as_str()) || normalized == "coordinator" {
        normalized
    } else {
        String::new()
    }
}

fn read_signals(root: &Path) -> BTreeMap<String, Value> {
    let mut latest = BTreeMap::new();
    for row in load_jsonl_values(&signals_path(root)) {
        let agent = row
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !agent.is_empty() {
            latest.insert(agent, row);
        }
    }
    latest
}

fn lookup_policy(policy: &Value, rule_id: &str) -> Option<Value> {
    let mut current = policy;
    for part in rule_id.split('.').filter(|part| !part.is_empty()) {
        current = current.as_object()?.get(part)?;
    }
    Some(current.clone())
}

async fn call_or_error(
    client: &McpHttpClient,
    agent_id: &str,
    tool_name: &str,
    args: Value,
) -> Value {
    match client.call_tool(agent_id, tool_name, args).await {
        Ok(payload) => payload,
        Err(error) => json!({
            "ok": false,
            "agent": agent_id,
            "error": error.to_string(),
            "offline": true,
            "result": {
                "offline": true,
            },
        }),
    }
}

fn agent_overall_status(payload: &Value) -> String {
    let result = payload.get("result").unwrap_or(payload);
    result
        .get("latest")
        .and_then(|latest| latest.get("overall_status"))
        .or_else(|| result.get("overall_status"))
        .or_else(|| result.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

async fn team_status_with_client(client: &McpHttpClient) -> Value {
    let (engineer, reviewer, auditor) = tokio::join!(
        call_or_error(
            client,
            "engineer",
            "engineer_ops_health",
            json!({"limit_history": 5})
        ),
        call_or_error(
            client,
            "reviewer",
            "reviewer_review_status",
            json!({"limit_history": 5})
        ),
        call_or_error(
            client,
            "auditor",
            "auditor_cross_audit_status",
            json!({"limit_history": 5})
        ),
    );

    let offline_agents = [
        ("engineer", &engineer),
        ("reviewer", &reviewer),
        ("auditor", &auditor),
    ]
    .into_iter()
    .filter_map(|(agent, payload)| {
        if payload["ok"].as_bool().unwrap_or(false) {
            None
        } else {
            Some(Value::String(agent.to_string()))
        }
    })
    .collect::<Vec<_>>();

    let engineering_status = agent_overall_status(&engineer);
    let review_status = agent_overall_status(&reviewer);
    let cross_audit_status = agent_overall_status(&auditor);

    let overall_status = if !offline_agents.is_empty() {
        "degraded"
    } else if [&engineering_status, &review_status, &cross_audit_status]
        .iter()
        .any(|status| matches!(status.to_ascii_lowercase().as_str(), "warn" | "fail"))
    {
        "warn"
    } else {
        "ok"
    };

    json!({
        "ok": true,
        "overall_status": overall_status,
        "summary": {
            "offline_agents": offline_agents,
            "engineering_status": engineering_status,
            "review_status": review_status,
            "cross_audit_status": cross_audit_status,
        },
        "agents": {
            "engineer": engineer,
            "reviewer": reviewer,
            "auditor": auditor,
        }
    })
}

fn route_intake(args: Value) -> Value {
    let user_text = args
        .get("user_text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if user_text.is_empty() {
        return json!({"ok": false, "error": "user_text is required"});
    }

    let requested_agent = resolve_requested_agent(
        args.get("requested_agent")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let intent = classify_intent(&user_text);
    let route_target = if requested_agent.is_empty() {
        intent_to_agent(&intent).to_string()
    } else {
        requested_agent.clone()
    };
    let reason = if requested_agent.is_empty() {
        format!("intent:{}", intent)
    } else {
        "explicit_request".to_string()
    };
    let (policy_mode, policy_reason) =
        classify_divergence_policy(&user_text, &intent, &route_target);

    json!({
        "ok": true,
        "gateway": "coordinator_mcp",
        "intent": intent,
        "requested_agent": requested_agent,
        "route_target": route_target,
        "reason": reason,
        "divergence_policy": build_divergence_policy(policy_mode, policy_reason, ""),
    })
}

fn dispatch(root: &Path, args: Value) -> Value {
    let agent = args
        .get("agent")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !SPECIALISTS.contains(&agent.as_str()) {
        return json!({"ok": false, "error": "unknown agent"});
    }
    let objective = args
        .get("objective")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if objective.is_empty() {
        return json!({"ok": false, "error": "objective is required"});
    }

    let tracking_id = format!("ktask_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let packet = json!({
        "tracking_id": tracking_id,
        "created_at": now_iso(),
        "agent": agent,
        "objective": objective,
        "deadline": args.get("deadline").and_then(Value::as_str).unwrap_or("").trim(),
        "status": "queued",
        "source": "coordinator_mcp",
    });
    let path = dispatch_queue_path(root);
    if let Err(error) = append_jsonl_value(&path, &packet) {
        return json!({"ok": false, "error": error.to_string()});
    }

    json!({
        "ok": true,
        "task_packet": packet,
        "path": path.to_string_lossy().replace('\\', "/"),
    })
}

fn decision_log(root: &Path, args: Value) -> Value {
    let context = args
        .get("context")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let decision = args
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let reasoning = args
        .get("reasoning")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if context.is_empty() || decision.is_empty() || reasoning.is_empty() {
        return json!({"ok": false, "error": "context, decision, and reasoning are required"});
    }

    let id = Uuid::new_v4().simple().to_string()[..12].to_string();
    let now = now_iso();
    let entry = json!({
        "id": id,
        "ts": now,
        "context": context,
        "decision": decision,
        "reasoning": reasoning,
    });
    let path = decision_dir(root).join(format!("{}.jsonl", &now[..10]));
    if let Err(error) = append_jsonl_value(&path, &entry) {
        return json!({"ok": false, "error": error.to_string()});
    }

    json!({
        "ok": true,
        "entry": entry,
        "path": path.to_string_lossy().replace('\\', "/"),
    })
}

fn policy_lookup(root: &Path, args: Value) -> Value {
    let policy = safe_json(&policy_path(root), json!({}));
    let rule_id = args
        .get("rule_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if rule_id.is_empty() {
        return json!({
            "ok": true,
            "rule_id": "",
            "value": policy,
        });
    }

    let Some(value) = lookup_policy(&policy, &rule_id) else {
        return json!({
            "ok": false,
            "error": "rule_not_found",
            "rule_id": rule_id,
        });
    };

    json!({
        "ok": true,
        "rule_id": rule_id,
        "value": value,
        "updated_at": policy.get("updated_at").and_then(Value::as_str).unwrap_or(""),
    })
}

fn normalize_signal(input: Option<&Value>) -> Value {
    match input {
        Some(value) if value.is_object() => value.clone(),
        Some(value) if !value.is_null() => json!({"stance": value.as_str().unwrap_or("").trim()}),
        _ => json!({}),
    }
}

fn conflict_surface(root: &Path, args: Value) -> Value {
    let latest = read_signals(root);
    let left = if args.get("signal_a").is_some() {
        normalize_signal(args.get("signal_a"))
    } else {
        latest.get("reviewer").cloned().unwrap_or_else(|| json!({}))
    };
    let right = if args.get("signal_b").is_some() {
        normalize_signal(args.get("signal_b"))
    } else {
        latest.get("auditor").cloned().unwrap_or_else(|| json!({}))
    };

    let left_stance = left
        .get("stance")
        .or_else(|| left.get("signal"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let right_stance = right
        .get("stance")
        .or_else(|| right.get("signal"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let conflict =
        !left_stance.is_empty() && !right_stance.is_empty() && left_stance != right_stance;

    json!({
        "ok": true,
        "conflict": conflict,
        "severity": if conflict { "high" } else { "low" },
        "requires_owner": conflict,
        "summary": format!("signal_a={} vs signal_b={}", if left_stance.is_empty() { "unknown" } else { &left_stance }, if right_stance.is_empty() { "unknown" } else { &right_stance }),
        "signal_a": left,
        "signal_b": right,
    })
}

fn owner_queue(root: &Path) -> Value {
    let payload = safe_json(&owner_queue_path(root), json!({}));
    json!({
        "ok": true,
        "payload": if payload.is_object() { payload } else { json!({}) },
    })
}

/// Aggregate session context in one call — used by the Coordinator gateway hook.
/// Returns: owner_queue summary, checklist health, latest signals, pending decisions.
fn session_brief(root: &Path) -> Value {
    // ── owner queue ────────────────────────────────────────────────────────
    let queue_raw = safe_json(&owner_queue_path(root), json!({}));
    let queue_count = queue_raw.get("count").and_then(Value::as_u64).unwrap_or(0);
    let queue_items: Vec<String> = queue_raw
        .get("actions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|a| {
                    a.get("requires_owner")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .take(3)
                .filter_map(|a| a.get("summary").and_then(Value::as_str))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // ── checklist / last report ────────────────────────────────────────────
    let report_raw = safe_json(&last_report_path(root), json!({}));
    let chk = report_raw
        .pointer("/checklist/summary")
        .cloned()
        .unwrap_or(json!({}));
    let chk_pass = chk.get("pass").and_then(Value::as_u64).unwrap_or(0);
    let chk_fail = chk.get("fail").and_then(Value::as_u64).unwrap_or(0);
    // ── latest agent signals ───────────────────────────────────────────────
    let signals = read_signals(root);
    let signal_summary: Vec<Value> = signals
        .iter()
        .map(|(agent, sig)| {
            json!({
                "agent": agent,
                "stance": sig.get("stance").or_else(|| sig.get("signal")).cloned().unwrap_or(Value::Null),
                "ts": sig.get("ts").or_else(|| sig.get("timestamp")).cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    // ── pending decisions: first from last_report, then from decision dir ──
    let mut pending_decisions: Vec<String> = report_raw
        .pointer("/report/decision_items")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .take(2)
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    if pending_decisions.is_empty() {
        if let Ok(entries) = std::fs::read_dir(decision_dir(root)) {
            let mut paths: Vec<_> = entries
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
                .map(|e| e.path())
                .collect();
            paths.sort();
            if let Some(latest) = paths.last() {
                let mut from_dir: Vec<String> = load_jsonl_values(latest)
                    .iter()
                    .filter_map(|row| {
                        row.get("context")
                            .and_then(Value::as_str)
                            .map(|s| s.to_string())
                    })
                    .collect();
                from_dir.reverse();
                pending_decisions = from_dir.into_iter().take(2).collect();
            }
        }
    }

    json!({
        "ok": true,
        "owner_queue": {
            "count": queue_count,
            "items": queue_items,
        },
        "checklist": {
            "pass": chk_pass,
            "fail": chk_fail,
        },
        "signals": signal_summary,
        "pending_decisions": pending_decisions,
    })
}

fn build_router(root: PathBuf, client: McpHttpClient) -> axum::Router {
    let empty_schema = json!({"type": "object", "properties": {}});
    let route_schema = json!({
        "type": "object",
        "properties": {
            "user_text": {"type": "string"},
            "requested_agent": {"type": "string"}
        },
        "required": ["user_text"]
    });
    let dispatch_schema = json!({
        "type": "object",
        "properties": {
            "agent": {"type": "string"},
            "objective": {"type": "string"},
            "deadline": {"type": "string"}
        },
        "required": ["agent", "objective"]
    });
    let decision_schema = json!({
        "type": "object",
        "properties": {
            "context": {"type": "string"},
            "decision": {"type": "string"},
            "reasoning": {"type": "string"}
        },
        "required": ["context", "decision", "reasoning"]
    });
    let policy_schema = json!({
        "type": "object",
        "properties": {
            "rule_id": {"type": "string"}
        }
    });
    let conflict_schema = json!({
        "type": "object",
        "properties": {
            "signal_a": {"type": "object"},
            "signal_b": {"type": "object"}
        }
    });
    let oracle_diverge_schema = json!({
        "type": "object",
        "properties": {
            "objective": {"type": "string"},
            "prompt": {"type": "string"},
            "domain": {"type": "string"},
            "mode": {"type": "string", "enum": ["quick", "standard", "deep"]},
            "min_options": {"type": "integer"},
            "constraints": {"type": "object"},
            "current_default": {"type": "string"},
            "stakeholders": {"type": "array", "items": {"type": "string"}},
            "frameworks": {"type": "array", "items": {"type": "string"}},
            "require_default_challenge": {"type": "boolean"},
            "require_outside_view": {"type": "boolean"},
            "task_name": {"type": "string"}
        },
        "required": ["objective", "prompt", "mode", "min_options"]
    });

    let (router, _state) = McpServer::builder("oracle-coordinator-mcp", "coordinator")
        .tool(
            "coordinator_team_status",
            "Aggregate team status via per-agent MCPs.",
            empty_schema.clone(),
            {
                let client = client.clone();
                move |_args: Value| {
                    let client = client.clone();
                    Box::pin(async move { team_status_with_client(&client).await })
                        as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_route_intake",
            "Classify owner intake and choose the specialist route target.",
            route_schema,
            move |args: Value| Box::pin(async move { route_intake(args) }) as BoxFuture<Value>,
        )
        .tool(
            "coordinator_dispatch",
            "Create a task packet for one specialist agent.",
            dispatch_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { dispatch(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_decision_log",
            "Persist one Coordinator decision log entry.",
            decision_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { decision_log(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_policy_lookup",
            "Lookup one Coordinator policy rule.",
            policy_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { policy_lookup(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_conflict_surface",
            "Surface disagreement between two signals.",
            conflict_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { conflict_surface(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_owner_queue",
            "Read pending owner approvals and actions.",
            empty_schema.clone(),
            {
                let root = root.clone();
                move |_args: Value| {
                    let root = root.clone();
                    Box::pin(async move { owner_queue(&root) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "coordinator_session_brief",
            "Return aggregated session context: owner queue, checklist health, agent signals, pending decisions.",
            empty_schema,
            {
                let root = root.clone();
                move |_args: Value| {
                    let root = root.clone();
                    Box::pin(async move { session_brief(&root) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "oracle_diverge",
            "Generate structured alternatives before convergence and optionally persist a divergence artifact for task-backed flows.",
            oracle_diverge_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { oracle_diverge(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .into_router();

    router
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("info");

    dotenvy::dotenv().ok();

    let default_port = port_from_env("MCP_COORDINATOR_PORT", DEFAULT_PORT);
    let (port, root) = parse_args(default_port);
    let client = McpHttpClient::from_env(Duration::from_secs(6))?;
    info!(port, root = %root.display(), "oracle-coordinator-server starting");

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("listening on http://{}", addr);
    axum::serve(listener, build_router(root, client)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    async fn start_mock_server(payload: Value) -> SocketAddr {
        let app = Router::new().route(
            "/tools/call",
            post(move || {
                let payload = payload.clone();
                async move { Json(payload) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn team_status_returns_partial_results_when_one_agent_is_offline() {
        let engineer =
            start_mock_server(json!({"ok": true, "result": {"latest": {"overall_status": "ok"}}}))
                .await;
        let auditor =
            start_mock_server(json!({"ok": true, "result": {"overall_status": "ok"}})).await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reviewer = listener.local_addr().unwrap();
        drop(listener);

        let client = McpHttpClient::with_base_urls(
            HashMap::from([
                ("engineer".to_string(), format!("http://{}", engineer)),
                ("reviewer".to_string(), format!("http://{}", reviewer)),
                ("auditor".to_string(), format!("http://{}", auditor)),
            ]),
            Duration::from_millis(300),
        )
        .unwrap();

        let payload = team_status_with_client(&client).await;
        assert_eq!(payload["overall_status"], "degraded");
        assert_eq!(payload["summary"]["offline_agents"], json!(["reviewer"]));
        assert_eq!(payload["summary"]["engineering_status"], "ok");
        assert_eq!(payload["summary"]["cross_audit_status"], "ok");
    }

    #[test]
    fn route_intake_prefers_intent_when_no_explicit_agent() {
        let payload = route_intake(json!({
            "user_text": "prepare a macro brief",
            "requested_agent": ""
        }));

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["route_target"], "reviewer");
        assert_eq!(payload["intent"], "intel");
        assert_eq!(payload["divergence_policy"]["mode"], "exempt");
    }

    #[test]
    fn route_intake_sets_required_divergence_for_strategy_tradeoff() {
        let payload = route_intake(json!({
            "user_text": "Choose between two strategy paths and prioritize the trade-off.",
            "requested_agent": ""
        }));

        assert_eq!(payload["divergence_policy"]["mode"], "required");
        assert_eq!(payload["divergence_policy"]["reason"], "strategy_tradeoff");
    }

    #[test]
    fn route_intake_sets_recommended_divergence_for_ui_concepting() {
        let payload = route_intake(json!({
            "user_text": "Brainstorm a new UI concept for the owner dashboard.",
            "requested_agent": ""
        }));

        assert_eq!(payload["divergence_policy"]["mode"], "recommended");
        assert_eq!(payload["divergence_policy"]["reason"], "new_design");
    }

    #[test]
    fn oracle_diverge_supports_quick_standard_and_deep_modes() {
        let dir = TempDir::new().unwrap();

        for (mode, min_options, min_reframes) in
            [("quick", 3, 1), ("standard", 4, 2), ("deep", 6, 3)]
        {
            let payload = oracle_diverge(
                dir.path(),
                json!({
                    "objective": "Compare ways to improve the deployment workflow",
                    "prompt": "We need alternatives before choosing one rollout path.",
                    "domain": "engineering",
                    "mode": mode,
                    "min_options": 3,
                    "current_default": "patch the workflow in place"
                }),
            );

            assert_eq!(payload["ok"], true, "mode={mode}");
            assert!(payload["problem_frame"].is_object(), "mode={mode}");
            assert!(
                !payload["default_assumptions"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "mode={mode}"
            );
            assert!(
                payload["reframes"].as_array().unwrap().len() >= min_reframes,
                "mode={mode}"
            );
            assert!(
                payload["options"].as_array().unwrap().len() >= min_options,
                "mode={mode}"
            );
            assert!(payload["coverage"].is_object(), "mode={mode}");

            for assumption in payload["default_assumptions"].as_array().unwrap() {
                let basis = assumption["basis"].as_str().unwrap();
                assert!(matches!(
                    basis,
                    "observed" | "inferred" | "assumed" | "unknown"
                ));
            }
            for option in payload["options"].as_array().unwrap() {
                let basis = option["basis"].as_str().unwrap();
                assert!(matches!(
                    basis,
                    "observed" | "inferred" | "assumed" | "unknown"
                ));
            }
        }
    }

    #[test]
    fn oracle_diverge_returns_deterministic_exemption_for_exempt_tasks() {
        let dir = TempDir::new().unwrap();
        let payload = oracle_diverge(
            dir.path(),
            json!({
                "objective": "Run tests for the gateway hook",
                "prompt": "Compile and verify the existing file without changing behavior.",
                "domain": "engineering",
                "mode": "quick",
                "min_options": 3
            }),
        );

        assert_eq!(payload["ok"], false);
        assert_eq!(payload["error_code"], "deterministic_task_exempt");
    }

    #[test]
    fn oracle_diverge_writes_task_backed_artifact() {
        let dir = TempDir::new().unwrap();
        let payload = oracle_diverge(
            dir.path(),
            json!({
                "objective": "Compare rollout options for a new workflow",
                "prompt": "Generate alternatives before choosing one implementation path.",
                "domain": "engineering",
                "mode": "standard",
                "min_options": 3,
                "task_name": "demo_task"
            }),
        );

        let artifact_path = dir
            .path()
            .join("tasks")
            .join("inbox")
            .join("demo_task")
            .join("divergence.json");
        assert_eq!(payload["ok"], true);
        assert!(artifact_path.exists());

        let artifact: Value =
            serde_json::from_str(&std::fs::read_to_string(&artifact_path).unwrap()).unwrap();
        assert_eq!(artifact["task_name"], "demo_task");
        assert_eq!(artifact["policy_mode"], "required");
        assert_eq!(artifact["source"], "oracle_diverge");
        assert_eq!(artifact["version"], DIVERGENCE_VERSION);
        assert!(artifact["options"].as_array().unwrap().len() >= 4);
        assert_eq!(
            payload["artifact_path"],
            artifact_path.to_string_lossy().replace('\\', "/")
        );
    }
}
