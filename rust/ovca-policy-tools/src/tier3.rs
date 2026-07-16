//! Tier 3 — Policy-as-Tool (output template / gate check)
//!
//! Tools: pre_change_notice, plan_before_dispatch, dispatch_blocker_check

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── pre_change_notice ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Create,
    Edit,
    Delete,
    Move,
    Overwrite,
}

impl ActionType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "create" => Some(Self::Create),
            "edit" => Some(Self::Edit),
            "delete" => Some(Self::Delete),
            "move" => Some(Self::Move),
            "overwrite" => Some(Self::Overwrite),
            _ => None,
        }
    }

    fn is_destructive(&self) -> bool {
        matches!(self, Self::Delete | Self::Move | Self::Overwrite)
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Edit => "EDIT",
            Self::Delete => "DELETE",
            Self::Move => "MOVE",
            Self::Overwrite => "OVERWRITE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeNotice {
    pub what: String,
    pub why: String,
    pub outcome: String,
    pub downside: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreChangeNoticeResult {
    pub notice: ChangeNotice,
    pub requires_approval: bool,
    pub display_text: String,
    pub missing: Vec<String>,
    pub valid: bool,
}

/// Pre-Change Notice — สร้าง notice ก่อนแตะ file system
pub fn pre_change_notice(
    action_type: &str,
    file_path: &str,
    reason: &str,
    expected_outcome: &str,
    risk_or_rollback: &str,
) -> PreChangeNoticeResult {
    let action = ActionType::from_str(action_type);
    let reason = reason.trim();
    let outcome = expected_outcome.trim();
    let risk = risk_or_rollback.trim();

    let mut missing: Vec<String> = Vec::new();
    if reason.is_empty() {
        missing.push("reason (why / authority)".to_string());
    }
    if outcome.is_empty() {
        missing.push("expected_outcome".to_string());
    }
    if risk.is_empty() {
        missing.push("risk_or_rollback".to_string());
    }

    let valid = missing.is_empty();
    let is_destructive = action.as_ref().map(|a| a.is_destructive()).unwrap_or(false);
    let requires_approval = is_destructive || valid;

    let action_type_upper = action_type.to_uppercase();
    let action_label = action
        .as_ref()
        .map(|a| a.as_str())
        .unwrap_or(action_type_upper.as_str());

    let mut display = format!(
        "⚠️ [{action_label}] {file_path}\n  ทำไม: {reason}\n  ผลที่คาด: {outcome}\n  Risk/Rollback: {risk}"
    );

    if is_destructive && valid {
        display = format!("⛔ {display}\n  → ต้องขอ approval ก่อน");
    }

    PreChangeNoticeResult {
        notice: ChangeNotice {
            what: format!("{action_label} {file_path}"),
            why: reason.to_string(),
            outcome: outcome.to_string(),
            downside: risk.to_string(),
        },
        requires_approval,
        display_text: display,
        missing,
        valid,
    }
}

// ── plan_before_dispatch ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousBatchScope {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousBatch {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub scope: Option<AutonomousBatchScope>,
    #[serde(default)]
    pub stop_conditions: Vec<String>,
    #[serde(default)]
    pub commit_policy: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub objective: Option<String>,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub files_affected: Vec<String>,
    #[serde(default)]
    pub risks: Vec<String>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub autonomous_batch: Option<AutonomousBatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanBeforeDispatchResult {
    pub valid: bool,
    pub missing_fields: Vec<String>,
    pub can_dispatch: bool,
    pub block_reason: Option<String>,
}

/// Plan Before Dispatch gate — validate plan ก่อน dispatch
pub fn plan_before_dispatch(plan: &Plan) -> PlanBeforeDispatchResult {
    let mut missing: Vec<String> = Vec::new();

    match &plan.objective {
        None => missing.push("objective".to_string()),
        Some(s) if s.trim().is_empty() => missing.push("objective".to_string()),
        _ => {}
    }
    if plan.steps.is_empty() {
        missing.push("steps".to_string());
    }
    if plan.files_affected.is_empty() {
        missing.push("files_affected".to_string());
    }
    if plan.risks.is_empty() {
        missing.push("risks".to_string());
    }
    if plan.acceptance_criteria.is_empty() {
        missing.push("acceptance_criteria".to_string());
    }
    if let Some(batch) = &plan.autonomous_batch {
        if batch.enabled {
            match &batch.authority {
                None => missing.push("autonomous_batch.authority".to_string()),
                Some(s) if s.trim().is_empty() => {
                    missing.push("autonomous_batch.authority".to_string())
                }
                _ => {}
            }
            match &batch.scope {
                None => {
                    missing.push("autonomous_batch.scope.include".to_string());
                    missing.push("autonomous_batch.scope.exclude".to_string());
                }
                Some(scope) => {
                    if scope.include.is_empty() {
                        missing.push("autonomous_batch.scope.include".to_string());
                    }
                    if scope.exclude.is_empty() {
                        missing.push("autonomous_batch.scope.exclude".to_string());
                    }
                }
            }
            if batch.stop_conditions.is_empty() {
                missing.push("autonomous_batch.stop_conditions".to_string());
            }
            if batch.commit_policy.is_none() {
                missing.push("autonomous_batch.commit_policy".to_string());
            }
        }
    }

    let can_dispatch = missing.is_empty();
    let block_reason = if can_dispatch {
        None
    } else {
        Some(format!("แผนยังไม่ครบ — ต้องระบุ: {} ก่อน", missing.join(", ")))
    };

    PlanBeforeDispatchResult {
        valid: can_dispatch,
        missing_fields: missing,
        can_dispatch,
        block_reason,
    }
}

// ── dispatch_blocker_check ────────────────────────────────────────────────────

const PLACEHOLDER_TOKENS: &[&str] = &["TODO", "PLACEHOLDER", "TBD", "FILL", "???"];

fn is_placeholder(s: &str) -> bool {
    let upper = s.to_uppercase();
    PLACEHOLDER_TOKENS.iter().any(|&t| upper.contains(t))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchBlockerInput {
    pub task_ref: Option<String>,
    pub checklist_ref: Option<String>,
    pub section_ref: Option<String>,
    pub objective: Option<String>,
    pub acceptance_ref: Option<String>,
    pub verification_ref: Option<String>,
    #[serde(default)]
    pub writable_scope: Vec<String>,
    pub dispatch_mode: Option<String>,
    #[serde(default = "default_stop_if_missing")]
    pub stop_if_missing: bool,
}

fn default_stop_if_missing() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchBlockerResult {
    pub ready: bool,
    pub missing_fields: Vec<String>,
    pub placeholder_fields: Vec<String>,
    pub verdict: String, // "PASS" | "FAIL"
    pub fail_reason: Option<String>,
}

/// Dispatch Blocker Gate — hard gate ก่อน scaffold/dispatch
pub fn dispatch_blocker_check(input: &DispatchBlockerInput) -> DispatchBlockerResult {
    let required: Vec<(&str, Option<&str>)> = vec![
        ("task_ref", input.task_ref.as_deref()),
        ("checklist_ref", input.checklist_ref.as_deref()),
        ("section_ref", input.section_ref.as_deref()),
        ("objective", input.objective.as_deref()),
        ("acceptance_ref", input.acceptance_ref.as_deref()),
        ("verification_ref", input.verification_ref.as_deref()),
        ("dispatch_mode", input.dispatch_mode.as_deref()),
    ];

    let mut missing: Vec<String> = Vec::new();
    let mut placeholder: Vec<String> = Vec::new();

    for (name, val) in &required {
        match val {
            None => missing.push(name.to_string()),
            Some(s) if s.trim().is_empty() => missing.push(name.to_string()),
            Some(s) if is_placeholder(s) => placeholder.push(name.to_string()),
            _ => {}
        }
    }

    if input.writable_scope.is_empty() {
        missing.push("writable_scope".to_string());
    }

    let ready = missing.is_empty() && placeholder.is_empty();
    let verdict = if ready { "PASS" } else { "FAIL" }.to_string();

    let fail_reason = if ready {
        None
    } else {
        let mut parts: Vec<String> = Vec::new();
        if input.stop_if_missing {
            parts.push("stop_if_missing=true —".to_string());
        }
        if !missing.is_empty() {
            parts.push(format!(
                "missing {} fields: {}",
                missing.len(),
                missing.join(", ")
            ));
        }
        if !placeholder.is_empty() {
            parts.push(format!("placeholder in: {}", placeholder.join(", ")));
        }
        Some(parts.join(" "))
    };

    DispatchBlockerResult {
        ready,
        missing_fields: missing,
        placeholder_fields: placeholder,
        verdict,
        fail_reason,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // pre_change_notice
    #[test]
    fn notice_valid_create() {
        let r = pre_change_notice(
            "create",
            "tasks/inbox/foo/task.md",
            "scaffold new task",
            "task packet ready",
            "ลบไฟล์ถ้า task ไม่ผ่าน",
        );
        assert!(r.valid);
        assert!(r.missing.is_empty());
    }

    #[test]
    fn notice_destructive_requires_approval() {
        let r = pre_change_notice(
            "delete",
            "tasks/inbox/foo/task.md",
            "archived",
            "inbox clean",
            "git checkout HEAD path",
        );
        assert!(r.requires_approval);
        assert_eq!(
            r.display_text,
            "⛔ ⚠️ [DELETE] tasks/inbox/foo/task.md\n  ทำไม: archived\n  ผลที่คาด: inbox clean\n  Risk/Rollback: git checkout HEAD path\n  → ต้องขอ approval ก่อน"
        );
    }

    #[test]
    fn notice_missing_reason_reported() {
        let r = pre_change_notice("edit", "config.py", "", "ok", "revert");
        assert!(r.missing.iter().any(|m| m.contains("reason")));
        assert!(!r.valid);
        assert!(!r.requires_approval);
        assert_eq!(
            r.display_text,
            "⚠️ [EDIT] config.py\n  ทำไม: \n  ผลที่คาด: ok\n  Risk/Rollback: revert"
        );
    }

    #[test]
    fn notice_has_four_notice_fields() {
        let r = pre_change_notice("create", "f.py", "r", "o", "rr");
        assert!(!r.notice.what.is_empty());
        assert!(!r.notice.why.is_empty());
        assert!(!r.notice.outcome.is_empty());
        assert!(!r.notice.downside.is_empty());
    }

    // plan_before_dispatch
    #[test]
    fn plan_valid_when_all_fields_present() {
        let plan = Plan {
            objective: Some("fix timeout".to_string()),
            steps: vec!["step 1".to_string()],
            files_affected: vec!["scripts/foo.py".to_string()],
            risks: vec!["regression".to_string()],
            acceptance_criteria: vec!["0 test failures".to_string()],
            autonomous_batch: None,
        };
        let r = plan_before_dispatch(&plan);
        assert!(r.valid);
        assert!(r.can_dispatch);
        assert!(r.missing_fields.is_empty());
    }

    #[test]
    fn plan_blocks_when_objective_missing() {
        let plan = Plan {
            objective: None,
            steps: vec!["s".to_string()],
            files_affected: vec!["f".to_string()],
            risks: vec!["r".to_string()],
            acceptance_criteria: vec!["a".to_string()],
            autonomous_batch: None,
        };
        let r = plan_before_dispatch(&plan);
        assert!(r.missing_fields.contains(&"objective".to_string()));
        assert!(!r.can_dispatch);
    }

    #[test]
    fn plan_blocks_when_acceptance_empty() {
        let plan = Plan {
            objective: Some("do x".to_string()),
            steps: vec!["s".to_string()],
            files_affected: vec!["f".to_string()],
            risks: vec!["r".to_string()],
            acceptance_criteria: vec![],
            autonomous_batch: None,
        };
        let r = plan_before_dispatch(&plan);
        assert!(r
            .missing_fields
            .contains(&"acceptance_criteria".to_string()));
    }

    #[test]
    fn plan_block_reason_lists_missing() {
        let plan = Plan {
            objective: Some("x".to_string()),
            steps: vec![],
            files_affected: vec![],
            risks: vec![],
            acceptance_criteria: vec![],
            autonomous_batch: None,
        };
        let r = plan_before_dispatch(&plan);
        let reason = r.block_reason.unwrap_or_default();
        assert!(reason.contains("steps"));
    }

    #[test]
    fn autonomous_batch_requires_batch_fields() {
        let plan = Plan {
            objective: Some("dispatch full batch".to_string()),
            steps: vec!["P1".to_string()],
            files_affected: vec!["scripts/foo.py".to_string()],
            risks: vec!["regression".to_string()],
            acceptance_criteria: vec!["tests pass".to_string()],
            autonomous_batch: Some(AutonomousBatch {
                enabled: true,
                authority: None,
                scope: None,
                stop_conditions: vec![],
                commit_policy: None,
            }),
        };
        let r = plan_before_dispatch(&plan);
        assert!(!r.can_dispatch);
        assert!(r
            .missing_fields
            .contains(&"autonomous_batch.authority".to_string()));
        assert!(r
            .missing_fields
            .contains(&"autonomous_batch.scope.include".to_string()));
        assert!(r
            .missing_fields
            .contains(&"autonomous_batch.commit_policy".to_string()));
    }

    #[test]
    fn autonomous_batch_valid_when_batch_fields_present() {
        let plan = Plan {
            objective: Some("dispatch full batch".to_string()),
            steps: vec!["P1".to_string()],
            files_affected: vec!["scripts/foo.py".to_string()],
            risks: vec!["regression".to_string()],
            acceptance_criteria: vec!["tests pass".to_string()],
            autonomous_batch: Some(AutonomousBatch {
                enabled: true,
                authority: Some("owner requested batch execution".to_string()),
                scope: Some(AutonomousBatchScope {
                    include: vec!["scripts/foo.py".to_string()],
                    exclude: vec![".env".to_string(), ".claude/*".to_string()],
                }),
                stop_conditions: vec!["verification fails and repair expands scope".to_string()],
                commit_policy: Some(serde_json::json!({
                    "allow_stage_commit": true,
                    "allow_push": false
                })),
            }),
        };
        let r = plan_before_dispatch(&plan);
        assert!(r.valid);
        assert!(r.can_dispatch);
        assert!(r.missing_fields.is_empty());
    }

    // dispatch_blocker_check
    #[test]
    fn blocker_pass_when_all_set() {
        let input = DispatchBlockerInput {
            task_ref: Some("fix_timeout".to_string()),
            checklist_ref: Some("CODEX_TASKCHECKLIST.md#fix_timeout".to_string()),
            section_ref: Some("S1".to_string()),
            objective: Some("แก้ timeout config".to_string()),
            acceptance_ref: Some("section 4 handoff".to_string()),
            verification_ref: Some("pytest -q".to_string()),
            writable_scope: vec!["scripts/config.py".to_string()],
            dispatch_mode: Some("fresh".to_string()),
            stop_if_missing: true,
        };
        let r = dispatch_blocker_check(&input);
        assert_eq!(r.verdict, "PASS");
        assert!(r.ready);
    }

    #[test]
    fn blocker_fail_when_checklist_missing() {
        let input = DispatchBlockerInput {
            task_ref: Some("fix_timeout".to_string()),
            checklist_ref: None,
            section_ref: Some("S1".to_string()),
            objective: Some("do x".to_string()),
            acceptance_ref: Some("ref".to_string()),
            verification_ref: Some("pytest".to_string()),
            writable_scope: vec!["f.py".to_string()],
            dispatch_mode: Some("fresh".to_string()),
            stop_if_missing: false,
        };
        let r = dispatch_blocker_check(&input);
        assert_eq!(r.verdict, "FAIL");
        assert!(r.missing_fields.contains(&"checklist_ref".to_string()));
    }

    #[test]
    fn blocker_fail_when_placeholder_in_task_ref() {
        let input = DispatchBlockerInput {
            task_ref: Some("TODO".to_string()),
            checklist_ref: Some("checklist".to_string()),
            section_ref: Some("S1".to_string()),
            objective: Some("obj".to_string()),
            acceptance_ref: Some("ref".to_string()),
            verification_ref: Some("v".to_string()),
            writable_scope: vec!["f".to_string()],
            dispatch_mode: Some("fresh".to_string()),
            stop_if_missing: true,
        };
        let r = dispatch_blocker_check(&input);
        assert_eq!(r.verdict, "FAIL");
        assert!(r.placeholder_fields.contains(&"task_ref".to_string()));
    }

    #[test]
    fn blocker_fail_when_writable_scope_empty() {
        let input = DispatchBlockerInput {
            task_ref: Some("t".to_string()),
            checklist_ref: Some("c".to_string()),
            section_ref: Some("s".to_string()),
            objective: Some("o".to_string()),
            acceptance_ref: Some("a".to_string()),
            verification_ref: Some("v".to_string()),
            writable_scope: vec![],
            dispatch_mode: Some("fresh".to_string()),
            stop_if_missing: false,
        };
        let r = dispatch_blocker_check(&input);
        assert!(r.missing_fields.contains(&"writable_scope".to_string()));
    }

    #[test]
    fn blocker_fail_reason_mentions_stop_if_missing() {
        let input = DispatchBlockerInput {
            task_ref: None,
            checklist_ref: None,
            section_ref: None,
            objective: None,
            acceptance_ref: None,
            verification_ref: None,
            writable_scope: vec![],
            dispatch_mode: None,
            stop_if_missing: true,
        };
        let r = dispatch_blocker_check(&input);
        let reason = r.fail_reason.unwrap_or_default();
        assert!(reason.contains("stop_if_missing=true"));
    }
}
