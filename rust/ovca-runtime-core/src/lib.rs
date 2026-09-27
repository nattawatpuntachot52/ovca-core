use anyhow::{Context, Result};
use chrono::Utc;
use ovca_storage::{append_jsonl, read_json, read_jsonl, write_json_atomic};
pub use ovca_types::{AgentId, Intent, RuntimeEvent};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub mod durable_guardrails;
pub mod engineer_verifier;
pub mod execution_lifecycle;
pub mod finalization;
pub mod guardrails;
pub mod independent_review;
pub mod local_verification_completion;
pub mod replay;
pub mod review_audit;
pub mod role_executor;
pub mod scheduler;
pub mod sqlite_execution;
pub mod workspace_capability;

pub use durable_guardrails::{
    ApprovalEnvelope, ApprovalStateCorruption, DurableApprovalError, DurableApprovalEvaluation,
    DurableApprovalRecord, DurableDecisionResult, DurableGuardrailAuthority, GuardedExecution,
    DEFAULT_APPROVAL_CAS_RETRY_LIMIT,
};
pub use engineer_verifier::{
    denial_code, derive_phase_event_id, derive_tool_identity, ledger_entry_from_receipt,
    ledger_entry_from_reconciliation, transition_allowed, CancellationRecordV1,
    DerivedToolIdentityV1, DurableToolObservationV1, DurableWorkspaceAuthorityV1,
    EngineerExecutionBindingV1, EngineerLogicalPlanV1, EngineerVerifierError,
    EngineerVerifierPhaseProjectionV1, EngineerVerifierPhaseV1, EngineerVerifierStateV1,
    EngineerVerifierTriggerV1, ExecutorCallStateV1, ExpectedInitialProjectionV1,
    PendingPhaseProjectionV1, PersistedRoleExecutionOutcomeV1, PersistedRoleExecutionUsageV1,
    PersistedRoleRetryCauseV1, PersistedVerificationTranscriptV1, PlannedToolEffectTemplateV1,
    PreparedWriteEffectV1, ResolvedEffectLedgerEntryV1, ResolvedEffectLedgerV1,
    ResolvedEffectResolutionV1, VerifierExecutionLimitsV1, VerifierExecutionStateV1,
    VerifierReplayPlanV1, WorkspaceDiffBridgeV1, WorkspaceDiffPathIdentityV1,
    WriteReconciliationV1, EMPTY_PAYLOAD_SHA256, ENGINEER_VERIFIER_CONTRACT_VERSION,
};
pub use execution_lifecycle::{
    CancellationRequest, ClaimRequest, CompletionRequest, ExecutionLifecycleError,
    ExecutionLifecycleKernel, ExecutionLifecycleRestoreError, ExecutionLifecycleSnapshot,
    FailureRequest, HeartbeatRequest, TaskExecutionSnapshot, WriteKeyOwner,
};
pub use finalization::{FinalizationError, FinalizationKernel};
pub use guardrails::{evaluate_guard_request, GuardEvaluationContext};
pub use independent_review::{
    audit_execution_request, completed_result, review_execution_request, typed_audit_verdict,
    typed_review_verdict, IndependentCallStateV1, IndependentReviewError,
    IndependentReviewExecutor, IndependentReviewPhaseV1, IndependentReviewResolutionV1,
    IndependentReviewStateV1, IndependentRoleExecutionRequest, IndependentRolePacketV1,
    OwnerEscalationReasonV1,
};
pub use local_verification_completion::{
    admit_local_verification_completion, completion_environment_names, completion_evidence_keys,
    validate_local_verification_completion_contract, validate_persisted_completion_material,
    LocalVerificationCompletionContract, LocalVerificationCompletionError,
    LocalVerificationCompletionTask, LocalVerificationObservation, VerifiedCompletionMaterial,
};
pub use replay::{replay_run, validate_event_chain, ReplayError, ReplayedRun};
pub use review_audit::{
    derive_review_audit_policy, evaluate_review_audit, validate_audit_decision,
    validate_review_decision, validate_review_evidence_context, AuditDecisionValidationContext,
    ReviewAuditError, ReviewAuditEvaluationContext, ReviewAuditPolicy,
    ReviewDecisionValidationContext, ValidatedAuditDecision, ValidatedReviewDecision,
};
pub use role_executor::{
    DeterministicFakeRoleExecutor, RoleExecutionOutcome, RoleExecutionRequest, RoleExecutionScript,
    RoleExecutionUsage, RoleExecutor, RoleExecutorError, RoleRetryCause, EXECUTION_TIMEOUT_CODE,
};
pub use scheduler::{schedule_tasks, ScheduleError};
pub use sqlite_execution::{
    DurableCommandResult, DurableExecutionAuthority, DurableExecutionError,
    EngineerVerifierCasOutcome, ExecutionRunEnvelope, ExecutionStateCorruption,
    IndependentReviewCasOutcome, InitializeRunResult, LoadedExecutionRun, WorkspaceRecoveryClaim,
    DEFAULT_EXECUTION_CAS_RETRY_LIMIT, EXECUTION_ENVELOPE_V1, EXECUTION_ENVELOPE_V2,
};
pub use workspace_capability::{
    BrokerClock, CleanupReason, PreparedWorkspaceState, SystemBrokerClock, ToolExecutionResult,
    TrustedCapabilityGrant, TrustedSealedWorkspace, TrustedToolReceipt, TrustedWorkspaceLease,
    WorkspaceCapabilityBroker, WorkspaceCapabilityError, WorkspaceLeaseState,
    WorkspaceRecoveryPermit, WorkspaceSeedFile,
};

pub const LLM_CALL_CONTRACT_VERSION: &str = "oracle_llm_call_contract.v1";
pub const EVENT_SCHEMA_VERSION: &str = "oracle_runtime_event.v1";
pub const SNAPSHOT_SCHEMA_VERSION: &str = "oracle_runtime_guard_snapshot.v1";

const EVENTS_RELATIVE_PATH: &str = "logs/runtime_guard/events.jsonl";
const SNAPSHOT_RELATIVE_PATH: &str = "logs/runtime_guard/latest.json";

const REVIEW_ACTION_MARKERS: &[&str] = &["review", "critique", "ตรวจงาน", "รีวิว", "ทบทวนงาน"];

const AUDIT_ACTION_MARKERS: &[&str] = &[
    "audit",
    "cross-check",
    "cross check",
    "independent verification",
    "independently verify",
    "ตรวจสอบอิสระ",
    "ตรวจสอบแบบอิสระ",
    "สอบทานอิสระ",
];

const ENGINEERING_ACTION_MARKERS: &[&str] = &[
    "implement",
    "fix",
    "debug",
    "patch",
    "refactor",
    "automate",
    "แก้บั๊ก",
    "แก้ bug",
    "ลงมือแก้",
    "เขียนโค้ด",
    "พัฒนาระบบ",
];

const INTENT_ACTION_MARKERS: &[(Intent, &[&str])] = &[
    (Intent::Review, REVIEW_ACTION_MARKERS),
    (Intent::Audit, AUDIT_ACTION_MARKERS),
    (Intent::Engineering, ENGINEERING_ACTION_MARKERS),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    pub id: AgentId,
    pub name: String,
    pub port: u16,
    pub persona: String,
    pub system_prompt: String,
    pub roles: Vec<String>,
    pub owner_chat_enabled: bool,
    pub scheduled_enabled: bool,
    pub role_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEventRecord {
    pub version: String,
    pub event_type: String,
    pub emitted_at: String,
    pub agent: String,
    pub resource: String,
    pub action: String,
    pub outcome: String,
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RuntimeGuardSnapshot {
    pub ok: bool,
    pub version: String,
    pub generated_at: String,
    pub event_count: usize,
    pub incident_count: usize,
    #[serde(default)]
    pub counts_by_type: BTreeMap<String, usize>,
    #[serde(default)]
    pub counts_by_verdict: BTreeMap<String, usize>,
    #[serde(default)]
    pub recent_events: Vec<RuntimeEventRecord>,
    #[serde(default)]
    pub recent_incidents: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct EventEmitter {
    root: PathBuf,
}

impl AgentProfile {
    fn new(
        id: AgentId,
        name: &str,
        persona: &str,
        system_prompt: &str,
        roles: &[&str],
        role_hint: &str,
    ) -> Self {
        Self {
            id,
            name: name.to_string(),
            port: id.port(),
            persona: persona.to_string(),
            system_prompt: system_prompt.to_string(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            owner_chat_enabled: true,
            scheduled_enabled: true,
            role_hint: role_hint.to_string(),
        }
    }
}

impl RuntimeEventRecord {
    fn from_event(event: RuntimeEvent) -> Self {
        Self {
            version: EVENT_SCHEMA_VERSION.to_string(),
            event_type: event.event_type,
            emitted_at: event.ts.to_rfc3339(),
            agent: event.agent,
            resource: event.resource,
            action: event.action,
            outcome: normalized_outcome(&event.outcome),
            context: event.context,
        }
    }
}

impl EventEmitter {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn events_path(&self) -> PathBuf {
        runtime_events_path(&self.root)
    }

    pub fn snapshot_path(&self) -> PathBuf {
        runtime_snapshot_path(&self.root)
    }

    pub fn emit(&self, event: RuntimeEvent) -> Result<()> {
        let record = RuntimeEventRecord::from_event(event);
        let events_path = self.events_path();
        append_jsonl(&events_path, &record)
            .with_context(|| format!("emit runtime event: {}", events_path.display()))?;

        let snapshot = build_runtime_guard_snapshot(&self.root, 12)?;
        let snapshot_path = self.snapshot_path();
        write_json_atomic(&snapshot_path, &snapshot).with_context(|| {
            format!("write runtime guard snapshot: {}", snapshot_path.display())
        })?;
        Ok(())
    }

    pub fn snapshot(&self, limit: usize) -> Result<RuntimeGuardSnapshot> {
        read_runtime_guard_snapshot(&self.root, limit)
    }
}

pub fn agent_profiles() -> Vec<AgentProfile> {
    vec![
        AgentProfile::new(
            AgentId::Coordinator,
            "Coordinator",
            "You are Coordinator, OVCA front door and delivery lead. Keep owner intent, scope, risk, and decisions explicit.",
            "You are Coordinator, mother agent. Synthesize specialist output for owner decisions with clear structure.",
            &["front_door", "scheduler", "synthesis", "governance"],
            "Mother agent / scheduler / control plane",
        ),
        AgentProfile::new(
            AgentId::Engineer,
            "Engineer",
            "You are Engineer, OVCA implementation lane. Own code changes, tests, and implementation self-review only inside scoped packets.",
            "You are Engineer, engineering agent. Structure as: Inputs -> Outputs -> Side effects -> Rollback.",
            &["engineering", "automation", "systems_design"],
            "Engineering, automation, and systems design",
        ),
        AgentProfile::new(
            AgentId::Reviewer,
            "Reviewer",
            "You are Reviewer, OVCA review lane. Run end-to-end review, evidence checks, and user-impact validation.",
            "You are Reviewer, review agent. Structure as: Evidence -> Findings -> Verification -> Recommendation.",
            &["review", "e2e_validation", "quality_gate"],
            "End-to-end review and quality validation",
        ),
        AgentProfile::new(
            AgentId::Auditor,
            "Auditor",
            "You are Auditor, OVCA cross-audit lane. Challenge assumptions, verify risk boundaries, and find missing evidence.",
            "You are Auditor, cross-audit agent. Structure as: Claim -> Countercheck -> Risk -> Decision impact.",
            &["cross_audit", "risk", "verification"],
            "Cross-audit, risk review, and verification",
        ),
    ]
}

pub fn agent_profile(agent_id: AgentId) -> AgentProfile {
    agent_profiles()
        .into_iter()
        .find(|profile| profile.id == agent_id)
        .expect("agent profile registry is missing a required agent")
}

pub fn tokenize_runtime_text(text: &str) -> BTreeSet<String> {
    token_split_regex()
        .split(&text.to_lowercase())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

pub fn classify_intent(text: &str) -> Intent {
    let low = text.to_lowercase();
    let tokens = tokenize_runtime_text(text);
    let mut best_match = (Intent::General, 0usize);
    let mut tied = false;

    for (intent, markers) in INTENT_ACTION_MARKERS {
        let score = markers
            .iter()
            .filter(|marker| keyword_matches(&low, &tokens, marker))
            .count();
        if score > best_match.1 {
            best_match = (*intent, score);
            tied = false;
        } else if score > 0 && score == best_match.1 {
            tied = true;
        }
    }

    if best_match.1 == 0 || tied {
        Intent::General
    } else {
        best_match.0
    }
}

pub fn parse_intent(raw: &str) -> Option<Intent> {
    raw.parse().ok()
}

pub fn intent_to_agent(intent: Intent) -> AgentId {
    intent.to_agent()
}

pub fn resolve_requested_agent(raw: &str) -> Option<AgentId> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "coordinator" => Some(AgentId::Coordinator),
        "engineer" => Some(AgentId::Engineer),
        "reviewer" => Some(AgentId::Reviewer),
        "auditor" => Some(AgentId::Auditor),
        _ => None,
    }
}

pub fn runtime_events_path(root: &Path) -> PathBuf {
    root.join(EVENTS_RELATIVE_PATH)
}

pub fn runtime_snapshot_path(root: &Path) -> PathBuf {
    root.join(SNAPSHOT_RELATIVE_PATH)
}

pub fn build_runtime_guard_snapshot(root: &Path, limit: usize) -> Result<RuntimeGuardSnapshot> {
    let events: Vec<RuntimeEventRecord> = read_jsonl(&runtime_events_path(root));
    let mut counts_by_type = BTreeMap::new();
    let mut counts_by_verdict = BTreeMap::new();

    for event in &events {
        *counts_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
        *counts_by_verdict
            .entry(normalized_outcome(&event.outcome))
            .or_insert(0) += 1;
    }

    let mut recent_events = events;
    recent_events.sort_by(|left, right| right.emitted_at.cmp(&left.emitted_at));
    recent_events.truncate(limit.max(1));

    Ok(RuntimeGuardSnapshot {
        ok: true,
        version: SNAPSHOT_SCHEMA_VERSION.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        event_count: recent_events.len().max(counts_by_type.values().sum()),
        incident_count: 0,
        counts_by_type,
        counts_by_verdict,
        recent_events,
        recent_incidents: vec![],
    })
}

pub fn read_runtime_guard_snapshot(root: &Path, limit: usize) -> Result<RuntimeGuardSnapshot> {
    let snapshot_path = runtime_snapshot_path(root);
    match read_json::<RuntimeGuardSnapshot>(&snapshot_path) {
        Ok(snapshot) => Ok(snapshot),
        Err(_) => build_runtime_guard_snapshot(root, limit),
    }
}

fn normalized_outcome(outcome: &str) -> String {
    let trimmed = outcome.trim();
    if trimmed.is_empty() {
        "observed".to_string()
    } else {
        trimmed.to_string()
    }
}

fn keyword_matches(low: &str, tokens: &BTreeSet<String>, keyword: &str) -> bool {
    let key = keyword.trim().to_lowercase();
    if key.is_empty() {
        return false;
    }
    if ascii_keyword_regex().is_match(&key) {
        return tokens.contains(&key);
    }
    low.contains(&key)
}

fn token_split_regex() -> &'static Regex {
    static TOKEN_SPLIT: OnceLock<Regex> = OnceLock::new();
    TOKEN_SPLIT.get_or_init(|| {
        Regex::new(r"[^a-z0-9_\u{0E00}-\u{0E7F}]+").expect("valid token split regex")
    })
}

fn ascii_keyword_regex() -> &'static Regex {
    static ASCII_KEYWORD: OnceLock<Regex> = OnceLock::new();
    ASCII_KEYWORD.get_or_init(|| Regex::new(r"^[a-z0-9_]+$").expect("valid ascii keyword regex"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn agent_profiles_cover_all_runtime_agents() {
        let profiles = agent_profiles();
        assert_eq!(profiles.len(), 4);
        assert_eq!(profiles[0].id, AgentId::Coordinator);
        assert_eq!(profiles[0].port, 18780);
        assert_eq!(profiles[1].id, AgentId::Engineer);
        assert_eq!(profiles[2].id, AgentId::Reviewer);
        assert_eq!(profiles[3].id, AgentId::Auditor);
        assert!(profiles[0].roles.iter().any(|role| role == "front_door"));
    }

    #[test]
    fn classify_intent_uses_actions_and_returns_general_for_domains_or_ties() {
        let cases = [
            ("review this API change", Intent::Review),
            ("ตรวจงานนี้ให้หน่อย", Intent::Review),
            ("audit the permission boundary", Intent::Audit),
            ("ช่วยตรวจสอบอิสระเรื่องสิทธิ์", Intent::Audit),
            ("fix the market data parser", Intent::Engineering),
            ("ช่วยแก้บั๊กระบบเทรด", Intent::Engineering),
            ("market macro stocks crypto portfolio", Intent::General),
            ("trading research strategy risk finance", Intent::General),
            ("ตลาด มหภาค หุ้น คริปโท พอร์ต เทรด", Intent::General),
            ("วิจัย กลยุทธ์ ความเสี่ยง การเงิน", Intent::General),
            ("review and audit this evidence", Intent::General),
            ("summarize the meeting notes", Intent::General),
        ];

        for (text, expected) in cases {
            assert_eq!(classify_intent(text), expected, "text={text}");
        }
    }

    #[test]
    fn parse_intent_accepts_legacy_inputs_and_returns_canonical_variants() {
        assert_eq!(parse_intent("review"), Some(Intent::Review));
        assert_eq!(parse_intent("intel"), Some(Intent::Review));
        assert_eq!(parse_intent("research"), Some(Intent::Audit));
        assert_eq!(parse_intent("trading"), Some(Intent::General));
        assert_eq!(parse_intent("unknown"), None);
    }

    #[test]
    fn resolve_requested_agent_accepts_only_known_ids() {
        assert_eq!(resolve_requested_agent("auditor"), Some(AgentId::Auditor));
        assert_eq!(resolve_requested_agent("reviewer"), Some(AgentId::Reviewer));
        assert_eq!(
            resolve_requested_agent("COORDINATOR"),
            Some(AgentId::Coordinator)
        );
        assert_eq!(resolve_requested_agent("aurora"), None);
        assert_eq!(resolve_requested_agent("hope"), None);
        assert_eq!(resolve_requested_agent("divina"), None);
        assert_eq!(resolve_requested_agent("unknown"), None);
    }

    #[test]
    fn event_emitter_writes_jsonl_and_snapshot() -> Result<()> {
        let dir = TempDir::new()?;
        let emitter = EventEmitter::new(dir.path());
        emitter.emit(RuntimeEvent {
            event_type: "oracle.session.started".to_string(),
            agent: "coordinator".to_string(),
            resource: "front_door".to_string(),
            action: "start".to_string(),
            outcome: "observed".to_string(),
            ts: Utc::now(),
            context: json!({"session_id": "warroom", "severity": "info"}),
        })?;

        let events: Vec<RuntimeEventRecord> = read_jsonl(&emitter.events_path());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].version, EVENT_SCHEMA_VERSION);
        assert_eq!(events[0].event_type, "oracle.session.started");

        let snapshot = read_runtime_guard_snapshot(dir.path(), 12)?;
        assert_eq!(snapshot.version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(snapshot.event_count, 1);
        assert_eq!(snapshot.counts_by_type["oracle.session.started"], 1);
        assert_eq!(snapshot.counts_by_verdict["observed"], 1);
        Ok(())
    }
}
