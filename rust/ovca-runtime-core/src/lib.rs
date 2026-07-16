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

pub const LLM_CALL_CONTRACT_VERSION: &str = "oracle_llm_call_contract.v1";
pub const EVENT_SCHEMA_VERSION: &str = "oracle_runtime_event.v1";
pub const SNAPSHOT_SCHEMA_VERSION: &str = "oracle_runtime_guard_snapshot.v1";

const EVENTS_RELATIVE_PATH: &str = "logs/runtime_guard/events.jsonl";
const SNAPSHOT_RELATIVE_PATH: &str = "logs/runtime_guard/latest.json";

const INTEL_KEYWORDS: &[&str] = &[
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
    "ตลาด",
    "หุ้น",
    "เศรษฐกิจ",
    "เงินเฟ้อ",
    "ดอกเบี้ย",
];

const RESEARCH_KEYWORDS: &[&str] = &[
    "hypothesis",
    "backtest",
    "strategy",
    "edge",
    "research",
    "statistical",
    "correlation",
    "robustness",
    "วิจัย",
    "ทดสอบ",
    "สมมติฐาน",
    "กลยุทธ์",
];

const TRADING_KEYWORDS: &[&str] = &[
    "trade",
    "position",
    "risk",
    "entry",
    "exit",
    "drawdown",
    "execution",
    "order",
    "พอร์ต",
    "เทรด",
    "stop loss",
    "hedge",
];

const ENGINEERING_KEYWORDS: &[&str] = &[
    "script",
    "code",
    "bug",
    "automate",
    "api",
    "python",
    "rust",
    "fix",
    "error",
    "pipeline",
    "ระบบ",
    "โค้ด",
    "ประสิทธิภาพ",
];

const INTENT_KEYWORDS: &[(Intent, &[&str])] = &[
    (Intent::Intel, INTEL_KEYWORDS),
    (Intent::Research, RESEARCH_KEYWORDS),
    (Intent::Trading, TRADING_KEYWORDS),
    (Intent::Engineering, ENGINEERING_KEYWORDS),
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

    for (intent, keywords) in INTENT_KEYWORDS {
        let score = keywords
            .iter()
            .filter(|keyword| keyword_matches(&low, &tokens, keyword))
            .count();
        if score > best_match.1 {
            best_match = (*intent, score);
        }
    }

    if best_match.1 == 0 {
        Intent::General
    } else {
        best_match.0
    }
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
    fn classify_intent_matches_twenty_sample_texts() {
        let cases = [
            ("market macro regime update", Intent::Intel),
            ("fed inflation path and rate outlook", Intent::Intel),
            ("crypto gold oil rotation check", Intent::Intel),
            ("ตลาดหุ้นและเงินเฟ้อคืนนี้", Intent::Intel),
            ("hypothesis backtest robustness review", Intent::Research),
            ("research strategy edge validation", Intent::Research),
            ("statistical correlation regime test", Intent::Research),
            ("วิจัยสมมติฐานกลยุทธ์ใหม่", Intent::Research),
            ("trade position risk review", Intent::Trading),
            ("entry exit order execution plan", Intent::Trading),
            ("drawdown hedge stop loss check", Intent::Trading),
            ("พอร์ตเทรดต้องลดความเสี่ยง", Intent::Trading),
            ("python api bug in pipeline", Intent::Engineering),
            ("rust code fix for error handling", Intent::Engineering),
            ("automate script for system task", Intent::Engineering),
            ("ระบบโค้ดมีปัญหาประสิทธิภาพ", Intent::Engineering),
            ("summarize the meeting notes", Intent::General),
            ("tell me a quick joke", Intent::General),
            ("owner wants a high level recap", Intent::General),
            ("ช่วยสรุปเรื่องนี้แบบสั้น", Intent::General),
        ];

        assert_eq!(cases.len(), 20);
        for (text, expected) in cases {
            assert_eq!(classify_intent(text), expected, "text={text}");
        }
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
