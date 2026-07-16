/// Oracle shared domain types.
/// No I/O. No async. Pure serde models.
/// All Python dict shapes are mirrored exactly so JSON round-trips are lossless.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ── Brain ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrainLink {
    pub id: String,
    #[serde(rename = "type")]
    pub link_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BrainNode {
    pub id: String,
    pub title: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub brain: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default = "default_active")]
    pub status: String,
    #[serde(default = "default_team")]
    pub visibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(default)]
    pub validity: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_locator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    #[serde(default)]
    pub links: Vec<BrainLink>,
    /// SHA-256(body + "|" + agent + "|" + epoch_ms) - immutable identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// content_hash of the previous version - null means genesis node
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    /// SHA-256(normalized body) - dedup key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
    /// Monotonic version counter - 1 for new nodes
    #[serde(default = "default_brain_node_version")]
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub math_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub math_score_at: Option<String>,
    #[serde(default)]
    pub summary: String,
    /// Body is the markdown content after the frontmatter block.
    #[serde(default)]
    pub body: String,
}

impl Default for BrainNode {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            node_type: String::new(),
            brain: String::new(),
            agent: String::new(),
            tags: vec![],
            aliases: vec![],
            confidence: None,
            status: "active".to_string(), // matches serde default_active
            visibility: "team".to_string(), // matches serde default_team
            valid_from: None,
            valid_to: None,
            validity: String::new(),
            created: String::new(),
            updated: String::new(),
            source_locator: None,
            sensitivity: None,
            evidence_refs: vec![],
            review_status: None,
            claim_ref: None,
            links: vec![],
            content_hash: None,
            parent_hash: None,
            body_hash: None,
            version: default_brain_node_version(),
            math_score: None,
            math_score_at: None,
            summary: String::new(),
            body: String::new(),
        }
    }
}

fn default_active() -> String {
    "active".to_string()
}
fn default_team() -> String {
    "team".to_string()
}
fn default_brain_node_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrainEdge {
    pub from_id: String,
    pub to_id: String,
    #[serde(rename = "type")]
    pub relation: String,
    #[serde(default)]
    pub source_brain: String,
    #[serde(default)]
    pub source_kind: String, // "frontmatter" | "wikilink"
    #[serde(default)]
    pub authoritative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrainIndex {
    pub version: String,
    pub brain: String,
    pub generated_at: String,
    pub node_count: usize,
    /// Merkle root of all content_hash values in this brain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    /// Timestamp of the latest merkle root computation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root_at: Option<String>,
    pub nodes: Vec<BrainNode>,
    pub edges: Vec<BrainEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrainWriteArgs {
    pub caller: String,
    pub brain: String,
    pub title: String,
    pub node_type: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub links: Vec<BrainLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default = "default_team")]
    pub visibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grounded_trace: Option<serde_json::Value>,
}

// ── MCP Protocol ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub ok: bool,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    pub result: serde_json::Value,
    #[serde(default)]
    pub trace: serde_json::Value,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default)]
    pub evidence: Vec<serde_json::Value>,
}

impl McpResponse {
    pub fn ok(name: &str, result: serde_json::Value) -> Self {
        Self {
            ok: true,
            name: name.to_string(),
            kind: "tool_result".to_string(),
            result,
            trace: serde_json::Value::Null,
            errors: vec![],
            confidence: None,
            evidence: vec![],
        }
    }

    pub fn err(name: &str, error: &str) -> Self {
        Self {
            ok: false,
            name: name.to_string(),
            kind: "tool_result".to_string(),
            result: serde_json::Value::Null,
            trace: serde_json::Value::Null,
            errors: vec![error.to_string()],
            confidence: None,
            evidence: vec![],
        }
    }

    pub fn offline(agent_id: &str) -> Self {
        Self::err("call_mcp_tool", &format!("mcp_offline:{}", agent_id))
    }
}

// ── Agents ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentId {
    Coordinator,
    Engineer,
    Reviewer,
    Auditor,
    // Legacy inactive/archive compatibility only.
    Aurora,
    Hope,
    Divina,
}

impl AgentId {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentId::Coordinator => "coordinator",
            AgentId::Engineer => "engineer",
            AgentId::Reviewer => "reviewer",
            AgentId::Auditor => "auditor",
            AgentId::Aurora => "aurora",
            AgentId::Hope => "hope",
            AgentId::Divina => "divina",
        }
    }

    pub fn port(self) -> u16 {
        match self {
            AgentId::Coordinator => 18780,
            AgentId::Engineer => 18784,
            AgentId::Reviewer => 18785,
            AgentId::Auditor => 18786,
            // Legacy variants deserialize old data but have no public runtime port.
            AgentId::Aurora | AgentId::Hope | AgentId::Divina => 0,
        }
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Public MCP server ports. Legacy compatibility variants are intentionally absent.
pub const MCP_PORTS: &[(&str, u16)] = &[
    ("policy-tools", 8775),
    ("coordinator", 18780),
    ("engineer", 18784),
    ("reviewer", 18785),
    ("auditor", 18786),
];

pub fn resolve_mcp_port(agent_id: &str) -> Option<u16> {
    MCP_PORTS
        .iter()
        .find(|(id, _)| *id == agent_id)
        .map(|(_, p)| *p)
}

// ── Intent / State Machine ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Intent {
    Intel,
    Research,
    Trading,
    Engineering,
    General,
}

impl Intent {
    pub fn to_agent(self) -> AgentId {
        match self {
            Intent::Intel => AgentId::Reviewer,
            Intent::Research => AgentId::Auditor,
            Intent::Trading => AgentId::Coordinator,
            Intent::Engineering => AgentId::Engineer,
            Intent::General => AgentId::Coordinator,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub intent: String,
    pub active_agent: String,
    pub rag_context: String,
    pub final_response: String,
    pub requested_agent: String,
    pub original_user_text: String,
    pub current_query: String,
    pub needs_rewrite: bool,
    pub rewrite_count: usize,
    pub max_rewrites: usize,
    pub grade_reason: String,
    pub gateway_route: String,
    pub gateway_used: bool,
    pub capsule_context: String,
    pub session_id: String,
    pub grounded_trace: serde_json::Value,
    pub grounded_confidence: String,
}

// ── Data Layer ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceSnapshot {
    pub symbol: String,
    pub price: f64,
    pub pct_change_24h: f64,
    pub volume_24h: f64,
    pub high_24h: f64,
    pub low_24h: f64,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalResult {
    pub symbol: String,
    pub price: f64,
    pub sma_20: Option<f64>,
    pub sma_60: Option<f64>,
    pub rsi_14: Option<f64>,
    /// "up" | "down"
    pub trend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioPosition {
    pub symbol: String,
    pub qty: f64,
    pub entry_price: f64,
    pub current_price: f64,
    pub unrealized_pnl: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortfolioState {
    pub positions: Vec<PortfolioPosition>,
    pub cash_usdt: f64,
    pub total_unrealized_pnl: f64,
    pub last_sync: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedEvent {
    pub event_type: String,
    pub keyword: String,
    pub source: String,
    pub headline: String,
    pub ts: String,
    /// "low" | "medium" | "high"
    pub severity: String,
}

// ── Scheduler ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunRecord {
    pub task_id: String,
    /// "ok" | "error" | "skipped"
    pub status: String,
    pub duration_ms: u64,
    pub ts: DateTime<Utc>,
    pub agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Runtime Events ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_type: String,
    pub agent: String,
    pub resource: String,
    pub action: String,
    pub outcome: String,
    pub ts: DateTime<Utc>,
    #[serde(default)]
    pub context: serde_json::Value,
}

// ── APPA Pipeline ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PromptStrategy {
    ZeroShot,
    FewShot,
    ChainOfThought,
    PromptChain,
    CriticalThinking,
    EffectiveCommunication,
}

impl fmt::Display for PromptStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PromptStrategy::ZeroShot => "ZERO_SHOT",
            PromptStrategy::FewShot => "FEW_SHOT",
            PromptStrategy::ChainOfThought => "CHAIN_OF_THOUGHT",
            PromptStrategy::PromptChain => "PROMPT_CHAIN",
            PromptStrategy::CriticalThinking => "CRITICAL_THINKING",
            PromptStrategy::EffectiveCommunication => "EFFECTIVE_COMMUNICATION",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssDecision {
    pub version: String,
    pub pss_decision_id: String,
    pub timestamp: DateTime<Utc>,
    pub input: PssInput,
    pub strategies: Vec<PromptStrategy>,
    pub primary_strategy: PromptStrategy,
    pub rationale: String,
    pub template_config: PssTemplateConfig,
}

impl PssDecision {
    pub fn new(input: PssInput, strategies: Vec<PromptStrategy>, rationale: &str) -> Self {
        let primary = strategies
            .first()
            .cloned()
            .unwrap_or(PromptStrategy::ZeroShot);
        Self {
            version: "1".to_string(),
            pss_decision_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            input,
            primary_strategy: primary,
            strategies,
            rationale: rationale.to_string(),
            template_config: PssTemplateConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssInput {
    pub task_type: String,
    pub phase: String,
    pub evidence_count: usize,
    pub output_format: String,
    pub agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PssTemplateConfig {
    pub cot_enabled: bool,
    pub cot_steps: Vec<String>,
    pub examples: Vec<String>,
    pub chain_phases: Vec<String>,
    pub sqp_enabled: bool,
    pub schema_type: String,
}

// ── Error Types ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("permission denied: caller={caller} brain={brain} action={action}")]
    PermissionDenied {
        caller: String,
        brain: String,
        action: String,
    },
    #[error("node not found: {id}")]
    NodeNotFound { id: String },
    #[error("brain index stale or missing: {brain}")]
    IndexStale { brain: String },
    #[error("LLM timeout after {ms}ms")]
    LlmTimeout { ms: u64 },
    #[error("MCP server offline: {agent}")]
    McpOffline { agent: String },
    #[error("storage error: {0}")]
    StorageError(#[from] std::io::Error),
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_port_map() {
        assert_eq!(AgentId::Coordinator.port(), 18780);
        assert_eq!(AgentId::Engineer.port(), 18784);
        assert_eq!(AgentId::Reviewer.port(), 18785);
        assert_eq!(AgentId::Auditor.port(), 18786);
        assert_eq!(AgentId::Aurora.port(), 0);
        assert_eq!(AgentId::Hope.port(), 0);
        assert_eq!(AgentId::Divina.port(), 0);
    }
    #[test]
    fn intent_to_agent_routing() {
        assert_eq!(Intent::Intel.to_agent(), AgentId::Reviewer);
        assert_eq!(Intent::Research.to_agent(), AgentId::Auditor);
        assert_eq!(Intent::Trading.to_agent(), AgentId::Coordinator);
        assert_eq!(Intent::Engineering.to_agent(), AgentId::Engineer);
        assert_eq!(Intent::General.to_agent(), AgentId::Coordinator);
    }

    #[test]
    fn mcp_response_ok_serializes() {
        let r = McpResponse::ok("brain_read", serde_json::json!({"nodes": []}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"name\":\"brain_read\""));
    }

    #[test]
    fn mcp_response_err_has_error() {
        let r = McpResponse::err("brain_write", "permission_denied");
        assert!(!r.ok);
        assert_eq!(r.errors[0], "permission_denied");
    }

    #[test]
    fn resolve_mcp_port_known() {
        assert_eq!(resolve_mcp_port("policy-tools"), Some(8775));
        assert_eq!(resolve_mcp_port("coordinator"), Some(18780));
        assert_eq!(resolve_mcp_port("aurora"), None);
    }

    #[test]
    fn resolve_mcp_port_unknown() {
        assert_eq!(resolve_mcp_port("nonexistent"), None);
    }

    #[test]
    fn pss_decision_roundtrip() {
        let input = PssInput {
            task_type: "validation".into(),
            phase: "mvp".into(),
            evidence_count: 0,
            output_format: "default".into(),
            agent: "engineer".into(),
        };
        let d = PssDecision::new(
            input,
            vec![PromptStrategy::ChainOfThought, PromptStrategy::PromptChain],
            "validation + mvp phase",
        );
        let json = serde_json::to_string(&d).unwrap();
        let d2: PssDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d2.primary_strategy, PromptStrategy::ChainOfThought);
        assert_eq!(d2.strategies.len(), 2);
    }

    #[test]
    fn brain_node_default_fields() {
        let n = BrainNode {
            id: "test-001".into(),
            title: "Test Node".into(),
            node_type: "Strategy".into(),
            brain: "oracle".into(),
            ..Default::default()
        };
        assert_eq!(n.status, "active");
        assert_eq!(n.visibility, "team");
        assert_eq!(n.version, 1);
        assert_eq!(n.math_score, None);
        assert_eq!(n.math_score_at, None);
    }

    #[test]
    fn brain_node_deserializes_missing_cam_fields() {
        let node: BrainNode = serde_json::from_str("{}").unwrap();
        assert_eq!(node.content_hash, None);
        assert_eq!(node.parent_hash, None);
        assert_eq!(node.body_hash, None);
        assert_eq!(node.version, 1);
        assert_eq!(node.math_score, None);
        assert_eq!(node.math_score_at, None);
    }

    #[test]
    fn brain_node_omits_none_content_hash_on_serialize() {
        let node = BrainNode::default();
        let value = serde_json::to_value(&node).unwrap();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("content_hash"));
        assert!(!obj.contains_key("parent_hash"));
        assert!(!obj.contains_key("body_hash"));
        assert!(!obj.contains_key("math_score"));
        assert!(!obj.contains_key("math_score_at"));
    }
}
