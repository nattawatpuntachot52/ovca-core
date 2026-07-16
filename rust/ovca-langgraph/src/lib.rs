// oracle-langgraph — Sprint stub. See PLAN_RUST_HOTPATH.md for full contract.
use anyhow::Result;
use ovca_brain::{search, BrainCache};
use ovca_llm_client::McpHttpClient;
use ovca_runtime_core::{
    classify_intent as runtime_classify_intent, intent_to_agent, resolve_requested_agent,
    tokenize_runtime_text,
};
use ovca_types::{AgentId, AgentState, Intent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub type IntentClassifier = Arc<dyn Fn(&str) -> Intent + Send + Sync>;
type SpecialistOverride = dyn Fn(AgentId, &GraphState) -> String + Send + Sync;

const DEFAULT_MAX_REWRITES: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphMessage {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub name: String,
}

impl GraphMessage {
    fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
            name: String::new(),
        }
    }

    fn assistant(name: &str, content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphState {
    #[serde(default)]
    pub messages: Vec<GraphMessage>,
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
    pub gateway_reason: String,
    pub gateway_used: bool,
    pub capsule_context: String,
    pub session_id: String,
    pub grounded_trace: Value,
    pub grounded_confidence: String,
    #[serde(default)]
    pub execution_trace: Vec<String>,
}

impl GraphState {
    pub fn new(user_text: &str, requested_agent: Option<&str>, session_id: &str) -> Self {
        let requested = requested_agent
            .and_then(resolve_requested_agent)
            .map(|agent| agent.as_str().to_string())
            .unwrap_or_default();
        Self {
            messages: vec![GraphMessage::user(user_text.trim())],
            requested_agent: requested,
            original_user_text: user_text.trim().to_string(),
            current_query: user_text.trim().to_string(),
            max_rewrites: DEFAULT_MAX_REWRITES,
            session_id: session_id.trim().to_string(),
            grounded_trace: json!({}),
            grounded_confidence: "low".to_string(),
            ..Self::default()
        }
    }

    pub fn into_agent_state(self) -> AgentState {
        AgentState {
            intent: self.intent,
            active_agent: self.active_agent,
            rag_context: self.rag_context,
            final_response: self.final_response,
            requested_agent: self.requested_agent,
            original_user_text: self.original_user_text,
            current_query: self.current_query,
            needs_rewrite: self.needs_rewrite,
            rewrite_count: self.rewrite_count,
            max_rewrites: self.max_rewrites,
            grade_reason: self.grade_reason,
            gateway_route: self.gateway_route,
            gateway_used: self.gateway_used,
            capsule_context: self.capsule_context,
            session_id: self.session_id,
            grounded_trace: self.grounded_trace,
            grounded_confidence: self.grounded_confidence,
        }
    }

    fn latest_specialist_answer(&self) -> Option<&GraphMessage> {
        self.messages.iter().rev().find(|message| {
            message.role == "assistant"
                && matches!(message.name.as_str(), "engineer" | "reviewer" | "auditor")
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GradeResult {
    pub needs_rewrite: bool,
    pub reason: String,
    pub coverage: f64,
    pub jaccard: f64,
    pub response_len: usize,
    pub overlap_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteDecision {
    Rewrite,
    Coordinator,
}

#[derive(Clone)]
pub struct OracleGraph {
    mcp: Arc<McpHttpClient>,
    brain: Arc<BrainCache>,
    classifier: IntentClassifier,
    root: PathBuf,
    specialist_override: Option<Arc<SpecialistOverride>>,
}

impl OracleGraph {
    pub fn new(
        mcp: Arc<McpHttpClient>,
        brain: Arc<BrainCache>,
        classifier: IntentClassifier,
        root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            mcp,
            brain,
            classifier,
            root: root.into(),
            specialist_override: None,
        }
    }

    pub fn from_env(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let mcp = Arc::new(McpHttpClient::from_env(Duration::from_secs(2))?);
        let brain = Arc::new(BrainCache::new(&root));
        let classifier: IntentClassifier = Arc::new(runtime_classify_intent);
        Ok(Self::new(mcp, brain, classifier, root))
    }

    pub fn with_specialist_override(
        mut self,
        specialist_override: Arc<SpecialistOverride>,
    ) -> Self {
        self.specialist_override = Some(specialist_override);
        self
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub async fn run(
        &self,
        user_text: &str,
        requested_agent: Option<&str>,
        session_id: &str,
    ) -> AgentState {
        self.run_detailed(user_text, requested_agent, session_id)
            .await
            .into_agent_state()
    }

    pub async fn run_detailed(
        &self,
        user_text: &str,
        requested_agent: Option<&str>,
        session_id: &str,
    ) -> GraphState {
        let mut state = GraphState::new(user_text, requested_agent, session_id);
        if state.max_rewrites == 0 {
            state.max_rewrites = DEFAULT_MAX_REWRITES;
        }
        self.run_graph(state).await
    }

    async fn run_graph(&self, state: GraphState) -> GraphState {
        let mut state = self.intake_node(state).await;
        let mut agent = self.route_intake(&state);
        if agent == AgentId::Coordinator {
            state.active_agent = agent.as_str().to_string();
            return self.coordinator_node(state).await;
        }

        loop {
            state = self.specialist_node(agent, state).await;
            state = self.grade_node(state).await;
            match self.route_after_grade(&state) {
                RouteDecision::Rewrite if state.rewrite_count < state.max_rewrites => {
                    state = self.rewrite_node(state).await;
                    agent = self.route_rewrite_target(&state);
                }
                RouteDecision::Rewrite | RouteDecision::Coordinator => break,
            }
        }

        self.coordinator_node(state).await
    }

    pub async fn intake_node(&self, mut state: GraphState) -> GraphState {
        push_trace(&mut state, "intake");

        let user_text = state.original_user_text.trim().to_string();
        let requested = resolve_requested_agent(&state.requested_agent);
        let local_intent = (self.classifier)(&user_text);
        let local_agent = requested.unwrap_or_else(|| intent_to_agent(local_intent));

        let (intent, gateway_route, gateway_reason, gateway_used) =
            match self.gateway_route(&user_text, requested).await {
                Some((gateway_intent, gateway_agent, reason)) => {
                    (gateway_intent, gateway_agent, reason, true)
                }
                None => (
                    local_intent,
                    local_agent,
                    if requested.is_some() {
                        "explicit_request".to_string()
                    } else {
                        format!("intent:{}", intent_name(local_intent))
                    },
                    false,
                ),
            };

        let (rag_context, capsule_context, retrieval_trace) =
            self.build_context(gateway_route, &user_text).await;

        state.intent = intent_name(intent).to_string();
        state.current_query = user_text.clone();
        state.gateway_route = gateway_route.as_str().to_string();
        state.gateway_reason = gateway_reason;
        state.gateway_used = gateway_used;
        state.rag_context = rag_context;
        state.capsule_context = capsule_context;
        state.rewrite_count = 0;
        state.needs_rewrite = false;
        state.grade_reason.clear();
        state.grounded_confidence = if state.rag_context.is_empty() {
            "low".to_string()
        } else {
            "medium".to_string()
        };
        state.grounded_trace = json!({
            "session_id": state.session_id.clone(),
            "execution_trace": state.execution_trace.clone(),
            "gateway_route": state.gateway_route.clone(),
            "gateway_reason": state.gateway_reason.clone(),
            "gateway_used": state.gateway_used,
            "retrieval": retrieval_trace,
        });
        state
    }

    pub fn route_intake(&self, state: &GraphState) -> AgentId {
        if let Some(agent) = resolve_requested_agent(&state.gateway_route) {
            return agent;
        }
        if let Some(agent) = resolve_requested_agent(&state.requested_agent) {
            return agent;
        }

        let intent = match state.intent.as_str() {
            "intel" => Intent::Intel,
            "research" => Intent::Research,
            "trading" => Intent::Trading,
            "engineering" => Intent::Engineering,
            _ => Intent::General,
        };
        intent_to_agent(intent)
    }

    pub async fn specialist_node(&self, agent: AgentId, mut state: GraphState) -> GraphState {
        push_trace(&mut state, agent.as_str());
        state.active_agent = agent.as_str().to_string();

        let response = if let Some(override_cb) = &self.specialist_override {
            override_cb(agent, &state)
        } else {
            self.call_specialist(agent, &state).await
        };

        state
            .messages
            .push(GraphMessage::assistant(agent.as_str(), response));
        state
    }

    pub async fn grade_node(&self, mut state: GraphState) -> GraphState {
        push_trace(&mut state, "grade");
        let answer = state
            .latest_specialist_answer()
            .map(|message| message.content.clone())
            .unwrap_or_default();
        let query = state.current_query.clone();
        let result = grade(&answer, &query);
        state.needs_rewrite = result.needs_rewrite;
        state.grade_reason = result.reason.clone();
        if let Some(trace) = state.grounded_trace.as_object_mut() {
            trace.insert(
                "grade".to_string(),
                json!({
                    "reason": result.reason,
                    "coverage": result.coverage,
                    "jaccard": result.jaccard,
                    "response_len": result.response_len,
                    "overlap_count": result.overlap_count,
                }),
            );
        }
        state
    }

    pub fn route_after_grade(&self, state: &GraphState) -> RouteDecision {
        if state.needs_rewrite && state.rewrite_count < state.max_rewrites {
            RouteDecision::Rewrite
        } else {
            RouteDecision::Coordinator
        }
    }

    pub async fn rewrite_node(&self, mut state: GraphState) -> GraphState {
        push_trace(&mut state, "rewrite");
        let active = resolve_requested_agent(&state.active_agent).unwrap_or(AgentId::Coordinator);
        let rewritten = rewrite_query(
            &state.original_user_text,
            &state.current_query,
            &state.grade_reason,
            active,
        );
        state.rewrite_count += 1;
        state.current_query = rewritten.clone();
        state.needs_rewrite = false;
        state.messages.push(GraphMessage::user(rewritten.clone()));

        let (rag_context, capsule_context, retrieval_trace) =
            self.build_context(active, &rewritten).await;
        state.rag_context = rag_context;
        state.capsule_context = capsule_context;
        if let Some(trace) = state.grounded_trace.as_object_mut() {
            trace.insert("rewrite_count".to_string(), json!(state.rewrite_count));
            trace.insert("rewrite_query".to_string(), json!(rewritten));
            trace.insert("retrieval_after_rewrite".to_string(), retrieval_trace);
        }
        state
    }

    pub async fn coordinator_node(&self, mut state: GraphState) -> GraphState {
        push_trace(&mut state, "coordinator");
        let active_agent = if matches!(
            state.active_agent.as_str(),
            "engineer" | "reviewer" | "auditor"
        ) {
            state.active_agent.clone()
        } else {
            "coordinator".to_string()
        };
        let specialist_answer = state
            .latest_specialist_answer()
            .map(|message| message.content.clone())
            .unwrap_or_else(|| direct_coordinator_answer(&state.current_query, &state.rag_context));

        let confidence = infer_confidence(&specialist_answer, &state);
        let final_response = synthesize_coordinator_response(
            &state.current_query,
            &active_agent,
            &specialist_answer,
            &state.rag_context,
            state.rewrite_count,
        );
        state.final_response = final_response.clone();
        state.active_agent = active_agent;
        state.grounded_confidence = confidence.to_string();
        state
            .messages
            .push(GraphMessage::assistant("coordinator", final_response));
        state.grounded_trace = json!({
            "session_id": state.session_id.clone(),
            "execution_trace": state.execution_trace.clone(),
            "route": state.gateway_route.clone(),
            "active_agent": state.active_agent.clone(),
            "rewrite_count": state.rewrite_count,
            "grade_reason": state.grade_reason.clone(),
            "grounded_confidence": state.grounded_confidence.clone(),
            "rag_context_preview": truncate_text(&state.rag_context, 320),
            "capsule_context": truncate_text(&state.capsule_context, 160),
        });
        state
    }

    async fn gateway_route(
        &self,
        user_text: &str,
        requested_agent: Option<AgentId>,
    ) -> Option<(Intent, AgentId, String)> {
        let payload = self
            .mcp
            .call_tool(
                "coordinator",
                "coordinator_route_intake",
                json!({
                    "user_text": user_text,
                    "requested_agent": requested_agent.map(AgentId::as_str).unwrap_or(""),
                }),
            )
            .await
            .ok()?;
        if !payload.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }

        let result = payload.get("result")?;
        let intent = match result.get("intent").and_then(Value::as_str).unwrap_or("") {
            "intel" => Intent::Intel,
            "research" => Intent::Research,
            "trading" => Intent::Trading,
            "engineering" => Intent::Engineering,
            _ => Intent::General,
        };
        let route = resolve_requested_agent(
            result
                .get("route_target")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        let reason = result
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("gateway")
            .to_string();
        Some((intent, route, reason))
    }

    fn route_rewrite_target(&self, state: &GraphState) -> AgentId {
        resolve_requested_agent(&state.active_agent).unwrap_or_else(|| self.route_intake(state))
    }

    async fn build_context(&self, route_target: AgentId, query: &str) -> (String, String, Value) {
        let mut snippets = Vec::new();
        let mut capsule = Vec::new();
        let mut hits = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut brains = vec!["oracle".to_string(), route_target.as_str().to_string()];
        brains.sort();
        brains.dedup();

        for brain_name in brains {
            let index = self.brain.get_or_load(&brain_name).await;
            for (score, node) in search::search_nodes(&index.nodes, query, 3) {
                if !seen_ids.insert(node.id.clone()) {
                    continue;
                }
                let summary = truncate_text(&first_nonempty(&node.summary, &node.body), 180);
                let snippet = if summary.is_empty() {
                    format!("[{}] {}", brain_name, node.title)
                } else {
                    format!("[{}] {} - {}", brain_name, node.title, summary)
                };
                if snippets.len() < 6 {
                    snippets.push(snippet);
                }
                if capsule.len() < 3 {
                    capsule.push(format!("- [{}] {}", brain_name, node.title));
                }
                hits.push(json!({
                    "brain": brain_name,
                    "id": node.id,
                    "title": node.title,
                    "score": score,
                    "summary": summary,
                }));
            }
        }

        (
            snippets.join("\n"),
            capsule.join("\n"),
            json!({
                "query": query,
                "hits": hits,
                "root": self.root.display().to_string(),
            }),
        )
    }

    async fn call_specialist(&self, agent: AgentId, state: &GraphState) -> String {
        let Some((target_agent, tool_name, args)) = specialist_tool(agent, &state.current_query)
        else {
            return format!(
                "Legacy agent '{}' is inactive; no MCP call was made. query={} context={}",
                agent.as_str(),
                state.current_query,
                truncate_text(&state.rag_context, 120)
            );
        };
        let payload = match self.mcp.call_tool(target_agent, tool_name, args).await {
            Ok(payload) => payload,
            Err(error) => {
                return format!(
                    "[fallback:{}] mcp_error={} query={} context={}",
                    agent.as_str(),
                    error,
                    state.current_query,
                    truncate_text(&state.rag_context, 120)
                );
            }
        };

        if !payload.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            return format!(
                "[fallback:{}] mcp_unavailable query={} context={}",
                agent.as_str(),
                state.current_query,
                truncate_text(&state.rag_context, 120)
            );
        }

        build_specialist_summary(
            agent,
            &state.current_query,
            &state.rag_context,
            payload.get("result").unwrap_or(&payload),
        )
    }
}

pub fn grade(response: &str, query: &str) -> GradeResult {
    let query_tokens = tokenize_runtime_text(query);
    let response_tokens = tokenize_runtime_text(response);
    let overlap_count = query_tokens.intersection(&response_tokens).count();
    let union_count = query_tokens.union(&response_tokens).count().max(1);
    let coverage = overlap_count as f64 / query_tokens.len().max(1) as f64;
    let jaccard = overlap_count as f64 / union_count as f64;
    let response_len = response.trim().chars().count();
    let reason = if response.trim().is_empty() {
        "empty_answer"
    } else if response
        .trim()
        .to_ascii_lowercase()
        .starts_with("[fallback:")
    {
        "fallback_answer"
    } else if response_len < 20 {
        "answer_too_short"
    } else if coverage < 0.1 {
        "low_coverage"
    } else {
        "ok"
    };

    GradeResult {
        needs_rewrite: reason != "ok",
        reason: reason.to_string(),
        coverage,
        jaccard,
        response_len,
        overlap_count,
    }
}

fn intent_name(intent: Intent) -> &'static str {
    match intent {
        Intent::Intel => "intel",
        Intent::Research => "research",
        Intent::Trading => "trading",
        Intent::Engineering => "engineering",
        Intent::General => "general",
    }
}

fn specialist_tool(agent: AgentId, query: &str) -> Option<(&'static str, &'static str, Value)> {
    match agent {
        AgentId::Reviewer => Some((
            "reviewer",
            "reviewer_review_status",
            json!({ "query": query }),
        )),
        AgentId::Auditor => Some((
            "auditor",
            "auditor_cross_audit_status",
            json!({ "query": query }),
        )),
        AgentId::Engineer => Some(("engineer", "engineer_automation_status", json!({}))),
        AgentId::Coordinator => Some(("coordinator", "coordinator_team_status", json!({}))),
        AgentId::Aurora | AgentId::Divina | AgentId::Hope => None,
    }
}

fn build_specialist_summary(
    agent: AgentId,
    query: &str,
    rag_context: &str,
    result: &Value,
) -> String {
    let context_hint = truncate_text(rag_context, 180);
    match agent {
        AgentId::Reviewer => {
            let overall_status = result
                .get("overall_status")
                .or_else(|| result.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let findings = join_array_field(result.get("findings"), "summary", 3);
            format!(
                "Reviewer review view for query '{query}'. Review status is {overall_status}. Findings observed: {findings}. Retrieval context: {context_hint}. Validate behavior end to end before claiming pass."
            )
        }
        AgentId::Auditor => {
            let overall_status = result
                .get("overall_status")
                .or_else(|| result.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let risks = join_array_field(result.get("risks"), "summary", 3);
            format!(
                "Auditor cross-audit view for query '{query}'. Audit status is {overall_status}. Risks observed: {risks}. Retrieval context: {context_hint}. Challenge unsupported assumptions before routing forward."
            )
        }
        AgentId::Engineer => {
            let overall_status = result
                .get("overall_status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let workers = join_array_field(result.get("workers"), "agent", 5);
            format!(
                "Engineer engineering view for query '{query}'. Automation overall status is {overall_status}. Workers observed: {workers}. Retrieval context: {context_hint}. Any implementation should state inputs outputs side effects and rollback."
            )
        }
        AgentId::Coordinator => direct_coordinator_answer(query, rag_context),
        AgentId::Aurora | AgentId::Divina | AgentId::Hope => format!(
            "Legacy agent '{}' is inactive and retained only for serialized-data compatibility. Query '{query}' was not routed to it. Retrieval context: {context_hint}.",
            agent.as_str()
        ),
    }
}

fn join_array_field(value: Option<&Value>, field: &str, limit: usize) -> String {
    let Some(rows) = value.and_then(Value::as_array) else {
        return "none".to_string();
    };
    let mut parts = Vec::new();
    for row in rows.iter().take(limit) {
        if let Some(text) = row.get(field).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                parts.push(truncate_text(trimmed, 80));
            }
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("; ")
    }
}

fn rewrite_query(
    original_question: &str,
    previous_query: &str,
    reason: &str,
    active_agent: AgentId,
) -> String {
    let suffix = match active_agent {
        AgentId::Engineer => "inputs outputs side effects rollback",
        AgentId::Reviewer => "end to end behavior evidence quality gate",
        AgentId::Auditor => "countercheck risk assumption verification",
        AgentId::Coordinator => "decision risk evidence next step",
        AgentId::Aurora => "legacy macro archive context only",
        AgentId::Divina => "legacy research archive context only",
        AgentId::Hope => "legacy portfolio archive context only",
    };
    format!(
        "{} | clarify_for={} | previous={} | focus={}",
        original_question.trim(),
        reason.trim(),
        truncate_text(previous_query, 96),
        suffix
    )
}

fn direct_coordinator_answer(query: &str, rag_context: &str) -> String {
    format!(
        "Coordinator direct synthesis for query '{query}'. Context available: {}. No specialist escalation was required, so the response should stay high level and decision-oriented.",
        truncate_text(rag_context, 180)
    )
}

fn synthesize_coordinator_response(
    query: &str,
    active_agent: &str,
    specialist_answer: &str,
    rag_context: &str,
    rewrite_count: usize,
) -> String {
    let evidence_line = first_nonempty(specialist_answer, rag_context);
    format!(
        "ข้อสรุป: เส้นทางงานนี้วิ่งผ่าน {active_agent} สำหรับคำถาม '{query}' และจบการสังเคราะห์โดย Coordinator\nหลักฐานที่รองรับ:\n- {}\n- บริบทเสริม: {}\nความมั่นใจ: {}\nสิ่งที่ยังไม่รู้:\n- หากต้องลงมือจริงควรตรวจสอบข้อมูลสดและข้อจำกัดล่าสุดอีกครั้ง",
        truncate_text(&evidence_line, 280),
        truncate_text(rag_context, 180),
        if specialist_answer.to_ascii_lowercase().starts_with("[fallback:") {
            "ต่ำ"
        } else if rewrite_count == 0 && !rag_context.trim().is_empty() {
            "สูง"
        } else {
            "กลาง"
        }
    )
}

fn infer_confidence(specialist_answer: &str, state: &GraphState) -> &'static str {
    if specialist_answer
        .to_ascii_lowercase()
        .starts_with("[fallback:")
    {
        "low"
    } else if !state.rag_context.trim().is_empty() && state.rewrite_count == 0 {
        "high"
    } else if !state.rag_context.trim().is_empty() {
        "medium"
    } else {
        "low"
    }
}

fn first_nonempty(primary: &str, fallback: &str) -> String {
    let primary = primary.trim();
    if !primary.is_empty() {
        primary.to_string()
    } else {
        fallback.trim().to_string()
    }
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn push_trace(state: &mut GraphState, step: &str) {
    state.execution_trace.push(step.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovca_types::{BrainIndex, BrainNode};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    fn write_brain_index(root: &std::path::Path, brain: &str, nodes: Vec<BrainNode>) {
        let (pkg, subdir) = match brain {
            "oracle" => ("oracle.brain", "brain"),
            "coordinator" => ("oracle.coordinator", "brain"),
            "reviewer" => ("oracle.reviewer", "brain"),
            "auditor" => ("oracle.auditor", "brain"),
            "engineer" => ("oracle.engineer", "brain"),
            other => panic!("unknown brain {other}"),
        };
        let brain_dir = root.join(pkg).join(subdir);
        fs::create_dir_all(&brain_dir).unwrap();
        let artifact = BrainIndex {
            version: "s7".to_string(),
            brain: brain.to_string(),
            generated_at: "2026-03-13T00:00:00Z".to_string(),
            node_count: nodes.len(),
            merkle_root: None,
            merkle_root_at: None,
            nodes,
            edges: vec![],
        };
        fs::write(
            brain_dir.join("brain_index.json"),
            serde_json::to_vec_pretty(&artifact).unwrap(),
        )
        .unwrap();
    }

    fn node(brain: &str, id: &str, title: &str, summary: &str, tags: &[&str]) -> BrainNode {
        BrainNode {
            id: id.to_string(),
            title: title.to_string(),
            node_type: "note".to_string(),
            brain: brain.to_string(),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            summary: summary.to_string(),
            body: format!("{summary}\nDetailed body for {title}"),
            ..Default::default()
        }
    }

    fn graph_with_override(
        root: &std::path::Path,
        responder: Arc<SpecialistOverride>,
    ) -> OracleGraph {
        write_brain_index(
            root,
            "oracle",
            vec![
                node(
                    "oracle",
                    "oracle-1",
                    "Macro Regime Note",
                    "market macro regime risk and portfolio context",
                    &["macro", "market"],
                ),
                node(
                    "oracle",
                    "oracle-2",
                    "Engineering Rollback",
                    "automation rollback inputs outputs for pipeline fixes",
                    &["engineering", "pipeline"],
                ),
            ],
        );
        write_brain_index(
            root,
            "reviewer",
            vec![node(
                "reviewer",
                "reviewer-1",
                "Evidence Review",
                "market inflation rate regime shift evidence and review risk",
                &["market", "inflation"],
            )],
        );
        write_brain_index(
            root,
            "auditor",
            vec![node(
                "auditor",
                "auditor-1",
                "Cross Audit Queue",
                "hypothesis backtest evidence confidence risk and robustness",
                &["hypothesis", "research"],
            )],
        );
        write_brain_index(
            root,
            "engineer",
            vec![node(
                "engineer",
                "engineer-1",
                "Automation Health",
                "automation inputs outputs side effects rollback for pipeline",
                &["automation", "pipeline"],
            )],
        );
        write_brain_index(root, "coordinator", vec![]);

        let mut base_urls = HashMap::new();
        base_urls.insert(
            "coordinator".to_string(),
            "http://127.0.0.1:65530".to_string(),
        );
        base_urls.insert("engineer".to_string(), "http://127.0.0.1:65534".to_string());
        base_urls.insert("reviewer".to_string(), "http://127.0.0.1:65535".to_string());
        base_urls.insert("auditor".to_string(), "http://127.0.0.1:65536".to_string());
        let mcp =
            Arc::new(McpHttpClient::with_base_urls(base_urls, Duration::from_millis(50)).unwrap());
        let brain = Arc::new(BrainCache::new(root));
        let classifier: IntentClassifier = Arc::new(runtime_classify_intent);
        OracleGraph::new(mcp, brain, classifier, root).with_specialist_override(responder)
    }

    #[test]
    fn grade_requires_coverage_and_min_length() {
        let ok = grade(
            "market macro regime update includes risk implication and portfolio timeframe",
            "market macro regime update",
        );
        assert!(!ok.needs_rewrite);
        assert!(ok.coverage >= 0.1);

        let short = grade("too short", "market macro regime update");
        assert!(short.needs_rewrite);
        assert_eq!(short.reason, "answer_too_short");
    }

    #[tokio::test]
    async fn all_five_intent_paths_match_expected_trace() {
        let dir = TempDir::new().unwrap();
        let responder: Arc<SpecialistOverride> = Arc::new(|agent, state| {
            match agent {
            AgentId::Reviewer => format!(
                "reviewer specialist answered {} with market macro regime risk implication review evidence using {}",
                state.current_query,
                truncate_text(&state.rag_context, 60)
            ),
            AgentId::Auditor => format!(
                "auditor specialist answered {} with hypothesis backtest evidence confidence cross audit using {}",
                state.current_query,
                truncate_text(&state.rag_context, 60)
            ),
            AgentId::Engineer => format!(
                "engineer specialist answered {} with automation inputs outputs side effects rollback and pipeline guidance using {}",
                state.current_query,
                truncate_text(&state.rag_context, 60)
            ),
            AgentId::Coordinator => "coordinator direct".to_string(),
            AgentId::Aurora | AgentId::Divina | AgentId::Hope =>
                "legacy agent inactive; no specialist response".to_string(),
        }
        });
        let graph = graph_with_override(dir.path(), responder);

        let cases = [
            (
                "market macro regime update",
                None,
                vec!["intake", "reviewer", "grade", "coordinator"],
            ),
            (
                "hypothesis backtest robustness review",
                None,
                vec!["intake", "auditor", "grade", "coordinator"],
            ),
            (
                "trade position risk review",
                None,
                vec!["intake", "coordinator"],
            ),
            (
                "python api bug in pipeline",
                None,
                vec!["intake", "engineer", "grade", "coordinator"],
            ),
            (
                "summarize owner meeting notes",
                None,
                vec!["intake", "coordinator"],
            ),
        ];

        for (message, requested, expected_trace) in cases {
            let state = graph.run_detailed(message, requested, "session-1").await;
            assert_eq!(state.execution_trace, expected_trace, "message={message}");
            assert!(!state.final_response.is_empty(), "message={message}");
        }
    }

    #[tokio::test]
    async fn rewrite_loop_terminates_at_max_rewrites() {
        let dir = TempDir::new().unwrap();
        let responder: Arc<SpecialistOverride> =
            Arc::new(|agent, _state| format!("[fallback:{}] insufficient", agent.as_str()));
        let graph = graph_with_override(dir.path(), responder);

        let mut state = GraphState::new("market macro regime update", None, "rewrite-session");
        state.max_rewrites = 2;
        let state = graph.run_graph(state).await;

        assert_eq!(state.rewrite_count, 2);
        assert_eq!(
            state.execution_trace,
            vec![
                "intake",
                "reviewer",
                "grade",
                "rewrite",
                "reviewer",
                "grade",
                "rewrite",
                "reviewer",
                "grade",
                "coordinator",
            ]
        );
        assert!(state.final_response.contains("Coordinator"));
    }

    #[tokio::test]
    async fn run_returns_structurally_correct_agent_state() {
        let dir = TempDir::new().unwrap();
        let responder: Arc<SpecialistOverride> = Arc::new(|agent, state| {
            format!(
                "{} answer for {} with enough overlap on hypothesis backtest evidence confidence and {}",
                agent.as_str(),
                state.current_query,
                truncate_text(&state.rag_context, 40)
            )
        });
        let graph = graph_with_override(dir.path(), responder);

        let result = graph
            .run(
                "hypothesis backtest robustness review",
                Some("auditor"),
                "graph-session",
            )
            .await;

        assert_eq!(result.intent, "research");
        assert_eq!(result.active_agent, "auditor");
        assert_eq!(result.gateway_route, "auditor");
        assert_eq!(result.session_id, "graph-session");
        assert!(!result.final_response.is_empty());
        assert!(result.grounded_trace["execution_trace"].is_array());
    }

    #[tokio::test]
    #[ignore = "requires live Rust MCP agent servers"]
    async fn live_mcp_path_smoke() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let graph = OracleGraph::from_env(root).unwrap();
        let result = graph
            .run("market macro regime update", None, "live-smoke")
            .await;
        assert!(!result.final_response.is_empty());
    }
}
