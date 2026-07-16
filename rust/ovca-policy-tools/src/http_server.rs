use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use ovca_mcp::sse::{broadcast_to_sse_stream, make_sse_channel};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};
use tokio::sync::broadcast;

use crate::tier1::{
    certainty_zone, claim_tag, drift_check, sati_check, support_disclose, temporal_gate,
    ClaimTagKind, SupportLevel, Zone,
};
use crate::tier2::{
    business_gate, decision_format, scamper_fill, BottleneckArea, ScamperFillInput,
};
use crate::tier3::{
    dispatch_blocker_check, plan_before_dispatch, pre_change_notice, DispatchBlockerInput, Plan,
};

const SERVER_NAME: &str = "oracle-policy-tools";

type ToolHandler = fn(Value) -> Value;

#[derive(Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub handler: ToolHandler,
}

#[derive(Clone)]
pub struct AppState {
    pub name: &'static str,
    pub tools: Arc<BTreeMap<String, ToolSpec>>,
    pub sse_tx: broadcast::Sender<String>,
}

#[derive(Debug, Deserialize)]
pub struct McpCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

pub fn build_router() -> Router {
    let (sse_tx, _) = make_sse_channel();
    let state = AppState {
        name: SERVER_NAME,
        tools: Arc::new(tool_specs()),
        sse_tx,
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/tools/list", get(tools_list_handler))
        .route("/tools/call", post(tools_call_handler))
        .route("/resources/list", get(resources_list_handler))
        .route("/resources/get", post(resources_get_handler))
        .route("/prompts/list", get(prompts_list_handler))
        .route("/prompts/get", post(prompts_get_handler))
        .route("/registry", get(registry_handler))
        .route("/sse", get(sse_handler))
        .with_state(state)
}

fn tool_specs() -> BTreeMap<String, ToolSpec> {
    let mut tools = BTreeMap::new();

    register_tool(
        &mut tools,
        "sati_check",
        "สัมปชัญญะ P1/P2/P3 — 3 คำถามก่อนทุก action ที่มีผลต่อระบบ",
        json!({
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "action ที่กำลังจะทำ"},
                "context": {"type": "string", "description": "เหตุผลเบื้องต้น (optional)"}
            },
            "required": ["action"]
        }),
        handle_sati_check,
    );
    register_tool(
        &mut tools,
        "temporal_gate",
        "Temporal Claim Gate — บล็อก causal/temporal claims ที่ไม่มี evidence",
        json!({
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "claim_type": {"type": "string", "enum": ["temporal", "causal", "numeric", "operational"]},
                "evidence_source": {"type": "string", "nullable": true}
            },
            "required": ["claim"]
        }),
        handle_temporal_gate,
    );
    register_tool(
        &mut tools,
        "support_disclose",
        "Support Sufficiency Disclosure — วัดระดับ support ของ claim",
        json!({
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "evidence_items": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["claim"]
        }),
        handle_support_disclose,
    );
    register_tool(
        &mut tools,
        "certainty_zone",
        "Certainty Zone C0–C4 — tag zone ก่อน recommend strategy/architecture",
        json!({
            "type": "object",
            "properties": {
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "context": {"type": "string"}
            },
            "required": ["confidence"]
        }),
        handle_certainty_zone,
    );
    register_tool(
        &mut tools,
        "claim_tag",
        "Reality-First Claim Tagging — tag observed/inferred/assumed/unknown",
        json!({
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "basis": {"type": "string", "nullable": true}
            },
            "required": ["claim"]
        }),
        handle_claim_tag,
    );
    register_tool(
        &mut tools,
        "drift_check",
        "Anti-Drift Self-Check — detect reasoning bugs (sycophancy, recency_bias, etc.)",
        json!({
            "type": "object",
            "properties": {
                "reasoning_snippet": {"type": "string"},
                "proposed_action": {"type": "string", "nullable": true}
            },
            "required": ["reasoning_snippet"]
        }),
        handle_drift_check,
    );
    register_tool(
        &mut tools,
        "scamper_fill",
        "SCAMPER Gate (filled) — validate completed SCAMPER pass ก่อน redesign",
        json!({
            "type": "object",
            "properties": {
                "base_object": {"type": "string"},
                "improvement_target": {"type": "string"},
                "eliminate": {"type": "array", "items": {"type": "string"}},
                "reverse": {"type": "array", "items": {"type": "string"}},
                "blind_spot": {"type": "string"},
                "smallest_next_experiment": {"type": "string"},
                "substitute": {"type": "array", "items": {"type": "string"}},
                "combine": {"type": "array", "items": {"type": "string"}},
                "adapt": {"type": "array", "items": {"type": "string"}},
                "modify": {"type": "array", "items": {"type": "string"}},
                "put_to_other_use": {"type": "array", "items": {"type": "string"}},
                "guardrail": {"type": "string"}
            },
            "required": ["base_object", "improvement_target", "eliminate", "reverse", "blind_spot", "smallest_next_experiment"]
        }),
        handle_scamper_fill,
    );
    register_tool(
        &mut tools,
        "business_gate",
        "Business OS Gate — diagnose bottleneck ก่อน recommend strategy/revenue",
        json!({
            "type": "object",
            "properties": {
                "recommendation": {"type": "string"},
                "domain": {"type": "string", "enum": ["lead", "sales", "delivery", "profit", "other"]},
                "bottleneck_evidence": {"type": "string", "nullable": true}
            },
            "required": ["recommendation"]
        }),
        handle_business_gate,
    );
    register_tool(
        &mut tools,
        "decision_format",
        "Decision Discipline — CEO output format validator (what_now/not/when/metric)",
        json!({
            "type": "object",
            "properties": {
                "topic": {"type": "string"},
                "options_considered": {"type": "array", "items": {"type": "string"}},
                "what_to_do_now": {"type": "string"},
                "what_not_to_do": {"type": "string"},
                "what_to_revisit_when": {"type": "string"},
                "metric_that_proves_it_worked": {"type": "string"},
                "confidence": {"type": "number"}
            },
            "required": ["topic"]
        }),
        handle_decision_format,
    );
    register_tool(
        &mut tools,
        "pre_change_notice",
        "Pre-Change Notice — สร้าง notice ก่อนแตะ file system (create/edit/delete/move/overwrite)",
        json!({
            "type": "object",
            "properties": {
                "action_type": {"type": "string", "enum": ["create", "edit", "delete", "move", "overwrite"]},
                "file_path": {"type": "string"},
                "reason": {"type": "string"},
                "expected_outcome": {"type": "string"},
                "risk_or_rollback": {"type": "string"}
            },
            "required": ["action_type", "file_path", "reason", "expected_outcome", "risk_or_rollback"]
        }),
        handle_pre_change_notice,
    );
    register_tool(
        &mut tools,
        "plan_before_dispatch",
        "Plan Before Dispatch gate — validate ว่าแผนมีองค์ประกอบครบก่อน dispatch",
        json!({
            "type": "object",
            "properties": {
                "plan": {
                    "type": "object",
                    "properties": {
                        "objective": {"type": "string"},
                        "steps": {"type": "array", "items": {"type": "string"}},
                        "files_affected": {"type": "array", "items": {"type": "string"}},
                        "risks": {"type": "array", "items": {"type": "string"}},
                        "acceptance_criteria": {"type": "array", "items": {"type": "string"}}
                    }
                }
            },
            "required": ["plan"]
        }),
        handle_plan_before_dispatch,
    );
    register_tool(
        &mut tools,
        "dispatch_blocker_check",
        "Dispatch Blocker Gate — hard gate ก่อน scaffold/pre-check/dispatch",
        json!({
            "type": "object",
            "properties": {
                "task_ref": {"type": "string", "nullable": true},
                "checklist_ref": {"type": "string", "nullable": true},
                "section_ref": {"type": "string", "nullable": true},
                "objective": {"type": "string", "nullable": true},
                "acceptance_ref": {"type": "string", "nullable": true},
                "verification_ref": {"type": "string", "nullable": true},
                "writable_scope": {"type": "array", "items": {"type": "string"}},
                "dispatch_mode": {"type": "string", "nullable": true},
                "stop_if_missing": {"type": "boolean"}
            }
        }),
        handle_dispatch_blocker_check,
    );

    tools
}

fn register_tool(
    tools: &mut BTreeMap<String, ToolSpec>,
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    handler: ToolHandler,
) {
    tools.insert(
        name.to_string(),
        ToolSpec {
            name,
            description,
            input_schema,
            handler,
        },
    );
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "name": state.name,
        "ts": now_iso(),
        "tools": state.tools.len(),
        "resources": 0,
        "prompts": 0,
    }))
}

async fn tools_list_handler(State(state): State<AppState>) -> impl IntoResponse {
    let tools = state
        .tools
        .values()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema.clone(),
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "ok": true,
        "count": tools.len(),
        "tools": tools,
    }))
}

async fn resources_list_handler() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "count": 0,
        "resources": [],
    }))
}

async fn prompts_list_handler() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "count": 0,
        "prompts": [],
    }))
}

async fn registry_handler(State(state): State<AppState>) -> impl IntoResponse {
    let tools = state.tools.keys().cloned().collect::<Vec<_>>();
    Json(json!({
        "ok": true,
        "name": state.name,
        "ts": now_iso(),
        "counts": {
            "tools": tools.len(),
            "resources": 0,
            "prompts": 0,
        },
        "tools": tools,
        "resources": [],
        "prompts": [],
    }))
}

async fn tools_call_handler(
    State(state): State<AppState>,
    Json(call): Json<McpCall>,
) -> impl IntoResponse {
    let Some(tool) = state.tools.get(&call.name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": format!("tool not found: {}", call.name)})),
        )
            .into_response();
    };

    let raw = (tool.handler)(call.arguments);
    let response = normalize_response(tool.name, raw, "tool");
    publish_event(
        &state,
        json!({
            "event": "tool_call",
            "tool": tool.name,
            "kind": "tool",
            "ok": response.get("ok").and_then(Value::as_bool).unwrap_or(false),
        }),
    );
    (StatusCode::OK, Json(response)).into_response()
}

async fn resources_get_handler(Json(call): Json<McpCall>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"detail": format!("resource not found: {}", call.name)})),
    )
}

async fn prompts_get_handler(Json(call): Json<McpCall>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"detail": format!("prompt not found: {}", call.name)})),
    )
}

async fn sse_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ready = json!({
        "event": "ready",
        "server": state.name,
        "ts": now_iso(),
    })
    .to_string();
    let ready_stream =
        stream::once(async move { Ok::<Event, Infallible>(Event::default().data(ready)) });
    let events = broadcast_to_sse_stream(state.sse_tx.subscribe());
    let stream = ready_stream.chain(events);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn publish_event(state: &AppState, event: Value) {
    let mut payload = Map::new();
    payload.insert("server".to_string(), Value::String(state.name.to_string()));
    payload.insert("ts".to_string(), Value::String(now_iso()));
    if let Value::Object(obj) = event {
        for (key, value) in obj {
            payload.insert(key, value);
        }
    }
    let _ = state.sse_tx.send(Value::Object(payload).to_string());
}

fn normalize_response(name: &str, raw: Value, kind: &str) -> Value {
    match raw {
        Value::Object(map) => normalize_object_response(name, map, kind),
        other => json!({
            "ok": true,
            "name": name,
            "kind": kind,
            "result": other,
            "trace": {},
            "errors": [],
            "evidence": [],
            "confidence": null,
        }),
    }
}

fn normalize_object_response(name: &str, map: Map<String, Value>, kind: &str) -> Value {
    let raw_value = Value::Object(map.clone());
    let errors = if let Some(items) = map.get("errors").and_then(Value::as_array) {
        Value::Array(
            items
                .iter()
                .map(|item| Value::String(item.as_str().unwrap_or("").to_string()))
                .collect(),
        )
    } else if let Some(error) = map.get("error").and_then(Value::as_str) {
        Value::Array(vec![Value::String(error.to_string())])
    } else {
        Value::Array(vec![])
    };

    let evidence = if let Some(items) = map.get("evidence").and_then(Value::as_array) {
        Value::Array(items.clone())
    } else if let Some(items) = map.get("evidence_hits").and_then(Value::as_array) {
        Value::Array(items.clone())
    } else {
        Value::Array(vec![])
    };

    let trace = match map.get("trace") {
        Some(Value::Object(obj)) => Value::Object(obj.clone()),
        Some(other) => json!({"raw_trace": other}),
        None => json!({}),
    };

    let mut payload = Map::new();
    payload.insert(
        "ok".to_string(),
        Value::Bool(map.get("ok").and_then(Value::as_bool).unwrap_or(true)),
    );
    payload.insert("name".to_string(), Value::String(name.to_string()));
    payload.insert("kind".to_string(), Value::String(kind.to_string()));
    payload.insert(
        "result".to_string(),
        map.get("result").cloned().unwrap_or(raw_value),
    );
    payload.insert("trace".to_string(), trace);
    payload.insert("errors".to_string(), errors);
    payload.insert("evidence".to_string(), evidence);
    payload.insert(
        "confidence".to_string(),
        map.get("confidence").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "error".to_string(),
        map.get("error").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "epistemic_tag".to_string(),
        map.get("epistemic_tag").cloned().unwrap_or(Value::Null),
    );
    if let Some(warnings) = map.get("_gate_warnings") {
        payload.insert("_gate_warnings".to_string(), warnings.clone());
    }
    if let Some(verdict) = map.get("_gate_verdict") {
        payload.insert("_gate_verdict".to_string(), verdict.clone());
    }
    Value::Object(payload)
}

fn handle_sati_check(args: Value) -> Value {
    let Some(action) = args.get("action").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "action is required"});
    };
    let action = action.trim();
    let context = args
        .get("context")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let result = sati_check(action, context);
    json!({
        "p1": result.p1,
        "p2": result.p2,
        "p3": result.p3,
        "proceed": result.proceed,
        "stop_reason": result.stop_reason,
    })
}

fn handle_temporal_gate(args: Value) -> Value {
    let Some(claim) = args.get("claim").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "claim is required"});
    };
    let claim = claim.trim();
    let claim_type = args
        .get("claim_type")
        .and_then(Value::as_str)
        .unwrap_or("causal");
    let evidence_source = args.get("evidence_source").and_then(Value::as_str);
    let result = temporal_gate(claim, claim_type, evidence_source);
    json!({
        "has_evidence": result.has_evidence,
        "verdict": result.verdict,
        "cite": result.cite,
        "safe_response": result.safe_response,
    })
}

fn handle_support_disclose(args: Value) -> Value {
    let Some(claim) = args.get("claim").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "claim is required"});
    };
    let claim = claim.trim();
    let evidence_items = string_array(args.get("evidence_items"));
    let evidence_refs = evidence_items
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let result = support_disclose(claim, &evidence_refs);
    json!({
        "level": support_level_name(&result.level),
        "label": result.label,
        "can_assert": result.can_assert,
        "disclosure_text": result.disclosure_text,
    })
}

fn handle_certainty_zone(args: Value) -> Value {
    let confidence = args
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let result = certainty_zone(confidence);
    json!({
        "zone": zone_name(&result.zone),
        "range": result.range,
        "action_required": result.action_required,
        "can_proceed": result.can_proceed,
        "confidence": result.confidence,
    })
}

fn handle_claim_tag(args: Value) -> Value {
    let Some(claim) = args.get("claim").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "claim is required"});
    };
    let claim = claim.trim();
    let basis = args.get("basis").and_then(Value::as_str);
    let result = claim_tag(claim, basis);
    json!({
        "tag": claim_tag_name(&result.tag),
        "explanation": result.explanation,
        "display_label": result.display_label,
    })
}

fn handle_drift_check(args: Value) -> Value {
    let Some(reasoning_snippet) = args.get("reasoning_snippet").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "reasoning_snippet is required"});
    };
    let reasoning_snippet = reasoning_snippet.trim();
    let proposed_action = args.get("proposed_action").and_then(Value::as_str);
    let result = drift_check(reasoning_snippet, proposed_action);
    let bugs = result
        .bugs_detected
        .into_iter()
        .map(|bug| {
            json!({
                "bug": bug.bug,
                "signal": bug.signal,
                "description": bug.description,
                "severity": match bug.severity {
                    crate::tier1::Severity::Warn => "warn",
                    crate::tier1::Severity::Stop => "stop",
                },
            })
        })
        .collect::<Vec<_>>();
    json!({
        "bugs_detected": bugs,
        "clean": result.clean,
        "stop": result.stop,
    })
}

fn handle_scamper_fill(args: Value) -> Value {
    let input = match serde_json::from_value::<ScamperFillInput>(args) {
        Ok(value) => value,
        Err(_) => return json!({"ok": false, "error": "invalid scamper_fill payload"}),
    };
    let result = scamper_fill(input);
    json!({
        "base_object": result.base_object,
        "improvement_target": result.improvement_target,
        "ideas": {
            "substitute": result.ideas.substitute,
            "combine": result.ideas.combine,
            "adapt": result.ideas.adapt,
            "modify": result.ideas.modify,
            "put_to_other_use": result.ideas.put_to_other_use,
            "eliminate": result.ideas.eliminate,
            "reverse": result.ideas.reverse,
        },
        "blind_spot": result.blind_spot,
        "guardrail": result.guardrail,
        "smallest_next_experiment": result.smallest_next_experiment,
        "missing": result.missing,
        "ready": result.ready,
    })
}

fn handle_business_gate(args: Value) -> Value {
    let recommendation = args
        .get("recommendation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if recommendation.is_empty() {
        return json!({"ok": false, "error": "recommendation is required"});
    }
    let domain = args
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("other");
    let bottleneck_evidence = args.get("bottleneck_evidence").and_then(Value::as_str);
    let result = business_gate(recommendation, domain, bottleneck_evidence);
    json!({
        "bottleneck_diagnosed": result.bottleneck_diagnosed,
        "bottleneck_area": bottleneck_area_name(&result.bottleneck_area),
        "bottleneck_evidence": result.bottleneck_evidence,
        "kpi_anchor": result.kpi_anchor.map(|anchor| json!({
            "do_x": anchor.do_x,
            "measure_y": anchor.measure_y,
            "target_z": anchor.target_z,
        })),
        "can_proceed": result.can_proceed,
        "block_reason": result.block_reason,
    })
}

fn handle_decision_format(args: Value) -> Value {
    let topic = args
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if topic.is_empty() {
        return json!({"ok": false, "error": "topic is required"});
    }
    let options_considered = string_array(args.get("options_considered"));
    let what_to_do_now = args
        .get("what_to_do_now")
        .and_then(Value::as_str)
        .unwrap_or("");
    let what_not_to_do = args
        .get("what_not_to_do")
        .and_then(Value::as_str)
        .unwrap_or("");
    let what_to_revisit_when = args
        .get("what_to_revisit_when")
        .and_then(Value::as_str)
        .unwrap_or("");
    let metric_that_proves_it_worked = args
        .get("metric_that_proves_it_worked")
        .and_then(Value::as_str)
        .unwrap_or("");
    let confidence = args
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5);
    let result = decision_format(
        topic,
        options_considered,
        what_to_do_now,
        what_not_to_do,
        what_to_revisit_when,
        metric_that_proves_it_worked,
        confidence,
    );
    json!({
        "topic": result.topic,
        "options_considered": result.options_considered,
        "what_to_do_NOW": result.what_to_do_now,
        "what_NOT_to_do": result.what_not_to_do,
        "what_to_revisit_when": result.what_to_revisit_when,
        "metric_that_proves_it_worked": result.metric_that_proves_it_worked,
        "certainty_zone": zone_name(&result.certainty_zone),
        "missing": result.missing,
        "complete": result.complete,
    })
}

fn handle_pre_change_notice(args: Value) -> Value {
    let required = (
        args.get("action_type").and_then(Value::as_str),
        args.get("file_path").and_then(Value::as_str),
        args.get("reason").and_then(Value::as_str),
        args.get("expected_outcome").and_then(Value::as_str),
        args.get("risk_or_rollback").and_then(Value::as_str),
    );
    let (
        Some(action_type),
        Some(file_path),
        Some(reason),
        Some(expected_outcome),
        Some(risk_or_rollback),
    ) = required
    else {
        return json!({"ok": false, "error": "action_type, file_path, reason, expected_outcome, and risk_or_rollback are required"});
    };
    let action_type = action_type.trim();
    let file_path = file_path.trim();
    let result = pre_change_notice(
        action_type,
        file_path,
        reason,
        expected_outcome,
        risk_or_rollback,
    );
    json!({
        "notice": {
            "what": format!("{} {}", action_type.to_lowercase(), file_path),
            "why": result.notice.why,
            "outcome": result.notice.outcome,
            "downside": result.notice.downside,
        },
        "requires_approval": result.requires_approval,
        "display_text": result.display_text,
        "missing": result.missing,
        "valid": result.valid,
    })
}

fn handle_plan_before_dispatch(args: Value) -> Value {
    let plan_value = args.get("plan").cloned().unwrap_or(Value::Null);
    let plan = match serde_json::from_value::<Plan>(plan_value) {
        Ok(value) => value,
        Err(_) => return json!({"ok": false, "error": "plan must be an object"}),
    };
    let result = plan_before_dispatch(&plan);
    json!({
        "valid": result.valid,
        "missing_fields": result.missing_fields,
        "can_dispatch": result.can_dispatch,
        "block_reason": result.block_reason,
    })
}

fn handle_dispatch_blocker_check(args: Value) -> Value {
    let input = match serde_json::from_value::<DispatchBlockerInput>(args) {
        Ok(value) => value,
        Err(_) => return json!({"ok": false, "error": "invalid dispatch_blocker_check payload"}),
    };
    let result = dispatch_blocker_check(&input);
    json!({
        "ready": result.ready,
        "missing_fields": result.missing_fields,
        "placeholder_fields": result.placeholder_fields,
        "verdict": result.verdict,
        "fail_reason": result.fail_reason,
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn support_level_name(level: &SupportLevel) -> &'static str {
    match level {
        SupportLevel::NoSupport => "no_support",
        SupportLevel::LowSupport => "low_support",
        SupportLevel::Supported => "supported",
    }
}

fn zone_name(zone: &Zone) -> &'static str {
    match zone {
        Zone::C0 => "C0",
        Zone::C1 => "C1",
        Zone::C2 => "C2",
        Zone::C3 => "C3",
        Zone::C4 => "C4",
    }
}

fn claim_tag_name(tag: &ClaimTagKind) -> &'static str {
    match tag {
        ClaimTagKind::Observed => "observed",
        ClaimTagKind::Inferred => "inferred",
        ClaimTagKind::Assumed => "assumed",
        ClaimTagKind::Unknown => "unknown",
    }
}

fn bottleneck_area_name(area: &BottleneckArea) -> &'static str {
    match area {
        BottleneckArea::Lead => "lead",
        BottleneckArea::Sales => "sales",
        BottleneckArea::Delivery => "delivery",
        BottleneckArea::Profit => "profit",
        BottleneckArea::Unknown => "unknown",
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, header},
    };
    use tower::util::ServiceExt;

    async fn call(
        app: Router,
        req: http::Request<Body>,
    ) -> (http::StatusCode, header::HeaderMap, Value) {
        let resp = ServiceExt::<http::Request<Body>>::oneshot(app, req)
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, headers, json)
    }

    #[tokio::test]
    async fn health_matches_python_shape() {
        let req = http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let (status, _headers, json) = call(build_router(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["name"], SERVER_NAME);
        assert_eq!(json["tools"], 12);
        assert_eq!(json["resources"], 0);
        assert_eq!(json["prompts"], 0);
        assert!(json.get("ts").and_then(Value::as_str).is_some());
    }

    #[tokio::test]
    async fn tools_list_contains_all_twelve_tools() {
        let req = http::Request::builder()
            .uri("/tools/list")
            .body(Body::empty())
            .unwrap();
        let (status, _headers, json) = call(build_router(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["count"], 12);
        let tools = json["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(tools.contains(&"sati_check"));
        assert!(tools.contains(&"dispatch_blocker_check"));
    }

    #[tokio::test]
    async fn sati_check_call_preserves_python_envelope() {
        let payload = json!({
            "name": "sati_check",
            "arguments": {
                "action": "edit task.md",
                "context": "phase1"
            }
        });
        let req = http::Request::builder()
            .method("POST")
            .uri("/tools/call")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let (status, _headers, json) = call(build_router(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["name"], "sati_check");
        assert_eq!(json["kind"], "tool");
        assert_eq!(json["result"]["proceed"], true);
        assert_eq!(json["trace"], json!({}));
        assert_eq!(json["errors"], json!([]));
    }

    #[test]
    fn present_empty_strings_reach_python_compatible_tool_logic() {
        assert_eq!(
            handle_sati_check(json!({"action": "", "context": ""})),
            json!({
                "p1": null,
                "p2": null,
                "p3": "[assumed] ผลที่ตามมายังไม่ verify — ต้องตรวจก่อนดำเนินการ",
                "proceed": false,
                "stop_reason": "P1 ยังไม่ชัด — ระบุ action ก่อน",
            })
        );
        assert_eq!(
            handle_temporal_gate(json!({"claim": "", "claim_type": "causal"})),
            json!({
                "has_evidence": false,
                "verdict": "block",
                "cite": null,
                "safe_response": "ยังยืนยันไม่ได้ค่ะ ต้องดู evidence ก่อน (ต้องมี log/timestamp/tool result รองรับ)",
            })
        );
        assert_eq!(
            handle_support_disclose(json!({"claim": "", "evidence_items": []})),
            json!({
                "level": "no_support",
                "label": "ยังยืนยันไม่ได้",
                "can_assert": false,
                "disclosure_text": "ยังยืนยันไม่ได้ค่ะ ไม่มี evidence รองรับ claim: ''",
            })
        );
        assert_eq!(
            handle_claim_tag(json!({"claim": "", "basis": null})),
            json!({
                "tag": "unknown",
                "explanation": "ไม่มี basis ระบุ — ยังไม่รู้และต้องบอกตรง ๆ",
                "display_label": "[unknown]",
            })
        );
        assert_eq!(
            handle_drift_check(json!({"reasoning_snippet": ""})),
            json!({"bugs_detected": [], "clean": true, "stop": false})
        );
        assert_eq!(
            handle_pre_change_notice(json!({
                "action_type": "edit",
                "file_path": "docs/a.md",
                "reason": "",
                "expected_outcome": "record",
                "risk_or_rollback": "revert",
            })),
            json!({
                "notice": {
                    "what": "edit docs/a.md",
                    "why": "",
                    "outcome": "record",
                    "downside": "revert",
                },
                "requires_approval": false,
                "display_text": "⚠️ [EDIT] docs/a.md\n  ทำไม: \n  ผลที่คาด: record\n  Risk/Rollback: revert",
                "missing": ["reason (why / authority)"],
                "valid": false,
            })
        );
    }

    #[test]
    fn absent_required_arguments_still_return_transport_errors() {
        let cases = [
            handle_sati_check(json!({"context": ""})),
            handle_temporal_gate(json!({"claim_type": "causal"})),
            handle_support_disclose(json!({"evidence_items": []})),
            handle_claim_tag(json!({"basis": null})),
            handle_drift_check(json!({"proposed_action": null})),
            handle_pre_change_notice(json!({
                "action_type": "edit",
                "file_path": "docs/a.md",
                "expected_outcome": "record",
                "risk_or_rollback": "revert",
            })),
        ];

        for result in cases {
            assert_eq!(result["ok"], false);
            assert!(result["error"].as_str().is_some());
        }
    }

    #[tokio::test]
    async fn pre_change_notice_notice_what_stays_lowercase_like_python() {
        let payload = json!({
            "name": "pre_change_notice",
            "arguments": {
                "action_type": "edit",
                "file_path": "task.md",
                "reason": "phase1",
                "expected_outcome": "stable contract",
                "risk_or_rollback": "revert startup path"
            }
        });
        let req = http::Request::builder()
            .method("POST")
            .uri("/tools/call")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let (status, _headers, json) = call(build_router(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["result"]["notice"]["what"], "edit task.md");
        assert_eq!(json["result"]["requires_approval"], true);
    }

    #[tokio::test]
    async fn registry_reports_tool_counts() {
        let req = http::Request::builder()
            .uri("/registry")
            .body(Body::empty())
            .unwrap();
        let (status, _headers, json) = call(build_router(), req).await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(json["ok"], true);
        assert_eq!(json["counts"]["tools"], 12);
        assert!(json["tools"].as_array().unwrap().len() >= 12);
    }

    #[tokio::test]
    async fn sse_endpoint_returns_event_stream_content_type() {
        let req = http::Request::builder()
            .uri("/sse")
            .body(Body::empty())
            .unwrap();
        let app = build_router();
        let resp = ServiceExt::<http::Request<Body>>::oneshot(app, req)
            .await
            .unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(content_type.contains("text/event-stream"));
    }
}
