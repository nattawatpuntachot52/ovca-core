"""
Policy gate helpers for agent task runtime code.

This module is a thin adapter over scripts.mcp.policy_tools_server. It keeps
runtime callers independent from the HTTP/SSE policy server.
"""
from __future__ import annotations

import inspect
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.mcp.policy_tools_server import (
    analytical_frame,
    business_story,
    certainty_zone,
    claim_tag,
    cognitive_route,
    dispatch_blocker_check,
    drift_check,
    leadership_alignment,
    people_execution_plan,
    plan_before_dispatch,
    sati_check,
    storyselling_pitch,
    strategy_review,
    support_disclose,
    temporal_gate,
)

ROOT = Path(__file__).parent.parent.parent
_configured_log = os.environ.get("OVCA_POLICY_GATE_LOG", "").strip()
POLICY_GATE_LOG: Path | None = Path(_configured_log) if _configured_log else None


def _shorten(value: object, limit: int = 500) -> object:
    if isinstance(value, dict):
        return {str(k): _shorten(v, limit=limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_shorten(item, limit=limit) for item in value[:20]]
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "..."
    return value


def _caller_name() -> str:
    try:
        frame = inspect.currentframe()
        caller = frame.f_back.f_back if frame and frame.f_back else None  # type: ignore[union-attr]
        if caller is None:
            return ""
        module = caller.f_globals.get("__name__", "")
        return f"{module}.{caller.f_code.co_name}".strip(".")
    except Exception:
        return ""


def _log_gate(tool: str, input_payload: dict[str, Any], result: dict[str, Any]) -> None:
    if POLICY_GATE_LOG is None:
        return
    try:
        POLICY_GATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "input_summary": _shorten(input_payload),
            "result_summary": _shorten(result),
            "caller": _caller_name(),
        }
        with POLICY_GATE_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        return


def _run(tool: str, input_payload: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    _log_gate(tool, input_payload, result)
    return result


def run_sati(action: str, context: str = "") -> dict[str, Any]:
    payload = {"action": action, "context": context}
    return _run("sati_check", payload, sati_check(action, context))


def gate_temporal_claim(
    claim: str,
    claim_type: str = "causal",
    evidence: str | None = None,
) -> dict[str, Any]:
    payload = {"claim": claim, "claim_type": claim_type, "evidence_source": evidence}
    return _run("temporal_gate", payload, temporal_gate(claim, claim_type, evidence))


def tag_claim(claim: str, basis: str | None = None) -> dict[str, Any]:
    payload = {"claim": claim, "basis": basis}
    return _run("claim_tag", payload, claim_tag(claim, basis))


def check_drift(reasoning: str, action: str | None = None) -> dict[str, Any]:
    payload = {"reasoning_snippet": reasoning, "proposed_action": action}
    return _run("drift_check", payload, drift_check(reasoning, action))


def check_confidence(confidence: float, context: str = "") -> dict[str, Any]:
    payload = {"confidence": confidence, "context": context}
    return _run("certainty_zone", payload, certainty_zone(confidence, context))


def check_support(claim: str, evidence_items: list[str] | None = None) -> dict[str, Any]:
    payload = {"claim": claim, "evidence_items": evidence_items or []}
    return _run("support_disclose", payload, support_disclose(claim, evidence_items))


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    payload = {"plan": dict(plan or {})}
    return _run("plan_before_dispatch", payload, plan_before_dispatch(payload["plan"]))


def validate_dispatch_blocker(blocker_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(blocker_input or {})
    result = dispatch_blocker_check(
        task_ref=payload.get("task_ref"),
        checklist_ref=payload.get("checklist_ref"),
        section_ref=payload.get("section_ref"),
        objective=payload.get("objective"),
        acceptance_ref=payload.get("acceptance_ref"),
        verification_ref=payload.get("verification_ref"),
        writable_scope=payload.get("writable_scope"),
        dispatch_mode=payload.get("dispatch_mode"),
        stop_if_missing=bool(payload.get("stop_if_missing", True)),
    )
    return _run("dispatch_blocker_check", payload, result)


def route_cognitive_request(
    owner_request: str,
    context: str = "",
    risk_level: str = "low",
    system_impact: bool = False,
) -> dict[str, Any]:
    payload = {
        "owner_request": owner_request,
        "context": context,
        "risk_level": risk_level,
        "system_impact": system_impact,
    }
    return _run("cognitive_route", payload, cognitive_route(owner_request, context, risk_level, system_impact))


def frame_analysis(frame_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(frame_input or {})
    result = analytical_frame(
        observed=payload.get("observed"),
        inferred=payload.get("inferred"),
        assumed=payload.get("assumed"),
        unknown=payload.get("unknown"),
        risk=payload.get("risk"),
        evidence_needed=payload.get("evidence_needed"),
        decision_enabled=payload.get("decision_enabled", ""),
        next_action=payload.get("next_action", ""),
    )
    return _run("analytical_frame", payload, result)


def review_strategy(review_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(review_input or {})
    result = strategy_review(
        objective=payload.get("objective", ""),
        current_bottleneck=payload.get("current_bottleneck", ""),
        options=payload.get("options"),
        tradeoffs=payload.get("tradeoffs"),
        leverage=payload.get("leverage"),
        non_goals=payload.get("non_goals"),
        decision_criteria=payload.get("decision_criteria"),
        recommended_decision=payload.get("recommended_decision", ""),
        next_action=payload.get("next_action", ""),
    )
    return _run("strategy_review", payload, result)


def build_business_story(story_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(story_input or {})
    result = business_story(
        payload.get("audience", ""),
        payload.get("context", ""),
        payload.get("tension", ""),
        payload.get("insight", ""),
        payload.get("choice", ""),
        payload.get("action", ""),
        payload.get("result", ""),
    )
    return _run("business_story", payload, result)


def build_storyselling_pitch(pitch_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(pitch_input or {})
    result = storyselling_pitch(
        payload.get("audience", ""),
        payload.get("pain", ""),
        payload.get("cost_of_inaction", ""),
        payload.get("new_belief", ""),
        payload.get("proof"),
        payload.get("offer", ""),
        payload.get("next_step", ""),
        payload.get("objection_risks"),
    )
    return _run("storyselling_pitch", payload, result)


def plan_people_execution(plan_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(plan_input or {})
    result = people_execution_plan(
        payload.get("objective", ""),
        payload.get("owner", ""),
        payload.get("scope_include"),
        payload.get("scope_exclude"),
        payload.get("acceptance_criteria"),
        payload.get("verification"),
        payload.get("cadence", ""),
        payload.get("decision_rights", ""),
        payload.get("risks"),
        payload.get("handoff_artifacts"),
    )
    return _run("people_execution_plan", payload, result)


def align_leadership(alignment_input: dict[str, Any]) -> dict[str, Any]:
    payload = dict(alignment_input or {})
    result = leadership_alignment(
        payload.get("why_this_matters", ""),
        payload.get("direction", ""),
        payload.get("principles"),
        payload.get("non_negotiables"),
        payload.get("what_good_looks_like"),
        payload.get("roles"),
        payload.get("learning_loop", ""),
        payload.get("next_decision", ""),
    )
    return _run("leadership_alignment", payload, result)
