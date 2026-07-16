"""
Policy Tools Server — Coordinator Governance Toolkit
Implements policy tools as pure logic plus MCP-registered tools.

Policy source: memory/oracle_coordinator_front_door_constitution.md
Spec:          docs/policy_tools_spec.md
"""

from __future__ import annotations

from typing import Any

# ─── Pure-logic implementations (no I/O, no LLM) ─────────────────────────────


def _clean_str(value: Any) -> str:
    return str(value or "").strip()


def _clean_list(value: list[str] | tuple[str, ...] | None) -> list[str]:
    return [str(item).strip() for item in (value or []) if str(item or "").strip()]


# ── Tier 1 ────────────────────────────────────────────────────────────────────

def sati_check(action: str, context: str = "") -> dict[str, Any]:
    """P1/P2/P3 — 3 คำถามก่อนทุก action"""
    action = action.strip()
    p1 = action if action else None
    p2 = context.strip() if context and context.strip() else None
    p3_tag = "assumed" if not context else "inferred"
    p3 = f"[{p3_tag}] ผลที่ตามมายังไม่ verify — ต้องตรวจก่อนดำเนินการ"

    proceed = bool(p1 and p2)
    stop_reason = None
    if not p1:
        stop_reason = "P1 ยังไม่ชัด — ระบุ action ก่อน"
    elif not p2:
        stop_reason = "P2 ยังตอบไม่ได้ — ต้องถาม owner ว่า authority คืออะไร"

    return {
        "p1": p1,
        "p2": p2,
        "p3": p3,
        "proceed": proceed,
        "stop_reason": stop_reason,
    }


_TEMPORAL_KEYWORDS = {
    "ทำไม", "เมื่อไหร่", "root cause", "timing", "background task",
    "failed", "ไม่แจ้งเตือน", "race condition", "timeout", "ก่อน", "หลัง",
    "พร้อมกัน", "why", "when", "because", "caused by", "due to",
}

_CLAIM_TYPES = {"temporal", "causal", "numeric", "operational"}


def temporal_gate(
    claim: str,
    claim_type: str = "causal",
    evidence_source: str | None = None,
) -> dict[str, Any]:
    """Temporal Claim Gate — บล็อก hallucination ด้าน timing/causal"""
    claim = claim.strip()
    claim_type = claim_type.strip().lower()
    if claim_type not in _CLAIM_TYPES:
        claim_type = "causal"

    has_evidence = bool(evidence_source and evidence_source.strip())
    verdict = "allow" if has_evidence else "block"
    cite = evidence_source.strip() if has_evidence else None

    safe_response = None
    if not has_evidence:
        # Detect what evidence is needed
        keywords_found = [k for k in _TEMPORAL_KEYWORDS if k.lower() in claim.lower()]
        hint = f"คำที่ trigger: {keywords_found}" if keywords_found else "ต้องมี log/timestamp/tool result รองรับ"
        safe_response = f"ยังยืนยันไม่ได้ค่ะ ต้องดู evidence ก่อน ({hint})"

    return {
        "has_evidence": has_evidence,
        "verdict": verdict,
        "cite": cite,
        "safe_response": safe_response,
    }


def support_disclose(
    claim: str,
    evidence_items: list[str] | None = None,
) -> dict[str, Any]:
    """Support Sufficiency Disclosure — วัดระดับ support ของ claim"""
    evidence_items = [e.strip() for e in (evidence_items or []) if e and e.strip()]
    n = len(evidence_items)

    if n == 0:
        level = "no_support"
        label = "ยังยืนยันไม่ได้"
        can_assert = False
        disclosure = f"ยังยืนยันไม่ได้ค่ะ ไม่มี evidence รองรับ claim: '{claim}'"
    elif n <= 2:
        level = "low_support"
        label = "support ต่ำ — หลักฐานยังน้อย"
        can_assert = False
        disclosure = f"support ต่ำค่ะ มีแค่ {n} evidence item — ยังเป็นข้อสรุปชั่วคราว"
    else:
        level = "supported"
        label = "supported"
        can_assert = True
        disclosure = f"supported — มี {n} evidence items รองรับ"

    return {
        "level": level,
        "label": label,
        "can_assert": can_assert,
        "disclosure_text": disclosure,
    }


_ZONE_TABLE = [
    (0.00, 0.40, "C0", "[0.00–0.40)", "ไม่เสนอ — แจ้ง owner ว่าต้องการข้อมูลอะไรเพิ่ม", False),
    (0.40, 0.60, "C1", "[0.40–0.60)", "เสนอได้ แต่ต้องบอกชัดว่ายังต้องการหลักฐานเพิ่ม", True),
    (0.60, 0.75, "C2", "[0.60–0.75)", "เสนอพร้อม flag ให้ owner ตรวจก่อน dispatch", True),
    (0.75, 0.90, "C3", "[0.75–0.90)", "เสนอ + record decision + proceed after approval", True),
    (0.90, 1.01, "C4", "[0.90–1.00]", "เสนอพร้อม dispatch-ready plan", True),
]


def certainty_zone(confidence: float, context: str = "") -> dict[str, Any]:
    """Certainty Zone C0–C4 — tag zone ก่อน recommend"""
    confidence = max(0.0, min(1.0, float(confidence)))
    for lo, hi, zone, rng, action, can_proceed in _ZONE_TABLE:
        if lo <= confidence < hi:
            return {
                "zone": zone,
                "range": rng,
                "action_required": action,
                "can_proceed": can_proceed,
                "confidence": confidence,
            }
    # fallback (confidence == 1.0 hits last bucket)
    return {
        "zone": "C4",
        "range": "[0.90–1.00]",
        "action_required": "เสนอพร้อม dispatch-ready plan",
        "can_proceed": True,
        "confidence": confidence,
    }


_VALID_TAGS = {"observed", "inferred", "assumed", "unknown"}


def claim_tag(claim: str, basis: str | None = None) -> dict[str, Any]:
    """Reality-First Claim Tagging — tag ทุก significant claim"""
    basis = (basis or "").strip()
    claim = claim.strip()

    if not basis:
        tag = "unknown"
        explanation = "ไม่มี basis ระบุ — ยังไม่รู้และต้องบอกตรง ๆ"
    elif any(w in basis.lower() for w in ("log", "file", "test", "output", "result", "timestamp")):
        tag = "observed"
        explanation = f"มี direct evidence: {basis}"
    elif any(w in basis.lower() for w in ("logic", "เพราะ", "น่าจะ", "therefore", "infer", "conclude")):
        tag = "inferred"
        explanation = f"สรุปจาก logic แต่ยังไม่ verify ตรง: {basis}"
    elif any(w in basis.lower() for w in ("assume", "สมมติ", "probably", "likely", "คิดว่า")):
        tag = "assumed"
        explanation = f"สมมติฐานที่ยังไม่ยืนยัน: {basis}"
    else:
        tag = "inferred"
        explanation = f"basis ไม่ชัดพอที่จะ verify ตรง: {basis}"

    return {
        "tag": tag,
        "explanation": explanation,
        "display_label": f"[{tag}]",
    }


_DRIFT_BUGS = {
    "sycophancy": {
        "signals": ["ขอโทษ", "sorry", "apologize", "โทษ", "ผิดพลาดที่"],
        "description": "เริ่มด้วย apology โดยไม่มี analysis",
        "severity": "stop",
    },
    "self_created_plan": {
        "signals": ["จะทำเลย", "implement ทันที", "ลงมือ", "เริ่มได้เลย", "จัดการให้เลย"],
        "description": "propose action โดยไม่มี authority_ref",
        "severity": "stop",
    },
    "recency_bias": {
        "signals": ["เมื่อกี้บอกว่า", "จากที่พึ่งพูด", "ข้อความล่าสุด", "เพิ่งบอก"],
        "description": "override decision เดิมเพราะข้อความล่าสุด",
        "severity": "warn",
    },
    "performance_bias": {
        "signals": ["แก้โค้ด", "edit file", "แก้ไฟล์", "fix the code", "change line"],
        "description": "เสนอ code change ก่อนเข้าใจ root cause",
        "severity": "warn",
    },
    "skip_foundation": {
        "signals": ["ข้ามไป", "skip", "ทำ step ถัดไป", "next task"],
        "description": "dispatch งาน N+1 ก่อน N เสร็จ",
        "severity": "warn",
    },
    "lazy_reading": {
        "signals": ["น่าจะเป็น", "คงจะ", "probably the same", "ตามเดิม"],
        "description": "หลุด critical constraint ใน task/spec",
        "severity": "warn",
    },
}


def drift_check(
    reasoning_snippet: str,
    proposed_action: str | None = None,
) -> dict[str, Any]:
    """Anti-Drift Self-Check — detect reasoning bugs ก่อนส่ง owner"""
    text = (reasoning_snippet + " " + (proposed_action or "")).lower()
    bugs_detected: list[dict[str, str]] = []

    for bug_name, meta in _DRIFT_BUGS.items():
        for signal in meta["signals"]:
            if signal.lower() in text:
                bugs_detected.append({
                    "bug": bug_name,
                    "signal": f"พบ '{signal}' ใน reasoning",
                    "description": meta["description"],
                    "severity": meta["severity"],
                })
                break  # one match per bug type is enough

    has_stop = any(b["severity"] == "stop" for b in bugs_detected)
    return {
        "bugs_detected": bugs_detected,
        "clean": len(bugs_detected) == 0,
        "stop": has_stop,
    }


# ── Tier 2 ────────────────────────────────────────────────────────────────────

def scamper_gate(
    base_object: str,
    improvement_target: str,
    context: str = "",
) -> dict[str, Any]:
    """SCAMPER Gate — structured ideation ก่อน redesign / recurring fix"""
    base_object = base_object.strip()
    improvement_target = improvement_target.strip()

    # Template scaffold — caller (or LLM) fills in ideas; we validate structure
    output: dict[str, Any] = {
        "base_object": base_object,
        "improvement_target": improvement_target,
        "ideas": {
            "substitute": [],
            "combine": [],
            "adapt": [],
            "modify": [],
            "put_to_other_use": [],
            "eliminate": [],   # mandatory ≥1
            "reverse": [],     # mandatory ≥1
        },
        "blind_spot": "",
        "guardrail": "",
        "smallest_next_experiment": "",
        "ready": False,
        "missing": [],
    }

    # Validate minimum pass
    missing: list[str] = []
    if not output["ideas"]["eliminate"]:
        missing.append("eliminate (≥1 idea required)")
    if not output["ideas"]["reverse"]:
        missing.append("reverse (≥1 idea required)")
    if not output["blind_spot"]:
        missing.append("blind_spot")
    if not output["smallest_next_experiment"]:
        missing.append("smallest_next_experiment")

    output["missing"] = missing
    output["ready"] = len(missing) == 0
    return output


def scamper_fill(
    base_object: str,
    improvement_target: str,
    eliminate: list[str],
    reverse: list[str],
    blind_spot: str,
    smallest_next_experiment: str,
    substitute: list[str] | None = None,
    combine: list[str] | None = None,
    adapt: list[str] | None = None,
    modify: list[str] | None = None,
    put_to_other_use: list[str] | None = None,
    guardrail: str = "",
) -> dict[str, Any]:
    """SCAMPER Gate (filled) — validate completed SCAMPER pass"""
    missing: list[str] = []
    if not eliminate:
        missing.append("eliminate")
    if not reverse:
        missing.append("reverse")
    if not blind_spot.strip():
        missing.append("blind_spot")
    if not smallest_next_experiment.strip():
        missing.append("smallest_next_experiment")

    return {
        "base_object": base_object,
        "improvement_target": improvement_target,
        "ideas": {
            "substitute": substitute or [],
            "combine": combine or [],
            "adapt": adapt or [],
            "modify": modify or [],
            "put_to_other_use": put_to_other_use or [],
            "eliminate": eliminate,
            "reverse": reverse,
        },
        "blind_spot": blind_spot,
        "guardrail": guardrail,
        "smallest_next_experiment": smallest_next_experiment,
        "missing": missing,
        "ready": len(missing) == 0,
    }


_BOTTLENECK_AREAS = {"lead", "sales", "delivery", "profit"}


def business_gate(
    recommendation: str,
    domain: str = "other",
    bottleneck_evidence: str | None = None,
) -> dict[str, Any]:
    """Business OS Gate — diagnose bottleneck ก่อน recommend strategy"""
    recommendation = recommendation.strip()
    domain = domain.strip().lower()
    has_evidence = bool(bottleneck_evidence and bottleneck_evidence.strip())

    bottleneck_area = domain if domain in _BOTTLENECK_AREAS else "unknown"
    bottleneck_diagnosed = has_evidence and bottleneck_area != "unknown"

    kpi_anchor = None
    if bottleneck_diagnosed:
        kpi_anchor = {
            "do_x": recommendation,
            "measure_y": f"metric ที่วัดผล {bottleneck_area}",
            "target_z": "ระบุเป้าหมายเป็นตัวเลขชัดเจน",
        }

    can_proceed = bottleneck_diagnosed
    block_reason = None
    if not bottleneck_diagnosed:
        if bottleneck_area == "unknown":
            block_reason = "ยังไม่ diagnose ว่าติดที่ lead/sales/delivery/profit — ต้องหา evidence ก่อน"
        else:
            block_reason = f"domain='{domain}' แต่ยังไม่มี bottleneck_evidence — ต้องระบุก่อน"

    return {
        "bottleneck_diagnosed": bottleneck_diagnosed,
        "bottleneck_area": bottleneck_area,
        "bottleneck_evidence": bottleneck_evidence,
        "kpi_anchor": kpi_anchor,
        "can_proceed": can_proceed,
        "block_reason": block_reason,
    }


def decision_format(
    topic: str,
    options_considered: list[str] | None = None,
    what_to_do_now: str = "",
    what_not_to_do: str = "",
    what_to_revisit_when: str = "",
    metric_that_proves_it_worked: str = "",
    confidence: float = 0.5,
) -> dict[str, Any]:
    """Decision Discipline — CEO output format validator"""
    options_considered = options_considered or []
    missing: list[str] = []
    if not what_to_do_now.strip():
        missing.append("what_to_do_NOW")
    if not what_not_to_do.strip():
        missing.append("what_NOT_to_do")
    if not what_to_revisit_when.strip():
        missing.append("what_to_revisit_when")
    if not metric_that_proves_it_worked.strip():
        missing.append("metric_that_proves_it_worked")

    zone_result = certainty_zone(confidence)

    return {
        "topic": topic,
        "options_considered": options_considered,
        "what_to_do_NOW": what_to_do_now,
        "what_NOT_to_do": what_not_to_do,
        "what_to_revisit_when": what_to_revisit_when,
        "metric_that_proves_it_worked": metric_that_proves_it_worked,
        "certainty_zone": zone_result["zone"],
        "missing": missing,
        "complete": len(missing) == 0,
    }


# ── Tier 3 ────────────────────────────────────────────────────────────────────

_DESTRUCTIVE_ACTIONS = {"delete", "move", "overwrite"}


def pre_change_notice(
    action_type: str,
    file_path: str,
    reason: str,
    expected_outcome: str,
    risk_or_rollback: str,
) -> dict[str, Any]:
    """Pre-Change Notice — notice ก่อนแตะ file system"""
    action_type = action_type.strip().lower()
    file_path = file_path.strip()
    reason = reason.strip()
    expected_outcome = expected_outcome.strip()
    risk_or_rollback = risk_or_rollback.strip()

    missing: list[str] = []
    if not reason:
        missing.append("reason (why / authority)")
    if not expected_outcome:
        missing.append("expected_outcome")
    if not risk_or_rollback:
        missing.append("risk_or_rollback")

    requires_approval = action_type in _DESTRUCTIVE_ACTIONS or not missing
    display = (
        f"⚠️ [{action_type.upper()}] {file_path}\n"
        f"  ทำไม: {reason}\n"
        f"  ผลที่คาด: {expected_outcome}\n"
        f"  Risk/Rollback: {risk_or_rollback}"
    )
    if requires_approval and action_type in _DESTRUCTIVE_ACTIONS:
        display = "⛔ " + display + "\n  → ต้องขอ approval ก่อน"

    return {
        "notice": {
            "what": f"{action_type} {file_path}",
            "why": reason,
            "outcome": expected_outcome,
            "downside": risk_or_rollback,
        },
        "requires_approval": requires_approval,
        "display_text": display,
        "missing": missing,
        "valid": len(missing) == 0,
    }


_REQUIRED_PLAN_FIELDS = ["objective", "steps", "files_affected", "risks", "acceptance_criteria"]


def _list_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, list):
        return len(value) == 0
    if isinstance(value, str):
        return not value.strip()
    return False


def plan_before_dispatch(plan: dict[str, Any]) -> dict[str, Any]:
    """Plan Before Dispatch gate — validate plan ก่อน dispatch"""
    missing: list[str] = []
    for field in _REQUIRED_PLAN_FIELDS:
        val = plan.get(field)
        if _list_missing(val):
            missing.append(field)

    batch = plan.get("autonomous_batch")
    if isinstance(batch, dict) and bool(batch.get("enabled")):
        scope = batch.get("scope") if isinstance(batch.get("scope"), dict) else {}
        batch_checks = {
            "autonomous_batch.authority": batch.get("authority"),
            "autonomous_batch.scope.include": scope.get("include"),
            "autonomous_batch.scope.exclude": scope.get("exclude"),
            "autonomous_batch.stop_conditions": batch.get("stop_conditions"),
            "autonomous_batch.commit_policy": batch.get("commit_policy"),
        }
        for field, value in batch_checks.items():
            if _list_missing(value):
                missing.append(field)

    can_dispatch = len(missing) == 0
    return {
        "valid": can_dispatch,
        "missing_fields": missing,
        "can_dispatch": can_dispatch,
        "block_reason": (
            f"แผนยังไม่ครบ — ต้องระบุ: {', '.join(missing)} ก่อน"
            if missing else None
        ),
    }


_REQUIRED_BLOCKER_FIELDS = [
    "task_ref", "checklist_ref", "section_ref", "objective",
    "acceptance_ref", "verification_ref", "dispatch_mode",
]


def dispatch_blocker_check(
    task_ref: str | None = None,
    checklist_ref: str | None = None,
    section_ref: str | None = None,
    objective: str | None = None,
    acceptance_ref: str | None = None,
    verification_ref: str | None = None,
    writable_scope: list[str] | None = None,
    dispatch_mode: str | None = None,
    stop_if_missing: bool = True,
) -> dict[str, Any]:
    """Dispatch Blocker Gate — hard gate ก่อน scaffold/dispatch"""
    inputs = {
        "task_ref": task_ref,
        "checklist_ref": checklist_ref,
        "section_ref": section_ref,
        "objective": objective,
        "acceptance_ref": acceptance_ref,
        "verification_ref": verification_ref,
        "dispatch_mode": dispatch_mode,
    }

    missing: list[str] = []
    placeholder: list[str] = []
    _placeholder_tokens = {"TODO", "PLACEHOLDER", "TBD", "FILL", "???"}

    for field, val in inputs.items():
        if not val or (isinstance(val, str) and not val.strip()):
            missing.append(field)
        elif isinstance(val, str) and any(t in val.upper() for t in _placeholder_tokens):
            placeholder.append(field)

    writable_scope = writable_scope or []
    if not writable_scope:
        missing.append("writable_scope")

    ready = len(missing) == 0 and len(placeholder) == 0
    verdict = "PASS" if ready else "FAIL"
    fail_reason = None
    if not ready:
        parts = []
        if missing:
            parts.append(f"missing {len(missing)} fields: {', '.join(missing)}")
        if placeholder:
            parts.append(f"placeholder in: {', '.join(placeholder)}")
        if stop_if_missing:
            parts.insert(0, "stop_if_missing=true —")
        fail_reason = " ".join(parts)

    return {
        "ready": ready,
        "missing_fields": missing,
        "placeholder_fields": placeholder,
        "verdict": verdict,
        "fail_reason": fail_reason,
    }


# ─── Cognitive Leadership advisory tools ─────────────────────────────────────

_COGNITIVE_ROUTES = {
    "literal",
    "analytical",
    "strategic",
    "scamper",
    "story",
    "storyselling",
    "people_execution",
    "leadership_alignment",
}


def cognitive_route(
    owner_request: str,
    context: str = "",
    risk_level: str = "low",
    system_impact: bool = False,
) -> dict[str, Any]:
    """Route a request to the lightest sufficient thinking mode."""
    text = f"{owner_request} {context}".lower()
    risk = _clean_str(risk_level).lower() or "low"
    if risk not in {"low", "medium", "high"}:
        risk = "medium"

    route = "literal"
    required_tools: list[str] = []
    gate_level = "none"
    reason = "small literal request"

    def has_any(words: tuple[str, ...]) -> bool:
        return any(word in text for word in words)

    if has_any(("redesign", "rethink", "scamper", "simplify", "workflow", "policy", "recurring", "failure", "blind spot")):
        route = "scamper"
        required_tools = ["scamper_fill"]
        gate_level = "hard"
        reason = "redesign or option-generation request"
    elif has_any(("dispatch", "agent", "people", "team", "owner", "cadence", "acceptance criteria", "handoff", "execution plan")):
        route = "people_execution"
        required_tools = ["people_execution_plan", "plan_before_dispatch", "dispatch_blocker_check"]
        gate_level = "hard"
        reason = "people or agent execution request"
    elif has_any(("leadership", "alignment", "principle", "direction", "non-negotiable", "vision")):
        route = "leadership_alignment"
        required_tools = ["leadership_alignment"]
        gate_level = "soft" if not system_impact else "hard"
        reason = "alignment or leadership request"
    elif has_any(("storyselling", "sell", "sales", "fundraising", "fundraise", "investor", "recruit", "offer", "pitch")):
        route = "storyselling"
        required_tools = ["storyselling_pitch"]
        gate_level = "advisory"
        reason = "decision/action narrative request"
    elif has_any(("story", "storytelling", "narrative", "positioning", "landing", "content")):
        route = "story"
        required_tools = ["business_story"]
        gate_level = "advisory"
        reason = "narrative clarity request"
    elif has_any(("strategy", "strategic", "roadmap", "prioritize", "resource", "business", "leverage", "option")):
        route = "strategic"
        required_tools = ["analytical_frame", "strategy_review", "business_gate"]
        gate_level = "soft"
        reason = "strategy or resource-allocation request"
    elif system_impact or risk == "high" or has_any(("recommend", "should", "analyze", "why", "root cause", "evidence", "decision")):
        route = "analytical"
        required_tools = ["analytical_frame", "claim_tag", "support_disclose"]
        gate_level = "soft"
        reason = "significant claim or recommendation request"

    return {
        "route": route,
        "required_tools": required_tools,
        "gate_level": gate_level,
        "reason": reason,
        "risk_level": risk,
        "system_impact": bool(system_impact),
    }


def analytical_frame(
    observed: list[str] | None = None,
    inferred: list[str] | None = None,
    assumed: list[str] | None = None,
    unknown: list[str] | None = None,
    risk: list[str] | None = None,
    evidence_needed: list[str] | None = None,
    decision_enabled: str = "",
    next_action: str = "",
) -> dict[str, Any]:
    """Evidence-first frame for significant claims or recommendations."""
    observed_items = _clean_list(observed)
    inferred_items = _clean_list(inferred)
    assumed_items = _clean_list(assumed)
    unknown_items = _clean_list(unknown)
    risk_items = _clean_list(risk)
    evidence_items = _clean_list(evidence_needed)
    decision = _clean_str(decision_enabled)
    action = _clean_str(next_action)

    missing: list[str] = []
    if not observed_items:
        missing.append("observed")
    if not action:
        missing.append("next_action")

    can_recommend = bool(observed_items and action)

    return {
        "observed": observed_items,
        "inferred": inferred_items,
        "assumed": assumed_items,
        "unknown": unknown_items,
        "risk": risk_items,
        "evidence_needed": evidence_items,
        "decision_enabled": decision,
        "next_action": action,
        "missing": missing,
        "can_recommend": can_recommend,
        "gate_level": "soft",
    }


def strategy_review(
    objective: str,
    current_bottleneck: str = "",
    options: list[str] | None = None,
    tradeoffs: list[str] | None = None,
    leverage: list[str] | None = None,
    non_goals: list[str] | None = None,
    decision_criteria: list[str] | None = None,
    recommended_decision: str = "",
    next_action: str = "",
) -> dict[str, Any]:
    """Strategy frame with options, tradeoffs, and decision criteria."""
    result = {
        "objective": _clean_str(objective),
        "current_bottleneck": _clean_str(current_bottleneck),
        "options": _clean_list(options),
        "tradeoffs": _clean_list(tradeoffs),
        "leverage": _clean_list(leverage),
        "non_goals": _clean_list(non_goals),
        "decision_criteria": _clean_list(decision_criteria),
        "recommended_decision": _clean_str(recommended_decision),
        "next_action": _clean_str(next_action),
    }
    missing = [
        field
        for field in ("objective", "options", "decision_criteria", "recommended_decision", "next_action")
        if _list_missing(result[field])
    ]
    result["missing"] = missing
    result["complete"] = len(missing) == 0
    result["gate_level"] = "soft"
    return result


def business_story(
    audience: str,
    context: str,
    tension: str,
    insight: str,
    choice: str,
    action: str,
    result: str,
) -> dict[str, Any]:
    """Business storytelling frame: context -> tension -> insight -> choice -> action -> result."""
    result_data = {
        "audience": _clean_str(audience),
        "context": _clean_str(context),
        "tension": _clean_str(tension),
        "insight": _clean_str(insight),
        "choice": _clean_str(choice),
        "action": _clean_str(action),
        "result": _clean_str(result),
    }
    missing = [field for field, value in result_data.items() if _list_missing(value)]
    result_data["missing"] = missing
    result_data["complete"] = len(missing) == 0
    result_data["gate_level"] = "advisory"
    return result_data


def storyselling_pitch(
    audience: str,
    pain: str,
    cost_of_inaction: str,
    new_belief: str,
    proof: list[str] | None,
    offer: str,
    next_step: str,
    objection_risks: list[str] | None = None,
) -> dict[str, Any]:
    """Storyselling frame for turning narrative into action."""
    result = {
        "audience": _clean_str(audience),
        "pain": _clean_str(pain),
        "cost_of_inaction": _clean_str(cost_of_inaction),
        "new_belief": _clean_str(new_belief),
        "proof": _clean_list(proof),
        "offer": _clean_str(offer),
        "next_step": _clean_str(next_step),
        "objection_risks": _clean_list(objection_risks),
    }
    missing = [
        field
        for field in ("audience", "pain", "cost_of_inaction", "new_belief", "proof", "offer", "next_step")
        if _list_missing(result[field])
    ]
    result["missing"] = missing
    result["complete"] = len(missing) == 0
    result["gate_level"] = "advisory"
    return result


def people_execution_plan(
    objective: str,
    owner: str,
    scope_include: list[str] | None,
    scope_exclude: list[str] | None,
    acceptance_criteria: list[str] | None,
    verification: list[str] | None,
    cadence: str,
    decision_rights: str,
    risks: list[str] | None,
    handoff_artifacts: list[str] | None,
) -> dict[str, Any]:
    """Execution plan for people or agents."""
    result = {
        "objective": _clean_str(objective),
        "owner": _clean_str(owner),
        "scope_include": _clean_list(scope_include),
        "scope_exclude": _clean_list(scope_exclude),
        "acceptance_criteria": _clean_list(acceptance_criteria),
        "verification": _clean_list(verification),
        "cadence": _clean_str(cadence),
        "decision_rights": _clean_str(decision_rights),
        "risks": _clean_list(risks),
        "handoff_artifacts": _clean_list(handoff_artifacts),
    }
    required = (
        "objective", "owner", "scope_include", "scope_exclude",
        "acceptance_criteria", "verification", "cadence",
        "decision_rights", "risks", "handoff_artifacts",
    )
    missing = [field for field in required if _list_missing(result[field])]
    result["missing"] = missing
    result["ready"] = len(missing) == 0
    result["gate_level"] = "hard"
    return result


def leadership_alignment(
    why_this_matters: str,
    direction: str,
    principles: list[str] | None,
    non_negotiables: list[str] | None,
    what_good_looks_like: list[str] | None,
    roles: list[str] | None,
    learning_loop: str,
    next_decision: str,
) -> dict[str, Any]:
    """Alignment frame for multi-person or multi-agent direction."""
    result = {
        "why_this_matters": _clean_str(why_this_matters),
        "direction": _clean_str(direction),
        "principles": _clean_list(principles),
        "non_negotiables": _clean_list(non_negotiables),
        "what_good_looks_like": _clean_list(what_good_looks_like),
        "roles": _clean_list(roles),
        "learning_loop": _clean_str(learning_loop),
        "next_decision": _clean_str(next_decision),
    }
    missing = [field for field, value in result.items() if _list_missing(value)]
    result["missing"] = missing
    result["complete"] = len(missing) == 0
    result["gate_level"] = "soft"
    return result


# ─── MCP Server registration ──────────────────────────────────────────────────

def build_server() -> Any:
    """Build and return configured MCPBaseServer with all policy tools registered."""
    try:
        from scripts.mcp.base_server import MCPBaseServer
    except ModuleNotFoundError:
        from base_server import MCPBaseServer  # type: ignore

    server = MCPBaseServer("oracle-policy-tools")

    # ── Tier 1 ──────────────────────────────────────────────────────────────

    @server.register_tool(
        "sati_check",
        "สัมปชัญญะ P1/P2/P3 — 3 คำถามก่อนทุก action ที่มีผลต่อระบบ",
        {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "action ที่กำลังจะทำ"},
                "context": {"type": "string", "description": "เหตุผลเบื้องต้น (optional)"},
            },
            "required": ["action"],
        },
    )
    def _sati_check(args: dict[str, Any]) -> dict[str, Any]:
        return sati_check(args["action"], args.get("context", ""))

    @server.register_tool(
        "temporal_gate",
        "Temporal Claim Gate — บล็อก causal/temporal claims ที่ไม่มี evidence",
        {
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "claim_type": {"type": "string", "enum": ["temporal", "causal", "numeric", "operational"]},
                "evidence_source": {"type": "string", "nullable": True},
            },
            "required": ["claim"],
        },
    )
    def _temporal_gate(args: dict[str, Any]) -> dict[str, Any]:
        return temporal_gate(
            args["claim"],
            args.get("claim_type", "causal"),
            args.get("evidence_source"),
        )

    @server.register_tool(
        "support_disclose",
        "Support Sufficiency Disclosure — วัดระดับ support ของ claim",
        {
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "evidence_items": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["claim"],
        },
    )
    def _support_disclose(args: dict[str, Any]) -> dict[str, Any]:
        return support_disclose(args["claim"], args.get("evidence_items"))

    @server.register_tool(
        "certainty_zone",
        "Certainty Zone C0–C4 — tag zone ก่อน recommend strategy/architecture",
        {
            "type": "object",
            "properties": {
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "context": {"type": "string"},
            },
            "required": ["confidence"],
        },
    )
    def _certainty_zone(args: dict[str, Any]) -> dict[str, Any]:
        return certainty_zone(args["confidence"], args.get("context", ""))

    @server.register_tool(
        "claim_tag",
        "Reality-First Claim Tagging — tag observed/inferred/assumed/unknown",
        {
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "basis": {"type": "string", "nullable": True},
            },
            "required": ["claim"],
        },
    )
    def _claim_tag(args: dict[str, Any]) -> dict[str, Any]:
        return claim_tag(args["claim"], args.get("basis"))

    @server.register_tool(
        "drift_check",
        "Anti-Drift Self-Check — detect reasoning bugs (sycophancy, recency_bias, etc.)",
        {
            "type": "object",
            "properties": {
                "reasoning_snippet": {"type": "string"},
                "proposed_action": {"type": "string", "nullable": True},
            },
            "required": ["reasoning_snippet"],
        },
    )
    def _drift_check(args: dict[str, Any]) -> dict[str, Any]:
        return drift_check(args["reasoning_snippet"], args.get("proposed_action"))

    # ── Tier 2 ──────────────────────────────────────────────────────────────

    @server.register_tool(
        "scamper_fill",
        "SCAMPER Gate (filled) — validate completed SCAMPER pass ก่อน redesign",
        {
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
                "guardrail": {"type": "string"},
            },
            "required": ["base_object", "improvement_target", "eliminate", "reverse", "blind_spot", "smallest_next_experiment"],
        },
    )
    def _scamper_fill(args: dict[str, Any]) -> dict[str, Any]:
        return scamper_fill(
            args["base_object"],
            args["improvement_target"],
            args["eliminate"],
            args["reverse"],
            args["blind_spot"],
            args["smallest_next_experiment"],
            substitute=args.get("substitute"),
            combine=args.get("combine"),
            adapt=args.get("adapt"),
            modify=args.get("modify"),
            put_to_other_use=args.get("put_to_other_use"),
            guardrail=args.get("guardrail", ""),
        )

    @server.register_tool(
        "business_gate",
        "Business OS Gate — diagnose bottleneck ก่อน recommend strategy/revenue",
        {
            "type": "object",
            "properties": {
                "recommendation": {"type": "string"},
                "domain": {"type": "string", "enum": ["lead", "sales", "delivery", "profit", "other"]},
                "bottleneck_evidence": {"type": "string", "nullable": True},
            },
            "required": ["recommendation"],
        },
    )
    def _business_gate(args: dict[str, Any]) -> dict[str, Any]:
        return business_gate(
            args["recommendation"],
            args.get("domain", "other"),
            args.get("bottleneck_evidence"),
        )

    @server.register_tool(
        "decision_format",
        "Decision Discipline — CEO output format validator (what_now/not/when/metric)",
        {
            "type": "object",
            "properties": {
                "topic": {"type": "string"},
                "options_considered": {"type": "array", "items": {"type": "string"}},
                "what_to_do_now": {"type": "string"},
                "what_not_to_do": {"type": "string"},
                "what_to_revisit_when": {"type": "string"},
                "metric_that_proves_it_worked": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["topic"],
        },
    )
    def _decision_format(args: dict[str, Any]) -> dict[str, Any]:
        return decision_format(
            args["topic"],
            args.get("options_considered"),
            args.get("what_to_do_now", ""),
            args.get("what_not_to_do", ""),
            args.get("what_to_revisit_when", ""),
            args.get("metric_that_proves_it_worked", ""),
            args.get("confidence", 0.5),
        )

    # ── Tier 3 ──────────────────────────────────────────────────────────────

    @server.register_tool(
        "cognitive_route",
        "Cognitive Leadership router - choose the lightest sufficient thinking mode",
        {
            "type": "object",
            "properties": {
                "owner_request": {"type": "string"},
                "context": {"type": "string"},
                "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
                "system_impact": {"type": "boolean"},
            },
            "required": ["owner_request"],
        },
    )
    def _cognitive_route(args: dict[str, Any]) -> dict[str, Any]:
        return cognitive_route(
            args["owner_request"],
            args.get("context", ""),
            args.get("risk_level", "low"),
            bool(args.get("system_impact", False)),
        )

    @server.register_tool(
        "analytical_frame",
        "Cognitive Leadership analytical frame - observed/inferred/assumed/unknown",
        {
            "type": "object",
            "properties": {
                "observed": {"type": "array", "items": {"type": "string"}},
                "inferred": {"type": "array", "items": {"type": "string"}},
                "assumed": {"type": "array", "items": {"type": "string"}},
                "unknown": {"type": "array", "items": {"type": "string"}},
                "risk": {"type": "array", "items": {"type": "string"}},
                "evidence_needed": {"type": "array", "items": {"type": "string"}},
                "decision_enabled": {"type": "string"},
                "next_action": {"type": "string"},
            },
        },
    )
    def _analytical_frame(args: dict[str, Any]) -> dict[str, Any]:
        return analytical_frame(
            observed=args.get("observed"),
            inferred=args.get("inferred"),
            assumed=args.get("assumed"),
            unknown=args.get("unknown"),
            risk=args.get("risk"),
            evidence_needed=args.get("evidence_needed"),
            decision_enabled=args.get("decision_enabled", ""),
            next_action=args.get("next_action", ""),
        )

    @server.register_tool(
        "strategy_review",
        "Cognitive Leadership strategy review - options, tradeoffs, leverage, decision",
        {
            "type": "object",
            "properties": {
                "objective": {"type": "string"},
                "current_bottleneck": {"type": "string"},
                "options": {"type": "array", "items": {"type": "string"}},
                "tradeoffs": {"type": "array", "items": {"type": "string"}},
                "leverage": {"type": "array", "items": {"type": "string"}},
                "non_goals": {"type": "array", "items": {"type": "string"}},
                "decision_criteria": {"type": "array", "items": {"type": "string"}},
                "recommended_decision": {"type": "string"},
                "next_action": {"type": "string"},
            },
            "required": ["objective"],
        },
    )
    def _strategy_review(args: dict[str, Any]) -> dict[str, Any]:
        return strategy_review(
            objective=args["objective"],
            current_bottleneck=args.get("current_bottleneck", ""),
            options=args.get("options"),
            tradeoffs=args.get("tradeoffs"),
            leverage=args.get("leverage"),
            non_goals=args.get("non_goals"),
            decision_criteria=args.get("decision_criteria"),
            recommended_decision=args.get("recommended_decision", ""),
            next_action=args.get("next_action", ""),
        )

    @server.register_tool(
        "business_story",
        "Cognitive Leadership business story - context, tension, insight, choice, action, result",
        {
            "type": "object",
            "properties": {
                "audience": {"type": "string"},
                "context": {"type": "string"},
                "tension": {"type": "string"},
                "insight": {"type": "string"},
                "choice": {"type": "string"},
                "action": {"type": "string"},
                "result": {"type": "string"},
            },
            "required": ["audience", "context", "tension", "insight", "choice", "action", "result"],
        },
    )
    def _business_story(args: dict[str, Any]) -> dict[str, Any]:
        return business_story(
            args["audience"],
            args["context"],
            args["tension"],
            args["insight"],
            args["choice"],
            args["action"],
            args["result"],
        )

    @server.register_tool(
        "storyselling_pitch",
        "Cognitive Leadership storyselling pitch - pain, proof, offer, next step",
        {
            "type": "object",
            "properties": {
                "audience": {"type": "string"},
                "pain": {"type": "string"},
                "cost_of_inaction": {"type": "string"},
                "new_belief": {"type": "string"},
                "proof": {"type": "array", "items": {"type": "string"}},
                "offer": {"type": "string"},
                "next_step": {"type": "string"},
                "objection_risks": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["audience", "pain", "cost_of_inaction", "new_belief", "proof", "offer", "next_step"],
        },
    )
    def _storyselling_pitch(args: dict[str, Any]) -> dict[str, Any]:
        return storyselling_pitch(
            args["audience"],
            args["pain"],
            args["cost_of_inaction"],
            args["new_belief"],
            args.get("proof"),
            args["offer"],
            args["next_step"],
            args.get("objection_risks"),
        )

    @server.register_tool(
        "people_execution_plan",
        "Cognitive Leadership people execution plan - owner, scope, cadence, verification",
        {
            "type": "object",
            "properties": {
                "objective": {"type": "string"},
                "owner": {"type": "string"},
                "scope_include": {"type": "array", "items": {"type": "string"}},
                "scope_exclude": {"type": "array", "items": {"type": "string"}},
                "acceptance_criteria": {"type": "array", "items": {"type": "string"}},
                "verification": {"type": "array", "items": {"type": "string"}},
                "cadence": {"type": "string"},
                "decision_rights": {"type": "string"},
                "risks": {"type": "array", "items": {"type": "string"}},
                "handoff_artifacts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["objective", "owner"],
        },
    )
    def _people_execution_plan(args: dict[str, Any]) -> dict[str, Any]:
        return people_execution_plan(
            args.get("objective", ""),
            args.get("owner", ""),
            args.get("scope_include"),
            args.get("scope_exclude"),
            args.get("acceptance_criteria"),
            args.get("verification"),
            args.get("cadence", ""),
            args.get("decision_rights", ""),
            args.get("risks"),
            args.get("handoff_artifacts"),
        )

    @server.register_tool(
        "leadership_alignment",
        "Cognitive Leadership alignment - direction, principles, roles, learning loop",
        {
            "type": "object",
            "properties": {
                "why_this_matters": {"type": "string"},
                "direction": {"type": "string"},
                "principles": {"type": "array", "items": {"type": "string"}},
                "non_negotiables": {"type": "array", "items": {"type": "string"}},
                "what_good_looks_like": {"type": "array", "items": {"type": "string"}},
                "roles": {"type": "array", "items": {"type": "string"}},
                "learning_loop": {"type": "string"},
                "next_decision": {"type": "string"},
            },
            "required": ["why_this_matters", "direction"],
        },
    )
    def _leadership_alignment(args: dict[str, Any]) -> dict[str, Any]:
        return leadership_alignment(
            args.get("why_this_matters", ""),
            args.get("direction", ""),
            args.get("principles"),
            args.get("non_negotiables"),
            args.get("what_good_looks_like"),
            args.get("roles"),
            args.get("learning_loop", ""),
            args.get("next_decision", ""),
        )

    @server.register_tool(
        "pre_change_notice",
        "Pre-Change Notice — สร้าง notice ก่อนแตะ file system (create/edit/delete/move/overwrite)",
        {
            "type": "object",
            "properties": {
                "action_type": {"type": "string", "enum": ["create", "edit", "delete", "move", "overwrite"]},
                "file_path": {"type": "string"},
                "reason": {"type": "string"},
                "expected_outcome": {"type": "string"},
                "risk_or_rollback": {"type": "string"},
            },
            "required": ["action_type", "file_path", "reason", "expected_outcome", "risk_or_rollback"],
        },
    )
    def _pre_change_notice(args: dict[str, Any]) -> dict[str, Any]:
        return pre_change_notice(
            args["action_type"],
            args["file_path"],
            args["reason"],
            args["expected_outcome"],
            args["risk_or_rollback"],
        )

    @server.register_tool(
        "plan_before_dispatch",
        "Plan Before Dispatch gate — validate ว่าแผนมีองค์ประกอบครบก่อน dispatch",
        {
            "type": "object",
            "properties": {
                "plan": {
                    "type": "object",
                    "properties": {
                        "objective": {"type": "string"},
                        "steps": {"type": "array", "items": {"type": "string"}},
                        "files_affected": {"type": "array", "items": {"type": "string"}},
                        "risks": {"type": "array", "items": {"type": "string"}},
                        "acceptance_criteria": {"type": "array", "items": {"type": "string"}},
                    },
                }
            },
            "required": ["plan"],
        },
    )
    def _plan_before_dispatch(args: dict[str, Any]) -> dict[str, Any]:
        return plan_before_dispatch(args["plan"])

    @server.register_tool(
        "dispatch_blocker_check",
        "Dispatch Blocker Gate — hard gate ก่อน scaffold/pre-check/dispatch",
        {
            "type": "object",
            "properties": {
                "task_ref": {"type": "string", "nullable": True},
                "checklist_ref": {"type": "string", "nullable": True},
                "section_ref": {"type": "string", "nullable": True},
                "objective": {"type": "string", "nullable": True},
                "acceptance_ref": {"type": "string", "nullable": True},
                "verification_ref": {"type": "string", "nullable": True},
                "writable_scope": {"type": "array", "items": {"type": "string"}},
                "dispatch_mode": {"type": "string", "nullable": True},
                "stop_if_missing": {"type": "boolean"},
            },
        },
    )
    def _dispatch_blocker_check(args: dict[str, Any]) -> dict[str, Any]:
        return dispatch_blocker_check(
            task_ref=args.get("task_ref"),
            checklist_ref=args.get("checklist_ref"),
            section_ref=args.get("section_ref"),
            objective=args.get("objective"),
            acceptance_ref=args.get("acceptance_ref"),
            verification_ref=args.get("verification_ref"),
            writable_scope=args.get("writable_scope"),
            dispatch_mode=args.get("dispatch_mode"),
            stop_if_missing=args.get("stop_if_missing", True),
        )

    return server
