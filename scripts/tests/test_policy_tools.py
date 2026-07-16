"""
Tests for Policy Tools — Coordinator Governance Toolkit
Covers all 12 tools across Tier 1, 2, 3.
"""

from __future__ import annotations

import pytest

from scripts.mcp.policy_tools_server import (
    # Tier 1
    sati_check,
    temporal_gate,
    support_disclose,
    certainty_zone,
    claim_tag,
    drift_check,
    # Tier 2
    scamper_fill,
    business_gate,
    decision_format,
    # Tier 3
    pre_change_notice,
    plan_before_dispatch,
    dispatch_blocker_check,
)


# ── Tier 1: sati_check ────────────────────────────────────────────────────────

class TestSatiCheck:
    def test_proceed_when_action_and_context_given(self):
        result = sati_check("ลบ task.md", "task ถูก archive แล้ว")
        assert result["proceed"] is True
        assert result["stop_reason"] is None
        assert result["p1"] == "ลบ task.md"
        assert result["p2"] == "task ถูก archive แล้ว"

    def test_block_when_no_context(self):
        result = sati_check("ลบ task.md")
        assert result["proceed"] is False
        assert result["stop_reason"] is not None
        assert "P2" in result["stop_reason"]

    def test_block_when_empty_action(self):
        result = sati_check("")
        assert result["proceed"] is False
        assert result["p1"] is None

    def test_p3_tagged_assumed_without_context(self):
        result = sati_check("edit config.py")
        assert "assumed" in result["p3"]

    def test_p3_tagged_inferred_with_context(self):
        result = sati_check("edit config.py", "เปลี่ยน timeout")
        assert "inferred" in result["p3"]


# ── Tier 1: temporal_gate ─────────────────────────────────────────────────────

class TestTemporalGate:
    def test_block_when_no_evidence(self):
        result = temporal_gate("task timeout เพราะ dispatch ช้า", "causal")
        assert result["verdict"] == "block"
        assert result["has_evidence"] is False
        assert result["safe_response"] is not None

    def test_allow_when_evidence_given(self):
        result = temporal_gate("dispatch ล้มเหลว", "causal", "logs/dispatch.log line 42")
        assert result["verdict"] == "allow"
        assert result["has_evidence"] is True
        assert result["cite"] == "logs/dispatch.log line 42"

    def test_unknown_claim_type_defaults_to_causal(self):
        result = temporal_gate("something happened", "unknown_type")
        assert result["verdict"] == "block"

    def test_safe_response_not_none_when_blocked(self):
        result = temporal_gate("race condition occurred", evidence_source=None)
        assert result["safe_response"] is not None
        assert "ยืนยัน" in result["safe_response"]


# ── Tier 1: support_disclose ──────────────────────────────────────────────────

class TestSupportDisclose:
    def test_no_support_when_empty_evidence(self):
        result = support_disclose("Engineer ทำงานปกติ", [])
        assert result["level"] == "no_support"
        assert result["can_assert"] is False

    def test_low_support_for_one_item(self):
        result = support_disclose("Engineer ทำงานปกติ", ["handoff exists"])
        assert result["level"] == "low_support"
        assert result["can_assert"] is False

    def test_low_support_for_two_items(self):
        result = support_disclose("Engineer ทำงานปกติ", ["handoff", "log line"])
        assert result["level"] == "low_support"

    def test_supported_for_three_items(self):
        result = support_disclose("Engineer ทำงานปกติ", ["handoff", "log", "test pass"])
        assert result["level"] == "supported"
        assert result["can_assert"] is True

    def test_strips_blank_evidence_items(self):
        # blank items stripped → 1 real item → low_support
        result = support_disclose("claim", ["", "  ", "real evidence"])
        assert result["level"] == "low_support"
        assert result["can_assert"] is False
        # 2 real items after stripping blanks → still low_support
        result2 = support_disclose("claim", ["  real  ", "", "item2"])
        assert result2["level"] == "low_support"


# ── Tier 1: certainty_zone ────────────────────────────────────────────────────

class TestCertaintyZone:
    @pytest.mark.parametrize("conf,zone,can_proceed", [
        (0.0,  "C0", False),
        (0.39, "C0", False),
        (0.40, "C1", True),
        (0.59, "C1", True),
        (0.60, "C2", True),
        (0.74, "C2", True),
        (0.75, "C3", True),
        (0.89, "C3", True),
        (0.90, "C4", True),
        (1.0,  "C4", True),
    ])
    def test_zone_boundaries(self, conf: float, zone: str, can_proceed: bool):
        result = certainty_zone(conf)
        assert result["zone"] == zone
        assert result["can_proceed"] == can_proceed

    def test_clamps_below_zero(self):
        result = certainty_zone(-0.5)
        assert result["zone"] == "C0"

    def test_clamps_above_one(self):
        result = certainty_zone(1.5)
        assert result["zone"] == "C4"


# ── Tier 1: claim_tag ─────────────────────────────────────────────────────────

class TestClaimTag:
    def test_unknown_when_no_basis(self):
        result = claim_tag("Engineer is running")
        assert result["tag"] == "unknown"

    def test_observed_with_log_basis(self):
        result = claim_tag("5 tests passed", "pytest output log showed 5 passed")
        assert result["tag"] == "observed"

    def test_inferred_with_logic_basis(self):
        # basis ที่มีแค่ logic keyword — ไม่มี log/file/test ทำให้ไม่ถูก classify เป็น observed
        result = claim_tag("dispatch succeeded", "เพราะ exit code = 0 therefore it worked")
        assert result["tag"] == "inferred"

    def test_assumed_with_assume_basis(self):
        result = claim_tag("task is done", "assume it completed because no error")
        assert result["tag"] == "assumed"

    def test_display_label_format(self):
        result = claim_tag("some claim", "test result showed pass")
        assert result["display_label"] == f"[{result['tag']}]"


# ── Tier 1: drift_check ───────────────────────────────────────────────────────

class TestDriftCheck:
    def test_clean_when_no_bugs(self):
        result = drift_check("หนูได้อ่าน spec แล้ว root cause คือ timeout config")
        assert result["clean"] is True
        assert result["stop"] is False
        assert result["bugs_detected"] == []

    def test_detects_sycophancy(self):
        result = drift_check("ขอโทษที่ไม่ได้ทำก่อน")
        bugs = [b["bug"] for b in result["bugs_detected"]]
        assert "sycophancy" in bugs
        assert result["stop"] is True

    def test_detects_performance_bias(self):
        result = drift_check("หนูจะแก้โค้ดตรงนี้เลย")
        bugs = [b["bug"] for b in result["bugs_detected"]]
        assert "performance_bias" in bugs

    def test_stop_true_for_stop_severity(self):
        result = drift_check("จะทำเลยไม่ต้องรอ")
        assert result["stop"] is True

    def test_multiple_bugs_detected(self):
        result = drift_check("ขอโทษมาก จะแก้ไฟล์เดี๋ยวนี้เลย")
        assert len(result["bugs_detected"]) >= 2


# ── Tier 2: scamper_fill ──────────────────────────────────────────────────────

class TestScamperFill:
    def test_ready_when_all_mandatory_filled(self):
        result = scamper_fill(
            base_object="dispatch flow",
            improvement_target="ลด timeout",
            eliminate=["ตัด pre-flight ซ้ำ"],
            reverse=["ให้ Engineer estimate ก่อน"],
            blind_spot="hidden dependency ที่โตขึ้น runtime",
            smallest_next_experiment="เพิ่ม size_estimate field แล้ว observe 3 tasks",
        )
        assert result["ready"] is True
        assert result["missing"] == []

    def test_not_ready_when_eliminate_missing(self):
        result = scamper_fill(
            base_object="flow",
            improvement_target="improve",
            eliminate=[],
            reverse=["reverse idea"],
            blind_spot="some blind spot",
            smallest_next_experiment="do x",
        )
        assert result["ready"] is False
        assert "eliminate" in result["missing"]

    def test_not_ready_when_reverse_missing(self):
        result = scamper_fill(
            base_object="flow",
            improvement_target="improve",
            eliminate=["remove x"],
            reverse=[],
            blind_spot="blind",
            smallest_next_experiment="exp",
        )
        assert "reverse" in result["missing"]

    def test_optional_fields_included(self):
        result = scamper_fill(
            base_object="x",
            improvement_target="y",
            eliminate=["e"],
            reverse=["r"],
            blind_spot="b",
            smallest_next_experiment="s",
            substitute=["sub1"],
            guardrail="be careful",
        )
        assert result["ideas"]["substitute"] == ["sub1"]
        assert result["guardrail"] == "be careful"


# ── Tier 2: business_gate ─────────────────────────────────────────────────────

class TestBusinessGate:
    def test_blocked_when_no_evidence(self):
        result = business_gate("เพิ่ม content ใน Telegram")
        assert result["can_proceed"] is False
        assert result["block_reason"] is not None

    def test_blocked_when_domain_unknown(self):
        result = business_gate("do something", "other", "some evidence")
        assert result["bottleneck_diagnosed"] is False

    def test_proceeds_when_domain_and_evidence_given(self):
        result = business_gate(
            "เพิ่ม lead gen campaign",
            "lead",
            "lead count ลดลง 30% ใน 2 เดือน จาก analytics"
        )
        assert result["can_proceed"] is True
        assert result["kpi_anchor"] is not None
        assert result["kpi_anchor"]["do_x"] is not None

    def test_kpi_anchor_null_when_not_diagnosed(self):
        result = business_gate("recommend x")
        assert result["kpi_anchor"] is None


# ── Tier 2: decision_format ───────────────────────────────────────────────────

class TestDecisionFormat:
    def test_complete_when_all_fields_filled(self):
        result = decision_format(
            topic="เลือก DB",
            what_to_do_now="ใช้ PostgreSQL",
            what_not_to_do="อย่า introduce ChromaDB",
            what_to_revisit_when="latency > 200ms",
            metric_that_proves_it_worked="p95 < 100ms",
            confidence=0.8,
        )
        assert result["complete"] is True
        assert result["missing"] == []
        assert result["certainty_zone"] == "C3"

    def test_missing_fields_reported(self):
        result = decision_format(topic="เลือก DB")
        assert "what_to_do_NOW" in result["missing"]
        assert result["complete"] is False

    def test_certainty_zone_from_confidence(self):
        result = decision_format(
            topic="x",
            what_to_do_now="do",
            what_not_to_do="not",
            what_to_revisit_when="when",
            metric_that_proves_it_worked="metric",
            confidence=0.3,
        )
        assert result["certainty_zone"] == "C0"


# ── Tier 3: pre_change_notice ─────────────────────────────────────────────────

class TestPreChangeNotice:
    def test_valid_create_notice(self):
        result = pre_change_notice(
            action_type="create",
            file_path="tasks/inbox/foo/task.md",
            reason="scaffold new task",
            expected_outcome="task packet ready",
            risk_or_rollback="ลบไฟล์ถ้า task ไม่ผ่าน",
        )
        assert result["valid"] is True
        assert result["missing"] == []

    def test_destructive_requires_approval(self):
        result = pre_change_notice(
            action_type="delete",
            file_path="tasks/inbox/foo/task.md",
            reason="archived",
            expected_outcome="inbox clean",
            risk_or_rollback="git checkout HEAD path",
        )
        assert result["requires_approval"] is True
        assert "⛔" in result["display_text"]

    def test_missing_reason_reported(self):
        result = pre_change_notice(
            action_type="edit",
            file_path="config.py",
            reason="",
            expected_outcome="ok",
            risk_or_rollback="revert",
        )
        assert "reason (why / authority)" in result["missing"]
        assert result["valid"] is False

    def test_notice_dict_has_four_keys(self):
        result = pre_change_notice("create", "f.py", "r", "o", "rr")
        assert set(result["notice"].keys()) == {"what", "why", "outcome", "downside"}


# ── Tier 3: plan_before_dispatch ──────────────────────────────────────────────

class TestPlanBeforeDispatch:
    def test_valid_when_all_fields_present(self):
        result = plan_before_dispatch({
            "objective": "fix timeout",
            "steps": ["step 1", "step 2"],
            "files_affected": ["scripts/foo.py"],
            "risks": ["regression"],
            "acceptance_criteria": ["0 test failures"],
        })
        assert result["valid"] is True
        assert result["can_dispatch"] is True
        assert result["missing_fields"] == []

    def test_blocks_when_objective_missing(self):
        result = plan_before_dispatch({
            "steps": ["s"],
            "files_affected": ["f"],
            "risks": ["r"],
            "acceptance_criteria": ["a"],
        })
        assert "objective" in result["missing_fields"]
        assert result["can_dispatch"] is False

    def test_blocks_when_acceptance_criteria_empty_list(self):
        result = plan_before_dispatch({
            "objective": "do x",
            "steps": ["s"],
            "files_affected": ["f"],
            "risks": ["r"],
            "acceptance_criteria": [],
        })
        assert "acceptance_criteria" in result["missing_fields"]

    def test_block_reason_lists_missing_fields(self):
        result = plan_before_dispatch({"objective": "x"})
        assert result["block_reason"] is not None
        assert "steps" in result["block_reason"]

    def test_autonomous_batch_requires_batch_fields(self):
        result = plan_before_dispatch({
            "objective": "dispatch full batch",
            "steps": ["P1"],
            "files_affected": ["scripts/foo.py"],
            "risks": ["regression"],
            "acceptance_criteria": ["tests pass"],
            "autonomous_batch": {"enabled": True},
        })
        assert result["can_dispatch"] is False
        assert "autonomous_batch.authority" in result["missing_fields"]
        assert "autonomous_batch.scope.include" in result["missing_fields"]
        assert "autonomous_batch.commit_policy" in result["missing_fields"]

    def test_autonomous_batch_valid_when_batch_fields_present(self):
        result = plan_before_dispatch({
            "objective": "dispatch full batch",
            "steps": ["P1"],
            "files_affected": ["scripts/foo.py"],
            "risks": ["regression"],
            "acceptance_criteria": ["tests pass"],
            "autonomous_batch": {
                "enabled": True,
                "authority": "owner requested batch execution",
                "scope": {
                    "include": ["scripts/foo.py"],
                    "exclude": [".env", ".claude/*"],
                },
                "stop_conditions": ["verification fails and repair expands scope"],
                "commit_policy": {"allow_stage_commit": True, "allow_push": False},
            },
        })
        assert result["valid"] is True
        assert result["can_dispatch"] is True
        assert result["missing_fields"] == []


# ── Tier 3: dispatch_blocker_check ────────────────────────────────────────────

class TestDispatchBlockerCheck:
    def test_pass_when_all_fields_set(self):
        result = dispatch_blocker_check(
            task_ref="fix_timeout",
            checklist_ref="CODEX_TASKCHECKLIST.md#fix_timeout",
            section_ref="S1",
            objective="แก้ timeout config",
            acceptance_ref="section 4 handoff",
            verification_ref="pytest -q",
            writable_scope=["scripts/config.py"],
            dispatch_mode="fresh",
            stop_if_missing=True,
        )
        assert result["verdict"] == "PASS"
        assert result["ready"] is True

    def test_fail_when_checklist_ref_missing(self):
        result = dispatch_blocker_check(
            task_ref="fix_timeout",
            checklist_ref=None,
            section_ref="S1",
            objective="do x",
            acceptance_ref="ref",
            verification_ref="pytest",
            writable_scope=["f.py"],
            dispatch_mode="fresh",
        )
        assert result["verdict"] == "FAIL"
        assert "checklist_ref" in result["missing_fields"]

    def test_fail_when_placeholder_in_field(self):
        result = dispatch_blocker_check(
            task_ref="TODO",
            checklist_ref="checklist",
            section_ref="S1",
            objective="obj",
            acceptance_ref="ref",
            verification_ref="v",
            writable_scope=["f"],
            dispatch_mode="fresh",
            stop_if_missing=True,
        )
        assert result["verdict"] == "FAIL"
        assert "task_ref" in result["placeholder_fields"]

    def test_fail_when_writable_scope_empty(self):
        result = dispatch_blocker_check(
            task_ref="t",
            checklist_ref="c",
            section_ref="s",
            objective="o",
            acceptance_ref="a",
            verification_ref="v",
            writable_scope=[],
            dispatch_mode="fresh",
        )
        assert "writable_scope" in result["missing_fields"]

    def test_fail_reason_mentions_stop_if_missing(self):
        result = dispatch_blocker_check(
            task_ref=None,
            stop_if_missing=True,
        )
        assert result["fail_reason"] is not None
        assert "stop_if_missing=true" in result["fail_reason"]
