from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_policy_gate_wraps_drift_check() -> None:
    from scripts.agent_tasks.policy_gate import check_drift

    result = check_drift("ขอโทษค่ะ หนูจะแก้โค้ดเลย")
    bugs = {item["bug"] for item in result["bugs_detected"]}

    assert "sycophancy" in bugs
    assert "performance_bias" in bugs
    assert result["stop"] is True


def test_policy_gate_validate_dispatch_blocker_maps_dict() -> None:
    from scripts.agent_tasks.policy_gate import validate_dispatch_blocker

    result = validate_dispatch_blocker(
        {
            "task_ref": "tasks/inbox/demo/task.md",
            "checklist_ref": "tasks/inbox/demo/awake_checklist.md",
            "section_ref": "demo.section",
            "objective": "wire policy gate",
            "acceptance_ref": "## Acceptance Criteria",
            "verification_ref": "## Verification Commands",
            "writable_scope": ["scripts/dispatch_runner.py"],
            "dispatch_mode": "manual",
            "stop_if_missing": True,
        }
    )

    assert result["verdict"] == "PASS"
    assert result["ready"] is True


def test_policy_gate_audit_log_is_best_effort(tmp_path, monkeypatch) -> None:
    import scripts.agent_tasks.policy_gate as policy_gate

    log_path = tmp_path / "logs" / "policy_gates.jsonl"
    monkeypatch.setattr(policy_gate, "POLICY_GATE_LOG", log_path)

    result = policy_gate.check_confidence(0.85)

    assert result["zone"] == "C3"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["tool"] == "certainty_zone"
