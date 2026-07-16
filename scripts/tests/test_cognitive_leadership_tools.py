from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_cognitive_route_sends_redesign_to_scamper() -> None:
    from scripts.mcp.policy_tools_server import cognitive_route

    result = cognitive_route(
        "redesign this policy workflow and remove duplication",
        risk_level="high",
        system_impact=True,
    )

    assert result["route"] == "scamper"
    assert result["gate_level"] == "hard"
    assert "scamper_fill" in result["required_tools"]


def test_cognitive_route_keeps_small_literal_lightweight() -> None:
    from scripts.mcp.policy_tools_server import cognitive_route

    result = cognitive_route("read this short note")

    assert result["route"] == "literal"
    assert result["required_tools"] == []
    assert result["gate_level"] == "none"


def test_analytical_frame_requires_observed_and_next_action() -> None:
    from scripts.mcp.policy_tools_server import analytical_frame

    blocked = analytical_frame(next_action="")
    assert blocked["can_recommend"] is False
    assert "observed" in blocked["missing"]
    assert "next_action" in blocked["missing"]

    ready = analytical_frame(
        observed=["policy file says SCAMPER already handles redesign"],
        inferred=["cognitive layer should route to SCAMPER"],
        unknown=["runtime host is not chosen"],
        risk=["governance bloat"],
        next_action="write gap audit before implementation",
    )
    assert ready["can_recommend"] is True
    assert ready["missing"] == []


def test_strategy_review_requires_decision_fields() -> None:
    from scripts.mcp.policy_tools_server import strategy_review

    result = strategy_review(
        objective="upgrade Coordinator thinking",
        options=["policy only", "tool only", "policy plus tools"],
        decision_criteria=["avoid SCAMPER duplication"],
        recommended_decision="policy plus tools",
        next_action="implement advisory route first",
    )

    assert result["complete"] is True
    assert result["missing"] == []


def test_storyselling_pitch_requires_proof_and_next_step() -> None:
    from scripts.mcp.policy_tools_server import storyselling_pitch

    result = storyselling_pitch(
        audience="founder",
        pain="too much information and not enough decision quality",
        cost_of_inaction="execution keeps moving without strategic clarity",
        new_belief="attention architecture is a leadership advantage",
        proof=["existing DMN essay", "existing Coordinator Thinking Policy"],
        offer="Cognitive Leadership System",
        next_step="run P0 gap audit",
    )

    assert result["complete"] is True
    assert result["missing"] == []


def test_people_execution_plan_is_hard_gate_shape() -> None:
    from scripts.mcp.policy_tools_server import people_execution_plan

    result = people_execution_plan(
        objective="run P0-P6",
        owner="Coordinator",
        scope_include=["docs", "scripts/mcp/policy_tools_server.py"],
        scope_exclude=["AGENTS.md", "CLAUDE.md"],
        acceptance_criteria=["tests pass"],
        verification=["pytest scripts/tests/test_cognitive_leadership_tools.py -q"],
        cadence="single batch",
        decision_rights="owner requested P0-P6",
        risks=["policy bloat"],
        handoff_artifacts=["verification.md"],
    )

    assert result["ready"] is True
    assert result["gate_level"] == "hard"


def test_policy_gate_adapter_logs_cognitive_route(tmp_path, monkeypatch) -> None:
    import scripts.agent_tasks.policy_gate as policy_gate

    log_path = tmp_path / "policy_gates.jsonl"
    monkeypatch.setattr(policy_gate, "POLICY_GATE_LOG", log_path)

    result = policy_gate.route_cognitive_request("prepare a pitch for investors")

    assert result["route"] == "storyselling"
    assert "storyselling_pitch" in result["required_tools"]
    assert "cognitive_route" in log_path.read_text(encoding="utf-8")


def test_mcp_server_registers_cognitive_tools() -> None:
    from scripts.mcp.policy_tools_server import build_server

    server = build_server()

    assert "cognitive_route" in server.tools
    assert "analytical_frame" in server.tools
    assert "people_execution_plan" in server.tools


def test_python_policy_surface_builds_without_uvicorn(monkeypatch) -> None:
    import builtins
    import importlib
    import scripts.mcp.policy_tools_server as policy_tools_server

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise AssertionError("uvicorn is not a declared public dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    module = importlib.reload(policy_tools_server)
    server = module.build_server()

    assert callable(server.app)
    assert len(server.tools) == 19
