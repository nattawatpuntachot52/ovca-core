"""Hermetic exact-JSON parity checks for the 12 shared Policy Tools."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.dont_write_bytecode = True

from scripts.mcp import policy_tools_server as python_policy_tools


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "rust" / "Cargo.toml"
SHARED_TOOLS = {
    "sati_check",
    "temporal_gate",
    "support_disclose",
    "certainty_zone",
    "claim_tag",
    "drift_check",
    "scamper_fill",
    "business_gate",
    "decision_format",
    "pre_change_notice",
    "plan_before_dispatch",
    "dispatch_blocker_check",
}

VALID_PLAN = {
    "objective": "audit",
    "steps": ["inspect"],
    "files_affected": ["docs/spec.md"],
    "risks": ["drift"],
    "acceptance_criteria": ["tests pass"],
}

VALID_BLOCKER = {
    "task_ref": "tasks/inbox/demo/task.md",
    "checklist_ref": "tasks/inbox/demo/checklist.md",
    "section_ref": "demo.section",
    "objective": "audit",
    "acceptance_ref": "## Acceptance",
    "verification_ref": "## Verification",
    "writable_scope": ["docs/spec.md"],
    "dispatch_mode": "manual",
    "stop_if_missing": True,
}

CASES: list[tuple[str, str, dict[str, Any]]] = [
    ("sati_check", "valid_thai", {"action": "ตรวจระบบ", "context": "owner approved"}),
    ("sati_check", "missing_context", {"action": "edit config", "context": ""}),
    ("sati_check", "empty_action", {"action": "", "context": ""}),
    (
        "temporal_gate",
        "blocked_no_evidence",
        {"claim": "race condition occurred", "claim_type": "causal"},
    ),
    (
        "temporal_gate",
        "allowed_with_evidence",
        {
            "claim": "dispatch failed",
            "claim_type": "causal",
            "evidence_source": "log line 42",
        },
    ),
    ("temporal_gate", "empty_claim", {"claim": "", "claim_type": "causal"}),
    ("support_disclose", "no_support", {"claim": "Engineer ready", "evidence_items": []}),
    (
        "support_disclose",
        "supported_three",
        {"claim": "Engineer ready", "evidence_items": ["handoff", "log", "test"]},
    ),
    ("support_disclose", "empty_claim", {"claim": "", "evidence_items": []}),
    ("certainty_zone", "clamp_low", {"confidence": -1.0}),
    ("certainty_zone", "boundary_c3", {"confidence": 0.75}),
    ("certainty_zone", "clamp_high", {"confidence": 2.0}),
    ("claim_tag", "unknown_no_basis", {"claim": "task done"}),
    (
        "claim_tag",
        "observed_log",
        {"claim": "tests passed", "basis": "pytest output log showed 5 passed"},
    ),
    ("claim_tag", "empty_claim", {"claim": "", "basis": None}),
    ("drift_check", "clean", {"reasoning_snippet": "reviewed evidence carefully"}),
    (
        "drift_check",
        "sycophancy_thai",
        {"reasoning_snippet": "ขอโทษค่ะ หนูจะแก้โค้ดเลย"},
    ),
    ("drift_check", "empty_snippet", {"reasoning_snippet": ""}),
    (
        "scamper_fill",
        "ready",
        {
            "base_object": "workflow",
            "improvement_target": "simpler",
            "eliminate": ["duplicate server"],
            "reverse": ["start from outage test"],
            "blind_spot": "network failure",
            "smallest_next_experiment": "golden parity",
            "guardrail": "no cutover without parity",
        },
    ),
    (
        "scamper_fill",
        "missing_eliminate",
        {
            "base_object": "workflow",
            "improvement_target": "simpler",
            "eliminate": [],
            "reverse": ["reverse order"],
            "blind_spot": "drift",
            "smallest_next_experiment": "one test",
        },
    ),
    (
        "scamper_fill",
        "missing_blind_and_experiment",
        {
            "base_object": "workflow",
            "improvement_target": "simpler",
            "eliminate": ["duplicate"],
            "reverse": ["reverse order"],
            "blind_spot": "",
            "smallest_next_experiment": "",
        },
    ),
    (
        "business_gate",
        "diagnosed",
        {
            "recommendation": "improve lead response",
            "domain": "lead",
            "bottleneck_evidence": "conversion log",
        },
    ),
    (
        "business_gate",
        "unknown_domain",
        {
            "recommendation": "improve system",
            "domain": "other",
            "bottleneck_evidence": "log",
        },
    ),
    (
        "business_gate",
        "missing_evidence",
        {"recommendation": "improve delivery", "domain": "delivery"},
    ),
    (
        "decision_format",
        "complete",
        {
            "topic": "authority",
            "options_considered": ["hybrid", "rust"],
            "what_to_do_now": "audit",
            "what_not_to_do": "cut over",
            "what_to_revisit_when": "parity passes",
            "metric_that_proves_it_worked": "36 cases match",
            "confidence": 0.8,
        },
    ),
    ("decision_format", "missing_fields", {"topic": "authority"}),
    (
        "decision_format",
        "low_confidence",
        {
            "topic": "authority",
            "what_to_do_now": "audit",
            "what_not_to_do": "migrate",
            "what_to_revisit_when": "evidence exists",
            "metric_that_proves_it_worked": "parity",
            "confidence": 0.3,
        },
    ),
    (
        "pre_change_notice",
        "valid_create",
        {
            "action_type": "create",
            "file_path": "docs/a.md",
            "reason": "audit",
            "expected_outcome": "record",
            "risk_or_rollback": "delete temp",
        },
    ),
    (
        "pre_change_notice",
        "destructive_delete",
        {
            "action_type": "delete",
            "file_path": "docs/a.md",
            "reason": "retire",
            "expected_outcome": "remove duplicate",
            "risk_or_rollback": "restore",
        },
    ),
    (
        "pre_change_notice",
        "missing_reason",
        {
            "action_type": "edit",
            "file_path": "docs/a.md",
            "reason": "",
            "expected_outcome": "record",
            "risk_or_rollback": "revert",
        },
    ),
    ("plan_before_dispatch", "valid", {"plan": VALID_PLAN}),
    (
        "plan_before_dispatch",
        "missing_acceptance",
        {"plan": {**VALID_PLAN, "acceptance_criteria": []}},
    ),
    (
        "plan_before_dispatch",
        "batch_missing_fields",
        {"plan": {**VALID_PLAN, "autonomous_batch": {"enabled": True}}},
    ),
    ("dispatch_blocker_check", "valid", VALID_BLOCKER),
    ("dispatch_blocker_check", "missing_fields", {"stop_if_missing": True}),
    (
        "dispatch_blocker_check",
        "placeholder",
        {**VALID_BLOCKER, "task_ref": "TODO"},
    ),
]

assert len(CASES) == 36
assert {tool for tool, _case, _arguments in CASES} == SHARED_TOOLS
assert len({(tool, case) for tool, case, _arguments in CASES}) == 36


def _request_json(
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    assert port != 8775
    return port


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _wait_for_health(base_url: str, process: subprocess.Popen[str]) -> dict[str, Any]:
    deadline = time.monotonic() + 20.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            pytest.fail(f"Rust policy-tools server exited during startup:\n{output}")
        try:
            return _request_json(f"{base_url}/health", timeout=1.0)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.1)
    pytest.fail(f"Rust policy-tools health check timed out: {last_error}")


def _wait_for_port_closed(port: int) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _port_open(port):
            return
        time.sleep(0.1)
    pytest.fail(f"Rust policy-tools listener remained open on port {port}")


@pytest.fixture(scope="module")
def rust_policy_tools_endpoint() -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="ovca-policy-tools-parity-") as temp_dir:
        temp_root = Path(temp_dir).resolve()
        assert REPO_ROOT not in temp_root.parents

        target_dir = temp_root / "cargo-target"
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target_dir)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        build = subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(MANIFEST_PATH),
                "--package",
                "ovca-policy-tools",
                "--bin",
                "ovca-policy-tools",
                "--locked",
            ],
            cwd=temp_root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        assert build.returncode == 0, (
            "cargo build failed\n"
            f"stdout:\n{build.stdout}\n"
            f"stderr:\n{build.stderr}"
        )

        executable = target_dir / "debug" / (
            "ovca-policy-tools.exe" if os.name == "nt" else "ovca-policy-tools"
        )
        assert executable.is_file()

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        process = subprocess.Popen(
            [str(executable), "--port", str(port), "--root", str(temp_root)],
            cwd=temp_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            health = _wait_for_health(base_url, process)
            assert health["ok"] is True
            assert health["name"] == "oracle-policy-tools"
            assert health["tools"] == 12

            tools_list = _request_json(f"{base_url}/tools/list")
            listed_names = {tool["name"] for tool in tools_list["tools"]}
            assert tools_list["count"] == 12
            assert listed_names == SHARED_TOOLS

            yield base_url
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5.0)
            if process.stdout is not None:
                process.stdout.close()
            _wait_for_port_closed(port)


@pytest.mark.parametrize(
    ("tool_name", "case_name", "arguments"),
    CASES,
    ids=[f"{tool}/{case}" for tool, case, _arguments in CASES],
)
def test_python_direct_result_matches_rust_endpoint_exactly(
    rust_policy_tools_endpoint: str,
    tool_name: str,
    case_name: str,
    arguments: dict[str, Any],
) -> None:
    del case_name
    python_result = getattr(python_policy_tools, tool_name)(**arguments)
    rust_response = _request_json(
        f"{rust_policy_tools_endpoint}/tools/call",
        payload={"name": tool_name, "arguments": arguments},
    )

    assert rust_response["ok"] is True
    assert rust_response["name"] == tool_name
    assert rust_response["kind"] == "tool"
    assert rust_response["result"] == python_result
