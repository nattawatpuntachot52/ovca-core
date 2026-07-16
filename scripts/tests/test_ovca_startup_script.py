from __future__ import annotations

import json
import os
import socket
import subprocess
import uuid
from pathlib import Path


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "ovca.ps1"
POWERSHELL = "powershell.exe"


def _run_powershell(
    arguments: list[str],
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", *arguments],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        cwd=cwd,
        check=False,
    )


def test_start_preflights_all_ports_before_build_or_launch(tmp_path: Path) -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    preflight = source.index("Assert-RequiredPortsAvailable $Services")
    build = source.index("& cargo build")
    launch = source.index("$process = Start-Process")
    assert preflight < build < launch

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        occupied.bind(("127.0.0.1", 8775))
        occupied.listen(1)
        result = _run_powershell(
            [
                "-File",
                str(SCRIPT),
                "start",
                "-DataRoot",
                str(tmp_path / "data"),
                "-TargetRoot",
                str(tmp_path / "target"),
                "-PidRoot",
                str(tmp_path / "pids"),
                "-LogRoot",
                str(tmp_path / "logs"),
            ]
        )

    assert result.returncode != 0
    assert "No services were launched" in (result.stdout + result.stderr)
    assert not list((tmp_path / "pids").glob("*.json"))


def test_in_repo_nonexistent_external_root_is_rejected_without_creation() -> None:
    candidate = ROOT / f"should-not-exist-{uuid.uuid4().hex}"
    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
try {{
    Resolve-ExternalDirectory '{candidate}' 'TestRoot' | Out-Null
    exit 2
}} catch {{
    if (Test-Path -LiteralPath '{candidate}') {{ exit 3 }}
}}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not candidate.exists()


def test_windows_argument_quoting_preserves_external_root_with_spaces(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    value = tmp_path / "external data root with spaces"
    output = tmp_path / "probe output with spaces.txt"
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
$code = 'import pathlib,sys; pathlib.Path(sys.argv[2]).write_text(sys.argv[1], encoding="utf-8")'
$arguments = Join-WindowsCommandLineArguments @('-c', $code, '{value}', '{output}')
$probe = Start-Process -FilePath python.exe -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
if ($probe.ExitCode -ne 0) {{ exit 2 }}
if ((Get-Content -LiteralPath '{output}' -Raw) -ne '{value}') {{ exit 3 }}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text(encoding="utf-8") == str(value)


def test_partial_startup_rollback_stops_only_matching_invocation_process(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    command = rf"""
. '{SCRIPT}' health -PidRoot '{tmp_path / 'unused'}'
$child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
$child.Refresh()
$exact = [pscustomobject]@{{
    service = 'test-child'
    port = 0
    pid = $child.Id
    executable = $child.Path
    started_at_utc = $child.StartTime.ToUniversalTime().ToString('o')
}}
$mismatch = [pscustomobject]@{{
    service = 'pre-existing'
    port = 0
    pid = $PID
    executable = 'not-the-current-executable'
    started_at_utc = '2000-01-01T00:00:00.0000000Z'
}}
try {{
    Stop-InvocationProcesses @(
        [pscustomobject]@{{ Receipt = $mismatch; ReceiptPath = $null }},
        [pscustomobject]@{{ Receipt = $exact; ReceiptPath = $null }}
    )
    if ($null -ne (Get-Process -Id $child.Id -ErrorAction SilentlyContinue)) {{ exit 2 }}
    if ($null -eq (Get-Process -Id $PID -ErrorAction SilentlyContinue)) {{ exit 3 }}
}} finally {{
    Stop-Process -Id $child.Id -ErrorAction SilentlyContinue
}}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_receipt_uses_launch_executable_and_rejects_empty_path(tmp_path: Path) -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "$executable = (Resolve-Path -LiteralPath $executable).Path" in source
    assert "Start-Process -FilePath $executable" in source
    assert "New-ProcessReceipt $service $process $executable" in source
    assert "executable = $process.Path" not in source

    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
$executable = (Resolve-Path -LiteralPath (Get-Command powershell.exe).Source).Path
$child = Start-Process -FilePath $executable -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
try {{
    $service = @{{ Name = 'test-child'; Port = 0 }}
    $receipt = New-ProcessReceipt $service $child $executable
    $serialized = $receipt | ConvertTo-Json | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$serialized.executable)) {{ exit 2 }}
    if ([string]$serialized.executable -ne $executable) {{ exit 3 }}
    try {{
        New-ProcessReceipt $service $child '' | Out-Null
        exit 4
    }} catch {{
        if ($_.Exception.Message -notlike 'Cannot create a process receipt*') {{ exit 5 }}
    }}
}} finally {{
    Stop-Process -Id $child.Id -ErrorAction SilentlyContinue
}}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_receipt_mismatch_refuses_to_operate_on_live_pid(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    pid_root = tmp_path / "pid root with spaces"
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
$script:ResolvedPidRoot = Resolve-ExternalDirectory '{pid_root}' 'PidRoot'
$current = Get-Process -Id $PID
$receipt = [pscustomobject][ordered]@{{
    service = 'mismatch'
    port = 0
    pid = $PID
    executable = 'not-the-current-executable'
    started_at_utc = $current.StartTime.ToUniversalTime().ToString('o')
}}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Receipt-Path 'mismatch') -Encoding UTF8
try {{
    Read-OwnedProcess @{{ Name = 'mismatch'; Port = 0 }} | Out-Null
    exit 2
}} catch {{
    if ($_.Exception.Message -notlike 'Process identity mismatch*') {{ exit 3 }}
}}
if ($null -eq (Get-Process -Id $PID -ErrorAction SilentlyContinue)) {{ exit 4 }}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_child_launch_canonicalizes_ambient_mcp_environment_and_working_directory(
    tmp_path: Path,
) -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    canonicalize = source.index("$previousMcpEnvironment = Set-CanonicalMcpEnvironment")
    launch = source.index("$process = Start-Process")
    assert canonicalize < launch
    assert "-WorkingDirectory $resolvedChildWorkingDirectory" in source

    canonical = {
        "MCP_AGENT_HOST": "127.0.0.1",
        "MCP_POLICY_PORT": "8775",
        "MCP_POLICY-TOOLS_PORT": "8775",
        "MCP_COORDINATOR_PORT": "18780",
        "MCP_ENGINEER_PORT": "18784",
        "MCP_REVIEWER_PORT": "18785",
        "MCP_AUDITOR_PORT": "18786",
        "MCP_POLICY-TOOLS_BASE_URL": "http://127.0.0.1:8775",
        "MCP_COORDINATOR_BASE_URL": "http://127.0.0.1:18780",
        "MCP_ENGINEER_BASE_URL": "http://127.0.0.1:18784",
        "MCP_REVIEWER_BASE_URL": "http://127.0.0.1:18785",
        "MCP_AUDITOR_BASE_URL": "http://127.0.0.1:18786",
    }
    ambient = {
        key: "ambient.invalid" if key == "MCP_AGENT_HOST" else "http://127.0.0.1:9"
        if key.endswith("BASE_URL")
        else "9"
        for key in canonical
    }
    caller = tmp_path / "adversarial caller with spaces"
    target = tmp_path / "external target with spaces"
    output = tmp_path / "child environment with spaces.json"
    caller.mkdir()
    target.mkdir()
    (caller / ".env").write_text(
        "MCP_AGENT_HOST=dotenv.invalid\nMCP_ENGINEER_PORT=9\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(ambient)
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    keys = ",".join(f"'{key}'" for key in canonical)
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
$safe = Resolve-SafeChildWorkingDirectory '{target}' (Get-Location).ProviderPath
$snapshot = Set-CanonicalMcpEnvironment
try {{
    $code = 'import json,os,pathlib,sys; keys=sys.argv[2:]; pathlib.Path(sys.argv[1]).write_text(json.dumps({{"cwd":os.getcwd(),"env":{{key:os.environ.get(key) for key in keys}}}}),encoding="utf-8")'
    $arguments = Join-WindowsCommandLineArguments @('-c', $code, '{output}', {keys})
    $probe = Start-Process -FilePath python.exe -ArgumentList $arguments -WorkingDirectory $safe -PassThru -Wait -WindowStyle Hidden
    if ($probe.ExitCode -ne 0) {{ exit 2 }}
}} finally {{
    Restore-McpEnvironment $snapshot
}}
$expected = Get-CanonicalMcpEnvironment
foreach ($entry in $expected.GetEnumerator()) {{
    $current = [System.Environment]::GetEnvironmentVariable($entry.Key, [System.EnvironmentVariableTarget]::Process)
    if ($current -ne '{ambient['MCP_AGENT_HOST']}' -and $entry.Key -eq 'MCP_AGENT_HOST') {{ exit 3 }}
    if ($entry.Key -ne 'MCP_AGENT_HOST' -and $current -ne '{ambient['MCP_ENGINEER_PORT']}' -and $entry.Key -notlike '*BASE_URL') {{ exit 4 }}
    if ($entry.Key -like '*BASE_URL' -and $current -ne '{ambient['MCP_ENGINEER_BASE_URL']}') {{ exit 5 }}
}}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env, cwd=caller)
    assert result.returncode == 0, result.stdout + result.stderr

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert Path(payload["cwd"]).resolve() == (target / "ovca child working directory").resolve()
    assert payload["env"] == canonical


def test_safe_child_working_directory_rejects_caller_subtree(tmp_path: Path) -> None:
    caller = tmp_path / "caller with spaces"
    target = caller / "target with spaces"
    caller.mkdir()
    env = os.environ.copy()
    env["OVCA_SCRIPT_TEST_MODE"] = "1"
    command = rf"""
. '{SCRIPT}' health -PidRoot 'unused'
try {{
    Resolve-SafeChildWorkingDirectory '{target}' '{caller}' | Out-Null
    exit 2
}} catch {{
    if ($_.Exception.Message -notlike 'TargetRoot must be outside the caller directory*') {{ exit 3 }}
}}
if (Test-Path -LiteralPath '{target}') {{ exit 4 }}
exit 0
"""
    result = _run_powershell(["-Command", command], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
