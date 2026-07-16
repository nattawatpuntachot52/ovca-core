[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('start', 'health', 'stop')]
    [string]$Command,
    [string]$DataRoot,
    [string]$TargetRoot,
    [Parameter(Mandatory = $true)]
    [string]$PidRoot,
    [string]$LogRoot
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Manifest = Join-Path $RepoRoot 'rust\Cargo.toml'
$Services = @(
    @{ Name = 'policy-tools'; Package = 'ovca-policy-tools'; Port = 8775 },
    @{ Name = 'coordinator'; Package = 'ovca-coordinator-server'; Port = 18780 },
    @{ Name = 'engineer'; Package = 'ovca-engineer-server'; Port = 18784 },
    @{ Name = 'reviewer'; Package = 'ovca-reviewer-server'; Port = 18785 },
    @{ Name = 'auditor'; Package = 'ovca-auditor-server'; Port = 18786 }
)

function Resolve-ExternalDirectory([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label is required" }
    $candidate = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if ($candidate -eq $RepoRoot -or $candidate.StartsWith($RepoRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be outside the repository"
    }
    [void][System.IO.Directory]::CreateDirectory($candidate)
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if ($resolved -eq $RepoRoot -or $resolved.StartsWith($RepoRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label resolved inside the repository"
    }
    return $resolved
}

function ConvertTo-WindowsCommandLineArgument([string]$Value) {
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append('\' * (($backslashes * 2) + 1))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append('\' * $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append('\' * ($backslashes * 2))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-WindowsCommandLineArguments([string[]]$Values) {
    return (($Values | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ }) -join ' ')
}

function Test-PathWithinDirectory([string]$Path, [string]$Directory) {
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullDirectory = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\')
    return $fullPath -eq $fullDirectory -or $fullPath.StartsWith(
        $fullDirectory + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Resolve-SafeChildWorkingDirectory([string]$ExternalRoot, [string]$CallerDirectory) {
    if (Test-PathWithinDirectory $ExternalRoot $CallerDirectory) {
        throw "TargetRoot must be outside the caller directory so child configuration discovery is isolated"
    }
    $resolved = Resolve-ExternalDirectory (Join-Path $ExternalRoot 'ovca child working directory') 'ChildWorkingDirectory'
    if (Test-PathWithinDirectory $resolved $CallerDirectory) {
        throw "ChildWorkingDirectory resolved inside the caller directory"
    }
    return $resolved
}

function Get-CanonicalMcpEnvironment() {
    return [ordered]@{
        'MCP_AGENT_HOST' = '127.0.0.1'
        'MCP_POLICY_PORT' = '8775'
        'MCP_POLICY-TOOLS_PORT' = '8775'
        'MCP_COORDINATOR_PORT' = '18780'
        'MCP_ENGINEER_PORT' = '18784'
        'MCP_REVIEWER_PORT' = '18785'
        'MCP_AUDITOR_PORT' = '18786'
        'MCP_POLICY-TOOLS_BASE_URL' = 'http://127.0.0.1:8775'
        'MCP_COORDINATOR_BASE_URL' = 'http://127.0.0.1:18780'
        'MCP_ENGINEER_BASE_URL' = 'http://127.0.0.1:18784'
        'MCP_REVIEWER_BASE_URL' = 'http://127.0.0.1:18785'
        'MCP_AUDITOR_BASE_URL' = 'http://127.0.0.1:18786'
    }
}

function Set-CanonicalMcpEnvironment() {
    $snapshot = [ordered]@{}
    $processEnvironment = [System.Environment]::GetEnvironmentVariables(
        [System.EnvironmentVariableTarget]::Process
    )
    try {
        foreach ($entry in (Get-CanonicalMcpEnvironment).GetEnumerator()) {
            $snapshot[$entry.Key] = [pscustomobject]@{
                IsSet = $processEnvironment.Contains($entry.Key)
                Value = $processEnvironment[$entry.Key]
            }
            [System.Environment]::SetEnvironmentVariable(
                $entry.Key,
                $entry.Value,
                [System.EnvironmentVariableTarget]::Process
            )
        }
    } catch {
        Restore-McpEnvironment $snapshot
        throw
    }
    return $snapshot
}

function Restore-McpEnvironment([System.Collections.IDictionary]$Snapshot) {
    foreach ($entry in $Snapshot.GetEnumerator()) {
        $value = if ($entry.Value.IsSet) { [string]$entry.Value.Value } else { $null }
        [System.Environment]::SetEnvironmentVariable(
            $entry.Key,
            $value,
            [System.EnvironmentVariableTarget]::Process
        )
    }
}

function Receipt-Path([string]$Name) {
    Join-Path $script:ResolvedPidRoot "$Name.json"
}

function Get-MatchingProcess([psobject]$Receipt) {
    $process = Get-Process -Id ([int]$Receipt.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    $actualPath = $process.Path
    $actualStart = $process.StartTime.ToUniversalTime().ToString('o')
    if ($actualPath -ne $Receipt.executable -or $actualStart -ne $Receipt.started_at_utc) {
        return $null
    }
    return $process
}

function New-ProcessReceipt([hashtable]$Service, [System.Diagnostics.Process]$Process, [string]$Executable) {
    if ([string]::IsNullOrWhiteSpace($Executable)) {
        throw "Cannot create a process receipt without an executable path"
    }
    return [pscustomobject][ordered]@{
        service = $Service.Name
        port = $Service.Port
        pid = $Process.Id
        executable = $Executable
        started_at_utc = $Process.StartTime.ToUniversalTime().ToString('o')
    }
}

function Read-OwnedProcess([hashtable]$Service) {
    $path = Receipt-Path $Service.Name
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $receipt = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $process = Get-MatchingProcess $receipt
    if ($null -eq $process -and $null -ne (Get-Process -Id ([int]$receipt.pid) -ErrorAction SilentlyContinue)) {
        throw "Process identity mismatch for $($Service.Name); refusing to operate on PID $($receipt.pid)"
    }
    return $process
}

function Assert-RequiredPortsAvailable([array]$RequiredServices) {
    $occupied = [System.Collections.Generic.List[int]]::new()
    foreach ($service in $RequiredServices) {
        $listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback,
            [int]$service.Port
        )
        $listener.ExclusiveAddressUse = $true
        try {
            $listener.Start()
        } catch [System.Net.Sockets.SocketException] {
            $occupied.Add([int]$service.Port)
        } finally {
            $listener.Stop()
        }
    }
    if ($occupied.Count -gt 0) {
        throw "Required ports are occupied: $($occupied -join ', '). No services were launched."
    }
}

function Stop-InvocationProcesses([array]$LaunchRecords) {
    for ($index = $LaunchRecords.Count - 1; $index -ge 0; $index--) {
        $record = $LaunchRecords[$index]
        $process = Get-MatchingProcess $record.Receipt
        if ($null -ne $process) {
            Stop-Process -Id $process.Id
            $process.WaitForExit(10000) | Out-Null
        }
        if ($record.ReceiptPath -and (Test-Path -LiteralPath $record.ReceiptPath)) {
            Remove-Item -LiteralPath $record.ReceiptPath -Force
        }
    }
}

# Tests dot-source the functions without touching directories, ports, or processes.
if ($env:OVCA_SCRIPT_TEST_MODE -eq '1') { return }

$script:ResolvedPidRoot = Resolve-ExternalDirectory $PidRoot 'PidRoot'

if ($Command -eq 'start') {
    $callerDirectory = (Get-Location).ProviderPath
    $resolvedData = Resolve-ExternalDirectory $DataRoot 'DataRoot'
    $resolvedLogs = Resolve-ExternalDirectory $LogRoot 'LogRoot'
    $resolvedTarget = Resolve-ExternalDirectory $TargetRoot 'TargetRoot'
    $resolvedChildWorkingDirectory = Resolve-SafeChildWorkingDirectory $resolvedTarget $callerDirectory

    # This all-or-nothing preflight runs before Cargo or Start-Process.
    Assert-RequiredPortsAvailable $Services

    foreach ($service in $Services) {
        if ($null -ne (Read-OwnedProcess $service)) {
            throw "$($service.Name) is already running from this receipt"
        }
    }

    $env:CARGO_TARGET_DIR = $resolvedTarget
    & cargo build --locked --manifest-path $Manifest --package ovca-policy-tools --package ovca-coordinator-server --package ovca-engineer-server --package ovca-reviewer-server --package ovca-auditor-server
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with exit code $LASTEXITCODE" }

    $launched = [System.Collections.Generic.List[object]]::new()
    $previousMcpEnvironment = Set-CanonicalMcpEnvironment
    try {
        try {
            foreach ($service in $Services) {
                $stdout = Join-Path $resolvedLogs "$($service.Name).out.log"
                $stderr = Join-Path $resolvedLogs "$($service.Name).err.log"
                $executable = Join-Path $resolvedTarget "debug\$($service.Package).exe"
                if (-not (Test-Path -LiteralPath $executable)) {
                    throw "Missing built executable: $executable"
                }
                $executable = (Resolve-Path -LiteralPath $executable).Path
                $arguments = Join-WindowsCommandLineArguments @(
                    '--port',
                    [string]$service.Port,
                    '--root',
                    $resolvedData
                )
                $process = Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $resolvedChildWorkingDirectory -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
                $process.Refresh()
                $receipt = New-ProcessReceipt $service $process $executable
                $receiptPath = Receipt-Path $service.Name
                $launched.Add([pscustomobject]@{ Receipt = $receipt; ReceiptPath = $receiptPath })
                $receipt | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
            }
        } catch {
            Stop-InvocationProcesses $launched
            throw
        }
    } finally {
        Restore-McpEnvironment $previousMcpEnvironment
    }
    return
}

if ($Command -eq 'health') {
    foreach ($service in $Services) {
        $process = Read-OwnedProcess $service
        $httpOk = $false
        if ($null -ne $process) {
            try {
                Invoke-RestMethod "http://127.0.0.1:$($service.Port)/health" -TimeoutSec 2 | Out-Null
                $httpOk = $true
            } catch {
                $httpOk = $false
            }
        }
        [pscustomobject]@{
            service = $service.Name
            process_owned = ($null -ne $process)
            healthy = $httpOk
            port = $service.Port
        }
    }
    return
}

foreach ($service in $Services) {
    $receiptPath = Receipt-Path $service.Name
    $process = Read-OwnedProcess $service
    if ($null -ne $process) {
        Stop-Process -Id $process.Id
        $process.WaitForExit(10000) | Out-Null
    }
    if (Test-Path -LiteralPath $receiptPath) {
        Remove-Item -LiteralPath $receiptPath -Force
    }
}
