# Immutable management code. In particular, elevated maintenance must never import
# modules from the active worker: those are a separate, less-privileged release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Maintenance.psm1')
$script:root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$script:control = Join-Path $script:root 'setup/headless-v1'
$script:inbox = Join-Path $script:root 'data/maintenance-v1'
$script:utf8 = [Text.UTF8Encoding]::new($false,$true)

function Read-HeadlessJson([string]$Path, [int]$Limit = 16384) {
    return $script:utf8.GetString([ValidationMaintenance]::ReadSnapshot($Path,$Limit)) | ConvertFrom-Json
}
function Open-HeadlessReadGuard {
    return [IO.FileStream]::new((Join-Path $script:control 'activation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Read-HeadlessActive {
    $path = Join-Path $script:control 'active.json'
    Assert-ProtectedPath $script:root; Assert-ProtectedPath (Split-Path $script:control)
    Assert-ProtectedPath $script:control; Assert-ProtectedPath $path
    $state = Read-HeadlessJson $path
    if (($state.PSObject.Properties.Name | Sort-Object) -join ',' -cne 'deployment,generation,policySha256,schema' -or
        $state.schema -cne 'd3d11-active-deployment/v1' -or $state.deployment -cnotmatch '^worker-v[1-9][0-9]{0,8}\z' -or
        $state.policySha256 -cnotmatch '^[0-9a-f]{64}\z' -or
        ($state.generation -isnot [int] -and $state.generation -isnot [long]) -or
        $state.generation -lt 1 -or $state.generation -gt 999999999) { throw 'maintenance_active_identity' }
    return $state
}
function Get-HeadlessWorkerPath($State) {
    $programRoot = Join-Path $script:root 'program'
    $program = Join-Path $programRoot $State.deployment
    Assert-ProtectedPath $programRoot; Assert-ProtectedPath $program
    $policyPath = Join-Path $program 'worker-policy.json'
    Assert-ProtectedPath $policyPath
    $bytes = [ValidationMaintenance]::ReadSnapshot($policyPath,65536)
    if ((Get-MaintenanceDigest $bytes) -cne $State.policySha256) { throw 'maintenance_policy_hash' }
    $policy = $script:utf8.GetString($bytes) | ConvertFrom-Json
    if ($policy.schema -cne 'd3d11-worker-policy/v1' -or $policy.executionContext -cne 'Session0') { throw 'maintenance_policy_context' }
    foreach ($file in $policy.files.PSObject.Properties) {
        if ($file.Name -cnotmatch '^[A-Za-z0-9.-]+\z' -or $file.Name -in @('.','..') -or $file.Value -cnotmatch '^[0-9a-f]{64}\z') { throw 'maintenance_policy_member' }
        $path = Join-Path $program $file.Name
        Assert-ProtectedPath $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.Value) { throw 'maintenance_worker_hash' }
    }
    foreach ($required in @('Start-ValidationWorker.ps1','Invoke-ValidationJobGateway.ps1','Validation.Runtime.cs')) {
        if (-not $policy.files.PSObject.Properties[$required]) { throw 'maintenance_worker_incomplete' }
    }
    return $program
}
function Read-HeadlessConfiguration {
    $path = Join-Path $script:control 'configuration.json'
    Assert-ProtectedPath $path
    $configuration = Read-HeadlessJson $path
    if ($configuration.schema -cne 'd3d11-headless-configuration/v1') { throw 'maintenance_configuration' }
    return $configuration
}
function Read-HeadlessPublicKey {
    $configuration = Read-HeadlessConfiguration
    $path = Join-Path $script:control 'publisher.xml'
    Assert-ProtectedPath $path
    $bytes = [ValidationMaintenance]::ReadSnapshot($path,4096)
    if ((Get-MaintenanceDigest $bytes) -cne $configuration.publisherSha256) { throw 'maintenance_publisher_identity' }
    return $script:utf8.GetString($bytes)
}
function Get-HeadlessStatus {
    $state = Read-HeadlessActive
    $receiptPath = Join-Path $script:control 'receipt.json'
    $receipt = if (Test-Path -LiteralPath $receiptPath) { Read-HeadlessJson $receiptPath } else { $null }
    return [ordered]@{schema='d3d11-maintenance-status/v1'; active=$state; receipt=$receipt
        requestPending=(Test-Path -LiteralPath (Join-Path $script:inbox 'request.json'))
        rebootQualified=$false; cleanInstallQualified=$false}
}
function Invoke-HeadlessMaintenanceGateway([string]$Operation) {
    # Async read has a deadline so an authenticated client cannot hold a process
    # indefinitely by keeping stdin open. Process exit closes the blocked reader.
    $text = [ValidationMaintenance]::ReadInput()
    if ($Operation -ceq 'maintenance-status') {
        if ($text -cne '') { throw 'maintenance_status_input' }
        return Get-HeadlessStatus
    }
    $verified = Read-MaintenanceEnvelope $text (Read-HeadlessPublicKey)
    $state = Read-HeadlessActive
    $receiptPath = Join-Path $script:control ('receipts/' + $verified.fields['requestId'] + '.json')
    if (Test-Path -LiteralPath $receiptPath) {
        $receipt = Read-HeadlessJson $receiptPath
        if ($receipt.requestId -ceq $verified.fields['requestId']) {
            if ($receipt.requestSha256 -cne $verified.sha256) { throw 'maintenance_nonce_conflict' }
            return $receipt
        }
    }
    Assert-MaintenanceTransition $verified.fields $state ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $lock = [IO.FileStream]::new((Join-Path $script:inbox 'inbox.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $path = Join-Path $script:inbox 'request.json'
        if (Test-Path -LiteralPath $path) {
            $pending = Read-MaintenanceEnvelope ($script:utf8.GetString([ValidationMaintenance]::ReadSnapshot($path,16384))) (Read-HeadlessPublicKey)
            if ($pending.sha256 -cne $verified.sha256) { throw 'maintenance_busy' }
        } else { Write-MaintenanceRecord $path ($text | ConvertFrom-Json) }
    } finally { $lock.Dispose() }
    return [ordered]@{schema='d3d11-maintenance-receipt/v1'; requestId=$verified.fields['requestId']; requestSha256=$verified.sha256; phase='queued'}
}
function Stop-HeadlessWorker($Task) {
    $Task.Enabled = $false
    $Task.Stop(0)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $workers = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
            $_.CommandLine -and $_.CommandLine.Replace('\','/').Contains($script:root.Replace('\','/') + '/program/') -and
            ($_.CommandLine.Contains('Start-ValidationWorker.ps1') -or $_.CommandLine.Contains('Start-ValidationHeadlessWorker.ps1'))
        })
        if ($Task.GetInstances(0).Count -eq 0 -and $workers.Count -eq 0) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'maintenance_worker_stop_timeout' }
        Start-Sleep -Milliseconds 100
    } while ($true)
}
function Open-HeadlessWriteGuard {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        try { return [IO.FileStream]::new((Join-Path $script:control 'activation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'maintenance_gateway_busy' }
            Start-Sleep -Milliseconds 100
        }
    } while ($true)
}
function Assert-HeadlessTask($Task) {
    Import-Module (Join-Path $PSScriptRoot 'Validation.Task.psm1')
    $configuration = Read-HeadlessConfiguration
    $xml = $script:utf8.GetString([ValidationMaintenance]::ReadSnapshot((Join-Path $script:control 'worker-task.xml'),32768))
    Assert-ValidationTaskDefinition $Task.Definition.XmlText $xml $configuration.accountSid ([bool]$Task.Enabled)
    Assert-ValidationTaskSecurity ($Task.GetSecurityDescriptor(7)) $configuration.workerTaskSddl
}

Export-ModuleMember -Function Read-HeadlessJson, Open-HeadlessReadGuard, Read-HeadlessActive, Get-HeadlessWorkerPath,
    Read-HeadlessConfiguration, Read-HeadlessPublicKey, Get-HeadlessStatus, Invoke-HeadlessMaintenanceGateway,
    Stop-HeadlessWorker, Open-HeadlessWriteGuard, Assert-HeadlessTask
