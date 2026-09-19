Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1') -Force
if (-not ('ValidationStore' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Validation.Runtime.cs') }
$script:root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$script:queue = Join-Path $script:root 'data\queue-v1'
$script:policy = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'worker-policy.json') | ConvertFrom-Json
if ($script:policy.schema -cne 'd3d11-worker-policy/v1') { throw 'invalid_policy' }
foreach ($entry in $script:policy.files.PSObject.Properties) {
    if ($entry.Name -cnotmatch '^[A-Za-z0-9.-]+$' -or $entry.Value -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot $entry.Name)).Hash.ToLowerInvariant() -cne $entry.Value) {
        throw 'deployment_hash_mismatch'
    }
}
$script:deploymentHash = Get-ValidationDigest ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'worker-policy.json')))

function Open-ValidationStore { return [ValidationStore]::new($script:queue) }
function Read-ValidationRecord($Store, [string]$Name) { return $Store.Read($Name) | ConvertFrom-Json }
function Write-ValidationRecord($Store, [string]$Name, $Record) { $Store.Write($Name, ($Record | ConvertTo-Json -Depth 20 -Compress)) }
function Get-ValidationDeployment { return $script:deploymentHash }
function Get-ValidationProgram { return $PSScriptRoot }
function Get-ValidationPolicy { return $script:policy }
function Get-ValidationHeartbeat($Store) {
    if (-not $Store.Exists('worker.json')) { Stop-ValidationRequest 'worker_unavailable' }
    $heartbeat = Read-ValidationRecord $Store 'worker.json'
    $age = ([DateTime]::UtcNow - [DateTime]::Parse($heartbeat.utc).ToUniversalTime()).TotalSeconds
    if ($age -lt 0 -or $age -gt 10 -or $heartbeat.deploymentSha256 -cne $script:deploymentHash) {
        Stop-ValidationRequest 'worker_unavailable'
    }
    return $heartbeat
}
function Get-ValidationJob($Store, $Request) {
    $name = 'job-' + $Request['jobId'] + '.json'
    if (-not $Store.Exists($name)) { Stop-ValidationRequest 'job_unavailable' }
    $job = Read-ValidationRecord $Store $name
    if ($job.capability -cne $Request['capability']) { Stop-ValidationRequest 'job_unavailable' }
    if ($job.deploymentSha256 -cne $script:deploymentHash) { Stop-ValidationRequest 'stale_deployment' }
    return $job
}
function Get-ValidationJobSummary($Job, [string]$Nonce) {
    return [ordered]@{
        schema = 'd3d11-job-response/v1'; nonce = $Nonce; jobId = $Job.jobId
        state = $Job.state; inputSha256 = $Job.inputSha256
        deploymentSha256 = $Job.deploymentSha256; executionNonce = $Job.executionNonce
        createdUtc = $Job.createdUtc; updatedUtc = $Job.updatedUtc
    }
}
function Invoke-ValidationOperation([string]$Operation, [string]$Text) {
    $request = ConvertFrom-ValidationRequest $Operation $Text
    $store = Open-ValidationStore
    try {
        if ($Operation -ceq 'submit') {
            $inputHash = Get-ValidationDigest ([Text.Encoding]::UTF8.GetBytes($Text))
            $indexName = 'request-' + $request['nonce'] + '.json'
            if ($store.Exists($indexName)) {
                $initial = Read-ValidationRecord $store $indexName
                if ($initial.inputSha256 -cne $inputHash) { Stop-ValidationRequest 'nonce_conflict' }
                if ($initial.deploymentSha256 -cne $script:deploymentHash) { Stop-ValidationRequest 'stale_deployment' }
            } else {
                $null = Get-ValidationHeartbeat $store
                if (@($store.Jobs()).Count -ge 128) { Stop-ValidationRequest 'job_quota_reached' }
                $now = [DateTime]::UtcNow.ToString('o')
                $initial = [pscustomobject][ordered]@{
                    jobId = [Guid]::NewGuid().ToString('N'); capability = New-ValidationNonce
                    requestNonce = $request['nonce']; requestText = $Text; inputSha256 = $inputHash
                    deploymentSha256 = $script:deploymentHash; sourceRevision = $script:policy.sourceRevision
                    kind = $request['kind']; durationMs = [int]$request['durationMs']; state = 'submitted'
                    createdUtc = $now; updatedUtc = $now; workerEpoch = ''; executionNonce = ''
                    cancelRequested = $false; exitCode = $null; result = $null
                }
                # The immutable nonce record precedes mutable state. A lost connection
                # between these writes can reconstruct only the initial job, never replay it.
                Write-ValidationRecord $store $indexName $initial
            }
            $name = 'job-' + $initial.jobId + '.json'
            if (-not $store.Exists($name)) { Write-ValidationRecord $store $name $initial }
            $job = Read-ValidationRecord $store $name
            $response = Get-ValidationJobSummary $job $request['nonce']
            $response['capability'] = $job.capability
            return $response
        }
        $job = Get-ValidationJob $store $request
        $name = 'job-' + $job.jobId + '.json'
        if ($Operation -ceq 'start' -and $job.state -ceq 'submitted') {
            if (([DateTime]::UtcNow - [DateTime]::Parse($job.createdUtc).ToUniversalTime()).TotalMinutes -gt 5) {
                $job.state = 'stale'
            } else {
                $heartbeat = Get-ValidationHeartbeat $store
                $job.workerEpoch = $heartbeat.epoch
                $job.executionNonce = New-ValidationNonce
                $job.state = 'queued'
            }
            $job.updatedUtc = [DateTime]::UtcNow.ToString('o')
            Write-ValidationRecord $store $name $job
        } elseif ($Operation -ceq 'cancel') {
            if ($job.state -cin @('submitted', 'queued')) { $job.state = 'cancelled' }
            if ($job.state -ceq 'running') { $job.cancelRequested = $true }
            $job.updatedUtc = [DateTime]::UtcNow.ToString('o')
            Write-ValidationRecord $store $name $job
        }
        $response = Get-ValidationJobSummary $job $request['nonce']
        if ($Operation -ceq 'results') {
            if ($job.state -cnotin @('completed', 'cancelled', 'timed_out', 'failed', 'stale')) {
                Stop-ValidationRequest 'results_incomplete'
            }
            $response['result'] = $job.result
            $response['exitCode'] = $job.exitCode
        }
        return $response
    } finally { $store.Dispose() }
}
Export-ModuleMember -Function Open-ValidationStore, Read-ValidationRecord, Write-ValidationRecord,
    Get-ValidationDeployment, Get-ValidationProgram, Get-ValidationPolicy,
    Get-ValidationHeartbeat, Invoke-ValidationOperation
