# Start only from the dedicated account's existing interactive, non-elevated logon.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Jobs.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Fixtures.psm1')
$session = & (Join-Path $PSScriptRoot 'Get-ValidationSession.ps1') | ConvertFrom-Json
if ($session.clientProtocolType -notin @(0,2) -or $session.connectionState -notin @(0,4)) { throw 'unsupported_session' }
$epoch = New-ValidationNonce
$deployment = Get-ValidationDeployment
$policy = Get-ValidationPolicy
# A held named mutex prevents simultaneous workers in different terminal sessions.
$singleton = [Threading.Mutex]::new($false, 'Global\D3D11ValidationWorker-v1')
try { $acquired = $singleton.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
if (-not $acquired) { $singleton.Dispose(); throw 'worker_already_running' }
$child = $null
$active = $null
$timer = $null
$fixture = $null
$execution = $null
try {
    while ($true) {
        $store = Open-ValidationStore
        try {
            $now = [DateTime]::UtcNow.ToString('o')
            Write-ValidationRecord $store 'worker.json' ([ordered]@{
                epoch = $epoch; utc = $now; deploymentSha256 = $deployment
                sessionId = $session.processSessionId; elevated = $false; dedicatedAccount = $true
                activeJob = $(if ($null -eq $active) { '' } else { $active.jobId })
            })
            if ($null -ne $active) {
                $name = 'job-' + $active.jobId + '.json'
                $latest = Read-ValidationRecord $store $name
                $terminal = ''
                if ($latest.cancelRequested) { $terminal = 'cancelled' }
                elseif ($timer.ElapsedMilliseconds -gt $fixture.timeoutMs) { $terminal = 'timed_out' }
                elseif ($child.Finished) {
                    $latest.exitCode = $child.ExitCode
                    $terminal = $(if ($latest.exitCode -eq 0) { 'completed' } else { 'failed' })
                }
                if ($terminal) {
                    $child.Dispose(); $child = $null
                    $fixtureEvidence = $null
                    $failureCode = $null
                    try { $fixtureEvidence = Complete-ValidationFixture $fixture $latest $terminal }
                    catch { $terminal = 'failed'; $failureCode = 'fixture_validation_failed' }
                    finally { if ($null -ne $fixture.outputGuard) { $fixture.outputGuard.Dispose() } }
                    $latest.state = $terminal; $latest.updatedUtc = $now
                    $latest.result = New-ValidationJobResult $latest $execution $fixtureEvidence $failureCode
                    Write-ValidationRecord $store $name $latest
                    $active = $null; $fixture = $null; $execution = $null
                }
            }
            if ($null -eq $active) {
                foreach ($path in $store.Jobs()) {
                    $name = [IO.Path]::GetFileName($path)
                    $job = Read-ValidationRecord $store $name
                    if ($job.state -cin @('queued','running') -and $job.workerEpoch -cne $epoch) {
                        $job.state = 'stale'; $job.updatedUtc = $now
                        Write-ValidationRecord $store $name $job
                    }
                    if ($job.state -cne 'queued') { continue }
                    $null = ConvertFrom-ValidationRequest 'submit' $job.requestText
                    if ($job.inputSha256 -cne (Get-ValidationDigest ([Text.Encoding]::UTF8.GetBytes($job.requestText))) -or
                        $job.deploymentSha256 -cne $deployment) { throw 'job_binding_mismatch' }
                    $job.state = 'running'; $job.updatedUtc = $now
                    Write-ValidationRecord $store $name $job
                    $timer = [Diagnostics.Stopwatch]::StartNew()
                    $execution = [pscustomobject]@{timer=$timer; session=$null; binarySha256=$null; childPid=$null}
                    try {
                        $execution.session = & (Join-Path $PSScriptRoot 'Get-ValidationSession.ps1') | ConvertFrom-Json
                        $fixture = New-ValidationFixture $job $execution.session
                        $exe = Join-Path $PSScriptRoot $fixture.executable
                        $execution.binarySha256 = $policy.files.($fixture.executable)
                        if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $execution.binarySha256) {
                            throw 'executable_hash_mismatch'
                        }
                        $child = [ValidationChild]::new($exe, $fixture.arguments, $PSScriptRoot)
                        $execution.childPid = $child.Id
                        $active = $job
                    } catch {
                        if ($null -ne $child) { $child.Dispose(); $child = $null }
                        if ($null -ne $fixture -and $null -ne $fixture.outputGuard) { $fixture.outputGuard.Dispose() }
                        $code = 'fixture_start_failed'
                        if ($_.Exception.Data['validationCode'] -ceq 'unapproved_session') { $code = 'unapproved_session' }
                        $job.state = 'failed'; $job.updatedUtc = [DateTime]::UtcNow.ToString('o')
                        $job.result = New-ValidationJobResult $job $execution $null $code
                        Write-ValidationRecord $store $name $job
                        $fixture = $null; $execution = $null
                    }
                    break
                }
            }
        } finally { $store.Dispose() }
        Start-Sleep -Milliseconds 100
    }
} finally {
    if ($null -ne $child) { $child.Dispose() }
    if ($null -ne $fixture -and $null -ne $fixture.outputGuard) { $fixture.outputGuard.Dispose() }
    $singleton.ReleaseMutex(); $singleton.Dispose()
}
