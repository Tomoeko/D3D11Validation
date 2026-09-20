# Only protected, deployed fixtures may choose executable arguments or output files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Unity.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Graphics.psm1')

function New-ValidationExecutableFixture([string]$Name, [string]$Arguments, [int]$Timeout, $Guard, $Output) {
    $policy = Get-Content -Raw (Join-Path $PSScriptRoot 'worker-policy.json') | ConvertFrom-Json
    return [pscustomobject]@{
        executable = Join-Path $PSScriptRoot $Name; binarySha256 = $policy.files.$Name
        workingDirectory = $PSScriptRoot; arguments = $Arguments; timeoutMs = $Timeout
        outputGuard = $Guard; outputDirectory = $Output
    }
}

function New-ValidationFixture($Job, $Session) {
    # A fixed rejection control proves pre-launch failures do not kill the worker.
    if ($Job.kind -ceq 'reject-session') { Stop-ValidationRequest 'unapproved_session' }
    if ($Job.kind -ceq 'diagnostic') {
        return New-ValidationExecutableFixture 'diagnostic.exe' ([string]$Job.durationMs) 2000 $null $null
    }
    $baseline = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'native-baseline.json') | ConvertFrom-Json
    $stateKey = [string]$Session.connectionState
    if ($stateKey -cnotin @($baseline.sessionProtocolsByConnectionState.PSObject.Properties.Name) -or
        $Session.executionContext -cne $baseline.executionContext -or $Session.processSessionId -ne $baseline.allowedSessionId -or
        $Session.clientProtocolType -ne $baseline.sessionProtocolsByConnectionState.$stateKey) {
        Stop-ValidationRequest 'unapproved_session'
    }
    $selection = '--luid ' + $baseline.adapter.luidLow + ' ' + ([uint32]$baseline.adapter.luidHigh)
    if ($Job.kind -cin @('reject-software','reject-other-gpu')) {
        $control = $baseline.rejectedAdapters.($Job.kind)
        $selection = '--luid ' + $control.luidLow + ' ' + ([uint32]$control.luidHigh)
    }
    if ($baseline.executionContext -ceq 'Session0') { $selection += ' --session0' }
    $unity = $Job.kind -ceq 'unity-startup' -or $Job.kind -cmatch '^unity-(recovered|regenerated|negative)-(on|off)-tier[0-2]-(traced|untraced|unhooked)$'
    if (($Job.kind -cnotin @('device','reject-software','reject-other-gpu') -and -not $unity) -or $Job.durationMs -ne 0 -or
        $Job.jobId -cnotmatch '^[0-9a-f]{32}$') { throw 'unapproved_fixture' }
    $parent = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation\data\native-jobs-v1'
    $parentGuard = [ValidationStore]::new($parent)
    try {
        $output = Join-Path $parent $Job.jobId
        if (Test-Path -LiteralPath $output) { throw 'output_already_exists' }
        $null = New-Item -ItemType Directory -Path $output
        $guard = [ValidationStore]::new($output)
    } finally { $parentGuard.Dispose() }
    try {
        if ($unity) { return New-ValidationUnityFixture $output $guard $Job.kind }
        return New-ValidationExecutableFixture 'device-probe.exe' ('"' + $output + '" ' + $selection) 15000 $guard $output
    } catch { $guard.Dispose(); throw }
}

function Get-ValidationArtifact($Guard, [string]$Name, [int]$Maximum) {
    $bytes = $Guard.ReadBytes($Name, $Maximum)
    return [ordered]@{name=$Name; byteLength=$bytes.Length; sha256=Get-ValidationDigest $bytes; base64=[Convert]::ToBase64String($bytes)}
}

function Get-ValidationFixtureFailureCode($Failure) {
    # Export only fixed diagnostic codes. Exception messages may contain private
    # host paths, so unknown failures must never be copied into remote results.
    $known = @('negative_fixture_unexpectedly_passed','unapproved_session_state',
        'adapter_identity_drift','operating_system_drift','device_preflight_mismatch',
        'runtime_identity_unavailable','runtime_identity_drift','session_drift',
        'failed_fixture_has_passing_report','runtime_signature_rejected',
        'runtime_signer_rejected','runtime_certificate_unavailable')
    $message = $Failure.Exception.Message
    if ($message -cin $known) { return $message }
    return 'fixture_validation_failed'
}

function Complete-ValidationFixture($Fixture, $Job, [string]$State) {
    if ($Job.kind -ceq 'diagnostic') { return $null }
    if ($Job.kind.StartsWith('unity-')) { return Complete-ValidationUnityFixture $Fixture $State }
    $artifacts = [Collections.Generic.List[object]]::new()
    if ($Fixture.outputGuard.Exists('adapters.json')) {
        $artifacts.Add((Get-ValidationArtifact $Fixture.outputGuard 'adapters.json' 65536))
    }
    $environment = $null
    if ($State -ceq 'completed') {
        if ($Job.kind -cne 'device') { throw 'negative_fixture_unexpectedly_passed' }
        $reportArtifact = Get-ValidationArtifact $Fixture.outputGuard 'report.json' 262144
        $pixelArtifact = Get-ValidationArtifact $Fixture.outputGuard 'pixels.bin' 256
        $report = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($reportArtifact.base64)) | ConvertFrom-Json
        $baseline = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'native-baseline.json') | ConvertFrom-Json
        if (-not $report.nativeHardwarePreflightPassed -or $report.fullQualificationComplete -or
            $report.adapter.software -or
            $report.featureLevel -ne $baseline.featureLevel -or $report.creationFlags -ne $baseline.creationFlags -or $report.elevated -or
            $report.format -cne 'R32G32B32A32_FLOAT' -or $report.width -ne 4 -or $report.height -ne 4 -or
            $report.pixelBytes -ne 256 -or -not $report.bitwiseReferenceMatch -or
            $pixelArtifact.sha256 -cne '0a78f8291ff96183544a2d497577bda6d191e0436e1050f60c7ef5854e627ee8') {
            throw 'device_preflight_mismatch'
        }
        $environment = Get-ValidationGraphicsEnvironment $report $baseline $baseline.creationFlags
        $artifacts.Add($reportArtifact); $artifacts.Add($pixelArtifact)
    } elseif ($Fixture.outputGuard.Exists('report.json')) { throw 'failed_fixture_has_passing_report' }
    return [ordered]@{
        artifacts = $artifacts; environment = $environment
        environmentSha256 = $(if ($null -eq $environment) { $null } else {
            Get-ValidationDigest ([Text.Encoding]::UTF8.GetBytes(($environment | ConvertTo-Json -Depth 10 -Compress)))
        })
    }
}
Export-ModuleMember -Function New-ValidationFixture, Complete-ValidationFixture, Get-ValidationFixtureFailureCode, Assert-ValidationRuntimeIdentity
