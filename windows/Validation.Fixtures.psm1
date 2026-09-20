# Only protected, deployed fixtures may choose executable arguments or output files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')

function New-ValidationFixture($Job, $Session) {
    # A fixed rejection control proves pre-launch failures do not kill the worker.
    if ($Job.kind -ceq 'reject-session') { Stop-ValidationRequest 'unapproved_session' }
    if ($Job.kind -ceq 'diagnostic') {
        return [pscustomobject]@{
            executable = 'diagnostic.exe'; arguments = [string]$Job.durationMs
            timeoutMs = 2000; outputGuard = $null; outputDirectory = $null
        }
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
    if ($Job.kind -cnotin @('device','reject-software','reject-other-gpu') -or $Job.durationMs -ne 0 -or
        $Job.jobId -cnotmatch '^[0-9a-f]{32}$') { throw 'unapproved_fixture' }
    $parent = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation\data\native-jobs-v1'
    $parentGuard = [ValidationStore]::new($parent)
    try {
        $output = Join-Path $parent $Job.jobId
        if (Test-Path -LiteralPath $output) { throw 'output_already_exists' }
        $null = New-Item -ItemType Directory -Path $output
        $guard = [ValidationStore]::new($output)
    } finally { $parentGuard.Dispose() }
    return [pscustomobject]@{
        executable = 'device-probe.exe'; arguments = '"' + $output + '" ' + $selection
        timeoutMs = 15000; outputGuard = $guard; outputDirectory = $output
    }
}

function Get-ValidationArtifact($Guard, [string]$Name, [int]$Maximum) {
    $bytes = $Guard.ReadBytes($Name, $Maximum)
    return [ordered]@{name=$Name; byteLength=$bytes.Length; sha256=Get-ValidationDigest $bytes; base64=[Convert]::ToBase64String($bytes)}
}

function Assert-ValidationRuntimeIdentity($Identity, $Pinned) {
    foreach ($field in @('file','version','sha256')) {
        if ($Identity.$field -cne $Pinned.$field) { throw 'runtime_identity_drift' }
    }
    if ($Identity.signatureStatus -cne 'Valid') { throw 'runtime_signature_rejected' }
    # Windows can select either a catalog or embedded signature for the same DLL.
    # Pin the exact approved certificate, signature type and subject per file.
    $matches = @($Pinned.signatures | Where-Object {
        $_.certificateSha256 -ceq $Identity.certificateSha256 -and
        $_.type -ceq $Identity.signatureType -and $_.signer -ceq $Identity.signer
    })
    if ($matches.Count -ne 1) { throw 'runtime_signer_rejected' }
}

function Get-ValidationRuntimeIdentity([string]$Path, $Pinned) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate) { throw 'runtime_certificate_unavailable' }
    $identity = [ordered]@{
        file = [IO.Path]::GetFileName($Path)
        version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        signatureStatus = [string]$signature.Status; signer = $signature.SignerCertificate.Subject
        signatureType = [string]$signature.SignatureType
        certificateSha256 = Get-ValidationDigest $signature.SignerCertificate.RawData
    }
    Assert-ValidationRuntimeIdentity $identity $Pinned
    return $identity
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
        $stateKey = [string]$report.connectionState
        if ($stateKey -cnotin @($baseline.sessionProtocolsByConnectionState.PSObject.Properties.Name) -or
            $report.executionContext -cne $baseline.executionContext) { throw 'unapproved_session_state' }
        foreach ($field in $baseline.adapter.PSObject.Properties) {
            if ($report.adapter.($field.Name) -cne $field.Value) { throw 'adapter_identity_drift' }
        }
        if ([Environment]::OSVersion.Version.ToString() -cne $baseline.operatingSystem) { throw 'operating_system_drift' }
        if (-not $report.nativeHardwarePreflightPassed -or $report.fullQualificationComplete -or
            $report.adapter.software -or
            $report.featureLevel -ne $baseline.featureLevel -or $report.creationFlags -ne $baseline.creationFlags -or $report.elevated -or
            $report.format -cne 'R32G32B32A32_FLOAT' -or $report.width -ne 4 -or $report.height -ne 4 -or
            $report.pixelBytes -ne 256 -or -not $report.bitwiseReferenceMatch -or
            $pixelArtifact.sha256 -cne '0a78f8291ff96183544a2d497577bda6d191e0436e1050f60c7ef5854e627ee8') {
            throw 'device_preflight_mismatch'
        }
        $identities = [Collections.Generic.List[object]]::new()
        foreach ($name in @('d3d11.dll','dxgi.dll','nvldumdx.dll','nvwgf2umx.dll')) {
            $paths = @($report.loadedModules | Where-Object { [IO.Path]::GetFileName($_) -ieq $name })
            if ($paths.Count -ne 1) { throw 'runtime_identity_unavailable' }
            $pinned = @($baseline.runtimeIdentities | Where-Object { $_.file -ceq $name })
            if ($pinned.Count -ne 1) { throw 'runtime_identity_drift' }
            $identity = Get-ValidationRuntimeIdentity $paths[0] $pinned[0]
            $identities.Add($identity)
        }
        $sessionAfter = & (Join-Path $PSScriptRoot 'Get-ValidationSession.ps1') -Context $baseline.executionContext | ConvertFrom-Json
        if ($sessionAfter.processSessionId -ne $report.sessionId -or
            $sessionAfter.clientProtocolType -ne $report.clientProtocolType -or
            $sessionAfter.connectionState -ne $report.connectionState -or
            $report.sessionId -ne $baseline.allowedSessionId -or
            $report.clientProtocolType -ne $baseline.sessionProtocolsByConnectionState.$stateKey) { throw 'session_drift' }
        $environment = [ordered]@{
            adapter = $report.adapter; featureLevel = $report.featureLevel; creationFlags = $report.creationFlags
            runtimeIdentities = $identities; operatingSystem = [Environment]::OSVersion.Version.ToString()
            processSessionId = $report.sessionId; clientProtocolType = $report.clientProtocolType
            executionContext = $report.executionContext
            connectionState = $report.connectionState; nativeHardwarePreflightPassed = $true
            fullQualificationComplete = $false
        }
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
