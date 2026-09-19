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
    if ($Session.connectionState -notin @(0,4) -or $Session.processSessionId -ne $baseline.allowedSessionId -or
        $Session.clientProtocolType -ne $baseline.sessionProtocolsByConnectionState.$stateKey) {
        Stop-ValidationRequest 'unapproved_session'
    }
    $selection = '--luid ' + $baseline.adapter.luidLow + ' ' + ([uint32]$baseline.adapter.luidHigh)
    if ($Job.kind -ceq 'reject-software') { $selection = [string]$baseline.softwareOrdinalsByConnectionState.$stateKey }
    if ($Job.kind -ceq 'reject-other-gpu') { $selection = [string]$baseline.otherGpuOrdinalsByConnectionState.$stateKey }
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

function Get-ValidationRuntimeIdentity([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows(?: Hardware Compatibility Publisher)?(?:,|$)') {
        throw 'runtime_signature_rejected'
    }
    return [ordered]@{
        file = [IO.Path]::GetFileName($Path)
        version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        signatureStatus = 'Valid'; signer = $signature.SignerCertificate.Subject
    }
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
        if ($report.connectionState -notin @(0,4)) { throw 'unapproved_session_state' }
        foreach ($field in $baseline.adapter.PSObject.Properties) {
            if ($field.Name -cne 'ordinal' -and $report.adapter.($field.Name) -cne $field.Value) { throw 'adapter_identity_drift' }
        }
        if ([Environment]::OSVersion.Version.ToString() -cne $baseline.operatingSystem) { throw 'operating_system_drift' }
        if (-not $report.nativeHardwarePreflightPassed -or $report.fullQualificationComplete -or
            $report.adapter.ordinal -ne $baseline.adapterOrdinalsByConnectionState.$stateKey -or $report.adapter.software -or
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
            $identity = Get-ValidationRuntimeIdentity $paths[0]
            $pinned = @($baseline.runtimeIdentities | Where-Object { $_.file -ceq $name })
            if ($pinned.Count -ne 1 -or $identity.version -cne $pinned[0].version -or
                $identity.sha256 -cne $pinned[0].sha256) { throw 'runtime_identity_drift' }
            $identities.Add($identity)
        }
        $sessionAfter = & (Join-Path $PSScriptRoot 'Get-ValidationSession.ps1') | ConvertFrom-Json
        if ($sessionAfter.processSessionId -ne $report.sessionId -or
            $sessionAfter.clientProtocolType -ne $report.clientProtocolType -or
            $sessionAfter.connectionState -ne $report.connectionState -or
            $report.sessionId -ne $baseline.allowedSessionId -or
            $report.clientProtocolType -ne $baseline.sessionProtocolsByConnectionState.$stateKey) { throw 'session_drift' }
        $environment = [ordered]@{
            adapter = $report.adapter; featureLevel = $report.featureLevel; creationFlags = $report.creationFlags
            runtimeIdentities = $identities; operatingSystem = [Environment]::OSVersion.Version.ToString()
            processSessionId = $report.sessionId; clientProtocolType = $report.clientProtocolType
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
Export-ModuleMember -Function New-ValidationFixture, Complete-ValidationFixture
