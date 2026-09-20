# Shared native runtime and actual-device identity validation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Adapter.psm1')

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

function Get-ValidationGraphicsEnvironment($Report, $Baseline, $Selection, [int]$CreationFlags, [int]$FeatureLevel = $Baseline.featureLevel) {
    $stateKey = [string]$report.connectionState
    if ($stateKey -cnotin @($baseline.sessionProtocolsByConnectionState.PSObject.Properties.Name) -or
        $report.executionContext -cne $baseline.executionContext) { throw 'unapproved_session_state' }
    Assert-ValidationActualAdapter $Report.adapter $Selection.adapter
    if ([Environment]::OSVersion.Version.ToString() -cne $baseline.operatingSystem) { throw 'operating_system_drift' }
    if ($Report.adapter.software -or $Report.elevated -or
        $Report.featureLevel -ne $FeatureLevel -or $Report.creationFlags -ne $CreationFlags) {
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
    if ($sessionAfter.bootUtc -cne $Selection.bootUtc -or
        $sessionAfter.processSessionId -ne $report.sessionId -or
        $sessionAfter.clientProtocolType -ne $report.clientProtocolType -or
        $sessionAfter.connectionState -ne $report.connectionState -or
        $report.sessionId -ne $baseline.allowedSessionId -or
        $report.clientProtocolType -ne $baseline.sessionProtocolsByConnectionState.$stateKey) { throw 'session_drift' }
    $environment = [ordered]@{
        adapter = $report.adapter; adapterSelection = $Selection; bootUtc = $Selection.bootUtc
        featureLevel = $report.featureLevel; creationFlags = $report.creationFlags
        runtimeIdentities = $identities; operatingSystem = [Environment]::OSVersion.Version.ToString()
        processSessionId = $report.sessionId; clientProtocolType = $report.clientProtocolType
        executionContext = $report.executionContext
        connectionState = $report.connectionState; nativeHardwarePreflightPassed = $true
        fullQualificationComplete = $false
    }
    return $environment
}

Export-ModuleMember -Function Assert-ValidationRuntimeIdentity, Get-ValidationRuntimeIdentity, Get-ValidationGraphicsEnvironment
