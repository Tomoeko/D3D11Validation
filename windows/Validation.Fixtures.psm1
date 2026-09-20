# Only protected, deployed fixtures may choose executable arguments or output files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Unity.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Graphics.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Adapter.psm1')

function New-ValidationExecutableFixture([string]$Name, [string]$Arguments, [int]$Timeout, $Guard, $Output) {
    $policy = Get-Content -Raw (Join-Path $PSScriptRoot 'worker-policy.json') | ConvertFrom-Json
    return [pscustomobject]@{
        executable = Join-Path $PSScriptRoot $Name; binarySha256 = $policy.files.$Name
        workingDirectory = $PSScriptRoot; arguments = $Arguments; timeoutMs = $Timeout
        outputGuard = $Guard; outputDirectory = $Output
    }
}

function Get-ValidationCurrentSelection([string]$Output, $Guard, $Baseline, $Session, [string]$Kind) {
    # Inventory is a separate bounded process, using the same pinned executable
    # as the native fixture. It creates no D3D device and has no fallback mode.
    $directory = Join-Path $Output 'selection'
    $null = New-Item -ItemType Directory -Path $directory
    $inventoryGuard = [ValidationStore]::new($directory)
    $child = $null
    $failureStage = 'adapter_inventory_launch_failed'
    try {
        $arguments = '"' + $directory + '"'
        if ($Baseline.executionContext -ceq 'Session0') { $arguments += ' --session0' }
        $probe = New-ValidationExecutableFixture 'device-probe.exe' $arguments 5000 $null $null
        if ((Get-FileHash -LiteralPath $probe.executable).Hash.ToLowerInvariant() -cne $probe.binarySha256) {
            throw 'executable_hash_mismatch'
        }
        $child = [ValidationChild]::new($probe.executable,$probe.arguments,$probe.workingDirectory)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not $child.Finished -and $timer.ElapsedMilliseconds -lt 5000) { Start-Sleep -Milliseconds 25 }
        if (-not $child.Finished -or $child.ExitCode -ne 0) { throw 'adapter_inventory_unavailable' }
        $child.Dispose(); $child = $null
        $failureStage = 'adapter_inventory_read_failed'
        $bytes = $inventoryGuard.ReadBytes('adapters.json',65536)
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        $failureStage = 'adapter_inventory_selection_failed'
        $adapter = Get-ValidationAdapterSelection ($text | ConvertFrom-Json) $Baseline $Kind
        $failureStage = 'adapter_inventory_publish_failed'
        $Guard.Write('selection-adapters.json',$text)
        return [ordered]@{mode='unique-current-inventory'; adapter=$adapter
            inventorySha256=Get-ValidationDigest $bytes; probeSha256=$probe.binarySha256; bootUtc=$Session.bootUtc}
    } catch {
        $code = Get-ValidationFixtureFailureCode $_
        if ($code -ceq 'fixture_validation_failed') { $_.Exception.Data['validationCode'] = $failureStage }
        throw
    } finally {
        if ($null -ne $child) { $child.Dispose() }
        $inventoryGuard.Dispose()
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
        $selectionKind = if ($unity) { 'device' } else { $Job.kind }
        $selection = Get-ValidationCurrentSelection $output $guard $baseline $Session $selectionKind
        if ($unity) { return New-ValidationUnityFixture $output $guard $Job.kind $selection }
        $arguments = '"' + $output + '" --luid ' + $selection.adapter.luidLow + ' ' + $selection.adapter.luidHigh
        if ($baseline.executionContext -ceq 'Session0') { $arguments += ' --session0' }
        $fixture = New-ValidationExecutableFixture 'device-probe.exe' $arguments 15000 $guard $output
        $fixture | Add-Member -NotePropertyName selection -NotePropertyValue $selection
        return $fixture
    } catch { $guard.Dispose(); throw }
}

function Get-ValidationArtifact($Guard, [string]$Name, [int]$Maximum) {
    $bytes = $Guard.ReadBytes($Name, $Maximum)
    return [ordered]@{name=$Name; byteLength=$bytes.Length; sha256=Get-ValidationDigest $bytes; base64=[Convert]::ToBase64String($bytes)}
}

function Get-ValidationFixtureFailureCode($Failure) {
    # Export only fixed diagnostic codes. Exception messages may contain private
    # host paths, so unknown failures must never be copied into remote results.
    $known = @('adapter_selection_contract','adapter_inventory_count','adapter_inventory_shape',
        'adapter_inventory_integer','adapter_inventory_duplicate_luid','adapter_policy_shape',
        'adapter_policy_integer','adapter_unique_identity_unavailable','adapter_inventory_unavailable',
        'adapter_inventory_launch_failed','adapter_inventory_read_failed','adapter_inventory_selection_failed',
        'adapter_inventory_publish_failed','executable_hash_mismatch','negative_fixture_unexpectedly_passed','unapproved_session_state',
        'adapter_identity_drift','operating_system_drift','device_preflight_mismatch',
        'runtime_identity_unavailable','runtime_identity_drift','session_drift',
        'failed_fixture_has_passing_report','runtime_signature_rejected',
        'runtime_signer_rejected','runtime_certificate_unavailable')
    $tag = $Failure.Exception.Data['validationCode']
    if ($tag -is [string] -and $tag -cin $known) { return $tag }
    $message = $Failure.Exception.Message
    if ($message -cin $known) { return $message }
    return 'fixture_validation_failed'
}

function Complete-ValidationFixture($Fixture, $Job, [string]$State) {
    if ($Job.kind -ceq 'diagnostic') { return $null }
    if ($Job.kind.StartsWith('unity-')) { return Complete-ValidationUnityFixture $Fixture $State }
    $artifacts = [Collections.Generic.List[object]]::new()
    $artifacts.Add((Get-ValidationArtifact $Fixture.outputGuard 'selection-adapters.json' 65536))
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
        $environment = Get-ValidationGraphicsEnvironment $report $baseline $Fixture.selection $baseline.creationFlags
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
