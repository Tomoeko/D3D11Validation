Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Unity.psm1')
$log = [Text.Encoding]::UTF8.GetBytes("Personal-path-sentinel`nDirect3D11 Example Hardware Adapter`nEntryPointNotFoundException: DXBCTraceBegin")
$result = Get-ValidationUnityStartupSummary $log $false
if (-not $result.direct3d11Mentioned -or -not $result.expectedGpuMentioned -or
    -not $result.traceEntryUnavailable -or $result.loadedRuntimeQualified -or
    $result.fullQualificationComplete -or $result.captureAvailable -or
    ($result | ConvertTo-Json) -match 'Personal-path-sentinel') { throw 'Startup privacy or scope violation' }
$failed = Get-ValidationUnityStartupSummary ([Text.Encoding]::UTF8.GetBytes('Failed to initialize graphics')) $false
if (-not $failed.graphicsInitializationFailed -or $failed.direct3d11Mentioned) { throw 'Startup failure was misreported' }
'PASS: Unity startup reports omit raw logs and cannot claim graphics qualification'
