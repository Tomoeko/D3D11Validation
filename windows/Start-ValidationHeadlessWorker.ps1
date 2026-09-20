# The one S4U task always targets this protected launcher. Updates change data only.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Headless.psm1')
$guard = Open-HeadlessReadGuard
try {
    $state = Read-HeadlessActive
    $program = Get-HeadlessWorkerPath $state
    & (Join-Path $program 'Start-ValidationWorker.ps1')
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
} finally { $guard.Dispose() }
