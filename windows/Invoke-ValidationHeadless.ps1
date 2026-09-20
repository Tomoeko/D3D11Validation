# Stable forced-command router. Maintenance never enters the fixture submission API.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$operation = $env:SSH_ORIGINAL_COMMAND
if ($operation -cnotin @('submit','start','status','results','cancel','maintenance','maintenance-status')) {
    [Console]::Error.WriteLine('{"error":"unsupported_operation"}'); exit 64
}
try {
    Import-Module (Join-Path $PSScriptRoot 'Validation.Headless.psm1')
    if ($operation -cin @('maintenance','maintenance-status')) {
        $response = Invoke-HeadlessMaintenanceGateway $operation
        [Console]::WriteLine(($response | ConvertTo-Json -Depth 10 -Compress))
    } else {
        # A held shared read denies maintenance activation until this bounded
        # gateway invocation exits. The worker is stopped separately before swap.
        $guard = Open-HeadlessReadGuard
        try {
            $state = Read-HeadlessActive
            $program = Get-HeadlessWorkerPath $state
            $LASTEXITCODE = 0
            & (Join-Path $program 'Invoke-ValidationJobGateway.ps1')
            $code = $LASTEXITCODE
        } finally { $guard.Dispose() }
        exit $code
    }
} catch { [Console]::Error.WriteLine('{"error":"maintenance_unavailable"}'); exit 64 }
