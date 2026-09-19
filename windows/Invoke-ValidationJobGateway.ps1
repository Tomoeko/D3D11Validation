# Forced SSH command; the environment string is matched, never evaluated.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:SSH_ORIGINAL_COMMAND -cnotin @('submit', 'start', 'status', 'results', 'cancel')) {
    [Console]::Error.WriteLine('{"error":"unsupported_operation"}')
    exit 64
}
try {
    Import-Module (Join-Path $PSScriptRoot 'Validation.Jobs.psm1') -Force
    $text = [ValidationInput]::Read()
    if ($env:SSH_ORIGINAL_COMMAND -ceq 'status' -and $text -ceq '') {
        $store = Open-ValidationStore
        try {
            $heartbeat = Get-ValidationHeartbeat $store
            $response = [ordered]@{
                schema = 'd3d11-validation-gateway/v2'; allowedOperations = @('submit','start','status','results','cancel')
                testExecutionEnabled = $true; worker = $heartbeat
            }
        } finally { $store.Dispose() }
    } else { $response = Invoke-ValidationOperation $env:SSH_ORIGINAL_COMMAND $text }
    [Console]::WriteLine(($response | ConvertTo-Json -Depth 20 -Compress))
} catch {
    $code = 'request_unavailable'
    $failure = $_.Exception
    while ($null -ne $failure) {
        if ($failure.Data.Contains('validationCode')) { $code = $failure.Data['validationCode']; break }
        $failure = $failure.InnerException
    }
    [Console]::Error.WriteLine((@{error=$code} | ConvertTo-Json -Compress))
    exit 64
}
