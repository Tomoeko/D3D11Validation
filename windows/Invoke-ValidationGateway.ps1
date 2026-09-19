# First-stage forced command. Test execution is intentionally unavailable.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Never interpret SSH_ORIGINAL_COMMAND as PowerShell, a path, or arguments.
if ($env:SSH_ORIGINAL_COMMAND -cne 'status') {
    [Console]::Error.WriteLine('{"error":"unsupported_operation"}')
    exit 64
}

try {
    $inventoryPath = Join-Path $PSScriptRoot 'Get-ValidationInventory.ps1'
    $inventory = & $inventoryPath | ConvertFrom-Json
    [ordered]@{
        schema = 'd3d11-validation-gateway/v1'
        phase = 'connection-bootstrap'
        allowedOperations = @('status')
        testExecutionEnabled = $false
        inventory = $inventory
    } | ConvertTo-Json -Depth 8
} catch {
    # Expose only diagnostic categories; exception messages can contain paths.
    $failure = [ordered]@{
        error = 'inventory_unavailable'
        exception = $_.Exception.GetType().Name
        category = $_.CategoryInfo.Category.ToString()
        line = $_.InvocationInfo.ScriptLineNumber
    }
    [Console]::Error.WriteLine(($failure | ConvertTo-Json -Compress))
    exit 69
}
