# Pure replay-history checks; no Windows account or filesystem changes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Archive.psm1') -Force
$checks = 0
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe archive history accepted.' }
    $script:checks++
}
$requests = [ordered]@{}
Add-ValidationArchivedRequest $requests ('a' * 64) ('b' * 64)
Add-ValidationArchivedRequest $requests ('a' * 64) ('b' * 64)
if ($requests.Count -ne 1) { throw 'Duplicate tombstone added.' }; $checks++
Reject { Add-ValidationArchivedRequest $requests ('a' * 64) ('c' * 64) }
foreach ($invalid in @('', '../request', ('A' * 64), ('g' * 64), ('a' * 63))) {
    Reject { Add-ValidationArchivedRequest $requests $invalid ('b' * 64) }
    Reject { Add-ValidationArchivedRequest $requests ('a' * 64) $invalid }
}
$record = [ordered]@{schema='d3d11-archived-requests/v1'; requests=$requests} | ConvertTo-Json | ConvertFrom-Json
$restored = ConvertFrom-ValidationArchive $record
if ($restored.Count -ne 1 -or $restored[('a' * 64)] -cne ('b' * 64)) { throw 'Archive roundtrip failed.' }; $checks++
$record.schema = 'unknown'
Reject { ConvertFrom-ValidationArchive $record }
for ($i = 0; $i -lt 9999; $i++) { Add-ValidationArchivedRequest $requests ($i.ToString('x64')) ('b' * 64) }
Reject { Add-ValidationArchivedRequest $requests ('c' * 64) ('b' * 64) }
Write-Output "PASS: $checks archived-request validation, replay, conflict and quota checks"
