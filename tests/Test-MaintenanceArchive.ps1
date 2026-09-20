Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Maintenance.psm1') -Force
$checks=0
$work = Join-Path (Join-Path $PSScriptRoot '../.local') ('maintenance-tests-' + [Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $work
function Make-Archive([string]$Name,[object[]]$Entries) {
    $path=Join-Path $work $Name
    $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew)
    $zip=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$false)
    try {
        foreach ($entry in $Entries) {
            $item=$zip.CreateEntry($entry.name)
            if ($entry.ContainsKey('attributes')) { $item.ExternalAttributes=$entry.attributes }
            $stream=$item.Open()
            try { $bytes=[Text.Encoding]::UTF8.GetBytes($entry.content); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
        }
    } finally { $zip.Dispose(); $file.Dispose() }
    return $path
}
function Extract([string]$Path,[string]$Destination) {
    return [ValidationMaintenance]::Extract($Path,$Destination,(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant())
}
function Reject([scriptblock]$Action) {
    $failed=$false; try { & $Action | Out-Null } catch { $failed=$true }
    if (-not $failed) { throw 'Expected archive rejection.' }; $script:checks++
}
try {
    $valid=Make-Archive 'good.zip' @(@{name='worker-v21/a.txt';content='hello'},@{name='unity-draw-v5/sub/a.txt';content='native'})
    $destination=Join-Path $work 'good'
    $roots=Extract $valid $destination
    if (($roots -join ',') -cne 'unity-draw-v5,worker-v21' -or [IO.File]::ReadAllText((Join-Path $destination 'worker-v21/a.txt')) -cne 'hello') { throw 'Extraction mismatch' }
    $checks++
    Reject { Extract $valid $destination }
    Reject { [ValidationMaintenance]::Extract($valid,(Join-Path $work 'bad-hash'),('0'*64)) }
    if (Test-Path (Join-Path $work 'bad-hash')) { throw 'Hash rejection wrote extraction files.' }
    foreach ($entries in @(
        @(@{name='worker-v21/a';content='x'},@{name='WORKER-v21/A';content='x'}),
        @(@{name='worker-v21/a';content='x'},@{name='worker-v21/a/b';content='x'}),
        @(@{name='worker-v21/a/';content=''}),
        @(@{name='worker-v21/../outside';content='x'}),
        @(@{name='worker-v21/a';content='x';attributes=[int](-1610612736)}),
        @(@{name='worker-v21/a';content='x';attributes=16}),
        @(@{name='headless-v2/privileged.ps1';content='x'}),
        @(@{name='worker-v21/CON.txt';content='x'}),
        @(@{name='worker-v21/a.';content='x'}),
        @(@{name='worker-v21/a'+[char]10;content='x'})
    )) {
        $id=[Guid]::NewGuid().ToString('N')
        $archive=Make-Archive ($id+'.zip') $entries
        $output=Join-Path $work $id
        Reject { Extract $archive $output }
        if (Test-Path $output) { throw 'Invalid namespace wrote extraction files.' }
    }
    $snapshot=[ValidationMaintenance]::ReadSnapshot((Join-Path $destination 'worker-v21/a.txt'),5)
    if ([Text.Encoding]::UTF8.GetString($snapshot) -cne 'hello') { throw 'Snapshot mismatch' }; $checks++
    Reject { [ValidationMaintenance]::ReadSnapshot((Join-Path $destination 'worker-v21/a.txt'),4) }
    $recordPath=Join-Path $work 'state.json'
    Write-MaintenanceRecord $recordPath @{generation=1}
    Write-MaintenanceRecord $recordPath @{generation=2}
    if ((Get-Content -Raw $recordPath | ConvertFrom-Json).generation -ne 2) { throw 'Atomic replacement failed' }; $checks++
} finally { Remove-Item -LiteralPath $work -Force -Recurse }
[ordered]@{schema='d3d11-maintenance-archive-tests/v1'; checksPassed=$checks; hostChanges=$false} | ConvertTo-Json
