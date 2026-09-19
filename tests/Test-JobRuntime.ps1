# Run manually as the standard validation account in the protected deployment.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not ('ValidationStore' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Validation.Runtime.cs') }
$base = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('D3D11Validation\data\runtime-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $base
$normal = Join-Path $base 'normal'
$outside = Join-Path $base 'outside'
$null = New-Item -ItemType Directory -Path $normal,$outside
$store = [ValidationStore]::new($normal)
$passed = [Collections.Generic.List[string]]::new()
try {
    $store.Write('record.json', '{"value":1}')
    $store.Write('record.json', '{"value":2}')
    if ($store.Read('record.json') -cne '{"value":2}') { throw 'atomic_roundtrip_failed' }
    $passed.Add('atomic_record_roundtrip')
    foreach ($name in @('../escape.json','..\escape.json','C:\escape.json','record.json:stream','UPPER.json')) {
        $rejected = $false
        try { $null = $store.Read($name) } catch { $rejected = $true }
        if (-not $rejected) { throw 'invalid_path_accepted' }
    }
    $passed.Add('invalid_paths_rejected')
    $outsideFile = Join-Path $outside 'sentinel.json'
    [IO.File]::WriteAllText($outsideFile, '{"preserve":true}')
    $hard = Join-Path $normal 'hard.json'
    $null = New-Item -ItemType HardLink -Path $hard -Target $outsideFile
    $rejected = $false
    try { $null = $store.Read('hard.json') } catch { $rejected = $true }
    if (-not $rejected) { throw 'hardlink_accepted' }
    $passed.Add('hardlink_rejected')
    $rejected = $false
    try { $store.Write('hard.json', '{}') } catch { $rejected = $true }
    if (-not $rejected -or [IO.File]::ReadAllText($outsideFile) -cne '{"preserve":true}') { throw 'hardlink_write_accepted' }
    $passed.Add('hardlink_write_preserves_target')
} finally { $store.Dispose() }
$junction = Join-Path $base 'junction'
$null = New-Item -ItemType Junction -Path $junction -Target $outside
$rejected = $false
try { $bad = [ValidationStore]::new($junction); $bad.Dispose() } catch { $rejected = $true }
if (-not $rejected) { throw 'junction_accepted' }
$passed.Add('junction_rejected')
$exe = Join-Path $PSScriptRoot 'diagnostic.exe'
$first = [ValidationChild]::new($exe, '5000', $PSScriptRoot)
$second = [ValidationChild]::new($exe, '5000', $PSScriptRoot)
try {
    $firstId = $first.Id
    $first.Dispose()
    if ($null -ne (Get-Process -Id $firstId -ErrorAction SilentlyContinue)) { throw 'owned_child_survived' }
    if ($second.Finished) { throw 'unrelated_child_stopped' }
    $passed.Add('cancel_kills_only_owned_process')
} finally { $first.Dispose(); $second.Dispose() }
[ordered]@{schema='d3d11-runtime-tests/v1'; passed=$passed; count=$passed.Count} | ConvertTo-Json
