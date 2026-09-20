Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Unity.psm1')
$trace = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/unity-trace.tsv'))
$lengths = Assert-ValidationUnityTrace $trace $true 45056 32
if ($lengths.Count -ne 4 -or $lengths['draw-0001-vs.bin'] -ne 340 -or $lengths['draw-0002-ps.bin'] -ne 264) {
    throw 'Full-container byte counts were lost'
}
$withoutCapture = $trace.Replace("capture`ton","capture`toff").Replace("`t340`t264`t","`t0`t0`t")
$null = Assert-ValidationUnityTrace $withoutCapture $false 45056 32
$nativeStartup = $trace.Replace("device`t45056", "device`t45312").Replace("context`t0", "context`t0`ncontext`t0")
$null = Assert-ValidationUnityTrace $nativeStartup $true 45056 32
$checks = 3
foreach ($changed in @(
    $trace.Replace("begin`t1`t42","begin`t1`t43"),
    $trace.Replace("end`t2`t1`t0","end`t2`t0`t0"),
    $trace.Replace('DrawIndexed','DrawAuto'),
    $trace.Replace("`t6`t1`t","`t6`t2`t"),
    $trace.Replace("`t340`t264`t","`t0`t264`t"),
    $trace.Replace('00000000','80004005'),
    ($trace + "error`tunsupported-draw-binding`n"),
    ($trace + "create-device`t00000000`n"),
    $trace.Replace("context`t0","context`t1"),
    $trace.Replace('45056','45312'),
    $trace.Replace("capture`ton","capture`toff")
    $trace.Replace("device`t45056", "device`t0"),
    ($trace + "context`t0`n"),
    $trace.Replace("context`t0", "context`t0`ncontext`t0`ncontext`t0"),
    $trace.Replace("device`t45056`t32", "device`t45056`t0")
)) {
    $rejected = $false
    try { $null = Assert-ValidationUnityTrace $changed $true 45056 32 } catch { $rejected = $true }
    if (-not $rejected) { throw 'Malformed or unsupported draw was accepted' }
    $checks++
}
$fields = ConvertFrom-ValidationTabFields ([Text.Encoding]::UTF8.GetBytes("schema`tfixture`nruntime`tfirst`nruntime`tsecond`n")) 'runtime'
if ($fields['runtime'].Count -ne 2) { throw 'Repeated runtime identity was lost' }
$rejected = $false
try { $null = ConvertFrom-ValidationTabFields ([Text.Encoding]::UTF8.GetBytes("schema`tfirst`nschema`tsecond`n")) 'runtime' }
catch { $rejected = $true }
if (-not $rejected) { throw 'Duplicate singleton field accepted' }
"PASS: $checks trace shape checks plus repeated-field and duplicate-field checks"
