Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Adapter.psm1') -Force
$checks=0
function Clone($Object) { return $Object | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json }
function Reject([scriptblock]$Action) {
    $failed=$false; try { & $Action | Out-Null } catch { $failed=$true }
    if (-not $failed) { throw ('Expected adapter rejection: ' + $Action) }; $script:checks++
}
$baseline=[pscustomobject]@{schema='d3d11-native-environment-baseline/v4'; adapterSelection='unique-current-inventory'
    adapter=[pscustomobject]@{name='Expected GPU';vendorId=1;deviceId=2;subsystemId=3;revision=4;software=$false}
    rejectedAdapters=[pscustomobject]@{'reject-software'=[pscustomobject]@{name='Software';vendorId=5;deviceId=6;software=$true}
        'reject-other-gpu'=[pscustomobject]@{name='Other GPU';vendorId=7;deviceId=8;software=$false}}}
$inventory=[pscustomobject]@{schema='d3d11-adapter-inventory/v2';qualified=$false;adapters=@(
    [pscustomobject]@{ordinal=0;name='Expected GPU';vendorId=1;deviceId=2;subsystemId=3;revision=4;flags=0;dedicatedVideoMemory=1024;luidLow=100;luidHigh=0},
    [pscustomobject]@{ordinal=1;name='Software';vendorId=5;deviceId=6;subsystemId=0;revision=0;flags=2;dedicatedVideoMemory=0;luidLow=200;luidHigh=0},
    [pscustomobject]@{ordinal=2;name='Other GPU';vendorId=7;deviceId=8;subsystemId=9;revision=10;flags=0;dedicatedVideoMemory=512;luidLow=300;luidHigh=0})}
$selected=Get-ValidationAdapterSelection $inventory $baseline
if ($selected.luidLow -ne 100) { throw 'Incorrect target' }; $checks++
foreach ($kind in @('reject-software','reject-other-gpu')) { $null=Get-ValidationAdapterSelection $inventory $baseline $kind; $checks++ }
# A new boot reorders adapters and reallocates every LUID. Stable hardware must
# select the new current identity, while actual-device validation stays exact.
$boot=Clone $inventory
$boot.adapters=@($boot.adapters[2],$boot.adapters[0],$boot.adapters[1])
for ($i=0;$i -lt 3;$i++) { $boot.adapters[$i].ordinal=$i; $boot.adapters[$i].luidLow=1000+$i }
$selected=Get-ValidationAdapterSelection $boot $baseline
if ($selected.ordinal -ne 1 -or $selected.luidLow -ne 1001) { throw 'Boot identity did not refresh' }; $checks++
$actual=[pscustomobject]@{name='Expected GPU';vendorId=1;deviceId=2;subsystemId=3;revision=4;software=$false;luidLow=1001;luidHigh=0;ordinal=1}
Assert-ValidationActualAdapter $actual $selected; $checks++
$actual.luidLow=100
Reject { Assert-ValidationActualAdapter $actual $selected }
$actual.luidLow=1001; $actual.ordinal=0
Reject { Assert-ValidationActualAdapter $actual $selected }
foreach ($field in @('vendorId','deviceId','subsystemId','revision','luidHigh')) {
    $actual=Clone $baseline.adapter
    $actual | Add-Member luidLow 1001; $actual | Add-Member luidHigh 0
    $actual.$field++
    Reject { Assert-ValidationActualAdapter $actual $selected }
}
$changed=Clone $inventory; $duplicate=Clone $changed.adapters[0]; $duplicate.ordinal=3; $duplicate.luidLow=400; $changed.adapters+=@($duplicate)
Reject { Get-ValidationAdapterSelection $changed $baseline }
$changed=Clone $inventory; $changed.adapters[1].luidLow=100
Reject { Get-ValidationAdapterSelection $changed $baseline }
foreach ($mutation in @(
    {param($d) $d.adapters[0].vendorId=9}, {param($d) $d.adapters[0].subsystemId=99},
    {param($d) $d.adapters[0].flags=2}, {param($d) $d.adapters[0].flags=1}, {param($d) $d.adapters[0].flags=8},
    {param($d) $d.adapters[0].luidLow=-1}, {param($d) $d.adapters[0].ordinal=1},
    {param($d) $d.adapters[0].luidLow='100'}, {param($d) $d.adapters[0].vendorId=1.5},
    {param($d) $d.adapters[0].name='EXPECTED GPU'}, {param($d) $d.qualified=$true}
)) {
    $changed=Clone $inventory; & $mutation $changed
    Reject { Get-ValidationAdapterSelection $changed $baseline }
}
$changed=Clone $baseline; $changed.adapter | Add-Member luidLow 100
Reject { Get-ValidationAdapterSelection $inventory $changed }
$changed=Clone $baseline; $changed.adapterSelection='first-match'
Reject { Get-ValidationAdapterSelection $inventory $changed }
[ordered]@{schema='d3d11-adapter-selection-tests/v1'; checksPassed=$checks; hardwareQualified=$false} | ConvertTo-Json
