# Select a current adapter from an observed inventory. LUIDs/ordinals are execution
# evidence, never permanent hardware policy. Ambiguous hardware fails closed.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ValidationUnsigned($Value, [uint64]$Maximum) {
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) -and
        $Value -ge 0 -and [uint64]$Value -le $Maximum
}
function Get-ValidationAdapterSelection($Inventory, $Baseline, [string]$Kind = 'device') {
    if ($Inventory.schema -cne 'd3d11-adapter-inventory/v2' -or $Inventory.qualified -isnot [bool] -or $Inventory.qualified -or
        $Baseline.schema -cne 'd3d11-native-environment-baseline/v4' -or $Baseline.adapterSelection -cne 'unique-current-inventory' -or
        $Kind -cnotin @('device','reject-software','reject-other-gpu')) { throw 'adapter_selection_contract' }
    $entries = @($Inventory.adapters)
    if ($entries.Count -lt 1 -or $entries.Count -gt 64) { throw 'adapter_inventory_count' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index=0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        if (($entry.PSObject.Properties.Name | Sort-Object) -join ',' -cne 'dedicatedVideoMemory,deviceId,flags,luidHigh,luidLow,name,ordinal,revision,subsystemId,vendorId' -or
            -not (Test-ValidationUnsigned $entry.ordinal 63) -or $entry.ordinal -ne $index -or
            $entry.name -isnot [string] -or $entry.name.Length -lt 1 -or $entry.name.Length -gt 128 -or $entry.name.Contains([char]0)) {
            throw 'adapter_inventory_shape'
        }
        foreach ($field in @('vendorId','deviceId','subsystemId','revision','flags','luidLow','luidHigh')) {
            if (-not (Test-ValidationUnsigned $entry.$field ([uint32]::MaxValue))) { throw 'adapter_inventory_integer' }
        }
        if ($entry.flags -band (-bnot 3) -or -not (Test-ValidationUnsigned $entry.dedicatedVideoMemory 1125899906842624)) { throw 'adapter_inventory_integer' }
        if (-not $seen.Add(([string]$entry.luidLow + ':' + [string]$entry.luidHigh))) { throw 'adapter_inventory_duplicate_luid' }
    }
    $pin = if ($Kind -ceq 'device') { $Baseline.adapter } else { $Baseline.rejectedAdapters.$Kind }
    $names = @($pin.PSObject.Properties.Name)
    $required = if ($Kind -ceq 'device') { @('name','vendorId','deviceId','subsystemId','revision','software') } else { @('name','vendorId','deviceId','software') }
    if (@(Compare-Object ($names | Sort-Object) ($required | Sort-Object)).Count -or
        $pin.name -isnot [string] -or $pin.software -isnot [bool] -or
        ($Kind -ceq 'device' -and $pin.software) -or ($Kind -ceq 'reject-software' -and -not $pin.software) -or
        ($Kind -ceq 'reject-other-gpu' -and $pin.software)) { throw 'adapter_policy_shape' }
    foreach ($name in $names | Where-Object { $_ -notin @('name','software') }) {
        if (-not (Test-ValidationUnsigned $pin.$name ([uint32]::MaxValue))) { throw 'adapter_policy_integer' }
    }
    $matches = @($entries | Where-Object {
        $entry = $_
        $match = ([bool]($entry.flags -band 2) -eq $pin.software) -and -not [bool]($entry.flags -band 1)
        foreach ($name in $names | Where-Object { $_ -cne 'software' }) {
            if ($entry.$name -cne $pin.$name) { $match = $false }
        }
        $match
    })
    if ($matches.Count -ne 1) { throw 'adapter_unique_identity_unavailable' }
    return $matches[0]
}
function Assert-ValidationActualAdapter($Actual, $Selected) {
    foreach ($field in @('name','vendorId','deviceId','subsystemId','revision','luidLow','luidHigh')) {
        if ($Actual.$field -cne $Selected.$field) { throw 'adapter_identity_drift' }
    }
    if ($Actual.software -isnot [bool] -or $Actual.software -or ($Selected.flags -band 3)) { throw 'adapter_identity_drift' }
    if ($Actual.PSObject.Properties['ordinal'] -and $Actual.ordinal -ne $Selected.ordinal) { throw 'adapter_identity_drift' }
}
Export-ModuleMember -Function Get-ValidationAdapterSelection, Assert-ValidationActualAdapter
