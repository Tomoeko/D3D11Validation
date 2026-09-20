Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Unity.psm1')
$root = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'validation-image-path-test')
$members = @('RuntimeProbe.exe','UnityPlayer.dll','MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll',
             'RuntimeProbe_Data/Managed/Assembly-CSharp.dll')
$checks = 0
foreach ($member in $members) {
    $expected = [IO.Path]::GetFullPath((Join-Path $root $member))
    $actual = Assert-ValidationPackageImagePath $root $member $expected
    if ($actual -cne $expected) { throw 'Exact package member was changed' }
    # The worker is Windows-only: ordinal case equivalence is intentional.
    $actual = Assert-ValidationPackageImagePath $root $member $expected.ToUpperInvariant()
    if ($actual -cne $expected) { throw 'Windows case equivalence was lost' }
    $checks += 2
    foreach ($observed in @(
        (Join-Path ($root + '-other') $member),
        (Join-Path $root ('child/../' + $member)),
        (Join-Path $root ($member + '.other')),
        $member,
        '',
        ($expected + "`n")
    )) {
        $rejected = $false
        try { $null = Assert-ValidationPackageImagePath $root $member $observed }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'An unrelated or ambiguous loaded path was accepted' }
        $checks++
    }
}
foreach ($member in @('../escape.dll','./image.dll','nested/../image.dll','/absolute.dll',
                      'nested//image.dll','image.dll/','image.dll.','image.dll ',
                      'C:stream.dll','image.dll:stream','nested\image.dll','')) {
    $rejected = $false
    try { $null = Assert-ValidationPackageImagePath $root $member (Join-Path $root 'image.dll') }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'An invalid package identity was accepted' }
    $checks++
}
'PASS: ' + $checks + ' loaded-image path association checks; no files read'
