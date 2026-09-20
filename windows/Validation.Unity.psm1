# Fixed private-player investigation and native draw evidence collection.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Protocol.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Graphics.psm1')

function Get-ValidationUnityPackage([ValidateSet('startup','draw','unhooked')][string]$Mode) {
    $manifestName = if ($Mode -ceq 'unhooked') { 'unhooked-package.json' } else { 'unity-package.json' }
    $manifest = Get-Content -Raw (Join-Path $PSScriptRoot $manifestName) | ConvertFrom-Json
    if ($manifest.schema -cne ('d3d11-unity-' + $Mode + '-package/v2') -or
        $manifest.deployment -cnotmatch ('^unity-' + $Mode + '-v[1-9][0-9]*$') -or
        $manifest.adapterSelection -cne 'unique-current-inventory' -or $manifest.PSObject.Properties['adapterOrdinal']) {
        throw 'invalid_unity_package'
    }
    $root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
    $program = Join-Path $root 'program'
    $package = Join-Path $program $manifest.deployment
    foreach ($path in @($root,$program,$package)) { Assert-ProtectedPath $path }
    $expected = @($manifest.files.PSObject.Properties)
    if ($expected.Count -lt 4 -or $expected.Count -gt 1024) { throw 'invalid_unity_package' }
    # Inventory every entry before recursive enumeration so a junction is never
    # traversed. The client cannot upload files or choose this package.
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($package)
    $actual = [Collections.Generic.List[string]]::new()
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            Assert-ProtectedPath $item.FullName
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
            else { $actual.Add($item.FullName.Substring($package.Length + 1).Replace('\','/')) }
        }
    }
    if ($actual.Count -ne $expected.Count) { throw 'unity_package_inventory_drift' }
    foreach ($file in $expected) {
        if ($file.Name -cnotmatch '^[A-Za-z0-9_-][A-Za-z0-9_. /-]*$' -or
            @($file.Name.Split('/') | Where-Object { $_ -in @('','.', '..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -or
            $file.Name -cnotin $actual -or $file.Value -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_unity_package' }
        if ((Get-FileHash -LiteralPath (Join-Path $package $file.Name)).Hash.ToLowerInvariant() -cne $file.Value) {
            throw 'unity_package_hash_drift'
        }
    }
    # Startup uses no local proxy. Draw packages allow only the reviewed capture
    # DLL; its forwarding target is checked against the pinned system runtime.
    $forbidden = if ($Mode -cne 'draw') { '^(d3d11|dxgi|dxbc_d3d11_original)\.dll$' } else { '^(dxgi|dxbc_d3d11_original)\.dll$' }
    if (@($actual | Where-Object { [IO.Path]::GetFileName($_) -imatch $forbidden }).Count) {
        throw 'unexpected_unity_runtime_wrapper'
    }
    $requiredFiles = @('RuntimeProbe.exe','UnityPlayer.dll','RuntimeProbe_Data/globalgamemanagers')
    if ($Mode -ceq 'startup') { $requiredFiles += 'fixture.bundle' }
    else {
        $requiredFiles += @('recovered.bundle','regenerated.bundle','negative.bundle')
        $requiredFiles += $(if ($Mode -ceq 'draw') { 'd3d11.dll' } else { 'validation-observer.dll' })
    }
    foreach ($required in $requiredFiles) {
        if ($required -cnotin $actual) { throw 'incomplete_unity_package' }
    }
    return [pscustomobject]@{directory=$package; manifest=$manifest}
}

function New-ValidationUnityFixture([string]$Output, $Guard, [string]$Kind, $Selection) {
    $mode = if ($Kind -ceq 'unity-startup') { 'startup' } elseif ($Kind.EndsWith('-unhooked')) { 'unhooked' } else { 'draw' }
    $profile = Get-ValidationUnityPackage $mode
    $package = $profile.directory
    $manifest = $profile.manifest
    $bundle = 'fixture.bundle'; $keyword = 'off'; $tier = '0'; $trace = ''
    if ($mode -cne 'startup') {
        if ($Kind -cnotmatch '^unity-(recovered|regenerated|negative)-(on|off)-tier([0-2])-(traced|untraced|unhooked)$') {
            throw 'invalid_unity_fixture'
        }
        $bundle = $Matches[1] + '.bundle'; $keyword = $Matches[2]; $tier = $Matches[3]
        $trace = if ($Matches[4] -ceq 'traced') { ' -trace on' } elseif ($Matches[4] -ceq 'unhooked') { ' -trace none' } else { ' -trace off' }
    }
    $arguments = '-batchmode -force-d3d11 -force-gfx-direct -force-device-index ' + $Selection.adapter.ordinal +
        ' -bundle "' + (Join-Path $package $bundle) + '" -output "' + $Output +
        '" -uv-variant ' + $keyword + ' -tier ' + $tier + $trace + ' -logFile "' + (Join-Path $Output 'unity-log.bin') + '"'
    return [pscustomobject]@{
        executable = Join-Path $package 'RuntimeProbe.exe'
        kind = $Kind; package = $profile; selection = $Selection
        binarySha256 = $manifest.files.'RuntimeProbe.exe'; workingDirectory = $package
        arguments = $arguments; timeoutMs = 60000; outputGuard = $Guard; outputDirectory = $Output
    }
}

function Get-ValidationUnityStartupSummary([byte[]]$Log, [bool]$CaptureAvailable) {
    $text = [Text.Encoding]::UTF8.GetString($Log)
    # Only explicit booleans and a content hash leave the host. Unity logs can
    # contain personal profile paths, so never return raw log lines or exceptions.
    return [ordered]@{
        schema='d3d11-unity-startup/v1'; logSha256=Get-ValidationDigest $Log; logBytes=$Log.Length
        direct3d11Mentioned=($text -match '(?i)Direct3D\s*11|Direct3D11')
        expectedGpuMentioned=($text -match 'Example Hardware Adapter')
        graphicsInitializationFailed=($text -match '(?i)Failed to initialize graphics|Failed to create graphics device|InitializeEngineGraphics failed')
        traceEntryUnavailable=($text -match 'EntryPointNotFoundException[^\r\n]*DXBCTraceBegin|Unable to find an entry point named .DXBCTraceBegin')
        captureAvailable=$CaptureAvailable; loadedRuntimeQualified=$false; fullQualificationComplete=$false
    }
}

function ConvertFrom-ValidationTabFields([byte[]]$Bytes, [string]$RepeatedKey) {
    $fields = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $text = [Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    foreach ($line in $text.TrimEnd([char[]]"`r`n").Split([char]10)) {
        $parts = $line.TrimEnd([char]13).Split([char]9)
        if ($parts.Count -ne 2 -or $parts[0] -cnotmatch '^[A-Za-z][A-Za-z0-9_]*$') { throw 'invalid_unity_record' }
        if (-not $fields.ContainsKey($parts[0])) { $fields.Add($parts[0],[Collections.Generic.List[string]]::new()) }
        elseif ($parts[0] -cne $RepeatedKey) { throw 'duplicate_unity_field' }
        $fields[$parts[0]].Add($parts[1])
    }
    return ,$fields
}

function Get-ValidationUnityField($Fields, [string]$Name) {
    if (-not $Fields.ContainsKey($Name) -or $Fields[$Name].Count -ne 1) { throw 'missing_unity_field' }
    return $Fields[$Name][0]
}

function Get-ValidationUnityArtifact($Fixture, [string]$Name, [int]$Maximum) {
    $bytes = $Fixture.outputGuard.ReadBytes($Name,$Maximum)
    return [ordered]@{name=$Name; byteLength=$bytes.Length
        sha256=Get-ValidationDigest $bytes; base64=[Convert]::ToBase64String($bytes)}
}

# Resolve only the exact package member before doing any I/O on an observed
# process path. A same-name image outside the protected package is not authority.
function Assert-ValidationPackageImagePath([string]$Root, [string]$Member, [string]$Observed) {
    if (-not [IO.Path]::IsPathRooted($Root) -or -not [IO.Path]::IsPathRooted($Observed) -or
        $Member -cnotmatch '^[A-Za-z0-9_-][A-Za-z0-9_. /-]*$' -or
        @($Member.Split('/') | Where-Object { $_ -in @('','.', '..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count) {
        throw 'invalid_loaded_image_path'
    }
    $expected = [IO.Path]::GetFullPath((Join-Path $Root $Member))
    $actual = [IO.Path]::GetFullPath($Observed)
    if (-not [string]::Equals($Observed,$actual,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($expected,$actual,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'loaded_image_outside_package'
    }
    return $expected
}

function Get-ValidationUnityImageIdentity($Package, [string]$Member, [string]$Observed) {
    $expected = Assert-ValidationPackageImagePath $Package.directory $Member $Observed
    $pin = @($Package.manifest.files.PSObject.Properties | Where-Object { $_.Name -ceq $Member })
    if ($pin.Count -ne 1 -or $pin[0].Value -cnotmatch '^[0-9a-f]{64}$') { throw 'unapproved_loaded_image' }
    Assert-ProtectedPath $expected
    $hash = (Get-FileHash -LiteralPath $expected).Hash.ToLowerInvariant()
    if ($hash -cne $pin[0].Value) { throw 'loaded_image_hash_drift' }
    return [ordered]@{file=$Member; sha256=$hash}
}

function Complete-ValidationUnityDraw($Fixture) {
    $manifest = $Fixture.package.manifest
    $artifacts = [Collections.Generic.List[object]]::new()
    $unhooked = $Fixture.kind.EndsWith('-unhooked')
    if ($unhooked -and $Fixture.outputGuard.Exists('draws.bin')) { throw 'unexpected_unity_instrumentation' }
    $names = @('device.bin','result.tsv','pixels.bin','selection-adapters.json')
    if (-not $unhooked) { $names += 'draws.bin' }
    $byName = @{}
    foreach ($name in $names) {
        $maximum = if ($name -ceq 'pixels.bin') { 256 } else { 262144 }
        $artifact = Get-ValidationUnityArtifact $Fixture $name $maximum
        $byName[$name] = $artifact
        $artifacts.Add($artifact)
    }
    $device = ConvertFrom-ValidationTabFields ([Convert]::FromBase64String($byName['device.bin'].base64)) 'runtime'
    if ((Get-ValidationUnityField $device 'schema') -cne 'd3d11-unity-device/v2' -or
        $device.Count -ne 16 -or -not $device.ContainsKey('runtime') -or $device['runtime'].Count -ne 4) { throw 'invalid_unity_device' }
    $adapter = [ordered]@{name=Get-ValidationUnityField $device 'name'}
    foreach ($field in @('vendorId','deviceId','subsystemId','revision','luidLow','luidHigh')) {
        $value = Get-ValidationUnityField $device $field
        if ($value -cnotmatch '^(0|[1-9][0-9]{0,9})$') { throw 'invalid_unity_device' }
        $adapter[$field] = [uint32]$value
    }
    if ((Get-ValidationUnityField $device 'software') -cne '0' -or (Get-ValidationUnityField $device 'sessionId') -cne '0') {
        throw 'invalid_unity_device'
    }
    $adapter.software = $false
    $report = [pscustomobject]@{
        adapter=[pscustomobject]$adapter; sessionId=0; elevated=$false; executionContext='Session0'
        clientProtocolType=-1; connectionState=-1; loadedModules=@($device['runtime'])
        featureLevel=[uint32](Get-ValidationUnityField $device 'featureLevel')
        creationFlags=[uint32](Get-ValidationUnityField $device 'creationFlags')
    }
    $baseline = Get-Content -Raw (Join-Path $PSScriptRoot 'native-baseline.json') | ConvertFrom-Json
    $environment = Get-ValidationGraphicsEnvironment $report $baseline $Fixture.selection $manifest.creationFlags $manifest.featureLevel
    $fields = ConvertFrom-ValidationTabFields ([Convert]::FromBase64String($byName['result.tsv'].base64)) 'keyword_decl'
    $images = [Collections.Generic.List[object]]::new()
    foreach ($role in @(
        @('processImage','RuntimeProbe.exe'),
        @('playerImage','UnityPlayer.dll'),
        @('monoImage','MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll')
    )) {
        $images.Add((Get-ValidationUnityImageIdentity $Fixture.package $role[1] (Get-ValidationUnityField $device $role[0])))
    }
    $harness = Get-ValidationUnityImageIdentity $Fixture.package 'RuntimeProbe_Data/Managed/Assembly-CSharp.dll' (Get-ValidationUnityField $fields 'harness_path')
    if ((Get-ValidationUnityField $fields 'harness_sha256') -cne $harness.sha256) { throw 'loaded_harness_drift' }
    $images.Add($harness)
    $environment.playerImages = $images.ToArray()
    # These selected engine/harness roles are not the complete loaded-module set.
    $environment.loadedImageClosureComplete = $false
    if ($Fixture.kind -cnotmatch '^unity-(recovered|regenerated|negative)-(on|off)-tier([0-2])-(traced|untraced|unhooked)$') { throw 'invalid_unity_fixture' }
    $bundle = $Matches[1] + '.bundle'; $keyword = $Matches[2]; $tier = $Matches[3]; $traced = $Matches[4] -ceq 'traced'
    $expectedFields = [ordered]@{
        schema='dxbc-private-player-draw-domain/v3'; instrumentation=$(if ($unhooked) { 'none' } elseif ($traced) { 'on' } else { 'off' }); bundle_sha256=$manifest.files.$bundle
        player_metadata_sha256=$manifest.files.'RuntimeProbe_Data/globalgamemanagers'
        unity_version='2021.3.35f1'; backend='Direct3D11'; device=$baseline.adapter.name
        render_threading='Direct'; fog_enabled='False'; fog_mode='Linear'
        fog_input_float32le='0000803e0000003f0000403f0000803f00000000000096430ad7233c'
        active_tier_enum=$tier; color_space='Gamma'; pass_count='1'; pass_name='PACKED_UV'
        uv_variant_enabled=$(if ($keyword -ceq 'on') { 'True' } else { 'False' })
        material_keyword_count='0'; mesh='canonical-quad-position-identity-v1'
        render_target='4x4-rgba32f-linear-depth24-msaa1'; pixel_bytes='256'
        pixels_sha256=$byName['pixels.bin'].sha256; repeated_pixels_equal='True'; set_pass='True'; supported='True'
    }
    foreach ($field in $expectedFields.GetEnumerator()) {
        if ((Get-ValidationUnityField $fields $field.Key) -cne $field.Value) { throw 'unity_profile_drift' }
    }
    if ($byName['pixels.bin'].byteLength -ne 256) { throw 'invalid_unity_pixels' }
    if (-not $unhooked) {
        $trace = [Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($byName['draws.bin'].base64))
        $traceLengths = Assert-ValidationUnityTrace $trace $traced $report.featureLevel $report.creationFlags
    }
    $dxbcEqual = $null
    if ($traced) {
        $dxbcEqual = $true
        foreach ($draw in @(1,2)) {
            foreach ($stage in @('vs','ps')) {
                $artifact = Get-ValidationUnityArtifact $Fixture ('draw-{0:d4}-{1}.bin' -f $draw,$stage) 16777216
                $bytes = [Convert]::FromBase64String($artifact.base64)
                if ($bytes.Length -ne $traceLengths[$artifact.name] -or $bytes.Length -lt 32 -or
                    [Text.Encoding]::ASCII.GetString($bytes,0,4) -cne 'DXBC' -or
                    [BitConverter]::ToUInt32($bytes,24) -ne $bytes.Length) { throw 'incomplete_unity_dxbc' }
                if ($artifact.sha256 -cne $manifest.referenceDxbc.$stage) { $dxbcEqual = $false }
                $artifacts.Add($artifact)
            }
        }
    }
    return [ordered]@{
        artifacts=$artifacts; environment=$environment
        environmentSha256=Get-ValidationDigest ([Text.Encoding]::UTF8.GetBytes(($environment | ConvertTo-Json -Depth 10 -Compress)))
        comparison=[ordered]@{case=$Fixture.kind; captureEnabled=$traced; drawHooksEnabled=(-not $unhooked); profileMatched=$true
            fullDxbcMatchesReference=$dxbcEqual; pixelsMatchReference=($byName['pixels.bin'].sha256 -ceq $manifest.referencePixels)
            repeatedPixelsEqual=$true; fullQualificationComplete=$false}
    }
}

function Assert-ValidationUnityTrace([string]$Text, [bool]$Traced, [uint32]$FeatureLevel, [uint32]$Flags) {
    $lengths = @{}
    $allRows = @($Text.TrimEnd([char[]]"`r`n").Split([char]10) | ForEach-Object { ,$_.TrimEnd([char]13).Split([char]9) })
    $creationCount = 0; $deviceCount = 0; $contextCount = 0; $drawStarted = $false
    $kept = [Collections.Generic.List[object]]::new()
    foreach ($row in $allRows) {
        if ($row[0] -ceq 'begin') { $drawStarted = $true }
        if ($row[0] -ceq 'create-device') {
            if ($drawStarted -or ($row -join "`t") -cne "create-device`t00000000") { throw 'invalid_unity_trace' }
            $creationCount++
        } elseif ($row[0] -ceq 'device') {
            # Startup capability probing may request a higher feature level than
            # the final Unity device. The labeled draw below pins the actual one.
            if ($drawStarted -or $row.Count -ne 3 -or $row[1] -notin @('45056','45312','49152','49408') -or
                $row[2] -cne [string]$Flags) { throw 'invalid_unity_trace' }
            $deviceCount++
        } elseif ($row[0] -ceq 'context') {
            if ($drawStarted -or ($row -join "`t") -cne "context`t0") { throw 'invalid_unity_trace' }
            $contextCount++
        } else { $kept.Add($row) }
    }
    $rows = $kept.ToArray()
    if ($creationCount -lt 1 -or $creationCount -gt 4 -or $deviceCount -lt 1 -or $deviceCount -gt $creationCount -or
        $contextCount -lt 1 -or $contextCount -gt $creationCount) { throw 'invalid_unity_trace' }
    $expectedMode = if ($Traced) { 'on' } else { 'off' }
    if (($rows[0] -join "`t") -cne "schema`td3d11-native-unity-draw/v1" -or
        ($rows[1] -join "`t") -cne "capture`t$expectedMode") { throw 'invalid_unity_trace' }
    if ($rows.Count -ne 10) { throw 'invalid_unity_trace' }
    $thread = $rows[2][2]
    if ($thread -cnotmatch '^[1-9][0-9]*$') { throw 'invalid_unity_trace' }
    foreach ($draw in @(1,2)) {
        $offset = 2 + ($draw - 1) * 4
        $command = $rows[$offset + 2]
        if (($rows[$offset] -join "`t") -cne "begin`t$draw`t$thread" -or
            ($rows[$offset + 1] -join "`t") -cne "active-device`t$draw`t$draw`t$FeatureLevel`t$Flags" -or
            ($rows[$offset + 3] -join "`t") -cne "end`t$draw`t1`t0" -or $command.Count -ne 17 -or
            ($command[0..9] -join "`t") -cne "draw`t$draw`tDrawIndexed`t6`t1`t0`t0`t0`t0`t$thread" -or
            ($command[12..16] -join "`t") -cne "0`t0`t0`t0`t0") { throw 'invalid_unity_trace' }
        if (($Traced -and ($command[10] -cnotmatch '^[1-9][0-9]*$' -or $command[11] -cnotmatch '^[1-9][0-9]*$')) -or
            (-not $Traced -and ($command[10] -cne '0' -or $command[11] -cne '0'))) { throw 'invalid_unity_trace' }
        $lengths[('draw-{0:d4}-vs.bin' -f $draw)] = [uint32]$command[10]
        $lengths[('draw-{0:d4}-ps.bin' -f $draw)] = [uint32]$command[11]
    }
    return $lengths
}

function Complete-ValidationUnityFixture($Fixture, [string]$State) {
    if ($Fixture.kind -cne 'unity-startup' -and $State -ceq 'completed') { return Complete-ValidationUnityDraw $Fixture }
    $log = $Fixture.outputGuard.ReadBytes('unity-log.bin', 2097152)
    $captured = $Fixture.outputGuard.Exists('pixels.bin')
    $summary = Get-ValidationUnityStartupSummary $log $captured
    $bytes = [Text.Encoding]::UTF8.GetBytes(($summary | ConvertTo-Json -Compress))
    return [ordered]@{
        artifacts=@([ordered]@{name='unity-startup.json'; byteLength=$bytes.Length
            sha256=Get-ValidationDigest $bytes; base64=[Convert]::ToBase64String($bytes)})
        environment=$null; environmentSha256=$null
    }
}

Export-ModuleMember -Function New-ValidationUnityFixture, Complete-ValidationUnityFixture, Get-ValidationUnityStartupSummary, ConvertFrom-ValidationTabFields, Assert-ValidationUnityTrace, Assert-ValidationPackageImagePath
