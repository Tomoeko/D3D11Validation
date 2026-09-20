Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Unity.psm1') -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('selector-unit-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $root
try {
    $profile = [byte[]]::new(72)
    [Text.Encoding]::ASCII.GetBytes('DVSEL001').CopyTo($profile,0)
    for ($i=8; $i -lt 40; $i++) { $profile[$i] = 0xab }
    $path = Join-Path $root 'selector-profile.bin'
    [IO.File]::WriteAllBytes($path,$profile)
    $hash = (Get-FileHash $path).Hash.ToLowerInvariant()
    $image = 'ab' * 32
    $package = [pscustomobject]@{directory=$root; manifest=[pscustomobject]@{files=[pscustomobject]@{'selector-profile.bin'=$hash; 'UnityPlayer.dll'=$image}}}
    $fields = @{
        schema=@('dxbc-private-player-draw-domain/v4'); selector_profile_sha256=@($hash); selector_image_sha256=@($image)
        selector_initial=@('0:0'); selector_before_1=@('0:0'); selector_after_1=@('0:0'); selector_before_2=@('0:0'); selector_after_2=@('0:0')
    }
    $invoke = {param($f,$p) & (Get-Module Validation.Unity) {param($fields,$package) Get-ValidationSelectorObservation $fields $package} $f $p}
    $result = & $invoke $fields $package
    if ($result.sampleCount -ne 5 -or $result.registeredShaderExtensions -ne 0 -or $result.customShaderKeywords -ne 0) { throw 'Invalid selector observation' }
    $checks = 1
    foreach ($name in @($fields.Keys)) {
        $changed = $fields.Clone(); $changed[$name] = @('changed')
        $rejected = $false
        try { $null = & $invoke $changed $package } catch { $rejected = $true }
        if (-not $rejected) { throw 'Changed selector observation accepted' }; $checks++
        $changed = $fields.Clone(); $changed.Remove($name)
        $rejected = $false
        try { $null = & $invoke $changed $package } catch { $rejected = $true }
        if (-not $rejected) { throw 'Missing selector observation accepted' }; $checks++
    }
    foreach ($value in @('1:0','0:1','00:0','0:0:0')) {
        $changed = $fields.Clone(); $changed.selector_after_2 = @($value)
        $rejected = $false
        try { $null = & $invoke $changed $package } catch { $rejected = $true }
        if (-not $rejected) { throw 'Shader extension state accepted' }; $checks++
    }
    $profile[8] = 0xcd; [IO.File]::WriteAllBytes($path,$profile)
    $rejected = $false
    try { $null = & $invoke $fields $package } catch { $rejected = $true }
    if (-not $rejected) { throw 'Changed profile accepted' }; $checks++
    "PASS: $checks selector observation checks"
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
