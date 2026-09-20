Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Graphics.psm1')
$baseline = Get-Content (Join-Path $PSScriptRoot '../config/native-baseline.json') -Raw | ConvertFrom-Json
$checks = 0
foreach ($runtime in $baseline.runtimeIdentities) {
    foreach ($signature in $runtime.signatures) {
        $valid = [ordered]@{file=$runtime.file; version=$runtime.version; sha256=$runtime.sha256
            signatureStatus='Valid'; signatureType=$signature.type; signer=$signature.signer
            certificateSha256=$signature.certificateSha256}
        Assert-ValidationRuntimeIdentity $valid $runtime
        $checks++
        foreach ($mutation in @(
            { param($i) $i.file = 'unapproved.dll' },
            { param($i) $i.version = 'unexpected' },
            { param($i) $i.sha256 = '0' * 64 },
            { param($i) $i.signatureStatus = 'NotTrusted' },
            { param($i) $i.signatureType = 'None' },
            { param($i) $i.signer = 'unapproved signer' },
            { param($i) $i.certificateSha256 = '0' * 64 }
        )) {
            $changed = $valid | ConvertTo-Json | ConvertFrom-Json
            & $mutation $changed
            $rejected = $false
            try { Assert-ValidationRuntimeIdentity $changed $runtime } catch { $rejected = $true }
            if (-not $rejected) { throw 'Unexpected accepted runtime identity mutation.' }
            $checks++
        }
    }
}
"PASS: $checks runtime identity acceptance/rejection checks"
