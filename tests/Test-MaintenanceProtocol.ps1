# Portable trust-boundary tests. No installation, network, task, or account changes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Maintenance.psm1') -Force
$checks = 0
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw ('Expected maintenance rejection after check ' + $script:checks + ': ' + $Action) }
    $script:checks++
}
$r = [ordered]@{version='1'; requestId=('a'*32); action='activate'; generation='1'; expectedPolicy=('b'*64)
    deployment='worker-v21'; policySha256=('c'*64); archiveSha256=('d'*64); archiveBytes='1000'; port='4433'
    ticket=('e'*48); certificateSha256=('f'*64); expiresUnix='1800000300'}
$text = $r | ConvertTo-Json -Compress
$request = Read-MaintenanceRequest $text
$checks++
$state = [pscustomobject]@{schema='d3d11-active-deployment/v1'; generation=1; deployment='worker-v20'; policySha256=('b'*64)}
Assert-MaintenanceTransition $request $state 1800000000
$checks++
foreach ($change in @(
    @{generation='0'}, @{generation='01'}, @{generation='1000000000'}, @{action='shell'}, @{deployment='../worker-v21'},
    @{deployment='worker-v021'}, @{deployment='worker-v21/other'}, @{archiveBytes='268435457'}, @{archiveBytes='1e8'},
    @{port='65536'}, @{port='0'}, @{port='0443'}, @{ticket='..'}, @{certificateSha256=('F'*64)}, @{expiresUnix='0'}
)) {
    $copy = [ordered]@{}; foreach ($key in $r.Keys) { $copy[$key] = $r[$key] }
    foreach ($key in $change.Keys) { $copy[$key] = $change[$key] }
    Reject { Read-MaintenanceRequest ($copy | ConvertTo-Json -Compress) }
}
foreach ($bad in @($text.Replace('"version":"1"','"version":"1","version":"1"'),
    $text.Replace('"version"','"Version"'), $text.Replace('"version":"1"','"version":1'),
    $text.Replace('"version"','"vers\u0069on"'), ($text.Substring(0,$text.Length-1)+',}'),
    ($text+'x'), (' '*16385), $text.Replace('"1"','{}'))) { Reject { Read-MaintenanceRequest $bad } }
Reject { Assert-MaintenanceTransition $request $state 1800000301 }
Reject { Assert-MaintenanceTransition $request $state 1799999000 }
$state.generation = 2
Reject { Assert-MaintenanceTransition $request $state 1800000000 }
$state.generation = 1; $state.policySha256 = '0'*64
Reject { Assert-MaintenanceTransition $request $state 1800000000 }
$state.policySha256 = 'b'*64; $state.deployment = 'worker-v21'
Reject { Assert-MaintenanceTransition $request $state 1800000000 }
foreach ($action in @('repair','archive')) {
    $copy = [ordered]@{}; foreach ($key in $r.Keys) { $copy[$key] = $r[$key] }
    $copy.action = $action
    foreach ($key in @('deployment','policySha256','archiveSha256','archiveBytes','port','ticket','certificateSha256')) { $copy[$key] = '-' }
    $null = Read-MaintenanceRequest ($copy | ConvertTo-Json -Compress); $checks++
    $copy.port = '443'
    Reject { Read-MaintenanceRequest ($copy | ConvertTo-Json -Compress) }
}
foreach ($name in @('worker-v21/worker-policy.json','unity-draw-v5/RuntimeProbe_Data/Managed/Assembly-CSharp.dll','unity-unhooked-v4/MonoBleedingEdge/a b.bin')) {
    Assert-MaintenanceMember $name; $checks++
}
foreach ($name in @('/worker-v21/a','worker-v21/../a','worker-v21/./a','worker-v21//a','worker-v21/a.','worker-v21/a ',
    'worker-v21/CON','worker-v21/con.txt','worker-v21/LPT1.log','worker-v21/a:b','worker-v21/a\b','worker-v21/a~1',
    ('worker-v21/a'+[char]0),('worker-v21/a'+[char]10),'headless-v2/a','worker-v21/','worker-v0/a','worker-v21/a?')) {
    Reject { Assert-MaintenanceMember $name }
}
$rsa = [Security.Cryptography.RSA]::Create(3072)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $signature = $rsa.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $envelope = [ordered]@{request=[Convert]::ToBase64String($bytes); signature=[Convert]::ToBase64String($signature)}
    $encoded = $envelope | ConvertTo-Json -Compress
    $verified = Read-MaintenanceEnvelope $encoded ($rsa.ToXmlString($false))
    if ($verified.sha256 -cne (Get-MaintenanceDigest $bytes) -or $verified.fields['requestId'] -cne $r.requestId) { throw 'Binding failed' }
    $checks++
    $signature[0] = $signature[0] -bxor 1
    $envelope.signature = [Convert]::ToBase64String($signature)
    Reject { Read-MaintenanceEnvelope ($envelope | ConvertTo-Json -Compress) ($rsa.ToXmlString($false)) }
    $envelope.signature = 'AA=='
    Reject { Read-MaintenanceEnvelope ($envelope | ConvertTo-Json -Compress) ($rsa.ToXmlString($false)) }
    $other = [Security.Cryptography.RSA]::Create(3072)
    try { Reject { Read-MaintenanceEnvelope $encoded ($other.ToXmlString($false)) } } finally { $other.Dispose() }
} finally { $rsa.Dispose() }
[ordered]@{schema='d3d11-maintenance-protocol-tests/v1'; checksPassed=$checks; hostChanges=$false} | ConvertTo-Json
