# The maintenance trust root is installed locally by an administrator. This module
# never imports or executes code from a remotely supplied worker deployment.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not ('ValidationMaintenance' -as [type])) {
    if ($PSVersionTable.PSEdition -ceq 'Desktop') {
        Add-Type -Path (Join-Path $PSScriptRoot 'Validation.Maintenance.cs') -ReferencedAssemblies System.IO.Compression, System.IO.Compression.FileSystem
    } else { Add-Type -Path (Join-Path $PSScriptRoot 'Validation.Maintenance.cs') }
}

function Get-MaintenanceDigest([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Read-MaintenanceFields([string]$Text, [string[]]$Names, [int]$MaximumValue = 256) {
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 16384 -or $MaximumValue -gt 12000) { throw 'maintenance_request_size' }
    # Small, flat ASCII wire format. No JSON escapes, aliases, duplicate fields,
    # numbers interpreted with rounding, nested values, or trailing commas.
    $body = $Text.Trim([char[]]" `r`n`t")
    if ($body.Length -lt 2 -or $body[0] -cne '{' -or $body[-1] -cne '}') { throw 'maintenance_request_format' }
    $body = $body.Substring(1,$body.Length - 2)
    $pattern = '\G[ \t\r\n]*"(?<key>[A-Za-z][A-Za-z0-9]*)"[ \t\r\n]*:[ \t\r\n]*"(?<value>[A-Za-z0-9_+/=-]{0,' + $MaximumValue + '})"[ \t\r\n]*(?:,|\z)'
    $matches = [regex]::Matches($body,$pattern,[Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromMilliseconds(100))
    $fields = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $consumed = 0
    foreach ($match in $matches) {
        $name = $match.Groups['key'].Value
        if ($fields.ContainsKey($name) -or $name -cnotin $Names) { throw 'maintenance_request_fields' }
        $fields.Add($name,$match.Groups['value'].Value)
        $consumed += $match.Length
    }
    if ($consumed -ne $body.Length -or $fields.Count -ne $Names.Count -or $body.TrimEnd().EndsWith(',')) { throw 'maintenance_request_fields' }
    return ,$fields
}

function Read-MaintenanceRequest([string]$Text) {
    $names = @('version','requestId','action','generation','expectedPolicy','deployment','policySha256',
        'archiveSha256','archiveBytes','port','ticket','certificateSha256','expiresUnix')
    $r = Read-MaintenanceFields $Text $names
    if ($r['version'] -cne '1' -or $r['requestId'] -cnotmatch '^[0-9a-f]{32}\z' -or
        $r['action'] -cnotin @('activate','repair','archive') -or
        $r['generation'] -cnotmatch '^[1-9][0-9]{0,8}\z' -or
        $r['expectedPolicy'] -cnotmatch '^[0-9a-f]{64}\z' -or
        $r['expiresUnix'] -cnotmatch '^[1-9][0-9]{9}\z') { throw 'maintenance_request_identity' }
    $download = @('deployment','policySha256','archiveSha256','archiveBytes','port','ticket','certificateSha256')
    if ($r['action'] -ceq 'activate') {
        if ($r['deployment'] -cnotmatch '^worker-v[1-9][0-9]{0,8}\z' -or
            $r['policySha256'] -cnotmatch '^[0-9a-f]{64}\z' -or
            $r['archiveSha256'] -cnotmatch '^[0-9a-f]{64}\z' -or
            $r['certificateSha256'] -cnotmatch '^[0-9a-f]{64}\z' -or
            $r['archiveBytes'] -cnotmatch '^[1-9][0-9]{0,8}\z' -or [long]$r['archiveBytes'] -gt 268435456 -or
            $r['port'] -cnotmatch '^[1-9][0-9]{0,4}\z' -or [int]$r['port'] -gt 65535 -or
            $r['ticket'] -cnotmatch '^[0-9a-f]{48}\z') { throw 'maintenance_download_identity' }
    } else {
        foreach ($name in $download) { if ($r[$name] -cne '-') { throw 'maintenance_unexpected_download' } }
    }
    return ,$r
}

function Read-MaintenanceEnvelope([string]$Text, [string]$PublicKeyXml) {
    $envelope = Read-MaintenanceFields $Text @('request','signature') 12000
    try {
        $bytes = [Convert]::FromBase64String($envelope['request'])
        $signature = [Convert]::FromBase64String($envelope['signature'])
    } catch { throw 'maintenance_signature_encoding' }
    if ($bytes.Length -gt 4096 -or $signature.Length -ne 384 -or
        [Convert]::ToBase64String($bytes) -cne $envelope['request'] -or
        [Convert]::ToBase64String($signature) -cne $envelope['signature']) { throw 'maintenance_signature_encoding' }
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $rsa.FromXmlString($PublicKeyXml)
        if ($rsa.KeySize -ne 3072 -or -not $rsa.VerifyData($bytes,$signature,
            [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
            throw 'maintenance_signature_invalid'
        }
    } finally { $rsa.Dispose() }
    $request = Read-MaintenanceRequest ([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
    return [pscustomobject]@{fields=$request; sha256=(Get-MaintenanceDigest $bytes)}
}

function Assert-MaintenanceTransition($Request, $State, [long]$NowUnix) {
    if ($State.schema -cne 'd3d11-active-deployment/v1' -or
        $State.generation -isnot [long] -and $State.generation -isnot [int] -or
        $State.generation -lt 1 -or $State.generation -ge 999999999 -or
        $State.deployment -cnotmatch '^worker-v[1-9][0-9]{0,8}\z' -or
        $State.policySha256 -cnotmatch '^[0-9a-f]{64}\z') { throw 'maintenance_active_identity' }
    if ([long]$Request['generation'] -ne $State.generation -or
        $Request['expectedPolicy'] -cne $State.policySha256) { throw 'maintenance_stale_generation' }
    $expiry = [long]$Request['expiresUnix']
    if ($expiry -lt $NowUnix -or $expiry -gt $NowUnix + 600) { throw 'maintenance_request_expired' }
    if ($Request['action'] -ceq 'activate' -and $Request['deployment'] -ceq $State.deployment) { throw 'maintenance_existing_deployment' }
}

function Assert-MaintenanceMember([string]$Name) {
    [ValidationMaintenance]::CheckMember($Name)
}

function Write-MaintenanceRecord([string]$Path, $Record) {
    # Caller establishes a protected parent and serializes writers before calling.
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 20 -Compress))
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $file = [IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$Path) }
}

Export-ModuleMember -Function Get-MaintenanceDigest, Read-MaintenanceFields, Read-MaintenanceRequest,
    Read-MaintenanceEnvelope, Assert-MaintenanceTransition, Assert-MaintenanceMember, Write-MaintenanceRecord
