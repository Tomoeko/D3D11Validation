# Shared request validation for the SSH dispatcher and interactive worker.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-ValidationRequest([string]$Code) {
    $validationFailure = [InvalidOperationException]::new($Code)
    $validationFailure.Data['validationCode'] = $Code
    throw $validationFailure
}

function Get-ValidationDigest([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function New-ValidationNonce {
    $bytes = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function ConvertFrom-ValidationRequest([string]$Operation, [string]$Text) {
    if ($Operation -cnotin @('submit', 'start', 'status', 'results', 'cancel')) {
        Stop-ValidationRequest 'unsupported_operation'
    }
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 8192) {
        Stop-ValidationRequest 'request_too_large'
    }
    $textValue = $Text.Trim([char[]]" `t`r`n")
    if ($textValue.Length -lt 2 -or $textValue[0] -ne '{' -or $textValue[-1] -ne '}') {
        Stop-ValidationRequest 'invalid_request'
    }
    $body = $textValue.Substring(1, $textValue.Length - 2)
    # The wire format is deliberately a flat object of bounded ASCII strings.
    # No escape forms, nested objects, case aliases, or duplicate keys are accepted.
    $pattern = '\G[ \t\r\n]*"(?<key>[A-Za-z][A-Za-z0-9]*)"[ \t\r\n]*:[ \t\r\n]*"(?<value>[A-Za-z0-9_-]{0,256})"[ \t\r\n]*(?:,|\z)'
    $fieldMatches = [regex]::Matches($body, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant,
        [TimeSpan]::FromMilliseconds(100))
    $fields = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $consumed = 0
    foreach ($match in $fieldMatches) {
        $key = $match.Groups['key'].Value
        if ($fields.ContainsKey($key) -or $fields.Count -ge 8) { Stop-ValidationRequest 'invalid_request' }
        $fields.Add($key, $match.Groups['value'].Value)
        $consumed += $match.Length
    }
    if ($consumed -ne $body.Length -or $body.TrimEnd([char[]]" `t`r`n").EndsWith(',')) {
        Stop-ValidationRequest 'invalid_request'
    }
    $required = @('version', 'nonce')
    if ($Operation -ceq 'submit') {
        $required += @('kind', 'durationMs')
    } else {
        $required += @('jobId', 'capability')
    }
    if ($fields.Count -ne $required.Count) { Stop-ValidationRequest 'invalid_fields' }
    foreach ($key in $required) {
        if (-not $fields.ContainsKey($key)) { Stop-ValidationRequest 'invalid_fields' }
    }
    if ($fields['version'] -cne '1' -or $fields['nonce'] -cnotmatch '^[0-9a-f]{64}$') {
        Stop-ValidationRequest 'invalid_request'
    }
    if ($Operation -ceq 'submit') {
        # Fixture names select protected server policy; no executable, adapter,
        # or destination path is accepted from the client.
        $unityDraw = $fields['kind'] -cmatch '^unity-(recovered|regenerated|negative)-(on|off)-tier[0-2]-(traced|untraced|unhooked)$'
        if (($fields['kind'] -cnotin @('diagnostic','device','reject-software','reject-other-gpu','reject-session','unity-startup') -and -not $unityDraw) -or $fields['durationMs'] -cnotmatch '^(0|[1-9][0-9]{0,3})$' -or
            [int]$fields['durationMs'] -gt 5000 -or ($fields['kind'] -cne 'diagnostic' -and $fields['durationMs'] -cne '0')) {
            Stop-ValidationRequest 'invalid_fixture'
        }
    } elseif ($fields['jobId'] -cnotmatch '^[0-9a-f]{32}$' -or
        $fields['capability'] -cnotmatch '^[0-9a-f]{64}$') {
        Stop-ValidationRequest 'invalid_job_identity'
    }
    return ,$fields
}

Export-ModuleMember -Function Stop-ValidationRequest, Get-ValidationDigest,
    New-ValidationNonce, ConvertFrom-ValidationRequest
