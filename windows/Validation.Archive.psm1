# Durable submission tombstones survive queue rotation without job capabilities.
Set-StrictMode -Version Latest

function Add-ValidationArchivedRequest($Requests, [string]$Nonce, [string]$Digest) {
    if ($Nonce -cnotmatch '^[0-9a-f]{64}$' -or $Digest -cnotmatch '^[0-9a-f]{64}$') {
        throw 'invalid_archive_request'
    }
    if ($Requests.Contains($Nonce)) {
        if ($Requests[$Nonce] -cne $Digest) { throw 'archive_nonce_conflict' }
    } else {
        if ($Requests.Count -ge 10000) { throw 'request_history_quota_reached' }
        $Requests[$Nonce] = $Digest
    }
}

function ConvertFrom-ValidationArchive($Record) {
    if ($Record.schema -cne 'd3d11-archived-requests/v1' -or
        @($Record.PSObject.Properties).Count -ne 2 -or
        $Record.requests -isnot [pscustomobject]) { throw 'invalid_archive_index' }
    $requests = [ordered]@{}
    foreach ($entry in $Record.requests.PSObject.Properties) {
        Add-ValidationArchivedRequest $requests $entry.Name $entry.Value
    }
    return ,$requests
}

Export-ModuleMember -Function Add-ValidationArchivedRequest, ConvertFrom-ValidationArchive
