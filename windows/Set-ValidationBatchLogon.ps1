# Fixed-account, operator-only privilege setup with targeted rollback ownership.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Status','Grant','Remove')][string]$Mode)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
$operator = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $operator.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the authorized elevated setup console.' }
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
Assert-ProtectedPath $root
Assert-ProtectedPath $PSScriptRoot
$source = Join-Path $PSScriptRoot 'Validation.LogonRights.cs'
Assert-ProtectedPath $source
if (-not ('ValidationLogonRights' -as [type])) { Add-Type -Path $source }
$account = Get-LocalUser -Name d3d11validator
if (-not $account.Enabled -or (Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object SID -eq $account.SID)) {
    throw 'The dedicated account must be enabled and non-administrative.'
}
$sid = $account.SID.Value
$before = @([ValidationLogonRights]::Read($sid))
$right = [ValidationLogonRights]::Batch
$journalDirectory = Join-Path $root 'setup'
$journalPath = Join-Path $journalDirectory 'batch-logon.json'
if ($Mode -ceq 'Status') {
    [ordered]@{batchLogonGranted=($right -cin $before); directDenyPresent=('SeDenyBatchLogonRight' -cin $before)
        accountIsStandard=$true; changesApplied=$false} | ConvertTo-Json
    return
}
if ('SeDenyBatchLogonRight' -cin $before) { throw 'Preserve the existing batch-logon denial for operator review.' }
if (-not (Test-Path -LiteralPath $journalDirectory)) { $null = New-Item -ItemType Directory -Path $journalDirectory }
Assert-ProtectedPath $journalDirectory
if (Test-Path -LiteralPath $journalPath) {
    Assert-ProtectedPath $journalPath
    $journal = Get-Content -Raw -LiteralPath $journalPath | ConvertFrom-Json
    if ($journal.schema -cne 'd3d11-batch-logon/v1' -or $journal.accountSid -cne $sid -or
        $journal.right -cne $right -or $journal.preExisting -isnot [bool]) { throw 'Preserve the conflicting ownership journal.' }
} else {
    if ($Mode -ceq 'Remove') { throw 'No setup ownership record; preserve existing rights.' }
    $journal = [pscustomobject][ordered]@{schema='d3d11-batch-logon/v1'; accountSid=$sid; right=$right
        preExisting=($right -cin $before); originalRights=$before; phase='prepared'}
}
function Save-Journal {
    $temporary = Join-Path $journalDirectory ([Guid]::NewGuid().ToString('N') + '.tmp')
    $bytes = [Text.Encoding]::UTF8.GetBytes(($journal | ConvertTo-Json -Depth 4))
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $journalPath) { [IO.File]::Replace($temporary, $journalPath, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $journalPath) }
}
Save-Journal # Durable intent precedes the single-right mutation.
$enabled = $Mode -ceq 'Grant'
$change = if ($enabled) { $right -cnotin $before } else { -not $journal.preExisting -and $right -cin $before }
if ($change) { [ValidationLogonRights]::SetBatch($sid, $enabled) }
$after = @([ValidationLogonRights]::Read($sid))
if (@(Compare-Object @($before | Where-Object { $_ -cne $right }) @($after | Where-Object { $_ -cne $right })).Count) {
    throw 'Unrelated account rights changed; preserve the journal for review.'
}
if (($enabled -and $right -cnotin $after) -or (-not $enabled -and -not $journal.preExisting -and $right -cin $after)) {
    throw 'Batch-logon right did not reach the expected state.'
}
$journal.phase = if ($enabled) { 'granted' } else { 'removed' }
Save-Journal
[ordered]@{batchLogonGranted=($right -cin $after); changesApplied=[bool]$change
    preExistingRightPreserved=[bool]$journal.preExisting; unrelatedRightsPreserved=$true; passwordStored=$false} | ConvertTo-Json
