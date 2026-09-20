# Operator maintenance; never callable through the SSH gateway.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^worker-v[1-9][0-9]*$')][string]$Deployment,
    [Parameter(Mandatory)][ValidatePattern('^queue-archive-v[1-9][0-9]*$')][string]$ArchiveName,
    [ValidatePattern('^queue-archive-v[1-9][0-9]*$')][string]$ImportArchive
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$program = Join-Path ($root + '/program') $Deployment
Import-Module (Join-Path $program 'Validation.Setup.psm1')
Import-Module (Join-Path $program 'Validation.Archive.psm1')
Assert-ProtectedPath $root
Assert-ProtectedPath ($root + '/program')
Assert-ProtectedPath $program
$administrator = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $administrator.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated operator required.' }
$task = Get-ScheduledTask -TaskName 'D3D11Validation-Worker'
if ($task.Settings.Enabled -or $task.State -eq 'Running' -or (Get-Service sshd).Status -ne 'Stopped') {
    throw 'Disable the owned task and stop validation SSH before archiving.'
}
# Disabled state can be reported before Task Scheduler has terminated its process.
# Wait for both the task instance and every validation worker process to disappear.
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$registered = $scheduler.GetFolder('\').GetTask('D3D11Validation-Worker')
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $workers = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
        $_.CommandLine -and $_.CommandLine.Replace('\','/').Contains($root.Replace('\','/') + '/program/') -and
        $_.CommandLine.Contains('Start-ValidationWorker.ps1')
    })
    if ($registered.GetInstances(0).Count -eq 0 -and $workers.Count -eq 0) { break }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Validation worker did not stop; preserve the queue.' }
    Start-Sleep -Milliseconds 100
} while ($true)
$queue = Join-Path ($root + '/data') 'queue-v1'
$archive = Join-Path ($root + '/data') $ArchiveName
$replacement = Join-Path ($root + '/data') ($ArchiveName + '-replacement')
if ((Test-Path $archive) -or (Test-Path $replacement)) { throw 'Preserve an existing archive or interrupted maintenance.' }
if (-not ('ValidationStore' -as [type])) { Add-Type -Path (Join-Path $program 'Validation.Runtime.cs') }
$store = [ValidationStore]::new($queue)
function Add-RequestRecord($Requests, [string]$Name, $Record) {
    $nonce = $Name.Substring(8,64)
    if ($Record.requestNonce -cne $nonce) { throw 'archive_request_identity_mismatch' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Record.requestText)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($digest -cne $Record.inputSha256) { throw 'archive_request_content_mismatch' }
    Add-ValidationArchivedRequest $Requests $nonce $digest
}
$inventory = [ordered]@{}
$requests = [ordered]@{}
try {
    foreach ($item in Get-ChildItem -LiteralPath $queue -Force) {
        if ($item.Name -ceq 'store.lock') { continue }
        if ($item.Name -cnotmatch '^(worker|archived-requests|job-[0-9a-f]{32}|request-[0-9a-f]{64})\.json$') {
            throw 'Unexpected queue entry; preserve it for review.'
        }
        $bytes = $store.ReadBytes($item.Name, 16777216)
        $record = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json
        if ($item.Name -ceq 'archived-requests.json') {
            $previous = ConvertFrom-ValidationArchive $record
            foreach ($entry in $previous.GetEnumerator()) { Add-ValidationArchivedRequest $requests $entry.Key $entry.Value }
        } elseif ($item.Name.StartsWith('request-')) {
            Add-RequestRecord $requests $item.Name $record
        }
        if ($item.Name.StartsWith('job-')) {
            $job = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
            if ($job.state -in @('queued','running')) { throw 'Resolve interrupted jobs before archiving.' }
            if ($job.state -cnotin @('submitted','completed','failed','timed_out','cancelled','stale')) { throw 'invalid_archived_job_state' }
            if ($job.state -ceq 'submitted' -and
                ([DateTime]::UtcNow - [DateTime]::Parse($job.createdUtc).ToUniversalTime()).TotalMinutes -le 5) {
                throw 'Resolve unexpired submissions before archiving.'
            }
        }
        $inventory[$item.Name] = (Get-FileHash -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    }
    $acl = Get-Acl -LiteralPath $queue
} finally { $store.Dispose() }
# Keep the exact pre-move hashes on protected storage even if later work fails.
$journalDirectory = Join-Path $root 'setup'
Assert-ProtectedPath $journalDirectory
$journal = Join-Path $journalDirectory ($ArchiveName + '-inventory.json')
if (Test-Path $journal) { throw 'Preserve the existing maintenance journal.' }
[IO.File]::WriteAllText($journal, ($inventory | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
Assert-ProtectedPath $journal
# One-time migration of a previous archive that predates durable tombstones.
# It must already be protected from the worker's writes; no capabilities are copied.
if ($ImportArchive) {
    $prior = Join-Path ($root + '/data') $ImportArchive
    Assert-ProtectedPath $prior
    foreach ($item in Get-ChildItem -LiteralPath $prior -Filter 'request-*.json') {
        Assert-ProtectedPath $item.FullName
        if ($item.Name -cnotmatch '^request-[0-9a-f]{64}\.json$' -or $item.Length -gt 16777216) { throw 'invalid_archive_request' }
        $record = Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
        Add-RequestRecord $requests $item.Name $record
    }
}
# Prepare the replacement before moving anything. A failed swap leaves the
# complete archive and replacement available; no evidence or identity is deleted.
$null = New-Item -ItemType Directory -Path $replacement
Set-Acl -LiteralPath $replacement -AclObject $acl
$store = [ValidationStore]::new($replacement)
try {
    $store.Write('archived-requests.json', ([ordered]@{schema='d3d11-archived-requests/v1'; requests=$requests} | ConvertTo-Json -Depth 4 -Compress))
} finally { $store.Dispose() }
Move-Item -LiteralPath $queue -Destination $archive
Move-Item -LiteralPath $replacement -Destination $queue
foreach ($entry in $inventory.GetEnumerator()) {
    if ((Get-FileHash -LiteralPath (Join-Path $archive $entry.Key)).Hash.ToLowerInvariant() -cne $entry.Value) {
        throw 'Archived content changed; keep transport and worker stopped.'
    }
}
$adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$runnerSid = (Get-LocalUser -Name d3d11validator).SID
foreach ($item in @((Get-Item -LiteralPath $archive)) + @(Get-ChildItem -LiteralPath $archive -Force)) {
    # Change ownership as well as permissions: a previous file owner could
    # otherwise restore write access to archived evidence.
    $security = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() }
                else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner($adminSid)
    $security.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($adminSid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow'))
    }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($runnerSid,'ReadAndExecute','Allow'))
    Set-Acl -LiteralPath $item.FullName -AclObject $security
    Assert-ProtectedPath $item.FullName
}
$store = [ValidationStore]::new($queue)
try { if ($store.Jobs().Count -ne 0) { throw 'Replacement queue is not empty.' } }
finally { $store.Dispose() }
[ordered]@{schema='d3d11-queue-archive/v1'; archive=$ArchiveName
    preservedRecords=$inventory.Count; previousCapabilitiesRemainInArchive=$true
    activeQueueEmpty=$true; archivedRequestCount=$requests.Count
    evidenceDeleted=$false; files=$inventory} | ConvertTo-Json -Depth 5
