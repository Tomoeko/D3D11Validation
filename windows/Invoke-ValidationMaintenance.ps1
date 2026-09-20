# Fixed SYSTEM scheduled action. Only authenticated data reaches this program.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Validation.Headless.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Maintenance.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$control = Join-Path $root 'setup/headless-v1'
$inbox = Join-Path $root 'data/maintenance-v1'
$guard = $null
$inboxGuard = $null
$receipt = $null
$receiptPath = $null
$verified = $null
function Save-Receipt {
    Write-MaintenanceRecord $receiptPath $receipt
    Write-MaintenanceRecord (Join-Path $control 'receipt.json') $receipt
}
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'maintenance_system_required' }
    Assert-ProtectedPath $root; Assert-ProtectedPath $control; Assert-ProtectedPath $PSScriptRoot
    # The listener may start before a link-local adapter becomes ready at boot.
    # Retry only the owned listener, at most three times per boot, and only once
    # its exact configured address is present. No firewall/configuration changes.
    $configuration = Read-HeadlessConfiguration
    $sshPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ssh/sshd_config'
    if ((Get-FileHash -LiteralPath $sshPath).Hash.ToLowerInvariant() -cne $configuration.sshConfigurationSha256) { throw 'maintenance_transport_drift' }
    $service = Get-Service sshd
    if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Automatic') {
        $transportPath = Join-Path $control 'transport-recovery.json'
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        $transport = if (Test-Path -LiteralPath $transportPath) { Read-HeadlessJson $transportPath } else { $null }
        if ($null -eq $transport -or $transport.boot -cne $boot) { $transport = [pscustomobject]@{boot=$boot; attempts=0} }
        if ($transport.attempts -lt 3 -and (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $configuration.listenAddress -ErrorAction SilentlyContinue)) {
            $transport.attempts++
            Write-MaintenanceRecord $transportPath $transport
            Start-Service sshd
        }
    }
    $pendingPath = Join-Path $inbox 'request.json'
    if (-not (Test-Path -LiteralPath $pendingPath)) { exit 0 }
    $inboxGuard = [IO.FileStream]::new((Join-Path $inbox 'inbox.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $bytes = [ValidationMaintenance]::ReadSnapshot($pendingPath,16384)
    $verified = Read-MaintenanceEnvelope ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) (Read-HeadlessPublicKey)
    $request = $verified.fields
    $receiptPath = Join-Path $control ('receipts/' + $request['requestId'] + '.json')
    if (Test-Path -LiteralPath $receiptPath) {
        $existing = Read-HeadlessJson $receiptPath
        if ($existing.requestSha256 -cne $verified.sha256) { throw 'maintenance_nonce_conflict' }
        # An interrupted request is never automatically executed again.
        Remove-Item -LiteralPath $pendingPath
        exit 0
    }
    if (@(Get-ChildItem -LiteralPath (Join-Path $control 'receipts') -File).Count -ge 4096) { throw 'maintenance_receipt_quota' }
    $state = Read-HeadlessActive
    Assert-MaintenanceTransition $request $state ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $lastPath = Join-Path $control 'receipt.json'
    if (Test-Path -LiteralPath $lastPath) {
        $last = Read-HeadlessJson $lastPath
        if ($last.phase -cnotin @('completed','failed') -and $request['action'] -cne 'repair') { throw 'maintenance_repair_required' }
    }
    $receipt = [ordered]@{schema='d3d11-maintenance-receipt/v1'; requestId=$request['requestId']; requestSha256=$verified.sha256
        action=$request['action']; generation=($state.generation + 1); phase='prepared'; failureCode=$null; qualification='not-run'}
    Write-MaintenanceRecord (Join-Path $control ('requests/' + $request['requestId'] + '.json')) ([Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json)
    Save-Receipt
    # Consume a generation before work starts, including failed attempts. This
    # prevents replay even if a later request replaces the latest status receipt.
    $state.generation++
    Write-MaintenanceRecord (Join-Path $control 'active.json') $state
    Remove-Item -LiteralPath $pendingPath
    $inboxGuard.Dispose(); $inboxGuard = $null
    $configuration = Read-HeadlessConfiguration
    if ($request['action'] -ceq 'activate') {
        $work = Join-Path $control ('staging/' + $request['requestId'])
        $null = New-Item -ItemType Directory -Path $work
        Assert-ProtectedPath $work
        $archive = Join-Path $work 'release.zip'
        [ValidationMaintenance]::Download($configuration.clientAddress,[int]$request['port'],$request['ticket'],
            $request['certificateSha256'],[long]$request['archiveBytes'],$request['archiveSha256'],$archive)
        $stage = Join-Path $work 'expanded'
        $roots = [ValidationMaintenance]::Extract($archive,$stage,$request['archiveSha256'])
        if ($request['deployment'] -cnotin $roots -or @($roots | Where-Object { $_.StartsWith('worker-') }).Count -ne 1) { throw 'maintenance_release_worker' }
        foreach ($name in $roots) {
            $source = Join-Path $stage $name
            $destination = Join-Path (Join-Path $root 'program') $name
            if (Test-Path -LiteralPath $destination) { throw 'maintenance_preserve_existing_deployment' }
            # No overwrite and no elevated execution of any extracted content.
            [IO.Directory]::Move($source,$destination)
            Assert-ProtectedPath $destination
        }
        $candidate = [pscustomobject]@{schema=$state.schema; generation=$state.generation; deployment=$request['deployment']; policySha256=$request['policySha256']}
        $null = Get-HeadlessWorkerPath $candidate
        $receipt.phase = 'staged'; Save-Receipt
    }
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $task = $scheduler.GetFolder('\').GetTask('D3D11Validation-Worker')
    Assert-HeadlessTask $task
    $receipt.phase = 'stopping'; Save-Receipt
    Stop-HeadlessWorker $task
    $guard = Open-HeadlessWriteGuard
    if ($request['action'] -ceq 'archive') {
        $archiveName = 'queue-archive-v' + $state.generation
        $null = & (Join-Path $PSScriptRoot 'Archive-ValidationQueue.ps1') -Deployment $state.deployment -ArchiveName $archiveName -Headless
    } elseif ($request['action'] -ceq 'activate') {
        Write-MaintenanceRecord (Join-Path $control 'active.json') $candidate
        $state = $candidate
    }
    $null = Get-HeadlessWorkerPath $state
    $receipt.phase = 'activated'; Save-Receipt
    $guard.Dispose(); $guard = $null
    $task.Enabled = $true
    $null = $task.Run($null)
    $receipt.phase = 'completed'; Save-Receipt
} catch {
    if ($null -eq $receipt -and $null -ne $verified -and $null -ne $inboxGuard -and $receiptPath -and -not (Test-Path -LiteralPath $receiptPath)) {
        # A signed request that expired while queued or lost its expected state
        # receives a durable rejection; it must not wedge the single-slot inbox.
        $receipt = [ordered]@{schema='d3d11-maintenance-receipt/v1'; requestId=$verified.fields['requestId']; requestSha256=$verified.sha256
            action=$verified.fields['action']; phase='rejected'; failureCode=$null; qualification='not-run'}
        if (@(Get-ChildItem -LiteralPath (Join-Path $control 'receipts') -File).Count -ge 4096) { $receipt=$null }
        else { Remove-Item -LiteralPath $pendingPath }
    }
    if ($null -ne $receipt) {
        $receipt['failedPhase'] = $receipt.phase
        $receipt.phase = 'failed'
        # Never serialize exception paths, command lines, or host/account names.
        $receipt.failureCode = 'maintenance_failed_requires_status_review'
        $failure = $_.Exception
        while ($null -ne $failure) {
            if ($failure.Message -cmatch '^maintenance_[a-z_]+\z') { $receipt.failureCode = $failure.Message; break }
            $failure = $failure.InnerException
        }
        Save-Receipt
    }
    exit 1
} finally {
    if ($null -ne $guard) { $guard.Dispose() }
    if ($null -ne $inboxGuard) { $inboxGuard.Dispose() }
}
