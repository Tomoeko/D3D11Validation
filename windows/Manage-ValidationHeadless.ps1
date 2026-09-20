# One local elevated entry point for the existing, qualified Windows installation.
# First adoption is explicit. This does not claim clean-install acceptance.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Install','Reinstall','Repair','Status','Remove')][string]$Mode,
    [ValidatePattern('^worker-v[1-9][0-9]{0,8}$')][string]$Deployment,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$PolicySha256,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$SourceManifestSha256,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$GatewaySha256,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$SshConfigurationSha256,
    [string]$PublisherKeyPath,
    [string]$ClientAddress,
    [switch]$ResumeRolledBack
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1 or newer on the Windows host.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this one-time setup in an elevated Windows PowerShell console.' }
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$installed = Join-Path $root 'program/headless-v1'
$control = Join-Path $root 'setup/headless-v1'
$gateway = Join-Path $root 'program/Invoke-ValidationGateway.ps1'
$sshConfiguration = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ssh/sshd_config'
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$folder = $scheduler.GetFolder('\')
$encoding = [Text.UTF8Encoding]::new($false)
$journalPath = Join-Path $control 'installation.json'
$resume = $false
if (Test-Path -LiteralPath $journalPath) {
    $installation = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    if ($installation.phase -cne 'installed') {
        if ($Mode -ceq 'Status') { $installation | ConvertTo-Json; return }
        if ($Mode -ceq 'Install' -and $ResumeRolledBack -and $installation.phase -ceq 'rolled-back' -and $installation.rollbackComplete -eq $true) { $resume=$true }
        else { throw 'Previous bootstrap did not finish. Original components were preserved; inspect installation.json before resuming.' }
    }
}

function Write-Durable([string]$Path,[byte[]]$Bytes) {
    $stream = [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Get-Digest([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Assert-SameHash([string]$Path,[string]$Expected) {
    if (-not $Expected -or (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -cne $Expected) { throw 'Preserve the mismatched installation component.' }
}
function New-TaskDefinition([string]$AccountSid,[string]$Script,[bool]$Maintenance) {
    # Use the explicit schema already qualified for the previous S4U worker,
    # including the principal/action ID. COM property defaults can be rewritten
    # during registration; an omitted execution setting is not an approval.
    $definition = $scheduler.NewTask(0)
    $escape = { param($Value) [Security.SecurityElement]::Escape([string]$Value) }
    $executable = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $installed $Script) + '"'
    $logon = if ($Maintenance) { '' } else { '<LogonType>S4U</LogonType>' }
    $limit = if ($Maintenance) { 'PT5M' } else { 'PT0S' }
    $repeat = if ($Maintenance) {
        '<TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>' + [DateTime]::Now.AddMinutes(1).ToString('s') + '</StartBoundary><Enabled>true</Enabled></TimeTrigger>'
    } else { '' }
    $restart = if ($Maintenance) { '' } else { '<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>' }
    $definition.XmlText = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>D3D11Validation</Author><Description>Fixed headless validation entry; release selection is protected data.</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger>$repeat</Triggers>
  <Principals><Principal id="Runner"><UserId>$AccountSid</UserId>$logon<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>$limit</ExecutionTimeLimit><Priority>7</Priority>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>$restart
  </Settings>
  <Actions Context="Runner"><Exec><Command>$(& $escape $executable)</Command><Arguments>$(& $escape $arguments)</Arguments><WorkingDirectory>$(& $escape $installed)</WorkingDirectory></Exec></Actions>
</Task>
"@
    return $definition
}

if (-not $resume -and ($Mode -cne 'Install' -or (Test-Path -LiteralPath (Join-Path $control 'configuration.json')))) {
    if (-not (Test-Path -LiteralPath (Join-Path $control 'configuration.json'))) { throw 'No completed bootstrap configuration exists; preserve partial state for review.' }
    Import-Module (Join-Path $installed 'Validation.Headless.psm1')
    Import-Module (Join-Path $installed 'Validation.Setup.psm1')
    Import-Module (Join-Path $installed 'Validation.Task.psm1')
    $configuration = Read-HeadlessConfiguration
    $task = $folder.GetTask('D3D11Validation-Worker')
    Assert-HeadlessTask $task
    $maintenance = $folder.GetTask('D3D11Validation-Maintenance')
    $expectedMaintenance = [IO.File]::ReadAllText((Join-Path $control 'maintenance-task.xml'))
    Assert-ValidationTaskDefinition $maintenance.Definition.XmlText $expectedMaintenance 'S-1-5-18' ([bool]$maintenance.Enabled)
    Assert-ValidationTaskSecurity ($maintenance.GetSecurityDescriptor(7)) 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    Assert-SameHash $gateway $configuration.routerSha256
    Assert-SameHash $sshConfiguration $configuration.sshConfigurationSha256
    if ($Mode -ceq 'Status' -or $Mode -ceq 'Install') {
        $status = Get-HeadlessStatus
        $status['workerTaskEnabled'] = [bool]$task.Enabled
        $status['maintenanceTaskEnabled'] = [bool]$maintenance.Enabled
        $status['sshStartup'] = [string](Get-Service sshd).StartType
        $status | ConvertTo-Json -Depth 10
        return
    }
    if ($Mode -cin @('Reinstall','Repair')) {
        # Preserve source, key, account, SSH identity, evidence, and deployments.
        $null = Get-HeadlessWorkerPath (Read-HeadlessActive)
        $task.Enabled=$true; $maintenance.Enabled=$true
        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        $null = $task.Run($null)
        Get-HeadlessStatus | ConvertTo-Json -Depth 10
        return
    }
    # Removal revokes the owned maintenance interface, restores the exact previous
    # gateway, and removes the owned startup tasks so reboot cannot resurrect
    # validation. Existing SSH keys and all evidence remain.
    $maintenance.Enabled=$false; $maintenance.Stop(0)
    Stop-HeadlessWorker $task
    $guard = Open-HeadlessWriteGuard
    try {
        $saved = Join-Path $control 'gateway-before.ps1'
        Assert-SameHash $saved $configuration.previousGatewaySha256
        $temporary = $gateway + '.restore-' + [Guid]::NewGuid().ToString('N')
        Write-Durable $temporary ([IO.File]::ReadAllBytes($saved))
        [IO.File]::Replace($temporary,$gateway,[NullString]::Value)
        # Remove only the two exact, verified startup definitions owned here.
        $folder.DeleteTask('D3D11Validation-Maintenance',0)
        $folder.DeleteTask('D3D11Validation-Worker',0)
        Stop-Service -Name sshd
        Set-Service -Name sshd -StartupType Disabled
        Write-Durable (Join-Path $control 'removed.json') ($encoding.GetBytes('{"schema":"d3d11-headless-removed/v1","evidencePreserved":true,"networkDisabled":true}'))
    } finally { $guard.Dispose() }
    Write-Output 'Removed owned startup tasks and disabled validation transport; evidence, accounts, keys and deployment files preserved.'
    return
}

# Authenticate the complete bootstrap source before importing any of its modules.
foreach ($value in @($Deployment,$PolicySha256,$SourceManifestSha256,$GatewaySha256,$SshConfigurationSha256,$PublisherKeyPath,$ClientAddress)) {
    if (-not $value) { throw 'Install requires all reviewed bootstrap parameters.' }
}
$manifestPath = Join-Path $PSScriptRoot 'source-manifest.json'
Assert-SameHash $manifestPath $SourceManifestSha256
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
foreach ($member in $manifest.PSObject.Properties) {
    if ($member.Name -cnotmatch '^[A-Za-z0-9.-]+\z' -or $member.Name -in @('.','..') -or $member.Value -cnotmatch '^[0-9a-f]{64}\z') { throw 'Invalid bootstrap source manifest.' }
    Assert-SameHash (Join-Path $PSScriptRoot $member.Name) $member.Value
}
foreach ($required in @('Validation.Headless.psm1','Validation.Maintenance.psm1','Validation.Maintenance.cs','Validation.Setup.psm1','Validation.Task.psm1','Manage-ValidationHeadless.ps1')) {
    if (-not $manifest.PSObject.Properties[$required]) { throw 'Incomplete bootstrap manifest.' }
}
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Task.psm1')
foreach ($path in @($root,(Join-Path $root 'program'),(Join-Path $root 'setup'),$gateway,$sshConfiguration)) { Assert-ProtectedPath $path }
Assert-SameHash $gateway $GatewaySha256
Assert-SameHash $sshConfiguration $SshConfigurationSha256
if (-not $resume -and ((Test-Path -LiteralPath $installed) -or (Test-Path -LiteralPath $control))) { throw 'Preserve incomplete or conflicting bootstrap directories for review.' }
$ip = $null
if (-not [Net.IPAddress]::TryParse($ClientAddress,[ref]$ip) -or $ip.ToString() -cne $ClientAddress -or
    $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.GetAddressBytes()[0] -ne 169 -or $ip.GetAddressBytes()[1] -ne 254) { throw 'Use the reviewed IPv4 link-local client address.' }
$sshText = Get-Content -Raw -LiteralPath $sshConfiguration
if ($sshText -notmatch ('(?m)^AllowUsers d3d11validator@' + [regex]::Escape($ClientAddress) + '\s*$') -or
    $sshText -notmatch '(?m)^PasswordAuthentication no\s*$' -or $sshText -notmatch '(?m)^DisableForwarding yes\s*$') { throw 'Existing SSH boundary differs from the supported reviewed configuration.' }
$service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if ($service.PathName.Trim('"') -ine (Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH/sshd.exe').Replace('/','\')) { throw 'Preserve the unrelated SSH service.' }
$account = Get-LocalUser -Name d3d11validator
if (-not $account.Enabled -or (Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object SID -eq $account.SID)) { throw 'Use the existing enabled standard validation account.' }
$sid = $account.SID.Value
$previous = $folder.GetTask('D3D11Validation-Worker')
$prior = $previous.Definition
$program = Join-Path (Join-Path $root 'program') $Deployment
Assert-ProtectedPath $program
Assert-SameHash (Join-Path $program 'worker-policy.json') $PolicySha256
if ((Resolve-ValidationTaskSid $prior.Principal.UserId) -cne $sid -or $prior.Principal.LogonType -ne 2 -or $prior.Principal.RunLevel -ne 0 -or
    $prior.RegistrationInfo.Author -cne 'D3D11Validation' -or $prior.Actions.Count -ne 1 -or
    $prior.Actions.Item(1).Arguments -cne ('-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $program 'Start-ValidationWorker.ps1') + '"') -or
    $prior.Actions.Item(1).WorkingDirectory -cne $program -or
    $prior.Actions.Item(1).Path -ine (Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe').Replace('/','\')) { throw 'Preserve the conflicting previous worker task.' }
$workerSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;' + $sid + ')'
Assert-ValidationTaskSecurity ($previous.GetSecurityDescriptor(7)) $workerSddl
try { $conflict = $folder.GetTask('D3D11Validation-Maintenance') } catch { if ($_.Exception.HResult -ne -2147024894) { throw }; $conflict=$null }
if ($null -ne $conflict) { throw 'Preserve the pre-existing maintenance task.' }
$publisher = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PublisherKeyPath).Path)
$rsa = [Security.Cryptography.RSA]::Create()
try {
    $publicXml = $encoding.GetString($publisher)
    if ($publicXml.Contains('<D>')) { throw 'Provide only the public publisher key.' }
    $rsa.FromXmlString($publicXml)
    if ($rsa.KeySize -ne 3072) { throw 'Use an RSA-3072 publisher key.' }
} finally { $rsa.Dispose() }
# Console-only secure input. The password never enters arguments, files or logs.
if ($sshText -notmatch '(?m)^ListenAddress (169\.254\.[0-9]+\.[0-9]+)\s*$') { throw 'Unsupported listen address.' }
$listenAddress = $Matches[1]
if ($resume) {
    # Preserve the failed bootstrap for inspection. Only a recorded successful
    # rollback, exact prior gateway/config, and the same publisher permit this.
    Assert-ProtectedPath $installed; Assert-ProtectedPath $control
    $oldConfiguration = Get-Content -LiteralPath (Join-Path $control 'configuration.json') -Raw | ConvertFrom-Json
    if ($oldConfiguration.previousGatewaySha256 -cne $GatewaySha256 -or
        $oldConfiguration.sshConfigurationSha256 -cne $SshConfigurationSha256 -or
        $oldConfiguration.publisherSha256 -cne (Get-Digest $publisher)) { throw 'Rolled-back bootstrap identity differs.' }
    $oldManifestPath = Join-Path $installed 'source-manifest.json'
    Assert-SameHash $oldManifestPath $oldConfiguration.sourceManifestSha256
    $oldManifest = Get-Content -LiteralPath $oldManifestPath -Raw | ConvertFrom-Json
    foreach ($item in $oldManifest.PSObject.Properties) {
        if ($item.Name -cnotmatch '^[A-Za-z0-9.-]+\z' -or $item.Name -in @('.','..')) { throw 'Invalid prior manifest.' }
        Assert-SameHash (Join-Path $installed $item.Name) $item.Value
    }
    $oldInbox = Join-Path $root 'data/maintenance-v1'
    if (@(Get-ChildItem -LiteralPath $oldInbox -Force).Count) { throw 'Preserve pending maintenance before bootstrap retry.' }
    $suffix = '.rolled-back-' + [Guid]::NewGuid().ToString('N')
    [IO.Directory]::Move($installed,($installed + $suffix))
    [IO.Directory]::Move($control,($control + $suffix))
    [IO.Directory]::Move($oldInbox,($oldInbox + $suffix))
}
$credential = Read-Host 'Validation account password (one-time S4U task registration; not stored)' -AsSecureString
if ($credential.Length -eq 0) { $credential.Dispose(); throw 'Registration credential was empty.' }
$previousXml = $prior.XmlText
$previousEnabled = [bool]$previous.Enabled
$previousRunning = $previous.GetInstances(0).Count -gt 0
$previousStartup = [string](Get-Service sshd).StartType
$previousGateway = [IO.File]::ReadAllBytes($gateway)
$workerTouched = $false
$maintenanceCreated = $false
$routerChanged = $false
try {
    $null = New-Item -ItemType Directory -Path $installed
    foreach ($member in $manifest.PSObject.Properties) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $member.Name) -Destination (Join-Path $installed $member.Name) }
    $null = New-Item -ItemType Directory -Path $control
    $installation = [ordered]@{schema='d3d11-headless-installation/v1'; phase='prepared'; rollbackComplete=$false}
    Write-Durable $journalPath ($encoding.GetBytes(($installation | ConvertTo-Json -Compress)))
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $installed 'source-manifest.json')
    foreach ($name in @('receipts','staging','requests')) { $null = New-Item -ItemType Directory -Path (Join-Path $control $name) }
    Write-Durable (Join-Path $control 'publisher.xml') $publisher
    Write-Durable (Join-Path $control 'activation.lock') ([byte[]]::new(0))
    Write-Durable (Join-Path $control 'gateway-before.ps1') ([IO.File]::ReadAllBytes($gateway))
    Write-Durable (Join-Path $control 'worker-before.xml') ($encoding.GetBytes($prior.XmlText))
    $inbox = Join-Path $root 'data/maintenance-v1'
    if (Test-Path -LiteralPath $inbox) { throw 'Preserve a conflicting maintenance inbox.' }
    $null = New-Item -ItemType Directory -Path $inbox
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($owner in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($owner),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $inbox -AclObject $acl
    $worker = New-TaskDefinition $sid 'Start-ValidationHeadlessWorker.ps1' $false
    $maintenance = New-TaskDefinition 'S-1-5-18' 'Invoke-ValidationMaintenance.ps1' $true
    Write-Durable (Join-Path $control 'worker-task.xml') ($encoding.GetBytes($worker.XmlText))
    Write-Durable (Join-Path $control 'maintenance-task.xml') ($encoding.GetBytes($maintenance.XmlText))
    $routerBytes = $encoding.GetBytes("`$global:LASTEXITCODE = 0`n& (Join-Path `$PSScriptRoot 'headless-v1/Invoke-ValidationHeadless.ps1')`nexit `$LASTEXITCODE`n")
    $configuration = [ordered]@{schema='d3d11-headless-configuration/v1'; accountSid=$sid; clientAddress=$ClientAddress; listenAddress=$listenAddress
        publisherSha256=(Get-Digest $publisher); workerTaskSddl=$workerSddl; previousGatewaySha256=$GatewaySha256
        routerSha256=(Get-Digest $routerBytes); sshConfigurationSha256=$SshConfigurationSha256; previousSshStartup=[string](Get-Service sshd).StartType
        sourceManifestSha256=$SourceManifestSha256}
    Write-Durable (Join-Path $control 'configuration.json') ($encoding.GetBytes(($configuration | ConvertTo-Json -Compress)))
    $active = [ordered]@{schema='d3d11-active-deployment/v1'; generation=1; deployment=$Deployment; policySha256=$PolicySha256}
    Write-Durable (Join-Path $control 'active.json') ($encoding.GetBytes(($active | ConvertTo-Json -Compress)))
    foreach ($item in @((Get-Item $installed),(Get-Item $control)) + @(Get-ChildItem $installed,$control -Recurse -Force)) { Assert-ProtectedPath $item.FullName }
    Import-Module (Join-Path $installed 'Validation.Headless.psm1')
    $null = Get-HeadlessWorkerPath ([pscustomobject]$active)
    $workerTouched = $true
    Stop-HeadlessWorker $previous
    $plain = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential)
    try { $task = $folder.RegisterTaskDefinition('D3D11Validation-Worker',$worker,20,$sid,[Runtime.InteropServices.Marshal]::PtrToStringBSTR($plain),2,$workerSddl) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($plain) }
    $null = $folder.RegisterTaskDefinition('D3D11Validation-Maintenance',$maintenance,18,'S-1-5-18',$null,5,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $maintenanceCreated = $true
    # Preserve both sides if Windows canonicalization differs. These protected
    # records contain no password and support precise comparison after rollback.
    Write-Durable (Join-Path $control 'worker-registration-observed.xml') ($encoding.GetBytes($task.Definition.XmlText))
    Assert-HeadlessTask $task
    $registeredMaintenance = $folder.GetTask('D3D11Validation-Maintenance')
    Write-Durable (Join-Path $control 'maintenance-registration-observed.xml') ($encoding.GetBytes($registeredMaintenance.Definition.XmlText))
    Assert-ValidationTaskDefinition $registeredMaintenance.Definition.XmlText $maintenance.XmlText 'S-1-5-18' ([bool]$registeredMaintenance.Enabled)
    Assert-ValidationTaskSecurity ($registeredMaintenance.GetSecurityDescriptor(7)) 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    $temporary = $gateway + '.headless-' + [Guid]::NewGuid().ToString('N')
    Write-Durable $temporary $routerBytes
    [IO.File]::Replace($temporary,$gateway,[NullString]::Value)
    $routerChanged = $true
    Set-Service -Name sshd -StartupType Automatic
    Start-Service -Name sshd
    $null = $task.Run($null)
    Import-Module (Join-Path $installed 'Validation.Maintenance.psm1')
    $installation.phase = 'installed'
    Write-MaintenanceRecord $journalPath $installation
    Write-Output 'Installed headless startup and signed maintenance. Run client acceptance before scheduling a reboot; reboot qualification remains not-run.'
} catch {
    $originalFailure = $_
    try {
        if ($maintenanceCreated) {
            $owned = $folder.GetTask('D3D11Validation-Maintenance')
            $owned.Enabled=$false; $owned.Stop(0)
            $folder.DeleteTask('D3D11Validation-Maintenance',0)
        }
        if ($routerChanged) {
            $restorePath = $gateway + '.rollback-' + [Guid]::NewGuid().ToString('N')
            Write-Durable $restorePath $previousGateway
            [IO.File]::Replace($restorePath,$gateway,[NullString]::Value)
        }
        if ($workerTouched) {
            $restoreTask = $scheduler.NewTask(0)
            $restoreTask.XmlText = $previousXml
            $restoreTask.Settings.Enabled = $previousEnabled
            $plain = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential)
            try { $restored = $folder.RegisterTaskDefinition('D3D11Validation-Worker',$restoreTask,20,$sid,[Runtime.InteropServices.Marshal]::PtrToStringBSTR($plain),2,$workerSddl) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($plain) }
            if ($previousRunning -and $previousEnabled) { $null=$restored.Run($null) }
        }
        Set-Service -Name sshd -StartupType $previousStartup
        if (Test-Path -LiteralPath $journalPath) {
            Import-Module (Join-Path $installed 'Validation.Maintenance.psm1')
            $installation.phase='rolled-back'; $installation.rollbackComplete=$true
            Write-MaintenanceRecord $journalPath $installation
        }
    } catch { throw 'Bootstrap failed and rollback needs local review. Preserve the installation journal and backups.' }
    throw $originalFailure
} finally { $credential.Dispose() }
