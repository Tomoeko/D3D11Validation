# Operator-only task setup. The SSH gateway cannot call this script.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Plan','Install','Update','Status','Enable','Disable')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^worker-v[1-9][0-9]*$')][string]$Deployment,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$PolicySha256,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$PlanSha256,
    [string]$OutputDirectory,
    [ValidatePattern('^worker-v[1-9][0-9]*$')][string]$PreviousDeployment,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$PreviousPolicySha256,
    [switch]$AtStartup,
    [switch]$PromptForRegistrationCredential
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([bool]$PreviousDeployment -ne [bool]$PreviousPolicySha256) { throw 'Supply both previous deployment fields.' }
if ($Mode -ceq 'Update' -and -not $PreviousDeployment) { throw 'Update requires the exact previous deployment.' }
Import-Module (Join-Path $PSScriptRoot 'Validation.Task.psm1')
Import-Module (Join-Path $PSScriptRoot 'Validation.Setup.psm1')
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'D3D11Validation'
$program = Join-Path (Join-Path $root 'program') $Deployment
$policyPath = Join-Path $program 'worker-policy.json'
$taskName = 'D3D11Validation-Worker'
$administrator = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $administrator.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use the authorized elevated setup console.'
}


Assert-ProtectedPath $root
Assert-ProtectedPath (Join-Path $root 'program')
Assert-ProtectedPath $program
Assert-ProtectedPath $policyPath
if ((Get-FileHash -LiteralPath $policyPath).Hash.ToLowerInvariant() -cne $PolicySha256) { throw 'Unexpected policy hash.' }
$policy = Get-Content -Raw -LiteralPath $policyPath | ConvertFrom-Json
if ($policy.executionContext -cne 'Session0') { throw 'Only an explicit Session0 deployment can be registered.' }
foreach ($file in $policy.files.PSObject.Properties) {
    if ($file.Name -cnotmatch '^[A-Za-z0-9.-]+$') { throw 'Invalid package filename.' }
    $path = Join-Path $program $file.Name
    Assert-ProtectedPath $path
    if ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $file.Value) { throw 'Deployment content changed.' }
}
$account = Get-LocalUser -Name d3d11validator
if (-not $account.Enabled -or (Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object SID -eq $account.SID)) {
    throw 'The dedicated account must be enabled and non-administrative.'
}
$sid = $account.SID.Value
$executable = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$arguments = '-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $program 'Start-ValidationWorker.ps1') + '"'
$escape = { param($Text) [Security.SecurityElement]::Escape([string]$Text) }
$trigger = if ($AtStartup) { '<BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger>' } else { '' }
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>D3D11Validation</Author><Description>Protected validation worker; policy $PolicySha256</Description></RegistrationInfo>
  <Triggers>$trigger</Triggers>
  <Principals><Principal id="Runner"><UserId>$sid</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Runner"><Exec><Command>$(& $escape $executable)</Command><Arguments>$(& $escape $arguments)</Arguments><WorkingDirectory>$(& $escape $program)</WorkingDirectory></Exec></Actions>
</Task>
"@
$sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;' + $sid + ')'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$definition = $service.NewTask(0)
$definition.XmlText = $xml # Ask the Windows scheduler to parse before making changes.
$plan = [ordered]@{
    schema='d3d11-worker-task-plan/v1'; taskName=$taskName; deployment=$Deployment
    policySha256=$PolicySha256; accountSid=$sid; sddl=$sddl; xml=$definition.XmlText
    atStartup=[bool]$AtStartup; passwordStored=$false; administrator=$false
    previousDeployment=$PreviousDeployment; previousPolicySha256=$PreviousPolicySha256
    purpose='Session 0 qualification; full Unity and fresh-boot acceptance remain pending'
}
$planText = $plan | ConvertTo-Json -Depth 5 -Compress
$hash = [Security.Cryptography.SHA256]::Create()
try { $digest = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($planText)))).Replace('-','').ToLowerInvariant() }
finally { $hash.Dispose() }

function Get-OwnedTask {
    try { $task = $folder.GetTask($taskName) }
    catch { if ($_.Exception.HResult -eq -2147024894) { return $null }; throw }
    $actual = $task.Definition
    $actualSid = Resolve-ValidationTaskSid $actual.Principal.UserId
    if ($actual.RegistrationInfo.Author -cne 'D3D11Validation' -or
        $actual.RegistrationInfo.Description -cne $definition.RegistrationInfo.Description -or
        $actualSid -cne $sid -or $actual.Principal.LogonType -ne 2 -or $actual.Principal.RunLevel -ne 0 -or
        $actual.Actions.Count -ne 1 -or $actual.Actions.Item(1).Path -cne $executable -or
        $actual.Actions.Item(1).Arguments -cne $arguments -or $actual.Actions.Item(1).WorkingDirectory -cne $program -or
        $actual.Triggers.Count -ne $definition.Triggers.Count -or
        $actual.Settings.ExecutionTimeLimit -cne 'PT0S' -or $actual.Settings.MultipleInstances -ne 2 -or
        $actual.Settings.RestartCount -ne 3 -or $actual.Settings.RestartInterval -cne 'PT1M') {
        throw 'Preserve the conflicting task for operator review.'
    }
    Assert-ValidationTaskDefinition $actual.XmlText $definition.XmlText $sid ([bool]$task.Enabled)
    Assert-ValidationTaskSecurity ($task.GetSecurityDescriptor(7)) $sddl
    return $task
}

if ($Mode -ceq 'Plan') {
    if (-not $OutputDirectory -or (Test-Path -LiteralPath $OutputDirectory)) { throw 'Supply a new plan directory.' }
    $null = New-Item -ItemType Directory -Path $OutputDirectory
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'task-plan.json'), $planText, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'worker-task.xml'), $definition.XmlText, [Text.Encoding]::Unicode)
    [ordered]@{schema=$plan.schema; planSha256=$digest; parsedByWindows=$true; changesApplied=$false
        taskName=$taskName; executionContext='Session0'; atStartup=[bool]$AtStartup
        passwordStored=$false; administrator=$false; restartAttempts=3} | ConvertTo-Json
    return
}
if ($Mode -cin @('Install','Update')) {
    if ($PlanSha256 -cne $digest) { throw 'A matching, reviewed plan hash is required.' }
    if ($Mode -ceq 'Install') {
        if ($PreviousDeployment) { throw 'Install cannot replace a previous deployment.' }
        if ($null -ne (Get-OwnedTask)) { throw 'Task exists; preserve it instead of overwriting.' }
    } else {
        # Reuse the same complete verification for the prior deployment. A task
        # name or author string alone is never proof of ownership.
        $null = & $PSCommandPath -Mode Status -Deployment $PreviousDeployment -PolicySha256 $PreviousPolicySha256 -AtStartup:$AtStartup
        $prior = $folder.GetTask($taskName)
        $backupDirectory = Join-Path $root 'setup'
        if (-not (Test-Path -LiteralPath $backupDirectory)) { $null = New-Item -ItemType Directory -Path $backupDirectory }
        Assert-ProtectedPath $backupDirectory
        $backup = Join-Path $backupDirectory ('task-before-' + [Guid]::NewGuid().ToString('N') + '.xml')
        [IO.File]::WriteAllText($backup, $prior.Definition.XmlText, [Text.Encoding]::Unicode)
    }
    if (-not $PromptForRegistrationCredential) {
        throw 'Cross-account S4U registration requires owner credential entry. Use -PromptForRegistrationCredential in the authorized local setup console.'
    }
    # Windows requires the other account's credential during registration, even
    # though S4U stores no password. Prompt locally; never accept a password as a
    # script argument, read one from a file, or place it in the plan or task XML.
    $accountName = $account.SID.Translate([Security.Principal.NTAccount]).Value
    $credential = Get-Credential -UserName $accountName -Message 'Enter the validation account password once to register the approved S4U task. Windows will not store it.'
    if ($null -eq $credential) { throw 'Registration cancelled; no task created.' }
    # Create only. Do not let Task Scheduler add a principal ACE with write access.
    try {
        $credentialSid = [Security.Principal.NTAccount]::new($credential.UserName).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($credentialSid -cne $sid) { throw 'The credential must belong to the reviewed validation account.' }
        if ($Mode -ceq 'Update') { $prior.Enabled = $false; $prior.Stop(0) }
        $flags = if ($Mode -ceq 'Update') { 20 } else { 18 }
        $task = $folder.RegisterTaskDefinition($taskName, $definition, $flags, $sid, $credential.GetNetworkCredential().Password, 2, $sddl)
    } finally {
        $credential.Password.Dispose()
        $credential = $null
    }
    try {
        $null = Get-OwnedTask
        if (-not $task.Enabled) { throw 'The new task was not enabled.' }
    } catch { $task.Enabled = $false; $task.Stop(0); throw }
    Write-Output 'PASS: protected S4U task registered; start it explicitly after stopping the prior worker.'
    return
}
$task = Get-OwnedTask
if ($null -eq $task) { throw 'The reviewed task is not installed.' }
if ($Mode -ceq 'Enable') { $task.Enabled = $true; $null = Get-OwnedTask }
if ($Mode -ceq 'Disable') { $task.Enabled = $false; $task.Stop(0) }
[ordered]@{taskName=$taskName; enabled=$task.Enabled; state=$task.State; lastTaskResult=$task.LastTaskResult
    executionContext='Session0'; administrator=$false; passwordStored=$false} | ConvertTo-Json
