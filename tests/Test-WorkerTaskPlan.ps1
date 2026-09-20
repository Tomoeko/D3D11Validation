# Pure definition/ACL tests: no task registration or host configuration changes.
[CmdletBinding()]
param([string]$ModulePath = (Join-Path $PSScriptRoot '../windows/Validation.Task.psm1'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$account = [Security.Principal.SecurityIdentifier]::new($sid).Translate([Security.Principal.NTAccount]).Value
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$definition = $service.NewTask(0)
$definition.Principal.UserId = $sid
$definition.Principal.LogonType = 2
$definition.Principal.RunLevel = 0
$definition.Settings.Enabled = $true
$definition.Settings.UseUnifiedSchedulingEngine = $true
$action = $definition.Actions.Create(0)
$action.Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$action.Arguments = '-NoProfile -File approved.ps1'
$expected = $definition.XmlText
$checks = 0
function Reject([scriptblock]$Operation) {
    $rejected = $false
    try { & $Operation } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unexpected accepted task mutation.' }
    $script:checks++
}
Assert-ValidationTaskDefinition $expected $expected $sid $true
$checks++
$alias = [xml]$expected
$alias.Task.Principals.Principal.UserId = $account
Assert-ValidationTaskDefinition $alias.OuterXml $expected $sid $true
$checks++
$disabled = [xml]$expected
$disabled.Task.Settings.Enabled = 'false'
Assert-ValidationTaskDefinition $disabled.OuterXml $expected $sid $false
$checks++
Reject { Assert-ValidationTaskDefinition $disabled.OuterXml $expected $sid $true }
foreach ($mutation in @(
    { param($d) $d.Task.Principals.Principal.UserId = 'S-1-5-18' },
    { param($d) $d.Task.Principals.Principal.LogonType = 'Password' },
    { param($d) $d.Task.Principals.Principal.RunLevel = 'HighestAvailable' },
    { param($d) $d.Task.Actions.Exec.Arguments = '-NoProfile -File other.ps1' },
    { param($d) $d.Task.Settings.UseUnifiedSchedulingEngine = 'false' },
    { param($d) $d.Task.Settings.ExecutionTimeLimit = 'PT1S' },
    { param($d) $null = $d.Task.Actions.AppendChild($d.Task.Actions.Exec.CloneNode($true)) }
)) {
    $changed = [xml]$expected
    & $mutation $changed
    Reject { Assert-ValidationTaskDefinition $changed.OuterXml $expected $sid $true }
}
$sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;' + $sid + ')'
Assert-ValidationTaskSecurity $sddl $sddl
$checks++
Assert-ValidationTaskSecurity ($sddl.Replace('D:P','D:PAI').Replace('FRFX','0x1200a9')) $sddl
$checks++
foreach ($changed in @(
    $sddl.Replace('FRFX','FA'),
    $sddl.Replace('D:P','D:'),
    $sddl.Replace('O:BA','O:BU'),
    ($sddl + '(A;;FRFX;;;WD)'),
    $sddl.Replace('(A;;FRFX','(A;CI;FRFX')
)) { Reject { Assert-ValidationTaskSecurity $changed $sddl } }
[ordered]@{schema='d3d11-task-definition-tests/v1'; checksPassed=$checks; hostChanges=$false} | ConvertTo-Json
