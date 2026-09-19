# Run before installing OpenSSH. Blocks inbound TCP for the new server executable.
# Existing applications, RDP, and unrelated firewall rules are not modified.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from the authorized elevated setup console.'
}
if ($env:WINDIR -ine 'C:\Windows') { throw 'Unexpected Windows installation path.' }
$serverPath = 'C:\Windows\System32\OpenSSH\sshd.exe'
$ruleName = 'D3D11Validation-InstallationGuard'
if ((Get-Service -Name sshd -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $serverPath)) {
    throw 'An existing SSH installation requires separate review.'
}
if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
    throw 'The installation guard already exists; inspect it instead of replacing it.'
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object Enabled -ne 'True').Count) {
    throw 'All Windows firewall profiles must be enabled.'
}
$bypass = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore |
    Where-Object OverrideBlockRules -eq $true | Get-NetFirewallRule |
    Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' })
if ($bypass.Count) { throw 'Authenticated bypass rules require separate review.' }

$null = New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Profile Any `
    -Direction Inbound -Action Block -Enabled True -Protocol TCP `
    -Program $serverPath -LocalAddress Any -RemoteAddress Any

$rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName
$application = $rule | Get-NetFirewallApplicationFilter
$port = $rule | Get-NetFirewallPortFilter
$address = $rule | Get-NetFirewallAddressFilter
if ($rule.Enabled -ne 'True' -or $rule.Action -ne 'Block' -or
    $rule.Direction -ne 'Inbound' -or $rule.Profile -ne 'Any' -or
    $application.Program -ine $serverPath -or $port.Protocol -ne 'TCP' -or
    $port.LocalPort -ne 'Any' -or $port.RemotePort -ne 'Any' -or
    $address.LocalAddress -ne 'Any' -or $address.RemoteAddress -ne 'Any') {
    throw 'The effective installation guard did not match the requested boundary. Do not install SSH.'
}
[ordered]@{
    schema = 'd3d11-installation-guard/v1'
    active = $true
    newSshInboundTcpBlocked = $true
    existingRulesModified = $false
    authenticatedBypassRules = $bypass.Count
} | ConvertTo-Json
