# Reversible rollback: retain files and evidence; revoke only this setup's access.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$configuration = 'C:\ProgramData\ssh\sshd_config'
$staged = 'C:\ProgramData\D3D11Validation\ssh\sshd_config'
if ((Get-FileHash -LiteralPath $configuration).Hash -cne
    (Get-FileHash -LiteralPath $staged).Hash) {
    throw 'The installed configuration changed; review ownership before rollback.'
}
Enable-NetFirewallRule -Name D3D11Validation-InstallationGuard -ErrorAction Stop
Stop-Service -Name sshd -ErrorAction Stop
Set-Service -Name sshd -StartupType Disabled -ErrorAction Stop
if (Get-NetTCPConnection -State Listen -LocalPort 22222 -ErrorAction SilentlyContinue) {
    throw 'A listener remains on the validation port; leave the guard enabled.'
}
Disable-LocalUser -Name d3d11validator -ErrorAction Stop
Disable-NetFirewallRule -Name D3D11Validation-In-TCP -ErrorAction Stop
if ((Get-Service sshd).Status -ne 'Stopped' -or
    (Get-Service sshd).StartType -ne 'Disabled' -or
    (Get-LocalUser d3d11validator).Enabled) {
    throw 'Rollback readback failed; preserve the installation guard.'
}
[ordered]@{
    schema = 'd3d11-connection-rollback/v1'
    serviceStoppedAndDisabled = $true
    accountDisabled = $true
    allowRuleDisabled = $true
    installationGuardEnabled = $true
    filesAndEvidenceRetained = $true
    personalAccessModified = $false
} | ConvertTo-Json
