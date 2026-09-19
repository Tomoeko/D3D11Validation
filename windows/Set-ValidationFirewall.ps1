# Apply a reviewed, hash-pinned plan while the installation guard remains active.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PlanPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPlanSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from the authorized elevated setup console.'
}

# Hash and parse the same bytes. Plan creation and address arithmetic live in
# New-ValidationConnectionPlan.ps1; this installer consumes only the reviewed file.
$planBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PlanPath).Path)
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $digest = ([BitConverter]::ToString($hasher.ComputeHash($planBytes))).Replace('-', '')
} finally { $hasher.Dispose() }
if ($digest -ine $ExpectedPlanSha256) { throw 'Connection plan hash mismatch.' }
$plan = [Text.UTF8Encoding]::new($false, $true).GetString($planBytes) | ConvertFrom-Json
$serverPath = 'C:\Windows\System32\OpenSSH\sshd.exe'
$names = @('D3D11Validation-In-TCP', 'D3D11Validation-Block-Other-IPv4',
    'D3D11Validation-Block-IPv6')
if ($plan.schema -cne 'd3d11-validation-connection-plan/v1' -or $plan.installed -or
    $plan.port -ne 22222 -or $plan.account -cne 'd3d11validator' -or $plan.administrator -or
    $plan.firewall.program -cne 'C:/Windows/System32/OpenSSH/sshd.exe' -or
    $plan.firewall.allowRule -cne $names[0] -or
    $plan.firewall.blockOtherIpv4Rule -cne $names[1] -or
    $plan.firewall.blockIpv6Rule -cne $names[2] -or
    ($plan.firewall.blockIpv6 -join ',') -cne '::/1,8000::/1' -or
    $plan.firewall.installationGuardRule -cne 'D3D11Validation-InstallationGuard' -or
    -not $plan.firewall.guardMustRemainEnabledUntilQualified) {
    throw 'Plan does not describe the approved bootstrap boundary.'
}
if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $plan.listenAddress)) {
    throw 'The planned Windows address is no longer assigned.'
}
$service = Get-Service -Name sshd
if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') {
    throw 'Keep the new SSH service stopped and disabled during provisioning.'
}
$guard = Get-NetFirewallRule -PolicyStore ActiveStore -Name $plan.firewall.installationGuardRule
if ($guard.Enabled -ne 'True' -or $guard.Action -ne 'Block') {
    throw 'The installation guard must remain active.'
}
$bypass = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore |
    Where-Object OverrideBlockRules -eq $true | Get-NetFirewallRule |
    Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' })
if ($bypass.Count) { throw 'Authenticated bypass rules require separate review.' }

$specifications = @(
    @{ Name = $names[0]; Action = 'Allow'; LocalAddress = @($plan.listenAddress);
        RemoteAddress = @($plan.clientAddress) },
    @{ Name = $names[1]; Action = 'Block'; LocalAddress = @('Any');
        RemoteAddress = @($plan.firewall.blockOtherIpv4) },
    @{ Name = $names[2]; Action = 'Block'; LocalAddress = @('Any');
        RemoteAddress = @($plan.firewall.blockIpv6) }
)
$common = @{
    Direction = 'Inbound'; Profile = 'Any'; Enabled = 'True'; Protocol = 'TCP'
    LocalPort = 22222; Program = $serverPath; Group = 'D3D11Validation'
}
foreach ($specification in $specifications) {
    # Resume partial provisioning only when each existing rule matches exactly.
    # Never replace a conflicting rule or report success after a failed creation.
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $specification.Name -ErrorAction SilentlyContinue
    if (-not $rule) {
        $null = New-NetFirewallRule @common @specification -DisplayName $specification.Name -ErrorAction Stop
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $specification.Name -ErrorAction Stop
    }
    $application = $rule | Get-NetFirewallApplicationFilter
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $security = $rule | Get-NetFirewallSecurityFilter
    if ($rule.Enabled -ne 'True' -or $rule.Action -ne $specification.Action -or
        $rule.Direction -ne 'Inbound' -or $rule.Profile -ne 'Any' -or
        $application.Program -ine $serverPath -or $port.Protocol -ne 'TCP' -or
        $port.LocalPort -ne '22222' -or $port.RemotePort -ne 'Any' -or
        $security.OverrideBlockRules -ne $false -or
        (Compare-Object @($specification.LocalAddress | Sort-Object) @($address.LocalAddress | Sort-Object)) -or
        (Compare-Object @($specification.RemoteAddress | Sort-Object) @($address.RemoteAddress | Sort-Object))) {
        throw 'An effective firewall rule differs from the reviewed plan. Keep the guard enabled.'
    }
}
[ordered]@{
    schema = 'd3d11-validation-firewall/v1'
    rulesVerified = $specifications.Count
    existingRulesModified = $false
    installationGuardStillEnabled = $true
    sshServiceStarted = $false
    networkTrafficTestsComplete = $false
} | ConvertTo-Json
