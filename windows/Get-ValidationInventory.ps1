# Read-only inventory. This does not qualify a D3D11 rendering device.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Run this inventory on the Windows validation host.'
}

$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$graphicsInventoryAvailable = $true
$graphicsAdapters = @()
try {
    $graphicsAdapters = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop |
    ForEach-Object {
        [ordered]@{
            name = $_.Name
            driverVersion = $_.DriverVersion
            status = $_.Status
        }
    })
} catch {
    # Key-only SSH tokens may not have access to WMI. Do not expand their rights
    # for optional inventory; the native device probe must qualify actual use.
    $graphicsInventoryAvailable = $false
}
$sshService = $null
$serviceQueryAvailable = $true
try {
    $sshService = Get-Service -Name sshd -ErrorAction Stop
} catch {
    # Restricted tokens can receive ObjectNotFound even for a running service.
    # A failed lookup cannot establish absence.
    $serviceQueryAvailable = $false
}
$session = Get-Process -Id $PID
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

[ordered]@{
    schema = 'd3d11-validation-inventory/v1'
    collectedUtc = [DateTime]::UtcNow.ToString('o')
    operatingSystem = [ordered]@{
        caption = $version.ProductName
        version = '{0}.{1}.{2}' -f $version.CurrentMajorVersionNumber,
            $version.CurrentMinorVersionNumber, $version.CurrentBuildNumber
        build = $version.CurrentBuildNumber
        architecture = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
    }
    graphicsInventoryAvailable = $graphicsInventoryAvailable
    graphicsAdapters = $graphicsAdapters
    session = [ordered]@{
        id = $session.SessionId
        elevated = $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    openSsh = [ordered]@{
        serverBinaryPresent = Test-Path -LiteralPath (
            Join-Path $env:WINDIR 'System32/OpenSSH/sshd.exe')
        serviceQueryAvailable = $serviceQueryAvailable
        servicePresent = if ($serviceQueryAvailable) { $null -ne $sshService } else { $null }
        serviceStatus = if ($null -ne $sshService) {
            $sshService.Status.ToString()
        } else { $null }
    }
    hardwareD3D11Qualified = $false
} | ConvertTo-Json -Depth 5
