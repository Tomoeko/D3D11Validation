# Read-only inventory. This does not qualify a D3D11 rendering device.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Run this inventory on the Windows validation host.'
}

$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$graphicsAdapters = @(Get-CimInstance -ClassName Win32_VideoController |
    ForEach-Object {
        [ordered]@{
            name = $_.Name
            driverVersion = $_.DriverVersion
            status = $_.Status
        }
    })
$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
$session = Get-Process -Id $PID
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

[ordered]@{
    schema = 'd3d11-validation-inventory/v1'
    collectedUtc = [DateTime]::UtcNow.ToString('o')
    operatingSystem = [ordered]@{
        caption = $operatingSystem.Caption
        version = $operatingSystem.Version
        build = $operatingSystem.BuildNumber
        architecture = $operatingSystem.OSArchitecture
    }
    graphicsAdapters = $graphicsAdapters
    session = [ordered]@{
        id = $session.SessionId
        elevated = $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    openSsh = [ordered]@{
        serverBinaryPresent = Test-Path -LiteralPath (
            Join-Path $env:WINDIR 'System32/OpenSSH/sshd.exe')
        servicePresent = $null -ne $sshService
        serviceStatus = if ($null -ne $sshService) {
            $sshService.Status.ToString()
        } else { $null }
    }
    hardwareD3D11Qualified = $false
} | ConvertTo-Json -Depth 5
