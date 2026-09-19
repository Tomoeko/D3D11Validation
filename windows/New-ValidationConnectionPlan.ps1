# Prepare local files for operator review. Does not install or change host access.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ListenAddress,
    [Parameter(Mandatory)][string]$ClientAddress,
    [Parameter(Mandatory)][string]$PublicKeyPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LinkLocalAddress([string]$Address) {
    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsedAddress) -or
        $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'This bootstrap requires a literal IPv4 link-local address.'
    }
    $octets = $parsedAddress.GetAddressBytes()
    if ($parsedAddress.ToString() -cne $Address -or
        $octets[0] -ne 169 -or $octets[1] -ne 254 -or
        $octets[2] -eq 0 -or $octets[2] -eq 255) {
        throw 'Only canonical addresses in the usable IPv4 link-local range are accepted.'
    }
}

Assert-LinkLocalAddress $ListenAddress
Assert-LinkLocalAddress $ClientAddress
if ($ListenAddress -ceq $ClientAddress) {
    throw 'The client and server must have different addresses.'
}

# Two disjoint ranges cover every IPv4 address except the approved client.
# Explicit blocks prevent unrelated broad allow rules from expanding SSH access.
$clientValue = [uint64]0
foreach ($octet in ([Net.IPAddress]::Parse($ClientAddress).GetAddressBytes())) {
    $clientValue = ($clientValue -shl 8) -bor $octet
}
function ConvertTo-IPv4Text([uint64]$Value) {
    return (@(24,16,8,0 | ForEach-Object { ($Value -shr $_) -band 255 }) -join '.')
}
$blockedIpv4 = @(
    ('0.0.0.0-' + (ConvertTo-IPv4Text ($clientValue - 1))),
    ((ConvertTo-IPv4Text ($clientValue + 1)) + '-255.255.255.255')
)

$keyText = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
if ($keyText -cnotmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]*)?$') {
    throw 'Supply a plain OpenSSH Ed25519 public key without authorized-key options.'
}
$encodedKey = $Matches[1]
$keyBytes = [Convert]::FromBase64String($encodedKey)
$expectedPrefix = [byte[]](0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
if ($keyBytes.Length -ne 51) { throw 'Invalid Ed25519 key length.' }
for ($index = 0; $index -lt $expectedPrefix.Length; $index++) {
    if ($keyBytes[$index] -ne $expectedPrefix[$index]) {
        throw 'Invalid Ed25519 key encoding.'
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$templatePath = Join-Path $repositoryRoot 'config/sshd_config.template'
$configuration = (Get-Content -LiteralPath $templatePath -Raw).
    Replace('@@LISTEN_ADDRESS@@', $ListenAddress).
    Replace('@@CLIENT_RESTRICTION@@', ('@' + $ClientAddress))
if ($configuration.Contains('@@LISTEN_ADDRESS@@') -or
    $configuration.Contains('@@CLIENT_RESTRICTION@@')) {
    throw 'Unresolved configuration token.'
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) {
    throw 'The output directory must not already exist; preserve earlier plans.'
}
$null = New-Item -ItemType Directory -Path $outputPath
$encoding = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $outputPath 'sshd_config'), $configuration, $encoding)
$authorizedKey = 'restrict,from="' + $ClientAddress + '" ssh-ed25519 ' + $encodedKey + "`n"
[IO.File]::WriteAllText((Join-Path $outputPath 'authorized_keys'), $authorizedKey, $encoding)

$manifest = [ordered]@{
    schema = 'd3d11-validation-connection-plan/v1'
    installed = $false
    account = 'd3d11validator'
    administrator = $false
    listenAddress = $ListenAddress
    clientAddress = $ClientAddress
    port = 22222
    accountPasswordStored = $false
    allowedOperations = @('status')
    deploymentRoot = 'C:/ProgramData/D3D11Validation'
    firewall = [ordered]@{
        program = 'C:/Windows/System32/OpenSSH/sshd.exe'
        allowRule = 'D3D11Validation-In-TCP'
        blockOtherIpv4Rule = 'D3D11Validation-Block-Other-IPv4'
        blockOtherIpv4 = $blockedIpv4
        blockIpv6Rule = 'D3D11Validation-Block-IPv6'
        # Windows Firewall rejects a zero-length IPv6 prefix. These halves cover it.
        blockIpv6 = @('::/1', '8000::/1')
        installationGuardRule = 'D3D11Validation-InstallationGuard'
        guardMustRemainEnabledUntilQualified = $true
    }
    files = @(
        foreach ($relativePath in @(
            'windows/Invoke-ValidationGateway.ps1',
            'windows/Get-ValidationInventory.ps1'
        )) {
            $sourcePath = Join-Path $repositoryRoot $relativePath
            [ordered]@{
                source = $relativePath
                sha256 = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
}
[IO.File]::WriteAllText((Join-Path $outputPath 'plan.json'),
    ($manifest | ConvertTo-Json -Depth 5), $encoding)
Write-Output 'Connection plan prepared. No accounts, services, keys, or firewall rules were installed.'
