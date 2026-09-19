# Apply only to the setup-owned bootstrap after reviewing its hashes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$GatewaySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$InventorySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ConfigurationSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\D3D11Validation'
$account = Get-LocalUser -Name d3d11validator
if (Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object SID -eq $account.SID) {
    throw 'The validation account must not be an administrator.'
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use the authorized elevated setup console.'
}

$expectedFiles = @{
    'program\Invoke-ValidationGateway.ps1' = $GatewaySha256
    'program\Get-ValidationInventory.ps1' = $InventorySha256
    'ssh\sshd_config' = $ConfigurationSha256
}
foreach ($relative in $expectedFiles.Keys) {
    $path = Join-Path $root $relative
    if ((Get-FileHash -LiteralPath $path).Hash -ine $expectedFiles[$relative]) {
        throw 'A staged source differs from the reviewed deployment.'
    }
}
foreach ($path in @($root, "$root\program", "$root\ssh") +
    @(Get-ChildItem -LiteralPath $root -Recurse -Force | Select-Object -ExpandProperty FullName)) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'A setup path is a reparse point.'
    }
}

function Set-ProtectedAcl([string]$Path, [bool]$Directory, [bool]$RunnerRead) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() }
        else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inheritance = if ($Directory) { 'ContainerInherit,ObjectInherit' } else { 'None' }
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            $inheritance, 'None', 'Allow'))
    }
    if ($RunnerRead) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $account.SID, 'ReadAndExecute', $inheritance, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    $actual = Get-Acl -LiteralPath $Path
    # Windows may normalize descriptor control flags. Compare effective ACEs,
    # owner, group, and inheritance protection instead of SDDL spelling.
    $describeRule = {
        '{0}|{1}|{2}|{3}|{4}|{5}' -f
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value,
            [int]$_.FileSystemRights, [int]$_.AccessControlType,
            [int]$_.InheritanceFlags, [int]$_.PropagationFlags, $_.IsInherited
    }
    $expectedRules = @($acl.Access | ForEach-Object $describeRule | Sort-Object)
    $actualRules = @($actual.Access | ForEach-Object $describeRule | Sort-Object)
    if (-not $actual.AreAccessRulesProtected -or
        $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or
        $actual.GetGroup([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or
        (Compare-Object $expectedRules $actualRules)) {
        throw 'Protected ACL readback differs from the requested descriptor.'
    }
}

# Protect the private key before granting inherited read access to the root.
# ssh-keygen can retain an explicit ACE for the creating personal account.
Set-ProtectedAcl "$root\ssh\ssh_host_ed25519_key" $false $false
Set-ProtectedAcl $root $true $true
foreach ($relative in $expectedFiles.Keys) {
    Set-ProtectedAcl (Join-Path $root $relative) $false $true
}
Set-ProtectedAcl "$root\ssh\authorized_keys" $false $true

$installedConfiguration = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path -LiteralPath $installedConfiguration) {
    if ((Get-FileHash -LiteralPath $installedConfiguration).Hash -ine $ConfigurationSha256) {
        throw 'Preserve the conflicting installed SSH configuration for review.'
    }
} else {
    Copy-Item -LiteralPath "$root\ssh\sshd_config" -Destination $installedConfiguration
}
Set-ProtectedAcl $installedConfiguration $false $false
& C:\Windows\System32\OpenSSH\sshd.exe -t
if ($LASTEXITCODE) { throw 'The installed SSH configuration was rejected.' }
Write-Output 'PASS: reviewed bootstrap hashes, exact protected ACLs, and installed SSH syntax.'
