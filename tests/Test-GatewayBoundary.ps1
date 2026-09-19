# Exercise real subprocess rejection, including shell metacharacters and subsystems.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$gateway = Join-Path $repositoryRoot 'windows/Invoke-ValidationGateway.ps1'
$shellPath = (Get-Process -Id $PID).Path
$previousCommand = $env:SSH_ORIGINAL_COMMAND
$previousNativePreference = $null
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $previousNativePreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
}

$commands = @('', 'STATUS', 'status ', ' status', "status`nwhoami", 'status; whoami',
    'status & whoami', '$(whoami)', 'powershell.exe', 'cmd.exe', 'sftp',
    'scp -t ../../outside', '../status', 'submit', 'start', 'results', 'cancel')
try {
    foreach ($command in $commands) {
        $env:SSH_ORIGINAL_COMMAND = $command
        # Redirect stderr to a task-owned file so Windows PowerShell 5.1 does not
        # promote native stderr to a terminating error before the exit-code check.
        $errorPath = [IO.Path]::GetTempFileName()
        try {
            $output = & $shellPath -NoLogo -NoProfile -NonInteractive -File $gateway 2> $errorPath
            $exitCode = $LASTEXITCODE
            $errorText = [IO.File]::ReadAllText($errorPath).Trim()
            if ($exitCode -ne 64 -or $output -or
                -not $errorText.Contains('"unsupported_operation"')) {
                throw 'Gateway accepted or mishandled an unsupported request.'
            }
        } finally {
            Remove-Item -LiteralPath $errorPath
        }
    }
} finally {
    $env:SSH_ORIGINAL_COMMAND = $previousCommand
    if ($null -ne $previousNativePreference) {
        $PSNativeCommandUseErrorActionPreference = $previousNativePreference
    }
}
Write-Output ("PASS: {0} rejected commands. SSH/ACL enforcement still requires host testing." -f $commands.Count)
