# Operator-only rollback. Never exposed by the SSH gateway.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^worker-v[1-9][0-9]*$')][string]$Deployment)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedSid = (Get-LocalUser -Name d3d11validator).SID.Value
$scriptPath = 'C:/ProgramData/D3D11Validation/program/' + $Deployment + '/Start-ValidationWorker.ps1'
$expectedImage = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$stopped = 0
foreach ($candidate in Get-CimInstance Win32_Process -Filter "Name='powershell.exe'") {
    if ($candidate.CommandLine -notlike ('*"' + $scriptPath + '"*') -and
        $candidate.CommandLine -notlike ('*' + $scriptPath)) { continue }
    $process = [Diagnostics.Process]::GetProcessById($candidate.ProcessId)
    try {
        # Hold the process handle while checking identity; Kill uses this same handle.
        $null = $process.Handle
        $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
        if ($owner.ReturnValue -ne 0 -or $owner.Sid -cne $expectedSid -or
            $process.MainModule.FileName -ine $expectedImage -or
            [Math]::Abs(($process.StartTime.ToUniversalTime() - $candidate.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 1) {
            throw 'Worker identity changed; refusing to stop it.'
        }
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'Worker did not exit.' }
        $stopped++
    } finally { $process.Dispose() }
}
[ordered]@{schema='d3d11-worker-stop/v1'; workersStopped=$stopped; personalProcessesModified=$false} | ConvertTo-Json
