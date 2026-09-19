# Run in the dedicated account's interactive logon, never in an elevated shell.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$sessionId = (Get-Process -Id $PID).SessionId
$dedicatedAccount = $identity.Name.EndsWith('\d3d11validator', [StringComparison]::OrdinalIgnoreCase)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $dedicatedAccount -or $elevated -or $sessionId -eq 0 -or
    -not [Environment]::UserInteractive) {
    throw 'An interactive, non-elevated validation-account logon is required.'
}

if (-not ('ValidationSession' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ValidationSession {
    [DllImport("wtsapi32.dll", SetLastError=true)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr server, int session, int kind, out IntPtr buffer, out int size);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();
    public static int Query(int session, int kind, bool word) {
        IntPtr buffer;
        int size;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, kind, out buffer, out size))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (size < (word ? 2 : 4)) throw new InvalidOperationException("Short session record");
            return word ? Marshal.ReadInt16(buffer) : Marshal.ReadInt32(buffer);
        } finally { WTSFreeMemory(buffer); }
    }
}
'@
}

[ordered]@{
    schema = 'd3d11-worker-session/v1'
    collectedUtc = [DateTime]::UtcNow.ToString('o')
    dedicatedAccount = $dedicatedAccount
    elevated = $elevated
    processSessionId = $sessionId
    userInteractive = [Environment]::UserInteractive
    clientProtocolType = [ValidationSession]::Query(-1, 16, $true)
    connectionState = [ValidationSession]::Query(-1, 8, $false)
    activeConsoleSessionId = [ValidationSession]::WTSGetActiveConsoleSessionId()
    hardwareD3D11Qualified = $false
} | ConvertTo-Json
