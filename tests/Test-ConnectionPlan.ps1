[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$generator = Join-Path $repositoryRoot 'windows/New-ValidationConnectionPlan.ps1'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('d3d11-plan-test-' + [Guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $scratch
$encoding = [Text.UTF8Encoding]::new($false)

try {
    # Synthetic public-key wire data; never install this test key on a host.
    $wireBytes = [byte[]](@(0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32) + (1..32))
    $publicKey = 'ssh-ed25519 ' + [Convert]::ToBase64String($wireBytes)
    $keyPath = Join-Path $scratch 'test.pub'
    [IO.File]::WriteAllText($keyPath, $publicKey, $encoding)
    $validOutput = Join-Path $scratch 'valid'
    $parameters = @{
        ListenAddress = '169.254.10.20'
        ClientAddress = '169.254.10.21'
        PublicKeyPath = $keyPath
        OutputDirectory = $validOutput
    }
    & $generator @parameters | Out-Null
    $plan = Get-Content -LiteralPath (Join-Path $validOutput 'plan.json') -Raw | ConvertFrom-Json
    if ($plan.installed -or $plan.administrator -or $plan.port -ne 22222 -or
        @($plan.allowedOperations).Count -ne 1 -or $plan.allowedOperations[0] -cne 'status') {
        throw 'The generated plan expanded the bootstrap access boundary.'
    }
    if (@($plan.firewall.blockOtherIpv4).Count -ne 2 -or
        $plan.firewall.blockOtherIpv4[0] -cne '0.0.0.0-169.254.10.20' -or
        $plan.firewall.blockOtherIpv4[1] -cne '169.254.10.22-255.255.255.255' -or
        ($plan.firewall.blockIpv6 -join ',') -cne '::/1,8000::/1' -or
        -not $plan.firewall.guardMustRemainEnabledUntilQualified) {
        throw 'Firewall ranges failed to exclude only the approved client.'
    }

    foreach ($boundary in @(
        @{ Client = '169.254.1.0'; Before = '169.254.0.255'; After = '169.254.1.1' },
        @{ Client = '169.254.254.255'; Before = '169.254.254.254'; After = '169.254.255.0' }
    )) {
        $boundaryParameters = $parameters.Clone()
        $boundaryParameters.ClientAddress = $boundary.Client
        $boundaryParameters.OutputDirectory = Join-Path $scratch $boundary.Client
        & $generator @boundaryParameters | Out-Null
        $boundaryPlan = Get-Content -LiteralPath (
            Join-Path $boundaryParameters.OutputDirectory 'plan.json') -Raw | ConvertFrom-Json
        if ($boundaryPlan.firewall.blockOtherIpv4[0] -cne ('0.0.0.0-' + $boundary.Before) -or
            $boundaryPlan.firewall.blockOtherIpv4[1] -cne ($boundary.After + '-255.255.255.255')) {
            throw 'Firewall exclusion ranges mishandled an octet boundary.'
        }
    }
    $configuration = Get-Content -LiteralPath (Join-Path $validOutput 'sshd_config') -Raw
    foreach ($required in @('PasswordAuthentication no', 'PermitTTY no',
        'DisableForwarding yes', 'AllowUsers d3d11validator@169.254.10.21',
        'ListenAddress 169.254.10.20')) {
        if (-not $configuration.Contains($required)) { throw 'Missing SSH restriction.' }
    }

    $invalidCases = @(
        @{ ClientAddress = '0.0.0.0' },
        @{ ClientAddress = '8.8.8.8' },
        @{ ClientAddress = '169.254.10.20' },
        @{ ClientAddress = '169.254.10.21/16' },
        @{ ClientAddress = '169.254.10.21*' },
        @{ ClientAddress = "169.254.10.21`nPasswordAuthentication yes" },
        @{ ClientAddress = '169.254.0.1' },
        @{ ListenAddress = '127.0.0.1' },
        @{ ListenAddress = '::1' },
        @{ ListenAddress = '169.254.255.1' },
        @{ ListenAddress = '169.254.010.020' }
    )
    $count = 0
    foreach ($invalidCase in $invalidCases) {
        $rejected = $false
        $testParameters = $parameters.Clone()
        $output = Join-Path $scratch ('invalid-' + $count)
        $testParameters.OutputDirectory = $output
        foreach ($key in $invalidCase.Keys) { $testParameters[$key] = $invalidCase[$key] }
        try { & $generator @testParameters | Out-Null } catch { $rejected = $true }
        if (-not $rejected -or (Test-Path -LiteralPath $output)) {
            throw 'Invalid address produced a connection plan.'
        }
        $count++
    }

    foreach ($invalidKey in @(('command="whoami" ' + $publicKey),
        ($publicKey + "`n" + $publicKey), 'ssh-ed25519 AAAA')) {
        [IO.File]::WriteAllText($keyPath, $invalidKey, $encoding)
        $testParameters = $parameters.Clone()
        $output = Join-Path $scratch ('invalid-key-' + $count)
        $testParameters.OutputDirectory = $output
        $rejected = $false
        try { & $generator @testParameters | Out-Null } catch { $rejected = $true }
        if (-not $rejected -or (Test-Path -LiteralPath $output)) {
            throw 'Invalid key produced a connection plan.'
        }
        $count++
    }
    [IO.File]::WriteAllText($keyPath, $publicKey, $encoding)
    $rejected = $false
    try { & $generator @parameters | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'An existing plan was overwritten.' }
    Write-Output ("PASS: valid plan, two firewall range boundaries, {0} rejected inputs, and overwrite protection." -f $count)
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
