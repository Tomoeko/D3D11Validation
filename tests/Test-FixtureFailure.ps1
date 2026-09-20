Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Fixtures.psm1')
foreach ($message in @('runtime_identity_drift','runtime_certificate_unavailable','session_drift')) {
    try { throw $message } catch {
        if ((Get-ValidationFixtureFailureCode $_) -cne $message) { throw 'Known failure code was lost.' }
    }
}
foreach ($message in @('arbitrary host path','runtime_identity_drift with private details','RUNTIME_IDENTITY_DRIFT')) {
    try { throw $message } catch {
        if ((Get-ValidationFixtureFailureCode $_) -cne 'fixture_validation_failed') { throw 'Unapproved exception text escaped.' }
    }
}
'PASS: six fixture failure privacy checks'
