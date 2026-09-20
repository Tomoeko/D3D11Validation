[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../windows/Validation.Protocol.psm1') -Force
$nonce = 'a' * 64
$capability = 'b' * 64
$jobId = 'c' * 32
$submit = '{"version":"1","nonce":"' + $nonce + '","kind":"diagnostic","durationMs":"200"}'
$job = '{"version":"1","nonce":"' + $nonce + '","jobId":"' + $jobId + '","capability":"' + $capability + '"}'
$null = ConvertFrom-ValidationRequest submit $submit
foreach ($operation in 'start','status','results','cancel') {
    $null = ConvertFrom-ValidationRequest $operation $job
}
foreach ($kind in 'device','reject-software','reject-other-gpu','reject-session') {
    $null = ConvertFrom-ValidationRequest submit ($submit.Replace('diagnostic',$kind).Replace('200','0'))
}
$unityKinds = @('unity-startup')
foreach ($bundle in 'recovered','regenerated','negative') {
    foreach ($keyword in 'on','off') {
        foreach ($tier in 0,1,2) {
            foreach ($capture in 'traced','untraced','unhooked') { $unityKinds += "unity-$bundle-$keyword-tier$tier-$capture" }
        }
    }
}
foreach ($kind in $unityKinds) {
    $null = ConvertFrom-ValidationRequest submit ($submit.Replace('diagnostic',$kind).Replace('200','0'))
}
$cases = @(
    @('submit', ''), @('submit', '{}'), @('submit', '[]'), @('submit', 'null'),
    @('submit', $submit.Replace('diagnostic','device')),
    @('submit', $submit.Replace('diagnostic','unity-recovered-off-tier0-traced')),
    @('submit', $submit.Replace('diagnostic','unity-recovered-off-tier3-traced').Replace('200','0')),
    @('submit', $submit.Replace('diagnostic','unity-unapproved-off-tier0-traced').Replace('200','0')),
    @('submit', $submit.Replace('}', ',"adapterOrdinal":"0"}')),
    @('submit', ($submit + ' trailing')), @('submit', ('[' + $submit + ']')),
    @('submit', $submit.Replace('"version":"1"', '"version":"1","version":"1"')),
    @('submit', $submit.Replace('"version"', '"Version"')),
    @('submit', $submit.Replace('"durationMs":"200"', '"durationMs":200')),
    @('submit', $submit.Replace('"durationMs":"200"', '"durationMs":"050"')),
    @('submit', $submit.Replace('"durationMs":"200"', '"durationMs":"5001"')),
    @('submit', $submit.Replace('"durationMs":"200"', '"durationMs":"-1"')),
    @('submit', $submit.Replace('"diagnostic"', '"powershell"')),
    @('submit', $submit.Replace('}', ',"executable":"cmd"}')),
    @('submit', $submit.Replace('}', ',"script":"whoami"}')),
    @('submit', $submit.Replace('"nonce"', '"\u006eonce"')),
    @('submit', $submit.Replace('}', ',}')),
    @('submit', $submit.Replace('"durationMs":"200"', '"durationMs":{"value":"200"}')),
    @('submit', $submit.Replace('"kind"', '"kind" ' + [char]0)),
    @('status', $job.Replace($jobId, '..-escape')),
    @('status', $job.Replace($jobId, $jobId.ToUpperInvariant())),
    @('status', $job.Replace($capability, '')),
    @('results', $job.Replace('}', ',"path":"outside"}')),
    @('status;whoami', $job), @('STATUS', $job), @(' status', $job),
    @('submit', (' ' * 8193 + $submit))
)
$caseIndex = 0
foreach ($case in $cases) {
    $rejected = $false
    try { $null = ConvertFrom-ValidationRequest $case[0] $case[1] }
    catch { $rejected = $null -ne $_.Exception.Data['validationCode'] }
    if (-not $rejected) { throw ('Protocol rejection failed for case ' + $caseIndex) }
    $caseIndex++
}
Write-Output ('PASS: ' + (9 + $unityKinds.Count) + ' valid requests and ' + $cases.Count + ' rejected protocol cases.')
