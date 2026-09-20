# Publication separates a recoverable incomplete submit from a lost accepted job.
Set-StrictMode -Version Latest

function Get-ValidationSubmissionInitial($Index) {
    if ($Index.schema -cne 'd3d11-submission-index/v1' -or
        $Index.phase -cnotin @('prepared','published')) { throw 'invalid_submission_history' }
    $initial = $Index.initial
    foreach ($field in @('jobId','capability','requestNonce','inputSha256','deploymentSha256')) {
        $length = if ($field -ceq 'jobId') { 32 } else { 64 }
        if ($initial.$field -cnotmatch ('^[0-9a-f]{' + $length + '}$')) { throw 'invalid_submission_history' }
    }
    if ($initial.state -cne 'submitted' -or $initial.executionNonce -cne '' -or
        $initial.workerEpoch -cne '' -or $initial.cancelRequested -ne $false -or
        $null -ne $initial.exitCode -or $null -ne $initial.result -or
        $initial.updatedUtc -cne $initial.createdUtc) { throw 'invalid_submission_history' }
    return $initial
}

function Get-ValidationPublicationAction($Index, $Job) {
    $initial = Get-ValidationSubmissionInitial $Index
    if ($null -eq $Job) {
        if ($Index.phase -ceq 'published') { throw 'accepted_job_record_missing' }
        return 'create'
    }
    foreach ($field in @('jobId','capability','requestNonce','requestText','inputSha256',
                         'deploymentSha256','sourceRevision','kind','durationMs','createdUtc')) {
        if ($Job.$field -cne $initial.$field) { throw 'submission_binding_mismatch' }
    }
    if ($Index.phase -ceq 'prepared') {
        if ($Job.state -cne 'submitted' -or $Job.executionNonce -cne '' -or
            $Job.workerEpoch -cne '' -or $Job.cancelRequested -ne $false -or
            $null -ne $Job.exitCode -or $null -ne $Job.result -or
            $Job.updatedUtc -cne $Job.createdUtc) { throw 'unpublished_job_was_modified' }
        return 'publish'
    }
    return 'reuse'
}

Export-ModuleMember -Function Get-ValidationSubmissionInitial, Get-ValidationPublicationAction
