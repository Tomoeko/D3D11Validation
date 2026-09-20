# Task Scheduler may return an account name instead of the submitted SID and add
# the auto-inherited DACL marker. Neither changes the principal or access masks.
Set-StrictMode -Version Latest

function Resolve-ValidationTaskSid([string]$Identity) {
    if ($Identity -cmatch '^S-1-[0-9-]+$') {
        return [Security.Principal.SecurityIdentifier]::new($Identity).Value
    }
    return [Security.Principal.NTAccount]::new($Identity).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-ValidationTaskDefinition([string]$Actual, [string]$Expected, [string]$Sid, [bool]$Enabled) {
    $actualXml = [xml]$Actual
    $expectedXml = [xml]$Expected
    foreach ($document in @($actualXml, $expectedXml)) {
        if ((Resolve-ValidationTaskSid $document.Task.Principals.Principal.UserId) -cne $Sid) {
            throw 'Task principal differs from the reviewed account.'
        }
        $document.Task.Principals.Principal.UserId = $Sid
        # Author and description are checked by the operator script. Windows adds
        # registration metadata such as URI; it cannot alter execution behavior.
        $registration = $document.DocumentElement.SelectSingleNode("*[local-name()='RegistrationInfo']")
        if ($null -ne $registration) { $null = $document.DocumentElement.RemoveChild($registration) }
    }
    # Enable/Disable are explicit lifecycle operations. Status must also be able
    # to inspect a safely disabled task without accepting any other difference.
    $expectedXml.Task.Settings.Enabled = $Enabled.ToString().ToLowerInvariant()
    if ($actualXml.OuterXml -cne $expectedXml.OuterXml) { throw 'Task behavior differs from the reviewed plan.' }
}

function Assert-ValidationTaskSecurity([string]$Actual, [string]$Expected) {
    $descriptors = foreach ($text in @($Actual, $Expected)) {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($text)
        # Keep protection, owner/group, every ACE, access mask and inheritance flag
        # exact. Only Windows' DACL bookkeeping marker is semantically irrelevant.
        $descriptor.SetFlags($descriptor.ControlFlags -band
            (-bnot [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited))
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    }
    if ($descriptors[0] -cne $descriptors[1]) { throw 'Unexpected task security descriptor.' }
}

Export-ModuleMember -Function Resolve-ValidationTaskSid, Assert-ValidationTaskDefinition, Assert-ValidationTaskSecurity
