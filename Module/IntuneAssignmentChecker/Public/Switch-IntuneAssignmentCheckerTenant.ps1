function Switch-IntuneAssignmentCheckerTenant {
    <#
    .SYNOPSIS
    Disconnects the current Microsoft Graph session and connects to another tenant.

    .DESCRIPTION
    Clears every tenant-scoped module cache before reconnecting. With no credential
    parameters, the normal interactive connection flow is used.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$AppId,
        [Parameter()][string]$TenantId,
        [Parameter()][string]$CertificateThumbprint,
        [Parameter()][PSCredential]$ClientSecretCredential,
        [Parameter()][SecureString]$AccessToken,
        [Parameter()][ValidateSet('Global', 'USGov', 'USGovDoD')][string]$Environment = 'Global',
        [Parameter()][ValidateSet('Core', 'Applications', 'Devices', 'Scripts', 'CloudPC', 'ScopeTags', 'Audit', 'Full')][string[]]$Capability = @('Full'),
        [Parameter()][switch]$SkipPermissionPrompt,
        [Parameter()][switch]$PassThru
    )

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    foreach ($variableName in @(
            'GraphEndpoint', 'GraphEnvironment', 'CurrentTenantId', 'CurrentTenantName',
            'CurrentUserUPN', 'TemplateIdToFamilyCache', 'ScopeTagLookup',
            'AssignmentFilterLookup', 'GroupInfoCache'
        )) {
        Set-Variable -Name $variableName -Scope Script -Value $null
    }

    $connect = @{ Environment = $Environment; Capability = $Capability; SkipPermissionPrompt = $SkipPermissionPrompt; PassThru = $true }
    foreach ($name in @('AppId', 'TenantId', 'CertificateThumbprint', 'ClientSecretCredential', 'AccessToken')) {
        if ($PSBoundParameters.ContainsKey($name)) { $connect[$name] = $PSBoundParameters[$name] }
    }
    $connection = Connect-IntuneAssignmentChecker @connect
    if ($PassThru) { $connection }
}
