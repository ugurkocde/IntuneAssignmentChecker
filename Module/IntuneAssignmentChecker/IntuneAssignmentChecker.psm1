#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

# Module-scoped variables (set by Connect-IntuneAssignmentChecker)
$script:GraphEndpoint = $null
$script:GraphEnvironment = $null
$script:CurrentTenantId = $null
$script:CurrentTenantName = $null
$script:CurrentUserUPN = $null
$script:TemplateIdToFamilyCache = $null
$script:ScopeTagLookup = $null
$script:IntentTemplateSubtypeToFamily = @{
    'antivirus'                       = 'endpointSecurityAntivirus'
    'diskEncryption'                  = 'endpointSecurityDiskEncryption'
    'firewall'                        = 'endpointSecurityFirewall'
    'endpointDetectionAndResponse'    = 'endpointSecurityEndpointDetectionAndResponse'
    'attackSurfaceReduction'          = 'endpointSecurityAttackSurfaceReduction'
    'accountProtection'               = 'endpointSecurityAccountProtection'
}

# Dot-source all private functions
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Private) {
    try { . $file.FullName }
    catch { Write-Error "Failed to load $($file.FullName): $_" }
}

# Dot-source all public functions
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Public) {
    try { . $file.FullName }
    catch { Write-Error "Failed to load $($file.FullName): $_" }
}

# Create alias for interactive mode
New-Alias -Name 'IntuneAssignmentChecker' -Value 'Invoke-IntuneAssignmentChecker' -Force

# Export public functions and alias
Export-ModuleMember -Function $Public.BaseName -Alias 'IntuneAssignmentChecker'
