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
$script:RequestedCapabilities = @('Full')
$script:CapabilityStatus = @()
$script:IntentTemplateSubtypeToFamily = @{
    'antivirus'                       = 'endpointSecurityAntivirus'
    'diskEncryption'                  = 'endpointSecurityDiskEncryption'
    'firewall'                        = 'endpointSecurityFirewall'
    'endpointDetectionAndResponse'    = 'endpointSecurityEndpointDetectionAndResponse'
    'attackSurfaceReduction'          = 'endpointSecurityAttackSurfaceReduction'
    'accountProtection'               = 'endpointSecurityAccountProtection'
}

# Required Microsoft Graph permissions used by connection and tenant-switch commands.
$script:RequiredPermissions = @(
    @{ Permission = "User.Read.All";                         Reason = "Required to read user profile information and check group memberships" }
    @{ Permission = "GroupMember.Read.All";                  Reason = "Required to read group memberships and basic group properties" }
    @{ Permission = "DeviceManagementConfiguration.Read.All"; Reason = "Allows reading Intune device configuration policies and their assignments" }
    @{ Permission = "DeviceManagementApps.Read.All";         Reason = "Necessary to read mobile app management policies and app configurations" }
    @{ Permission = "DeviceManagementManagedDevices.Read.All"; Reason = "Required to read managed device information and compliance policies" }
    @{ Permission = "Device.Read.All";                       Reason = "Needed to read device information from Entra ID" }
    @{ Permission = "DeviceManagementScripts.Read.All";      Reason = "Needed to read device management and health scripts" }
    @{ Permission = "CloudPC.Read.All";                      Reason = "Required to read Windows 365 Cloud PC provisioning policies and settings (optional if W365 not licensed)" }
    @{ Permission = "DeviceManagementRBAC.Read.All";         Reason = "Required to read role scope tags for scope tag display and filtering" }
    @{ Permission = "DeviceManagementServiceConfig.Read.All"; Reason = "Required to read Autopilot deployment profiles and enrollment status page configurations" }
)

$script:CapabilityProfiles = [ordered]@{
    Core         = @('User.Read.All', 'GroupMember.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All')
    Applications = @('DeviceManagementApps.Read.All')
    Devices      = @('DeviceManagementManagedDevices.Read.All', 'Device.Read.All')
    Scripts      = @('DeviceManagementScripts.Read.All')
    CloudPC      = @('CloudPC.Read.All')
    ScopeTags    = @('DeviceManagementRBAC.Read.All')
    Audit        = @('DeviceManagementApps.Read.All')
    Full         = @()
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
