#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#PSScriptInfo
.VERSION 3.4.4
.GUID c6e25ec6-5787-45ef-95af-8abeb8a17daf
.AUTHOR ugurk
.PROJECTURI https://github.com/ugurkocde/IntuneAssignmentChecker
.DESCRIPTION
This script enables IT administrators to efficiently analyze and audit Intune assignments. It checks assignments for specific users, groups, or devices, displays all policies and their assignments, identifies unassigned policies, detects empty groups in assignments, and searches for specific settings across policies.
.RELEASENOTES
Version 3.4.4:
- Fix Permission Error for Health Scripts

Version 3.4.3:
- Fixed critical assignment accuracy issues affecting group policy checks (Fixes #79, #80)
- Resolved Settings Catalog policies not showing in group assignments (Fixes #80)
- Fixed Compare Groups to properly detect and display excluded assignments with [EXCLUDED] tag (Fixes #44)
- Improved assignment processing to handle ALL assignments instead of just first one
- Enhanced exclusion detection in group comparison feature

Version 3.4.2:
- Fixed Android policy detection - now properly identifies and displays Android platform policies (Fixes #86)
- Fixed assignment accuracy - now shows ALL assigned groups instead of just the first one (Fixes #87)
- Fixed exclusion group names - now displays actual group names instead of generic "Group Exclusion" (Fixes #63, #84)
- Added platform detection for all device configuration and compliance policies
- Improved assignment processing to handle multiple assignments correctly
- Enhanced group name resolution for all assignment types

Version 3.4.1:
- Updated release date

Version 3.4.0:
- NEW: Added "Show All Failed Assignments" feature (option 11) to display policy deployment failures
- Added support for Windows 365 Cloud PC Provisioning Policies and User Settings
- Updated HTML export to include these new policy types
- Enhanced assignment checking functionality
- Removed deprecated Administrative Templates option (was option 10)
- Renumbered menu options: Compare Groups is now option 10

Version 3.3.3:
- Fixed HTML Export bug (#70)
- Added display for Autopilot and Enrollment Status Page profiles

Version 3.3.2:
- Added support for Endpoint Security tab (Antivirus profiles, Disk Encryption, etc.)
- Added Autopilot deployment profiles and ESP assignment checks
#>

param(
    [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific users")]
    [switch]$CheckUser,

    [Parameter(Mandatory = $false, HelpMessage = "User Principal Names to check, comma-separated")]
    [string]$UserPrincipalNames,

    [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific groups")]
    [switch]$CheckGroup,

    [Parameter(Mandatory = $false, HelpMessage = "Group names or IDs to check, comma-separated")]
    [string]$GroupNames,

    [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific devices")]
    [switch]$CheckDevice,

    [Parameter(Mandatory = $false, HelpMessage = "Device names to check, comma-separated")]
    [string]$DeviceNames,

    [Parameter(Mandatory = $false, HelpMessage = "Show all policies and their assignments")]
    [switch]$ShowAllPolicies,

    [Parameter(Mandatory = $false, HelpMessage = "Show all 'All Users' assignments")]
    [switch]$ShowAllUsersAssignments,

    [Parameter(Mandatory = $false, HelpMessage = "Show all 'All Devices' assignments")]
    [switch]$ShowAllDevicesAssignments,

    [Parameter(Mandatory = $false, HelpMessage = "Skip execution - used for testing")]
    [switch]$SkipExecution,
    
    [Parameter(Mandatory = $false, HelpMessage = "Generate HTML report")]
    [switch]$GenerateHTMLReport,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show policies without assignments")]
    [switch]$ShowPoliciesWithoutAssignments,
    
    [Parameter(Mandatory = $false, HelpMessage = "Check for empty groups in assignments")]
    [switch]$CheckEmptyGroups,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show all Administrative Templates")]
    [switch]$ShowAdminTemplates,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show all failed assignments")]
    [switch]$ShowFailedAssignments,
    
    [Parameter(Mandatory = $false, HelpMessage = "Compare assignments between groups")]
    [switch]$CompareGroups,
    
    [Parameter(Mandatory = $false, HelpMessage = "Groups to compare assignments between, comma-separated")]
    [string]$CompareGroupNames,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show app install summary report")]
    [switch]$ShowAppInstallSummary,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show compliance policy device summary")]
    [switch]$ShowComplianceSummary,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show configuration policy device summary")]
    [switch]$ShowConfigurationSummary,
    
    [Parameter(Mandatory = $false, HelpMessage = "Export results to CSV")]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path for the exported CSV file")]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "App ID for authentication")]
    [string]$AppId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Tenant ID for authentication")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Certificate Thumbprint for authentication")]
    [string]$CertificateThumbprint,
    
    [Parameter(Mandatory = $false, HelpMessage = "Environment (Global, USGov, USGovDoD)")]
    [ValidateSet("Global", "USGov", "USGovDoD")]
    [string]$Environment = "Global"
)

# Check if any command-line parameters were provided
$parameterMode = $false
$selectedOption = $null

if ($CheckUser) { $parameterMode = $true; $selectedOption = '1' }
elseif ($CheckGroup) { $parameterMode = $true; $selectedOption = '2' }
elseif ($CheckDevice) { $parameterMode = $true; $selectedOption = '3' }
elseif ($ShowAllPolicies) { $parameterMode = $true; $selectedOption = '4' }
elseif ($ShowAllUsersAssignments) { $parameterMode = $true; $selectedOption = '5' }
elseif ($ShowAllDevicesAssignments) { $parameterMode = $true; $selectedOption = '6' }
elseif ($GenerateHTMLReport) { $parameterMode = $true; $selectedOption = '7' }
elseif ($ShowPoliciesWithoutAssignments) { $parameterMode = $true; $selectedOption = '8' }
elseif ($CheckEmptyGroups) { $parameterMode = $true; $selectedOption = '9' }
elseif ($CompareGroups) { $parameterMode = $true; $selectedOption = '10' }
elseif ($ShowFailedAssignments) { $parameterMode = $true; $selectedOption = '11' }
elseif ($ShowAppInstallSummary) { $parameterMode = $true; $selectedOption = '12' }
elseif ($ShowComplianceSummary) { $parameterMode = $true; $selectedOption = '14' }
elseif ($ShowConfigurationSummary) { $parameterMode = $true; $selectedOption = '16' }

<#
.SYNOPSIS
    Checks Intune policy and app assignments for users, groups, and devices.

.DESCRIPTION
    This script helps IT administrators analyze and audit Intune assignments by:
    - Checking assignments for specific users, groups, or devices
    - Showing all policies and their assignments
    - Finding policies without assignments
    - Identifying empty groups in assignments
    - Searching for specific settings across policies

.PARAMETER CheckUser
    Check assignments for specific users.

.PARAMETER UserPrincipalNames
    User Principal Names to check, comma-separated.

.PARAMETER CheckGroup
    Check assignments for specific groups.

.PARAMETER GroupNames
    Group names or IDs to check, comma-separated.

.PARAMETER CheckDevice
    Check assignments for specific devices.

.PARAMETER DeviceNames
    Device names to check, comma-separated.

.PARAMETER ShowAllPolicies
    Show all policies and their assignments.

.PARAMETER ShowAllUsersAssignments
    Show all 'All Users' assignments.

.PARAMETER ShowAllDevicesAssignments
    Show all 'All Devices' assignments.

.PARAMETER GenerateHTMLReport
    Generate HTML report.

.PARAMETER ShowPoliciesWithoutAssignments
    Show policies without assignments.

.PARAMETER CheckEmptyGroups
    Check for empty groups in assignments.

.PARAMETER ShowAdminTemplates
    Show all Administrative Templates.

.PARAMETER CompareGroups
    Compare assignments between groups.

.PARAMETER CompareGroupNames
    Groups to compare assignments between, comma-separated.

.PARAMETER ExportToCSV
    Export results to CSV.

.PARAMETER ExportPath
    Path for the exported CSV file.

.PARAMETER AppId
    App ID for authentication.

.PARAMETER TenantId
    Tenant ID for authentication.

.PARAMETER CertificateThumbprint
    Certificate Thumbprint for authentication.

.PARAMETER Environment
    Environment (Global, USGov, USGovDoD).

.EXAMPLE
    .\IntuneAssignmentChecker_v3.ps1 -CheckUser -UserPrincipalNames "user1@contoso.com,user2@contoso.com"
    Checks assignments for the specified users.

.EXAMPLE
    .\IntuneAssignmentChecker_v3.ps1 -CheckGroup -GroupNames "Marketing Team"
    Checks assignments for the specified group.

.EXAMPLE
    .\IntuneAssignmentChecker_v3.ps1 -ShowAllPolicies -ExportToCSV -ExportPath "C:\Temp\AllPolicies.csv"
    Shows all policies and exports the results to CSV.

.AUTHOR
    Ugur Koc (@ugurkocde)
    GitHub: https://github.com/ugurkocde/IntuneAssignmentChecker
    Sponsor: https://github.com/sponsors/ugurkocde
    Changelog: https://github.com/ugurkocde/IntuneAssignmentChecker/releases

.REQUIRED PERMISSIONS
    - User.Read.All                    (Read user profiles)
    - Group.Read.All                   (Read group information)
    - Device.Read.All                  (Read device information)
    - DeviceManagementApps.Read.All    (Read app management data)
    - DeviceManagementConfiguration.Read.All    (Read device configurations)
    - DeviceManagementManagedDevices.Read.All   (Read device management data)
#>

################################ Prerequisites #####################################################

# Fill in your App ID, Tenant ID, and Certificate Thumbprint
# Use parameter values if provided, otherwise use defaults
$appid = if ($AppId) { $AppId } else { '<YourAppIdHere>' } # App ID of the App Registration
$tenantid = if ($TenantId) { $TenantId } else { '<YourTenantIdHere>' } # Tenant ID of your EntraID
$certThumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { '<YourCertificateThumbprintHere>' } # Thumbprint of the certificate associated with the App Registration
# $certName = '<YourCertificateNameHere>' # Name of the certificate associated with the App Registration

####################################################################################################

# Version of the local script
$localVersion = "3.4.4"

Write-Host "🔍 INTUNE ASSIGNMENT CHECKER" -ForegroundColor Cyan
Write-Host "Made by Ugur Koc with" -NoNewline; Write-Host " ❤️  and ☕" -NoNewline
Write-Host " | Version" -NoNewline; Write-Host " $localVersion" -ForegroundColor Yellow -NoNewline
Write-Host " | Last updated: " -NoNewline; Write-Host "2025-09-19" -ForegroundColor Magenta
Write-Host ""
Write-Host "📢 Feedback & Issues: " -NoNewline -ForegroundColor Cyan
Write-Host "https://github.com/ugurkocde/IntuneAssignmentChecker/issues" -ForegroundColor White
Write-Host "📄 Changelog: " -NoNewline -ForegroundColor Cyan
Write-Host "https://github.com/ugurkocde/IntuneAssignmentChecker/releases" -ForegroundColor White
Write-Host ""
Write-Host "💝 Support this Project: " -NoNewline -ForegroundColor Cyan
Write-Host "https://github.com/sponsors/ugurkocde" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  DISCLAIMER: This script is provided AS IS without warranty of any kind." -ForegroundColor Yellow
Write-Host ""

####################################################################################################
# Autoupdate function

# URL to the version file on GitHub
$versionUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/refs/heads/main/version_v3.txt"

# URL to the latest script on GitHub
$scriptUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/IntuneAssignmentChecker_v3.ps1"

# Determine the script path based on whether it's run as a file or from an IDE
if ($PSScriptRoot) {
    $newScriptPath = Join-Path $PSScriptRoot "IntuneAssignmentChecker_v3.ps1"
}
else {
    $currentDirectory = Get-Location
    $newScriptPath = Join-Path $currentDirectory "IntuneAssignmentChecker_v3.ps1"
}

# Flag to control auto-update behavior
$autoUpdate = $true  # Set to $false to disable auto-update

try {
    # Fetch the latest version number from GitHub
    $latestVersion = Invoke-RestMethod -Uri $versionUrl
    
    # Compare versions using System.Version for proper semantic versioning
    $local = [System.Version]::new($localVersion)
    $latest = [System.Version]::new($latestVersion)
    
    if ($local -lt $latest) {
        Write-Host "A new version is available: $latestVersion (you are running $localVersion)" -ForegroundColor Yellow
        if ($autoUpdate) {
            Write-Host "AutoUpdate is enabled. Downloading the latest version..." -ForegroundColor Yellow
            try {
                # Download the latest version of the script
                Invoke-WebRequest -Uri $scriptUrl -OutFile $newScriptPath
                Write-Host "The latest version has been downloaded to $newScriptPath" -ForegroundColor Yellow
                Write-Host "Please restart the script to use the updated version." -ForegroundColor Yellow
            }
            catch {
                Write-Host "An error occurred while downloading the latest version. Please download it manually from: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Auto-update is disabled. Get the latest version at:" -ForegroundColor Yellow
            Write-Host "https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor Cyan
            Write-Host "" 
        }
    }
    elseif ($local -gt $latest) {
        Write-Host "Note: You are running a pre-release version ($localVersion)" -ForegroundColor Magenta
        Write-Host ""
    }
}
catch {
    Write-Host "Unable to check for updates. Continue with current version..." -ForegroundColor Gray
}

####################################################################################################

# Do not change the following code

# Script-level variables
$script:GraphEndpoint = $null
$script:GraphEnvironment = $null

# Ask user to select the Intune environment
function Set-Environment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )
    
    if ($EnvironmentName) {
        switch ($EnvironmentName) {
            'Global' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGov' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGovDoD' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            default {
                Write-Host "Invalid environment name. Using interactive selection." -ForegroundColor Yellow
                # Fall through to interactive selection
            }
        }
    }
    
    # Interactive selection if no valid environment name was provided
    do {
        Write-Host "Select Intune Tenant Environment:" -ForegroundColor Cyan
        Write-Host "  [1] Global" -ForegroundColor White
        Write-Host "  [2] USGov" -ForegroundColor White
        Write-Host "  [3] USGovDoD" -ForegroundColor White
        Write-Host ""
        Write-Host "  [0] Exit" -ForegroundColor White
        Write-Host ""
        Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline

        $selection = Read-Host

        switch ($selection) {
            '1' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '2' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '3' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '0' {
                Write-Host "Thank you for using IntuneAssignmentChecker! 👋" -ForegroundColor Green
                Write-Host "If you found this tool helpful, please consider:" -ForegroundColor Cyan
                Write-Host "- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor White
                Write-Host "- Supporting the project: https://github.com/sponsors/ugurkocde" -ForegroundColor White
                Write-Host ""
                exit
            }
            default {
                Write-Host "Invalid choice, please select 1,2,3, or 0" -ForegroundColor Red
            }
        }
    } while ($selection -ne '0')
}

# Skip execution if SkipExecution flag is set (for testing)
if ($SkipExecution) {
    return
}

# Connect to Microsoft Graph using certificate-based authentication

try {
    # Define required permissions with reasons
    $requiredPermissions = @(
        @{
            Permission = "User.Read.All"
            Reason     = "Required to read user profile information and check group memberships"
        },
        @{
            Permission = "Group.Read.All"
            Reason     = "Needed to read group information and memberships"
        },
        @{
            Permission = "DeviceManagementConfiguration.Read.All"
            Reason     = "Allows reading Intune device configuration policies and their assignments"
        },
        @{
            Permission = "DeviceManagementApps.Read.All"
            Reason     = "Necessary to read mobile app management policies and app configurations"
        },
        @{
            Permission = "DeviceManagementManagedDevices.Read.All"
            Reason     = "Required to read managed device information and compliance policies"
        },
        @{
            Permission = "Device.Read.All"
            Reason     = "Needed to read device information from Entra ID"
        },
        @{
            Permission = "DeviceManagementScripts.ReadWrite.All"
            Reason     = "Needed to read and write device management and health scripts"
        }
    )

    # Check if any of the variables are not set or contain placeholder values
    if (-not $appid -or $appid -eq '<YourAppIdHere>' -or
        -not $tenantid -or $tenantid -eq '<YourTenantIdHere>' -or
        -not $certThumbprint -or $certThumbprint -eq '<YourCertificateThumbprintHere>') {
        Write-Host "App ID, Tenant ID, or Certificate Thumbprint is missing or not set correctly." -ForegroundColor Red
        $manualConnection = Read-Host "Would you like to attempt a manual interactive connection? (y/n)"
        if ($manualConnection -eq 'y') {
            # Manual connection using interactive login
            Write-Host "Attempting manual interactive connection (you need privileges to consent permissions)..." -ForegroundColor Yellow
            $permissionsList = ($requiredPermissions | ForEach-Object { $_.Permission }) -join ', '
            # In parameter mode, use the Environment parameter (which defaults to Global)
            # In interactive mode, always prompt for environment selection
            if ($parameterMode) {
                Set-Environment -EnvironmentName $Environment
            }
            else {
                Set-Environment  # Prompt for environment selection in interactive mode
            }
            $connectionResult = Connect-MgGraph -Scopes $permissionsList -Environment $script:GraphEnvironment -NoWelcome -ErrorAction Stop
        }
        else {
            Write-Host "Script execution cancelled by user." -ForegroundColor Red
            exit
        }
    }
    else {
        # In parameter mode, use the Environment parameter (which defaults to Global)
        # In interactive mode, always prompt for environment selection
        if ($parameterMode) {
            Set-Environment -EnvironmentName $Environment
        }
        else {
            Set-Environment  # Prompt for environment selection in interactive mode
        }
        $connectionResult = Connect-MgGraph -ClientId $appid -TenantId $tenantid -Environment $script:GraphEnvironment -CertificateThumbprint $certThumbprint -NoWelcome -ErrorAction Stop
    }
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green

    # Check and display the current permissions
    $context = Get-MgContext
    $currentPermissions = $context.Scopes

    Write-Host "Checking required permissions:" -ForegroundColor Cyan
    $missingPermissions = @()
    foreach ($permissionInfo in $requiredPermissions) {
        $permission = $permissionInfo.Permission
        $reason = $permissionInfo.Reason

        # Check if either the exact permission or a "ReadWrite" version of it is granted
        $hasPermission = $currentPermissions -contains $permission -or $currentPermissions -contains $permission.Replace(".Read", ".ReadWrite")

        if ($hasPermission) {
            Write-Host "  [✓] $permission" -ForegroundColor Green
            Write-Host "      Reason: $reason" -ForegroundColor Gray
        }
        else {
            Write-Host "  [✗] $permission" -ForegroundColor Red
            Write-Host "      Reason: $reason" -ForegroundColor Gray
            $missingPermissions += $permission
        }
    }

    if ($missingPermissions.Count -eq 0) {
        Write-Host "All required permissions are present." -ForegroundColor Green
        Write-Host ""
    }
    else {
        Write-Host "WARNING: The following permissions are missing:" -ForegroundColor Red
        $missingPermissions | ForEach-Object { 
            $missingPermission = $_
            $reason = ($requiredPermissions | Where-Object { $_.Permission -eq $missingPermission }).Reason
            Write-Host "  - $missingPermission" -ForegroundColor Yellow
            Write-Host "    Reason: $reason" -ForegroundColor Gray
        }
        Write-Host "The script will continue, but it may not function correctly without these permissions." -ForegroundColor Red
        Write-Host "Please ensure these permissions are granted to the app registration for full functionality." -ForegroundColor Yellow
        
        $continueChoice = Read-Host "Do you want to continue anyway? (y/n)"
        if ($continueChoice -ne 'y') {
            Write-Host "Script execution cancelled by user." -ForegroundColor Red
            exit
        }
    }
}
catch {
    Write-Host "Failed to connect to Microsoft Graph. Error: $_" -ForegroundColor Red
    
    # Additional error handling for certificate issues
    if ($_.Exception.Message -like "*Certificate with thumbprint*was not found*") {
        Write-Host "The specified certificate was not found or has expired. Please check your certificate configuration." -ForegroundColor Yellow
    }
    
    exit
}

# Common Functions
function Get-IntuneAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,
        
        [Parameter(Mandatory = $true)]
        [string]$EntityId,
        
        [Parameter(Mandatory = $false)]
        [string]$GroupId = $null
    )

    # Determine the correct assignments URI based on EntityType
    $actualAssignmentsUri = $null
    # $isResolvedAppProtectionPolicy = $false # Flag if we resolved a generic App Protection Policy. Not strictly needed with current logic.

    if ($EntityType -eq "deviceAppManagement/managedAppPolicies") {
        # For generic App Protection Policies, determine the specific policy type first
        $policyDetailsUri = "$GraphEndpoint/beta/deviceAppManagement/managedAppPolicies/$EntityId"
        try {
            $policyDetailsResponse = Invoke-MgGraphRequest -Uri $policyDetailsUri -Method Get
            $policyODataType = $policyDetailsResponse.'@odata.type'
            $specificPolicyTypePath = switch ($policyODataType) {
                "#microsoft.graph.androidManagedAppProtection" { "androidManagedAppProtections" }
                "#microsoft.graph.iosManagedAppProtection" { "iosManagedAppProtections" }
                "#microsoft.graph.windowsManagedAppProtection" { "windowsManagedAppProtections" }
                default { $null }
            }
            if ($specificPolicyTypePath) {
                $actualAssignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/$specificPolicyTypePath('$EntityId')/assignments"
            }
            else {
                Write-Warning "Could not determine specific App Protection Policy type for $EntityId from OData type '$policyODataType'."
                return [System.Collections.ArrayList]::new() # Return empty ArrayList
            }
        }
        catch {
            Write-Warning "Error fetching details for App Protection Policy '$EntityId': $($_.Exception.Message)"
            return [System.Collections.ArrayList]::new() # Return empty ArrayList
        }
    }
    elseif ($EntityType -eq "mobileAppConfigurations") {
        $actualAssignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileAppConfigurations('$EntityId')/assignments"
    }
    elseif ($EntityType -like "deviceAppManagement/*ManagedAppProtections") {
        # Already specific App Protection Policy type
        # Example: deviceAppManagement/iosManagedAppProtections
        $actualAssignmentsUri = "$GraphEndpoint/beta/$EntityType('$EntityId')/assignments" # EntityType already includes deviceAppManagement
    }
    else {
        # General device management entities
        $actualAssignmentsUri = "$GraphEndpoint/beta/deviceManagement/$EntityType('$EntityId')/assignments"
    }

    if (-not $actualAssignmentsUri) {
        # This case should ideally be covered by the logic above, but as a fallback:
        Write-Warning "Could not determine a valid assignments URI for EntityType '$EntityType' and EntityId '$EntityId'."
        return [System.Collections.ArrayList]::new() # Return empty ArrayList
    }

    $assignmentsToReturn = [System.Collections.ArrayList]::new()
    try {
        $allAssignmentsForEntity = [System.Collections.ArrayList]::new()
        $currentAssignmentsPageUri = $actualAssignmentsUri
        do {
            $pagedAssignmentResponse = Invoke-MgGraphRequest -Uri $currentAssignmentsPageUri -Method Get
            if ($pagedAssignmentResponse -and $null -ne $pagedAssignmentResponse.value) {
                $allAssignmentsForEntity.AddRange($pagedAssignmentResponse.value)
            }
            $currentAssignmentsPageUri = $pagedAssignmentResponse.'@odata.nextLink'
        } while (![string]::IsNullOrEmpty($currentAssignmentsPageUri))

        # Ensure $allAssignmentsForEntity is not null before trying to iterate
        $assignmentList = if ($allAssignmentsForEntity) { $allAssignmentsForEntity } else { @() }

        foreach ($assignment in $assignmentList) {
            $currentAssignmentReason = $null
            $currentTargetGroupId = $null # Initialize to null

            if ($assignment.target -and $assignment.target.'@odata.type') {
                $odataType = $assignment.target.'@odata.type'
                
                if ($odataType -eq '#microsoft.graph.groupAssignmentTarget') {
                    $currentTargetGroupId = $assignment.target.groupId
                    if ($GroupId) {
                        # Specific group check requested
                        if ($currentTargetGroupId -eq $GroupId) {
                            $currentAssignmentReason = "Direct Assignment"
                        }
                    }
                    else {
                        # No specific group, list all group assignments
                        $currentAssignmentReason = "Group Assignment"
                    }
                }
                elseif ($odataType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    $currentTargetGroupId = $assignment.target.groupId
                    if ($GroupId) {
                        # Specific group check requested
                        if ($currentTargetGroupId -eq $GroupId) {
                            $currentAssignmentReason = "Direct Exclusion"
                        }
                    }
                    else {
                        # No specific group, list all group exclusions
                        $currentAssignmentReason = "Group Exclusion"
                    }
                }
                elseif (-not $GroupId) {
                    # Only consider non-group assignments if NOT querying for a specific group
                    $currentAssignmentReason = switch ($odataType) {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        default { $null }
                    }
                }
            }
            else {
                Write-Warning "Assignment item for EntityId '$EntityId' (URI: $actualAssignmentsUri) is missing 'target' or 'target.@odata.type' property. Assignment data: $($assignment | ConvertTo-Json -Depth 3)"
            }
            
            if ($currentAssignmentReason) {
                $null = $assignmentsToReturn.Add(@{
                        Reason  = $currentAssignmentReason
                        GroupId = $currentTargetGroupId
                        Apps    = $null # 'Apps' property is not directly available from general assignments endpoint
                    })
            }
        }
    }
    catch {
        Write-Warning "Error fetching assignments from '$actualAssignmentsUri': $($_.Exception.Message)"
    }
    
    return $assignmentsToReturn
}

function Get-IntuneEntities {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Select = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Expand = ""
    )

    # Handle special cases for app management and specific deviceManagement endpoints
    if ($EntityType -like "deviceAppManagement/*" -or $EntityType -eq "deviceManagement/templates" -or $EntityType -eq "deviceManagement/intents") {
        $baseUri = "$GraphEndpoint/beta"
        $actualEntityType = $EntityType
    }
    else {
        $baseUri = "$GraphEndpoint/beta/deviceManagement"
        $actualEntityType = "$EntityType"
    }
    
    $currentUri = "$baseUri/$actualEntityType"
    if ($Filter) { $currentUri += "?`$filter=$Filter" }
    if ($Select) { $currentUri += $(if ($Filter) { "&" }else { "?" }) + "`$select=$Select" }
    if ($Expand) { $currentUri += $(if ($Filter -or $Select) { "&" }else { "?" }) + "`$expand=$Expand" }

    $entities = [System.Collections.ArrayList]::new() # Initialize as ArrayList

    do {
        try {
            $response = Invoke-MgGraphRequest -Uri $currentUri -Method Get -ErrorAction Stop
            if ($null -ne $response -and $null -ne $response.value) {
                if ($response.value -is [array]) {
                    $entities.AddRange($response.value)
                }
                else {
                    $entities.Add($response.value)
                }
            }
            $currentUri = $response.'@odata.nextLink'
        }
        catch {
            Write-Warning "Error fetching entities for $EntityType from $currentUri : $($_.Exception.Message)"
            $currentUri = $null # Stop pagination on error
        }
    } while ($currentUri)

    return $entities
}

function Get-PolicyPlatform {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Policy
    )

    # Get the platform based on the @odata.type
    $odataType = $Policy.'@odata.type'

    if ($null -eq $odataType) {
        return "Unknown"
    }

    switch -Regex ($odataType) {
        "android" {
            if ($odataType -like "*WorkProfile*") {
                return "Android Work Profile"
            }
            elseif ($odataType -like "*DeviceOwner*") {
                return "Android Enterprise"
            }
            else {
                return "Android"
            }
        }
        "ios|iPad|iPhone" {
            if ($odataType -like "*macOS*") {
                return "macOS"
            }
            else {
                return "iOS/iPadOS"
            }
        }
        "windows" {
            if ($odataType -like "*windows10*" -or $odataType -like "*windows81*") {
                return "Windows"
            }
            elseif ($odataType -like "*windowsPhone*") {
                return "Windows Phone"
            }
            else {
                return "Windows"
            }
        }
        "macOS|mac" {
            return "macOS"
        }
        "aosp" {
            return "Android (AOSP)"
        }
        default {
            # For Settings Catalog and other generic types, try to determine from other properties
            if ($Policy.platforms) {
                return $Policy.platforms -join ", "
            }
            elseif ($Policy.technologies) {
                # Settings catalog might have technologies property
                return "Settings Catalog"
            }
            else {
                return "Multi-Platform"
            }
        }
    }
}

function Get-FailureRate {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Object
    )

    if ($Object.TotalCount -eq 0) {
        return 0
    }

    return [math]::Round(($Object.FailedCount / $Object.TotalCount) * 100, 2)
}

function Get-GroupInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    try {
        $groupUri = "$GraphEndpoint/v1.0/groups/$GroupId"
        $group = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        return @{
            Id          = $group.id
            DisplayName = $group.displayName
            Success     = $true
        }
    }
    catch {
        return @{
            Id          = $GroupId
            DisplayName = "Unknown Group"
            Success     = $false
        }
    }
}

function Get-DeviceInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    $deviceUri = "$GraphEndpoint/v1.0/devices?`$filter=displayName eq '$DeviceName'"
    $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get
    
    if ($deviceResponse.value) {
        return @{
            Id          = $deviceResponse.value[0].id
            DisplayName = $deviceResponse.value[0].displayName
            Success     = $true
        }
    }
    
    return @{
        Id          = $null
        DisplayName = $DeviceName
        Success     = $false
    }
}

function Get-UserInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        $userUri = "$GraphEndpoint/v1.0/users/$UserPrincipalName"
        $user = Invoke-MgGraphRequest -Uri $userUri -Method Get
        return @{
            Id                = $user.id
            UserPrincipalName = $user.userPrincipalName
            Success           = $true
        }
    }
    catch {
        return @{
            Id                = $null
            UserPrincipalName = $UserPrincipalName
            Success           = $false
        }
    }
}

function Get-GroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Device")]
        [string]$ObjectType
    )

    $uri = "$GraphEndpoint/v1.0/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf?`$select=id,displayName"
    $response = Invoke-MgGraphRequest -Uri $uri -Method Get
    
    return $response.value
}

function Process-MultipleAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$Assignments,

        [Parameter(Mandatory = $false)]
        [string]$TargetGroupId = $null
    )

    $processedAssignments = [System.Collections.ArrayList]::new()

    foreach ($assignment in $Assignments) {
        $assignmentInfo = @{
            Reason    = $assignment.Reason
            GroupId   = $assignment.GroupId
            GroupName = $null
        }

        # Get group name for both assignments and exclusions
        if ($assignment.GroupId) {
            $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
            if ($groupInfo.Success) {
                $assignmentInfo.GroupName = $groupInfo.DisplayName
            }
        }

        # If we're checking for a specific group
        if ($TargetGroupId) {
            if ($assignment.GroupId -eq $TargetGroupId) {
                $null = $processedAssignments.Add($assignmentInfo)
            }
        }
        else {
            $null = $processedAssignments.Add($assignmentInfo)
        }
    }

    return $processedAssignments
}

function Get-AssignmentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]$Assignments
    )

    if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
        return @{
            Type   = "None"
            Target = "Not Assigned"
        }
    }

    $assignment = $Assignments[0]  # Take the first assignment
    $type = switch ($assignment.Reason) {
        "All Users" { "All Users"; break }
        "All Devices" { "All Devices"; break }
        "Group Assignment" { "Group"; break }
        default { "None" }
    }

    $target = switch ($type) {
        "All Users" { "All Users" }
        "All Devices" { "All Devices" }
        "Group" {
            if ($assignment.GroupId) {
                $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                $groupInfo.DisplayName
            }
            else {
                "Unknown Group"
            }
        }
        default { "Not Assigned" }
    }

    return @{
        Type   = $type
        Target = $target
    }
}

function Get-AssignmentFailures {
    Write-Host "Fetching assignment failures..." -ForegroundColor Green
    
    $failedAssignments = [System.Collections.ArrayList]::new()
    $headers = @{
        'Authorization' = "Bearer $($global:graphApiToken)"
        'Content-Type'  = 'application/json'
    }
    
    # 1. Get App Install Failures
    # Note: App installation status endpoint requires specific permissions and may not be available in all environments
    <# Temporarily disabled due to endpoint availability
    Write-Host "Checking app installation failures..." -ForegroundColor Yellow
    try {
        $reportBody = @{
            filter = ""
            select = @(
                "DeviceName", "UserPrincipalName", "Platform", "AppVersion",
                "InstallState", "InstallStateDetail", "ErrorCode", "HexErrorCode",
                "ApplicationId", "AppInstallState", "AppInstallStateDetails",
                "LastModifiedDateTime", "DeviceId", "UserId", "UserName"
            )
            skip = 0
            top = 50
        } | ConvertTo-Json
        
        $allAppFailures = @()
        $skip = 0
        
        do {
            $reportBody = @{
                filter = ""
                select = @(
                    "DeviceName", "UserPrincipalName", "Platform", "AppVersion",
                    "InstallState", "InstallStateDetail", "ErrorCode", "HexErrorCode",
                    "ApplicationId", "AppInstallState", "AppInstallStateDetails",
                    "LastModifiedDateTime", "DeviceId", "UserId", "UserName"
                )
                skip = $skip
                top = 50
            } | ConvertTo-Json
            
            $uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getMobileApplicationManagementAppStatusReport"
            $response = try {
                Invoke-MgGraphRequest -Uri $uri -Method POST -Body $reportBody
            } catch {
                # If the new endpoint fails, try the alternative endpoint
                $uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getAppStatusOverviewReport"
                Invoke-MgGraphRequest -Uri $uri -Method POST -Body $reportBody
            }
            
            if ($response.values) {
                $appFailures = $response.values | Where-Object {
                    $_[6] -ne 0 -or  # ErrorCode
                    $_[4] -eq "failed" -or  # InstallState
                    $_[9] -eq "failed"  # AppInstallState
                }
                
                foreach ($failure in $appFailures) {
                    $allAppFailures += [PSCustomObject]@{
                        Type = "App"
                        PolicyName = "Application ID: $($failure[8])"  # ApplicationId
                        Target = if ($failure[1]) { "User: $($failure[1])" } else { "Device: $($failure[0])" }
                        ErrorCode = if ($failure[7]) { "Error: 0x$($failure[7])" } else { "Error: $($failure[6])" }  # HexErrorCode or ErrorCode
                        ErrorDescription = if ($failure[5] -and $failure[10]) { "$($failure[5]) - $($failure[10])" } elseif ($failure[5]) { $failure[5] } elseif ($failure[10]) { $failure[10] } else { "Installation failed" }
                        LastAttempt = $failure[11]  # LastModifiedDateTime
                    }
                }
                $skip += 50
            }
        } while ($response.values -and $response.values.Count -eq 50)
        
        Write-Host "Found $($allAppFailures.Count) app installation failures" -ForegroundColor Green
        $failedAssignments.AddRange($allAppFailures)
    }
    catch {
        Write-Host "Error fetching app installation failures: $($_.Exception.Message)" -ForegroundColor Red
    }
    #>
    
    # 2. Get Device Configuration Policy Failures
    Write-Host "Checking device configuration policy failures..." -ForegroundColor Yellow
    try {
        $configPoliciesUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
        $configPolicies = (Invoke-MgGraphRequest -Uri $configPoliciesUri -Method GET).value
        
        foreach ($policy in $configPolicies) {
            $statusUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$($policy.id)')/deviceStatuses"
            $statuses = (Invoke-MgGraphRequest -Uri $statusUri -Method GET).value
            
            $failures = $statuses | Where-Object { 
                $_.status -in @("error", "conflict", "notApplicable") -or
                $_.complianceGracePeriodExpirationDateTime -and 
                [DateTime]$_.complianceGracePeriodExpirationDateTime -lt [DateTime]::Now
            }
            
            foreach ($failure in $failures) {
                $null = $failedAssignments.Add([PSCustomObject]@{
                        Type             = "Device Configuration"
                        PolicyName       = $policy.displayName
                        Target           = "Device: $($failure.deviceDisplayName)"
                        ErrorCode        = "$($failure.status)"
                        ErrorDescription = if ($failure.userPrincipalName) { "$($failure.userPrincipalName)" } else { "No additional details" }
                        LastAttempt      = $failure.lastReportedDateTime
                    })
            }
        }
    }
    catch {
        Write-Host "Error fetching device configuration failures: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # 3. Get Compliance Policy Failures
    Write-Host "Checking compliance policy failures..." -ForegroundColor Yellow
    try {
        $compliancePoliciesUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $compliancePolicies = (Invoke-MgGraphRequest -Uri $compliancePoliciesUri -Method GET).value
        
        foreach ($policy in $compliancePolicies) {
            $statusUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($policy.id)')/deviceStatuses"
            $statuses = (Invoke-MgGraphRequest -Uri $statusUri -Method GET).value
            
            $failures = $statuses | Where-Object { 
                $_.status -in @("error", "conflict", "notApplicable", "nonCompliant")
            }
            
            foreach ($failure in $failures) {
                $null = $failedAssignments.Add([PSCustomObject]@{
                        Type             = "Compliance Policy"
                        PolicyName       = $policy.displayName
                        Target           = "Device: $($failure.deviceDisplayName)"
                        ErrorCode        = "$($failure.status)"
                        ErrorDescription = if ($failure.userPrincipalName) { "$($failure.userPrincipalName)" } else { "No additional details" }
                        LastAttempt      = $failure.lastReportedDateTime
                    })
            }
        }
    }
    catch {
        Write-Host "Error fetching compliance policy failures: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $failedAssignments
}

# New deployment metrics functions
function Get-AppsInstallSummaryReport {
    param (
        [string]$Search = ""
    )

    $body = @{
        search = $Search
    } | ConvertTo-Json
    
    try {
        $response = Invoke-MgGraphRequest -Uri "beta/deviceManagement/reports/microsoft.graph.getAppsInstallSummaryReport" `
            -Method "POST" `
            -ContentType "application/json" `
            -Body $body `
            -OutputType HttpResponseMessage `
            -ErrorAction Stop

        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $parsed = $content | ConvertFrom-Json
                
        if ($parsed -and $parsed.Values) {
            $schema = $parsed.Schema
            $rows = $parsed.Values
            $results = @()
                    
            # Convert rows to objects
            foreach ($row in $rows) {
                $props = @{}
                for ($i = 0; $i -lt $schema.Count; $i++) {
                    $columnName = $schema[$i].Column
                    $value = $row[$i]
                    $props[$columnName] = $value
                }
                        
                # Calculate total devices and success rate for apps
                $installed = [int64]$props.InstalledDeviceCount
                $failed = [int64]$props.FailedDeviceCount
                $pending = [int64]$props.PendingInstallDeviceCount
                $notInstalled = [int64]$props.NotInstalledDeviceCount
                $notApplicable = [int64]$props.NotApplicableDeviceCount
                
                # Total devices that received the app (excluding NotApplicable)
                $totalTargeted = $installed + $failed + $pending + $notInstalled
                
                $props.TotalCount = $totalTargeted
                $props.InstalledCount = $installed
                $props.FailedCount = $failed
                $props.PendingCount = $pending
                $props.SuccessRate = if ($totalTargeted -gt 0) {
                    [Math]::Round(($installed / $totalTargeted) * 100, 2)
                } else { 0 }
                        
                $results += [PSCustomObject]$props
            }
            
            return $results
        } else {
            Write-Warning "No data returned from app install summary report"
            return $null
        }
    } catch {
        Write-Warning "Error returning app install summary report for Search: $Search - $($_.Exception.Message)"
        return $null
    }
}

function Get-CompliancePolicyDeviceSummaryReport {
    param(
        [string]$CompliancePolicyId,
        [string]$CompliancePolicyName,
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$Platform = 'All',
        [string]$ExportPath,
        [switch]$IncludeAllPolicies
    )
    
    try {
        $objectsToProcess = @()
        
        # Get all objects if requested
        if ($IncludeAllPolicies) {
            Write-Verbose "Retrieving all compliance objects"
            $uri = "/beta/deviceManagement/deviceCompliancePolicies"
            $allPoliciesResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
            $objectsToProcess = $allPoliciesResponse.value | ForEach-Object {
                @{
                    Id = $_.id
                    Name = $_.displayName
                    Platform = $_.'@odata.type' -replace '.*\.', ''
                }
            }
        }
        # Resolve object ID if name is provided
        elseif ($CompliancePolicyName) {
            Write-Verbose "Resolving object ID for object name: $CompliancePolicyName"
            $uri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$CompliancePolicyName'"
            $objectResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
            
            if ($objectResponse.value.Count -eq 0) {
                throw "No compliance object found with name: $CompliancePolicyName"
            }
            elseif ($objectResponse.value.Count -gt 1) {
                throw "Multiple compliance objects found with name: $CompliancePolicyName. Please use CompliancePolicyId parameter instead."
            }
            
            $object = $objectResponse.value[0]
            $objectsToProcess = @(@{
                Id = $object.id
                Name = $object.displayName
                Platform = $object.'@odata.type' -replace '.*\.', ''
            })
        }
        # Use provided object ID
        elseif ($CompliancePolicyId) {
            # Get object details
            $uri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies('$CompliancePolicyId')"
            try {
                $object = Invoke-MgGraphRequest -Method GET -Uri $uri
                $objectsToProcess = @(@{
                    Id = $object.id
                    Name = $object.displayName
                    Platform = $object.'@odata.type' -replace '.*\.', ''
                })
            }
            catch {
                Write-Warning "Could not retrieve object details for ID: $CompliancePolicyId. Will proceed with report."
                $objectsToProcess = @(@{
                    Id = $CompliancePolicyId
                    Name = "Unknown Object"
                    Platform = "Unknown"
                })
            }
        }
        else {
            throw "Please specify either CompliancePolicyId, CompliancePolicyName, or use -IncludeAllPolicies"
        }
        
        # Build platform filter
        $platformFilter = switch ($Platform) {
            'Windows' { "((OS eq 'Windows') or (OS eq 'Windows10x') or (OS eq 'WindowsMobile') or (OS eq 'WindowsHolographic'))" }
            'iOS' { "(OS eq 'iOS')" }
            'Android' { "((OS eq 'Android') or (OS eq 'AndroidEnterprise') or (OS eq 'AndroidWork'))" }
            'macOS' { "(OS eq 'macOS')" }
            'All' { $null }
        }
        
        $allResults = @()
        
        foreach ($objectInfo in $objectsToProcess) {
            Write-Verbose "Processing object: $($objectInfo.Name) ($($objectInfo.Id))"
            
            # Build filter
            $filters = @("(PolicyId eq '$($objectInfo.Id)')")
            if ($platformFilter) {
                $filters += $platformFilter
            }
            $filter = $filters -join ' and '
            
            # Prepare request parameters
            $params = @{
                filter = $filter
                skip = 0
                top = 50
                select = @()
                orderBy = @()
                search = ""
            }
            
            $body = $params | ConvertTo-Json -Depth 10
            
            # Note: The Microsoft URI uses "Compliace" (not "Compliance")—this is intentionally matching Microsoft's official endpoint spelling.
            $response = Invoke-MgGraphRequest -Method POST `
                -Uri "$GraphEndpoint/beta/deviceManagement/reports/microsoft.graph.getDeviceStatusSummaryByCompliacePolicyReport" `
                -Body $body `
                -OutputType HttpResponseMessage
            
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $parsed = $content | ConvertFrom-Json
            
            if ($parsed -and $parsed.Values) {
                $schema = $parsed.Schema
                $rows = $parsed.Values
                
                # Convert rows to CompliancePolicy objects
                foreach ($row in $rows) {
                    $props = @{
                        CompliancePolicyName = $objectInfo.Name
                    }
                    for ($i = 0; $i -lt $schema.Count; $i++) {
                        $columnName = $schema[$i].Column
                        $value = $row[$i]
                        $props[$columnName] = $value
                    }
                    
                    # Calculate total devices and compliance rate
                    $compliant = [int64]$props.NumberOfCompliantDevices
                    $nonCompliant = [int64]$props.NumberOfNonCompliantDevices
                    $other = [int64]$props.NumberOfOtherDevices
                    $total = $compliant + $nonCompliant + $other
                    
                    $props.TotalDevices = $total
                    $props.ComplianceRate = if ($total -gt 0) {
                        [Math]::Round(($compliant / $total) * 100, 2)
                    } else { 0 }
                    
                    $allResults += [PSCustomObject]$props
                }
            }
        }
        
        return $allResults
    }
    catch {
        Write-Error "Failed to generate compliance report: $_"
        return $null
    }
}

function Get-ConfigurationPolicyDeviceSummaryReport {
    [CmdletBinding()]
    param(
        [string]$ConfigurationPolicyId,
        [string]$ConfigurationPolicyName,
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$Platform = 'All',
        [string]$ExportPath,
        [switch]$IncludeAllPolicies
    )
    
    try {
        $ConfigurationPoliciesToProcess = @()

        # Get all objects if requested
        if ($IncludeAllPolicies) {
            Write-Host "`nPlease wait while retrieving all configuration policies..." -ForegroundColor Yellow
            $allPolicies = @()
            
            # Get Device Configurations using Get-IntuneEntities
            Write-Verbose "Fetching device configurations"
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            Write-Verbose "Found $($deviceConfigs.Count) device configurations"
            foreach ($config in $deviceConfigs) {
                $allPolicies += @{
                    Id = $config.id
                    Name = $config.displayName
                    Type = "DeviceConfiguration"
                    Platform = switch -Regex ($config.'@odata.type' -replace '.*\.', '') {
                        'windows' { 'Windows' }
                        'macOS' { 'macOS' }
                        'ios' { 'iOS' }
                        'android' { 'Android' }
                        default { 'Unknown' }
                    }
                }
            }
            
            # Get Settings Catalog policies using Get-IntuneEntities
            Write-Verbose "Fetching settings catalog policies"
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            Write-Verbose "Found $($settingsCatalog.Count) settings catalog policies"
            foreach ($policy in $settingsCatalog) {
                $allPolicies += @{
                    Id = $policy.id
                    Name = $policy.name
                    Type = "SettingsCatalog"
                    Platform = switch -Regex ($policy.platforms) {
                        'windows' { 'Windows' }
                        'macOS' { 'macOS' }
                        'iOS' { 'iOS' }
                        'android' { 'Android' }
                        default { 'Unknown' }
                    }
                }
            }
            
            $ConfigurationPoliciesToProcess = $allPolicies
            Write-Verbose "Total policies to process: $($ConfigurationPoliciesToProcess.Count)"
        }
        # Resolve ConfigurationPolicy ID if name is provided
        elseif ($ConfigurationPolicyName) {
            Write-Verbose "Resolving ID for ConfigurationPolicy: $ConfigurationPolicyName"
            $ConfigurationPolicy = $null
            $policyType = $null
            # Try device configurations first
            Write-Verbose "Searching device configurations for: $ConfigurationPolicyName"
            $ConfigurationPolicy = @(Get-IntuneEntities -EntityType "deviceConfigurations" -Filter "displayName eq '$ConfigurationPolicyName'")
            Write-Verbose "Device configurations found: $($ConfigurationPolicy.Count)"
            $policyType = "DeviceConfiguration"
            if ($ConfigurationPolicy.Count -eq 0) {
                # Try settings catalog
                Write-Verbose "Searching settings catalog for: $ConfigurationPolicyName"
                $ConfigurationPolicy = @(Get-IntuneEntities -EntityType "configurationPolicies" -Filter "name eq '$ConfigurationPolicyName'")
                Write-Verbose "Settings catalog policies found: $($ConfigurationPolicy.Count)"
                $policyType = "SettingsCatalog"
            } elseif ($ConfigurationPolicy.Count -gt 1) {
                throw "Multiple configuration policies found with name: $ConfigurationPolicyName. Please use ConfigurationPolicyId parameter instead."
            }
            
            if ($null -eq $ConfigurationPolicy) {
                throw "No configuration policy found with name: $ConfigurationPolicyName"
            }
            
            Write-Verbose "Found policy: $($ConfigurationPolicy.displayName ?? $ConfigurationPolicy.name) (ID: $($ConfigurationPolicy.id))"
            $ConfigurationPoliciesToProcess = @(@{
                Id = $ConfigurationPolicy.id
                Name = $ConfigurationPolicy.displayName ?? $ConfigurationPolicy.name
                Type = $policyType
                Platform = if ($policyType -eq 'SettingsCatalog') {
                    switch -Regex ($ConfigurationPolicy.platforms) {
                        'windows' { 'Windows' }
                        'macOS' { 'macOS' }
                        'iOS' { 'iOS' }
                        'android' { 'Android' }
                        default { 'Unknown' }
                    }
                } else {
                    switch -Regex ($ConfigurationPolicy.'@odata.type' -replace '.*\.', '') {
                        'windows' { 'Windows' }
                        'macOS' { 'macOS' }
                        'ios' { 'iOS' }
                        'android' { 'Android' }
                        default { 'Unknown' }
                    }
                }
            })
            Write-Verbose "Policy type: $($ConfigurationPoliciesToProcess.Type), Platform: $($ConfigurationPoliciesToProcess.Platform)"
        }elseif ($ConfigurationPolicyId) {
            Write-Verbose "Looking up configuration policy by ID: $ConfigurationPolicyId"
            # Try to get ConfigurationPolicy details
            $ConfigurationPolicy = $null
            try {
                $uri = "$GraphEndpoint/beta/deviceManagement/deviceConfigurations('$ConfigurationPolicyId')"
                Write-Verbose "Trying device configuration endpoint: $uri"
                $ConfigurationPolicy = Invoke-MgGraphRequest -Method GET -Uri $uri
                $type = "DeviceConfiguration"
                Write-Verbose "Found as device configuration"
            } catch {
                Write-Verbose "Not found in device configurations, trying settings catalog"
                # Try settings catalog
                try {
                    $uri = "$GraphEndpoint/beta/deviceManagement/configurationPolicies('$ConfigurationPolicyId')"
                    Write-Verbose "Trying settings catalog endpoint: $uri"
                    $ConfigurationPolicy = Invoke-MgGraphRequest -Method GET -Uri $uri
                    $type = "SettingsCatalog"
                    Write-Verbose "Found as settings catalog policy"
                } catch {
                    Write-Verbose "Policy not found in either location"
                    throw "Configuration policy not found with ID: $ConfigurationPolicyId"
                }
            }
            
            $ConfigurationPoliciesToProcess = @(@{
                Id = $ConfigurationPolicy.id
                Name = $ConfigurationPolicy.displayName ?? $ConfigurationPolicy.name
                Type = $type
                Platform = if ($type -eq 'SettingsCatalog') {
                    switch -Regex ($ConfigurationPolicy.platforms) {
                        'windows' { 'Windows' }
                        'macOS' { 'macOS' }
                        'iOS' { 'iOS' }
                        'android' { 'Android' }
                        default { 'Unknown' }
                    }
                } else {
                    $ConfigurationPolicy.'@odata.type' -replace '.*\.', ''
                }
            })
        }else {
            throw "Please specify either ConfigurationPolicyId, ConfigurationPolicyName, or use -IncludeAllPolicies"
        }
        
        # Filter by platform if specified
        if ($Platform -ne 'All') {
            Write-Verbose "Filtering policies by platform: $Platform"
            $beforeCount = $ConfigurationPoliciesToProcess.Count
            $ConfigurationPoliciesToProcess = $ConfigurationPoliciesToProcess | Where-Object {
                $_.Platform -match $Platform
            }
            Write-Verbose "Policies after platform filter: $($ConfigurationPoliciesToProcess.Count) (filtered out $($beforeCount - $ConfigurationPoliciesToProcess.Count))"
        }
        
        if ($ConfigurationPoliciesToProcess.Count -eq 0) {
            Write-Warning "No configuration policies found for the specified criteria"
            Write-Verbose "Exiting function - no policies to process"
            return $null
        }
        
        Write-Verbose "Starting to process $($ConfigurationPoliciesToProcess.Count) configuration policies"
        
        $allResults = @()
        
        foreach ($ConfigurationPolicyInfo in $ConfigurationPoliciesToProcess) {
            Write-Verbose "Processing policy: $($ConfigurationPolicyInfo.Name) ($($ConfigurationPolicyInfo.Id))"
            
            # Build filter based on ConfigurationPolicy type
            $policyFilter = if ($ConfigurationPolicyInfo.Type -eq 'SettingsCatalog') {
                "(PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy')"
            } else {
                "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy'))"
            }
            Write-Verbose "Using policy filter: $policyFilter"
            
            # Prepare request parameters
            $params = @{
                filter = "($policyFilter) and (PolicyId eq '$($ConfigurationPolicyInfo.Id)')"
                skip = 0
                top = 50
                select = @()
                orderBy = @()
                search = ""
            }
            Write-Verbose "Request filter: $($params.filter)"
            
            $body = $params | ConvertTo-Json -Depth 10
            Write-Verbose "Request body: $body"
            
            try {
                $uri = "$GraphEndpoint/beta/deviceManagement/reports/getConfigurationPolicyDeviceSummaryReport"
                Write-Verbose "Calling API: $uri"
                $response = Invoke-MgGraphRequest -Method POST `
                    -Uri $uri `
                    -Body $body `
                    -ContentType "application/json" `
                    -OutputType HttpResponseMessage
                
                if ($null -eq $response) {
                    Write-Warning "No response received from API for policy: $($ConfigurationPolicyInfo.Name)"
                    Write-Verbose "Response was null"
                    continue
                }
                
                $responseContent = $response.Content.ReadAsStringAsync().Result
                Write-Verbose "Response content length: $($responseContent.Length) characters"
                $parsed = $responseContent | ConvertFrom-Json -Depth 10
                
                if ($parsed -and $parsed.Values) {
                    $schema = $parsed.Schema
                    $rows = $parsed.Values
                    Write-Verbose "Retrieved $($rows.Count) rows for policy $($ConfigurationPolicyInfo.Name)"
                    Write-Verbose "Schema columns: $($schema.Column -join ', ')"
                    
                    # Convert rows to ConfigurationPolicys
                    foreach ($row in $rows) {
                        $props = @{
                            ConfigurationPolicyName = $ConfigurationPolicyInfo.Name
                            ConfigurationPolicyType = $ConfigurationPolicyInfo.Type
                        }
                        for ($i = 0; $i -lt $schema.Count; $i++) {
                            $columnName = $schema[$i].Column
                            $value = $row[$i]
                            $props[$columnName] = $value
                        }
                        
                        # Calculate total devices and success rate
                        $success = [int64]($props.NumberOfCompliantDevices ?? 0)
                        $errorCount = [int64]($props.NumberOfErrorDevices ?? 0)
                        $conflict = [int64]($props.NumberOfConflictDevices ?? 0)
                        $notApplicable = [int64]($props.NumberOfNotApplicableDevices ?? 0)
                        $pending = [int64]($props.NumberOfInProgressDevices ?? 0)
                        $nonCompliant = [int64]($props.NumberOfNonCompliantDevices ?? 0)
                        
                        Write-Verbose "Device counts - Compliant: $success, NonCompliant: $nonCompliant, Error: $errorCount, Conflict: $conflict, NotApplicable: $notApplicable, InProgress: $pending"
                        
                        $total = $success + $nonCompliant + $errorCount + $conflict + $pending
                        
                        $props.TotalDevices = $total
                        $props.SuccessRate = if ($total -gt 0) {
                            [Math]::Round(($success / $total) * 100, 2)
                        } else { 0 }
                        
                        # Add friendly names for counts
                        $props.CompliantCount = $success
                        $props.NonCompliantCount = $nonCompliant
                        $props.ErrorCount = $errorCount
                        $props.ConflictCount = $conflict
                        $props.InProgressCount = $pending
                        
                        $allResults += [PSCustomObject]$props
                    }
                    Write-Verbose "Processed $($rows.Count) rows for policy $($ConfigurationPolicyInfo.Name)"
                }
                else {
                    Write-Verbose "No data returned for policy $($ConfigurationPolicyInfo.Name)"
                }
            } catch {
                Write-Warning "Failed to get summary for policy $($ConfigurationPolicyInfo.Name): $_"
            }
        }
        
        Write-Verbose "Completed processing all policies. Total results: $($allResults.Count)"
        return $allResults
    } catch {
        Write-Error "Failed to generate configuration policy summary report: $_"
        Write-Verbose "Exception details: $($_.Exception.Message)"
        Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
        return $null
    }
}

# Failure Report Functions (60% failure threshold)
function Get-AppInstallFailuresReport {
    param (
        [string]$Search = "",
        [decimal]$FailureThreshold = 60
    )
    
    Write-Verbose "Getting app install failures with threshold: $FailureThreshold%"
    
    # Get all app install summaries
    $allApps = Get-AppsInstallSummaryReport -Search $Search
    
    if ($null -eq $allApps -or $allApps.Count -eq 0) {
        Write-Verbose "No apps found"
        return @()
    }
    
    # Filter apps with failure rate >= threshold
    # Only consider apps that have devices and calculate failure rate based on FailedCount
    $failedApps = $allApps | Where-Object {
        # Skip apps with no devices
        if ($_.TotalCount -eq 0) {
            return $false
        }
        
        # Calculate failure rate as: (FailedCount / TotalCount) * 100
        $failureRate = Get-FailureRate $_
        
        $failureRate -ge $FailureThreshold
    } | ForEach-Object {
        # Add failure rate for easier display based on FailedCount
        $failureRate = Get-FailureRate $_
        $_ | Add-Member -MemberType NoteProperty -Name "FailureRate" -Value $failureRate -Force
        $_
    } | Sort-Object -Property FailureRate -Descending
    
    Write-Verbose "Found $($failedApps.Count) apps with failure rate >= $FailureThreshold%"
    return $failedApps
}

function Get-CompliancePolicyFailuresReport {
    param(
        [string]$CompliancePolicyName,
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$Platform = 'All',
        [switch]$IncludeAllObjects,
        [decimal]$FailureThreshold = 60
    )
    
    Write-Verbose "Getting compliance policy failures with threshold: $FailureThreshold%"
    
    # Get compliance summary based on parameters
    $params = @{}
    if ($CompliancePolicyName) { 
        $params.CompliancePolicyName = $CompliancePolicyName 
    } else {
        # If no specific policy name is provided, include all policies
        $params.IncludeAllPolicies = $true
    }
    if ($Platform -ne 'All') { $params.Platform = $Platform }
    
    $allPolicies = Get-CompliancePolicyDeviceSummaryReport @params
    
    if ($null -eq $allPolicies -or $allPolicies.Count -eq 0) {
        Write-Verbose "No compliance policies found"
        return @()
    }
    
    # Filter policies with non-compliance rate >= threshold
    $failedPolicies = $allPolicies | Where-Object {
        $nonComplianceRate = 100 - $_.ComplianceRate
        $nonComplianceRate -ge $FailureThreshold
    } | ForEach-Object {
        # Add non-compliance rate for easier display
        $_ | Add-Member -MemberType NoteProperty -Name "NonComplianceRate" -Value (100 - $_.ComplianceRate) -Force
        $_
    } | Sort-Object -Property NonComplianceRate -Descending
    
    Write-Verbose "Found $($failedPolicies.Count) policies with non-compliance rate >= $FailureThreshold%"
    return $failedPolicies
}

function Get-ConfigurationPolicyFailuresReport {
    param(
        [string]$ConfigurationPolicyName,
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$Platform = 'All',
        [switch]$IncludeAllPolicies,
        [decimal]$FailureThreshold = 60
    )
    
    Write-Verbose "Getting configuration policy failures with threshold: $FailureThreshold%"
    
    # Get configuration summary based on parameters
    $params = @{}
    if ($ConfigurationPolicyName) { $params.ConfigurationPolicyName = $ConfigurationPolicyName }
    if ($IncludeAllPolicies) { $params.IncludeAllPolicies = $true }
    if ($Platform -ne 'All') { $params.Platform = $Platform }
    
    $allPolicies = Get-ConfigurationPolicyDeviceSummaryReport @params
    
    if ($null -eq $allPolicies -or $allPolicies.Count -eq 0) {
        Write-Verbose "No configuration policies found"
        return @()
    }
    
    # Filter policies with failure rate >= threshold
    $failedPolicies = $allPolicies | Where-Object {
        $failureRate = 100 - $_.SuccessRate
        $failureRate -ge $FailureThreshold
    } | ForEach-Object {
        # Add failure rate for easier display
        $_ | Add-Member -MemberType NoteProperty -Name "FailureRate" -Value (100 - $_.SuccessRate) -Force
        $_
    } | Sort-Object -Property FailureRate -Descending
    
    Write-Verbose "Found $($failedPolicies.Count) policies with failure rate >= $FailureThreshold%"
    return $failedPolicies
}
function Show-SaveFileDialog {
    param (
        [string]$DefaultFileName
    )

    # If running on macOS, auto-save to a default temp directory
    if ($IsMacOS) {
        $reportDir = Join-Path -Path ([Environment]::GetFolderPath("UserProfile")) -ChildPath "Downloads/IntuneAssignmentChecker_Reports"
        if (-not (Test-Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir | Out-Null
        }
        $filePath = Join-Path -Path $reportDir -ChildPath $DefaultFileName
        Write-Host "Saving report to: $filePath" -ForegroundColor Yellow
        return $filePath
    }

    # If running PowerShell 7 or newer, use cross-platform Read-Host prompt first
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # Use the user’s Temp folder as default directory
        $defaultDir  = $env:TEMP
        $defaultPath = Join-Path -Path $defaultDir -ChildPath $DefaultFileName
        $prompt      = "Enter file path to save (default: $defaultPath)"
        $path        = Read-Host $prompt
        # If the user just presses Enter, return the temp-folder path
        if ([string]::IsNullOrWhiteSpace($path)) {
            return $defaultPath
        }
        return $path
    }

    # Fallback to Windows SaveFileDialog if on Windows
    if ($IsWindows) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $saveFileDialog.Filter   = "Excel files (*.xlsx)|*.xlsx|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            $saveFileDialog.FileName = $DefaultFileName
            $saveFileDialog.Title    = "Save Policy Report"
            if ($saveFileDialog.ShowDialog() -eq 'OK') {
                return $saveFileDialog.FileName
            }
        } catch {
            Write-Warning "Unable to show file dialog: $_"
        }
    }

    return $null
}


function Export-PolicyData {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$ExportData,
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    if ($extension -eq '.xlsx') {
        # Check if ImportExcel module is installed
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Host "The ImportExcel module is required for Excel export. Would you like to install it? (y/n)" -ForegroundColor Yellow
            $install = Read-Host
            if ($install -eq 'y') {
                try {
                    Install-Module -Name ImportExcel -Force -Scope CurrentUser
                    Write-Host "ImportExcel module installed successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to install ImportExcel module. Falling back to CSV export." -ForegroundColor Red
                    $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
                    $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
                    Write-Host "Results exported to $FilePath" -ForegroundColor Green
                    return
                }
            }
            else {
                Write-Host "Falling back to CSV export." -ForegroundColor Yellow
                $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
                $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
                Write-Host "Results exported to $FilePath" -ForegroundColor Green
                return
            }
        }

        try {
            $ExportData | Export-Excel -Path $FilePath -AutoSize -AutoFilter -WorksheetName "Intune Assignments" -TableName "IntuneAssignments"
            Write-Host "Results exported to $FilePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to export to Excel. Falling back to CSV export." -ForegroundColor Red
            $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
            $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
            Write-Host "Results exported to $FilePath" -ForegroundColor Green
        }
    }
    else {
        $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
        Write-Host "Results exported to $FilePath" -ForegroundColor Green
    }
}

function Add-ExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Items,
        [Parameter(Mandatory = $false)]
        [object]$AssignmentReason = "N/A"
    )
    
    foreach ($item in $Items) {
        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }
        
        # Handle different types of assignment reason input
        $reason = if ($AssignmentReason -is [scriptblock]) {
            & $AssignmentReason $item
        }
        elseif ($item.AssignmentReason) {
            $item.AssignmentReason
        }
        elseif ($item.AssignmentSummary) {
            $item.AssignmentSummary
        }
        else {
            $AssignmentReason
        }
        
        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$itemName (ID: $($item.id))"
                AssignmentReason = $reason
            })
    }
}

function Add-AppExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Apps,
        [string]$AssignmentReason = "N/A"
    )
    
    foreach ($app in $Apps) {
        $appName = if ($app.displayName) { $app.displayName } else { $app.name }
        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$appName (ID: $($app.id))"
                AssignmentReason = "$AssignmentReason - $($app.AssignmentIntent)"
            })
    }
}

function Show-Menu {    
    Write-Host "Assignment Checks:" -ForegroundColor Cyan
    Write-Host "  [1] Check User(s) Assignments" -ForegroundColor White
    Write-Host "  [2] Check Group(s) Assignments" -ForegroundColor White
    Write-Host "  [3] Check Device(s) Assignments" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Policy Overview:" -ForegroundColor Cyan
    Write-Host "  [4] Show All Policies and Their Assignments" -ForegroundColor White
    Write-Host "  [5] Show All 'All Users' Assignments" -ForegroundColor White
    Write-Host "  [6] Show All 'All Devices' Assignments" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Advanced Options:" -ForegroundColor Cyan
    Write-Host "  [7] Generate HTML Report" -ForegroundColor White
    Write-Host "  [8] Show Policies Without Assignments" -ForegroundColor White
    Write-Host "  [9] Check for Empty Groups in Assignments" -ForegroundColor White
    Write-Host "  [10] Compare Assignments Between Groups" -ForegroundColor White
    Write-Host "  [11] Show All Failed Assignments" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Deployment Metrics:" -ForegroundColor Cyan
    Write-Host "  [12] App Install Summary Report" -ForegroundColor White
    Write-Host "  [13] App Install Failures (>60% failure rate)" -ForegroundColor White
    Write-Host "  [14] Compliance Policy Deployment Summary" -ForegroundColor White
    Write-Host "  [15] Compliance Policy Failures (>60% non-compliance)" -ForegroundColor White
    Write-Host "  [16] Configuration Policy Deployment Summary" -ForegroundColor White
    Write-Host "  [17] Configuration Policy Failures (>60% failure rate)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "System:" -ForegroundColor Cyan
    Write-Host "  [0] Exit" -ForegroundColor White
    Write-Host "  [98] Support the Project 💝" -ForegroundColor Magenta
    Write-Host "  [99] Report a Bug or Request a Feature" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline
}

# Function to handle export
function Export-ResultsIfRequested {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$DefaultFileName,
        [switch]$ForceExport,
        [string]$CustomExportPath
    )
    
    if ($ForceExport -or $ExportToCSV) {
        $exportPath = if ($CustomExportPath) {
            $CustomExportPath
        }
        elseif ($IsMacOS) {
            # On macOS, use Downloads folder instead of file dialog
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $fileName = if ($DefaultFileName) { $DefaultFileName } else { "IntuneReport_$timestamp.csv" }
            $exportDir = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads/IntuneAssignmentChecker_Reports"
            if (-not (Test-Path $exportDir)) {
                New-Item -ItemType Directory -Path $exportDir | Out-Null
            }
            $fullPath = Join-Path $exportDir $fileName
            Write-Host "`nExporting to: $fullPath" -ForegroundColor Yellow
            $fullPath
        }
        else {
            Show-SaveFileDialog -DefaultFileName $DefaultFileName
        }
        
        if ($exportPath) {
            Export-PolicyData -ExportData $ExportData -FilePath $exportPath
        }
    }
    else {
        $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
        if ($export -eq 'y') {
            if ($IsMacOS) {
                # On macOS, use Downloads folder instead of file dialog
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $fileName = if ($DefaultFileName) { $DefaultFileName } else { "IntuneReport_$timestamp.csv" }
                $exportDir = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads/IntuneAssignmentChecker_Reports"
                if (-not (Test-Path $exportDir)) {
                    New-Item -ItemType Directory -Path $exportDir | Out-Null
                }
                $exportPath = Join-Path $exportDir $fileName
                Write-Host "`nExporting to: $exportPath" -ForegroundColor Yellow
            }
            else {
                $exportPath = Show-SaveFileDialog -DefaultFileName $DefaultFileName
            }
            
            if ($exportPath) {
                Export-PolicyData -ExportData $ExportData -FilePath $exportPath
            }
        }
    }
}

# Move this code to the beginning of the script, right after the param block

# Define valid menu options
$validMenuOptions = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '98', '99', '0')

# Main script logic
do {
    # Only show menu in interactive mode
    if (-not $parameterMode) {
        Show-Menu
        $selection = Read-Host
    }
    else {
        $selection = $selectedOption
    }

    switch ($selection) {
        '1' {
            Write-Host "User selection chosen" -ForegroundColor Green

            # Get User Principal Names from parameter or prompt
            if ($parameterMode -and $UserPrincipalNames) {
                $upnInput = $UserPrincipalNames
            }
            else {
                # Prompt for one or more User Principal Names
                Write-Host "Please enter User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
                $upnInput = Read-Host
            }
    
            # Validate input
            if ([string]::IsNullOrWhiteSpace($upnInput)) {
                Write-Host "No UPN provided. Please try again with a valid UPN." -ForegroundColor Red
                if ($parameterMode) { exit 1 } else { continue }
            }
    
            $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
            if ($upns.Count -eq 0) {
                Write-Host "No valid UPNs provided. Please try again with at least one valid UPN." -ForegroundColor Red
                if ($parameterMode) { exit 1 } else { continue }
            }

            $exportData = [System.Collections.ArrayList]::new()

            foreach ($upn in $upns) {
                Write-Host "Checking following UPN: $upn" -ForegroundColor Yellow

                # Get User Info
                $userInfo = Get-UserInfo -UserPrincipalName $upn
                if (-not $userInfo.Success) {
                    Write-Host "User not found: $upn" -ForegroundColor Red
                    Write-Host "Please verify the User Principal Name is correct." -ForegroundColor Yellow
                    continue
                }

                # Get User Group Memberships
                try {
                    $groupMemberships = Get-GroupMemberships -ObjectId $userInfo.Id -ObjectType "User"
                    Write-Host "User Group Memberships: $($groupMemberships.displayName -join ', ')" -ForegroundColor Green
                }
                catch {
                    Write-Host "Error fetching group memberships for user: $upn" -ForegroundColor Red
                    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
                    continue
                }

                Write-Host "Fetching Intune Profiles and Applications for the user ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections for relevant policies
                $relevantPolicies = @{
                    DeviceConfigs               = @()
                    SettingsCatalog             = @()
                    AdminTemplates              = @()
                    CompliancePolicies          = @()
                    AppProtectionPolicies       = @()
                    AppConfigurationPolicies    = @()
                    AppsRequired                = @()
                    AppsAvailable               = @()
                    AppsUninstall               = @()
                    PlatformScripts             = @()
                    HealthScripts               = @()
                    AntivirusProfiles           = @()
                    DiskEncryptionProfiles      = @()
                    FirewallProfiles            = @()
                    EndpointDetectionProfiles   = @()
                    AttackSurfaceProfiles       = @()
                    DeploymentProfiles          = @()
                    ESPProfiles                 = @()
                    CloudPCProvisioningPolicies = @()
                    CloudPCUserSettings         = @()
                }

                # Get Device Configurations
                Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
                $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
                foreach ($config in $deviceConfigs) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.DeviceConfigs += $config
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.DeviceConfigs += $config
                            break
                        }
                    }
                }

                # Get Settings Catalog Policies
                Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
                $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
                foreach ($policy in $settingsCatalog) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.SettingsCatalog += $policy
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.SettingsCatalog += $policy
                            break
                        }
                    }
                }

                # Get Administrative Templates
                Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
                $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
                foreach ($template in $adminTemplates) {
                    $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.AdminTemplates += $template
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.AdminTemplates += $template
                            break
                        }
                    }
                }

                # Get Compliance Policies
                Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
                $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
                foreach ($policy in $compliancePolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.CompliancePolicies += $policy
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.CompliancePolicies += $policy
                            break
                        }
                    }
                }

                # Get App Protection Policies
                Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
                $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
                foreach ($policy in $appProtectionPolicies) {
                    $policyType = $policy.'@odata.type'
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        try {
                            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                            $assignments = @()
                            foreach ($assignment in $assignmentResponse.value) {
                                $assignmentReason = $null
                                switch ($assignment.target.'@odata.type') {
                                    '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                                        $assignmentReason = "All Users"
                                    }
                                    '#microsoft.graph.groupAssignmentTarget' {
                                        if (!$GroupId -or $assignment.target.groupId -eq $GroupId) {
                                            $assignmentReason = "Group Assignment"
                                        }
                                    }
                                    '#microsoft.graph.exclusionGroupAssignmentTarget' {
                                        if (!$GroupId -or $assignment.target.groupId -eq $GroupId) {
                                            $assignmentReason = "Group Exclusion"
                                        }
                                    }
                                }

                                if ($assignmentReason) {
                                    $assignments += @{
                                        Reason  = $assignmentReason
                                        GroupId = $assignment.target.groupId
                                    }
                                }
                            }

                            if ($assignments.Count -gt 0) {
                                $assignmentSummary = $assignments | ForEach-Object {
                                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                        $color = if ($_.Reason -eq "Group Exclusion") { "Red" } else { "White" }
                                        "$($_.Reason) - $($groupInfo.DisplayName)"
                                    }
                                    else {
                                        $_.Reason
                                    }
                                }
                                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                                $relevantPolicies.AppProtectionPolicies += $policy
                            }
                        }
                        catch {
                            Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }

                # Get App Configuration Policies
                Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
                $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
                foreach ($policy in $appConfigPolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or 
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.AppConfigurationPolicies += $policy
                            break
                        }
                    }
                }

                # Fetch and process Applications
                Write-Host "Fetching Applications..." -ForegroundColor Yellow
                $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink') {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count
                $currentApp = 0

                foreach ($app in $allApps) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn) {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    $isExcluded = $false
                    $isIncluded = $false

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                            $groupMemberships.id -contains $assignment.target.groupId) {
                            $isExcluded = $true
                            break
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' -or
                            ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                            $groupMemberships.id -contains $assignment.target.groupId)) {
                            $isIncluded = $true
                        }
                    }

                    if ($isIncluded -and -not $isExcluded) {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Included" -Force
                        switch ($assignment.intent) {
                            "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                            "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                            "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                        }
                    }
                    elseif ($isExcluded) {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                        switch ($assignment.intent) {
                            "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                            "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                            "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Get Platform Scripts
                Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
                $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
                foreach ($script in $platformScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or 
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.PlatformScripts += $script
                            break
                        }
                    }
                }

                # Get Proactive Remediation Scripts
                Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
                $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
                foreach ($script in $healthScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -eq "All Users" -or 
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.HealthScripts += $script
                            break
                        }
                    }
                }

                # Get Endpoint Security - Antivirus Policies
                Write-Host "Fetching Antivirus Policies..." -ForegroundColor Yellow
                $antivirusPoliciesFound = [System.Collections.ArrayList]::new()
                $processedAntivirusIds = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForAntivirus = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesAntivirus = $configPoliciesForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

                if ($matchingConfigPoliciesAntivirus) {
                    foreach ($policy in $matchingConfigPoliciesAntivirus) {
                        if ($processedAntivirusIds.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if ($assignmentDetail.Reason -eq "All Users" -or
                                    ($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$antivirusPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$antivirusPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForAntivirus = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsAntivirus = $allIntentsForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
                
                if ($matchingIntentsAntivirus) {
                    foreach ($policy in $matchingIntentsAntivirus) {
                        if ($processedAntivirusIds.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if ($assignmentDetails.Reason -eq "All Users" -or
                                    ($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$antivirusPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$antivirusPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.AntivirusProfiles = $antivirusPoliciesFound
                
                # Get Endpoint Security - Disk Encryption Policies
                Write-Host "Fetching Disk Encryption Policies..." -ForegroundColor Yellow
                $diskEncryptionPoliciesFound = [System.Collections.ArrayList]::new()
                $processedDiskEncryptionIds = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForDiskEncryption = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesDiskEnc = $configPoliciesForDiskEncryption | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
                
                if ($matchingConfigPoliciesDiskEnc) {
                    foreach ($policy in $matchingConfigPoliciesDiskEnc) {
                        if ($processedDiskEncryptionIds.Add($policy.id)) {
                            # Ensure unique processing
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                # Get-IntuneAssignments returns an array of hashtables
                                if ($assignmentDetail.Reason -eq "All Users" -or
                                    ($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$diskEncryptionPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$diskEncryptionPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents (excluding those already found)
                $allIntentsForDiskEncryption = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsDiskEnc = $allIntentsForDiskEncryption | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

                if ($matchingIntentsDiskEnc) {
                    foreach ($policy in $matchingIntentsDiskEnc) {
                        if ($processedDiskEncryptionIds.Add($policy.id)) {
                            # Ensure unique processing
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }

                                if ($assignmentDetails.Reason -eq "All Users" -or
                                    ($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$diskEncryptionPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$diskEncryptionPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.DiskEncryptionProfiles = $diskEncryptionPoliciesFound
                
                # Get Endpoint Security - Firewall Policies
                Write-Host "Fetching Firewall Policies..." -ForegroundColor Yellow
                $firewallPoliciesFound = [System.Collections.ArrayList]::new()
                $processedFirewallIds = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForFirewall = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesFirewall = $configPoliciesForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

                if ($matchingConfigPoliciesFirewall) {
                    foreach ($policy in $matchingConfigPoliciesFirewall) {
                        if ($processedFirewallIds.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if ($assignmentDetail.Reason -eq "All Users" -or
                                    ($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$firewallPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$firewallPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForFirewall = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsFirewall = $allIntentsForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

                if ($matchingIntentsFirewall) {
                    foreach ($policy in $matchingIntentsFirewall) {
                        if ($processedFirewallIds.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if ($assignmentDetails.Reason -eq "All Users" -or
                                    ($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$firewallPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$firewallPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.FirewallProfiles = $firewallPoliciesFound
                
                # Get Endpoint Security - Endpoint Detection and Response Policies
                Write-Host "Fetching Endpoint Detection and Response Policies..." -ForegroundColor Yellow
                $edrPoliciesFound = [System.Collections.ArrayList]::new()
                $processedEDRIds = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForEDR = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesEDR = $configPoliciesForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

                if ($matchingConfigPoliciesEDR) {
                    foreach ($policy in $matchingConfigPoliciesEDR) {
                        if ($processedEDRIds.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if ($assignmentDetail.Reason -eq "All Users" -or
                                    ($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$edrPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$edrPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForEDR = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsEDR = $allIntentsForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

                if ($matchingIntentsEDR) {
                    foreach ($policy in $matchingIntentsEDR) {
                        if ($processedEDRIds.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if ($assignmentDetails.Reason -eq "All Users" -or
                                    ($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$edrPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$edrPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.EndpointDetectionProfiles = $edrPoliciesFound
                
                # Get Endpoint Security - Attack Surface Reduction Policies
                Write-Host "Fetching Attack Surface Reduction Policies..." -ForegroundColor Yellow
                $asrPoliciesFound = [System.Collections.ArrayList]::new()
                $processedASRIds = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForASR = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesASR = $configPoliciesForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

                if ($matchingConfigPoliciesASR) {
                    foreach ($policy in $matchingConfigPoliciesASR) {
                        if ($processedASRIds.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if ($assignmentDetail.Reason -eq "All Users" -or
                                    ($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$asrPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$asrPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForASR = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsASR = $allIntentsForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

                if ($matchingIntentsASR) {
                    foreach ($policy in $matchingIntentsASR) {
                        if ($processedASRIds.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if ($assignmentDetails.Reason -eq "All Users" -or
                                    ($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId)) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$asrPoliciesFound.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$asrPoliciesFound.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.AttackSurfaceProfiles = $asrPoliciesFound

                # Get Windows 365 Cloud PC Provisioning Policies
                Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
                try {
                    $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
                    foreach ($policy in $cloudPCProvisioningPolicies) {
                        $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
                        foreach ($assignment in $assignments) {
                            if ($assignment.Reason -eq "All Users" -or
                                ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                                $relevantPolicies.CloudPCProvisioningPolicies += $policy
                                break
                            }
                            elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                $relevantPolicies.CloudPCProvisioningPolicies += $policy
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
                }

                # Get Windows 365 Cloud PC User Settings
                Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
                try {
                    $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
                    foreach ($setting in $cloudPCUserSettings) {
                        $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
                        foreach ($assignment in $assignments) {
                            if ($assignment.Reason -eq "All Users" -or
                                ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                                $relevantPolicies.CloudPCUserSettings += $setting
                                break
                            }
                            elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                $relevantPolicies.CloudPCUserSettings += $setting
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
                }

                # Display results
                Write-Host "`nAssignments for User: $upn" -ForegroundColor Green

                # Display Device Configurations
                Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
                if ($relevantPolicies.DeviceConfigs.Count -eq 0) {
                    Write-Host "No Device Configurations found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f "Configuration Name", "Platform", "Configuration ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator

                    foreach ($config in $relevantPolicies.DeviceConfigs) {
                        $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                        if ($configName.Length -gt 42) {
                            $configName = $configName.Substring(0, 39) + "..."
                        }

                        $platform = Get-PolicyPlatform -Policy $config
                        if ($platform.Length -gt 17) {
                            $platform = $platform.Substring(0, 14) + "..."
                        }

                        $configId = $config.id
                        if ($configId.Length -gt 32) {
                            $configId = $configId.Substring(0, 29) + "..."
                        }

                        $assignment = $config.AssignmentReason
                        if ($assignment.Length -gt 17) {
                            $assignment = $assignment.Substring(0, 14) + "..."
                        }

                        $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f $configName, $platform, $configId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Settings Catalog Policies
                Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
                if ($relevantPolicies.SettingsCatalog.Count -eq 0) {
                    Write-Host "No Settings Catalog Policies found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($policy in $relevantPolicies.SettingsCatalog) {
                        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                        if ($policyName.Length -gt 47) {
                            $policyName = $policyName.Substring(0, 44) + "..."
                        }
                        
                        $policyId = $policy.id
                        if ($policyId.Length -gt 37) {
                            $policyId = $policyId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $policy.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Administrative Templates
                Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
                if ($relevantPolicies.AdminTemplates.Count -eq 0) {
                    Write-Host "No Administrative Templates found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Template Name", "Template ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($template in $relevantPolicies.AdminTemplates) {
                        $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                        if ($templateName.Length -gt 47) {
                            $templateName = $templateName.Substring(0, 44) + "..."
                        }
                        
                        $templateId = $template.id
                        if ($templateId.Length -gt 37) {
                            $templateId = $templateId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $template.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $templateName, $templateId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Compliance Policies
                Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
                if ($relevantPolicies.CompliancePolicies.Count -eq 0) {
                    Write-Host "No Compliance Policies found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($policy in $relevantPolicies.CompliancePolicies) {
                        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                        if ($policyName.Length -gt 47) {
                            $policyName = $policyName.Substring(0, 44) + "..."
                        }
                        
                        $policyId = $policy.id
                        if ($policyId.Length -gt 37) {
                            $policyId = $policyId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $policy.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display App Protection Policies
                Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
                if ($relevantPolicies.AppProtectionPolicies.Count -eq 0) {
                    Write-Host "No App Protection Policies found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f "Policy Name", "Policy ID", "Type", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($policy in $relevantPolicies.AppProtectionPolicies) {
                        $policyName = $policy.displayName
                        if ($policyName.Length -gt 37) {
                            $policyName = $policyName.Substring(0, 34) + "..."
                        }
                        
                        $policyId = $policy.id
                        if ($policyId.Length -gt 27) {
                            $policyId = $policyId.Substring(0, 24) + "..."
                        }
                        
                        $policyType = switch ($policy.'@odata.type') {
                            "#microsoft.graph.androidManagedAppProtection" { "Android" }
                            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                            default { "Unknown" }
                        }
                        
                        $assignment = $policy.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f $policyName, $policyId, $policyType, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display App Configuration Policies
                Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
                if ($relevantPolicies.AppConfigurationPolicies.Count -eq 0) {
                    Write-Host "No App Configuration Policies found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($policy in $relevantPolicies.AppConfigurationPolicies) {
                        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                        if ($policyName.Length -gt 47) {
                            $policyName = $policyName.Substring(0, 44) + "..."
                        }
                        
                        $policyId = $policy.id
                        if ($policyId.Length -gt 37) {
                            $policyId = $policyId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $policy.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Platform Scripts
                Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
                if ($relevantPolicies.PlatformScripts.Count -eq 0) {
                    Write-Host "No Platform Scripts found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Script Name", "Script ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($script in $relevantPolicies.PlatformScripts) {
                        $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                        if ($scriptName.Length -gt 47) {
                            $scriptName = $scriptName.Substring(0, 44) + "..."
                        }
                        
                        $scriptId = $script.id
                        if ($scriptId.Length -gt 37) {
                            $scriptId = $scriptId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $script.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $scriptName, $scriptId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Proactive Remediation Scripts
                Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
                if ($relevantPolicies.HealthScripts.Count -eq 0) {
                    Write-Host "No Proactive Remediation Scripts found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Script Name", "Script ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($script in $relevantPolicies.HealthScripts) {
                        $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                        if ($scriptName.Length -gt 47) {
                            $scriptName = $scriptName.Substring(0, 44) + "..."
                        }
                        
                        $scriptId = $script.id
                        if ($scriptId.Length -gt 37) {
                            $scriptId = $scriptId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $script.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $scriptName, $scriptId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Required Apps
                Write-Host "`n------- Required Apps -------" -ForegroundColor Cyan
                if ($relevantPolicies.AppsRequired.Count -eq 0) {
                    Write-Host "No Required Apps found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($app in $relevantPolicies.AppsRequired) {
                        $appName = $app.displayName
                        if ($appName.Length -gt 47) {
                            $appName = $appName.Substring(0, 44) + "..."
                        }
                        
                        $appId = $app.id
                        if ($appId.Length -gt 37) {
                            $appId = $appId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $app.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                        if ($assignment -like "*Exclusion*") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Available Apps
                Write-Host "`n------- Available Apps -------" -ForegroundColor Cyan
                if ($relevantPolicies.AppsAvailable.Count -eq 0) {
                    Write-Host "No Available Apps found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($app in $relevantPolicies.AppsAvailable) {
                        $appName = $app.displayName
                        if ($appName.Length -gt 47) {
                            $appName = $appName.Substring(0, 44) + "..."
                        }
                        
                        $appId = $app.id
                        if ($appId.Length -gt 37) {
                            $appId = $appId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $app.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                        if ($assignment -like "*Exclusion*") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Uninstall Apps
                Write-Host "`n------- Uninstall Apps -------" -ForegroundColor Cyan
                if ($relevantPolicies.AppsUninstall.Count -eq 0) {
                    Write-Host "No Uninstall Apps found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($app in $relevantPolicies.AppsUninstall) {
                        $appName = $app.displayName
                        if ($appName.Length -gt 47) {
                            $appName = $appName.Substring(0, 44) + "..."
                        }
                        
                        $appId = $app.id
                        if ($appId.Length -gt 37) {
                            $appId = $appId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $app.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                        if ($assignment -like "*Exclusion*") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }
                
                # Display Endpoint Security - Antivirus Profiles
                Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
                if ($relevantPolicies.AntivirusProfiles.Count -eq 0) {
                    Write-Host "No Antivirus Profiles found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($profile in $relevantPolicies.AntivirusProfiles) {
                        $profileName = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" }
                        if ($profileName.Length -gt 47) {
                            $profileName = $profileName.Substring(0, 44) + "..."
                        }
                        
                        $profileId = $profile.id
                        if ($profileId.Length -gt 37) {
                            $profileId = $profileId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $profile.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }
                
                # Display Endpoint Security - Disk Encryption Profiles
                Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
                if ($relevantPolicies.DiskEncryptionProfiles.Count -eq 0) {
                    Write-Host "No Disk Encryption Profiles found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($profile in $relevantPolicies.DiskEncryptionProfiles) {
                        $profileName = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" }
                        if ($profileName.Length -gt 47) {
                            $profileName = $profileName.Substring(0, 44) + "..."
                        }
                        
                        $profileId = $profile.id
                        if ($profileId.Length -gt 37) {
                            $profileId = $profileId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $profile.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }
                
                # Display Endpoint Security - Firewall Profiles
                Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
                if ($relevantPolicies.FirewallProfiles.Count -eq 0) {
                    Write-Host "No Firewall Profiles found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($profile in $relevantPolicies.FirewallProfiles) {
                        $profileName = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" }
                        if ($profileName.Length -gt 47) {
                            $profileName = $profileName.Substring(0, 44) + "..."
                        }
                        
                        $profileId = $profile.id
                        if ($profileId.Length -gt 37) {
                            $profileId = $profileId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $profile.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }
                
                # Display Endpoint Security - Endpoint Detection and Response Profiles
                Write-Host "`n------- Endpoint Security - Endpoint Detection and Response Profiles -------" -ForegroundColor Cyan
                if ($relevantPolicies.EndpointDetectionProfiles.Count -eq 0) {
                    Write-Host "No Endpoint Detection and Response Profiles found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($profile in $relevantPolicies.EndpointDetectionProfiles) {
                        $profileName = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" }
                        if ($profileName.Length -gt 47) {
                            $profileName = $profileName.Substring(0, 44) + "..."
                        }
                        
                        $profileId = $profile.id
                        if ($profileId.Length -gt 37) {
                            $profileId = $profileId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $profile.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }
                
                # Display Endpoint Security - Attack Surface Reduction Profiles
                Write-Host "`n------- Endpoint Security - Attack Surface Reduction Profiles -------" -ForegroundColor Cyan
                if ($relevantPolicies.AttackSurfaceProfiles.Count -eq 0) {
                    Write-Host "No Attack Surface Reduction Profiles found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($profile in $relevantPolicies.AttackSurfaceProfiles) {
                        $profileName = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" }
                        if ($profileName.Length -gt 47) {
                            $profileName = $profileName.Substring(0, 44) + "..."
                        }
                        
                        $profileId = $profile.id
                        if ($profileId.Length -gt 37) {
                            $profileId = $profileId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $profile.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Windows 365 Cloud PC Provisioning Policies
                Write-Host "`n------- Windows 365 Cloud PC Provisioning Policies -------" -ForegroundColor Cyan
                if ($relevantPolicies.CloudPCProvisioningPolicies.Count -eq 0) {
                    Write-Host "No Windows 365 Cloud PC Provisioning Policies found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($policy in $relevantPolicies.CloudPCProvisioningPolicies) {
                        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Policy" }
                        if ($policyName.Length -gt 47) {
                            $policyName = $policyName.Substring(0, 44) + "..."
                        }
                        
                        $policyId = $policy.id
                        if ($policyId.Length -gt 37) {
                            $policyId = $policyId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $policy.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Display Windows 365 Cloud PC User Settings
                Write-Host "`n------- Windows 365 Cloud PC User Settings -------" -ForegroundColor Cyan
                if ($relevantPolicies.CloudPCUserSettings.Count -eq 0) {
                    Write-Host "No Windows 365 Cloud PC User Settings found" -ForegroundColor Gray
                }
                else {
                    # Create table header
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Setting Name", "Setting ID", "Assignment"
                    $separator = "-" * 120
                    Write-Host $separator
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator
                    
                    foreach ($setting in $relevantPolicies.CloudPCUserSettings) {
                        $settingName = if (-not [string]::IsNullOrWhiteSpace($setting.displayName)) { $setting.displayName } elseif (-not [string]::IsNullOrWhiteSpace($setting.name)) { $setting.name } else { "Unnamed Setting" }
                        if ($settingName.Length -gt 47) {
                            $settingName = $settingName.Substring(0, 44) + "..."
                        }
                        
                        $settingId = $setting.id
                        if ($settingId.Length -gt 37) {
                            $settingId = $settingId.Substring(0, 34) + "..."
                        }
                        
                        $assignment = $setting.AssignmentReason
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $settingName, $settingId, $assignment
                        if ($assignment -eq "Excluded") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $separator
                }

                # Add all data to export
                Add-ExportData -ExportData $exportData -Category "User" -Items @([PSCustomObject]@{
                        displayName      = $upn
                        id               = $userInfo.Id
                        AssignmentReason = "N/A"
                    }

                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $relevantPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $relevantPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $relevantPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $relevantPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $relevantPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $relevantPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $relevantPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $relevantPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items $relevantPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items $relevantPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $relevantPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $relevantPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $relevantPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $relevantPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $relevantPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $relevantPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                )
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUserAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '2' {
            Write-Host "Group selection chosen" -ForegroundColor Green

            # Prompt for Group names or IDs
            Write-Host "Please enter Group names or Object IDs, separated by commas (,): " -ForegroundColor Cyan
            Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
            $groupInput = Read-Host

            if ([string]::IsNullOrWhiteSpace($groupInput)) {
                Write-Host "No group information provided. Please try again." -ForegroundColor Red
                continue
            }

            $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }
            $exportData = [System.Collections.ArrayList]::new()

            foreach ($input in $groupInputs) {
                Write-Host "`nProcessing input: $input" -ForegroundColor Yellow

                # Initialize variables
                $groupId = $null
                $groupName = $null

                # Check if input is a GUID
                if ($input -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                    $groupInfo = Get-GroupInfo -GroupId $input
                    if (-not $groupInfo.Success) {
                        Write-Host "No group found with ID: $input" -ForegroundColor Red
                        continue
                    }
                    $groupId = $groupInfo.Id
                    $groupName = $groupInfo.DisplayName
                }
                else {
                    # Try to find group by display name
                    $groupUri = "$GraphEndpoint/v1.0/groups?`$filter=displayName eq '$input'"
                    $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get

                    if ($groupResponse.value.Count -eq 0) {
                        Write-Host "No group found with name: $input" -ForegroundColor Red
                        continue
                    }
                    elseif ($groupResponse.value.Count -gt 1) {
                        Write-Host "Multiple groups found with name: $input. Please use the Object ID instead:" -ForegroundColor Red
                        foreach ($group in $groupResponse.value) {
                            Write-Host "  - $($group.displayName) (ID: $($group.id))" -ForegroundColor Yellow
                        }
                        continue
                    }

                    $groupId = $groupResponse.value[0].id
                    $groupName = $groupResponse.value[0].displayName
                }

                Write-Host "Found group: $groupName (ID: $groupId)" -ForegroundColor Green
                Write-Host "Fetching Intune Profiles and Applications for the group ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections for relevant policies
                $relevantPolicies = @{
                    DeviceConfigs               = @()
                    SettingsCatalog             = @()
                    AdminTemplates              = @()
                    CompliancePolicies          = @()
                    AppProtectionPolicies       = @()
                    AppConfigurationPolicies    = @()
                    AppsRequired                = @()
                    AppsAvailable               = @()
                    AppsUninstall               = @()
                    PlatformScripts             = @()
                    HealthScripts               = @()
                    # Endpoint Security profiles
                    AntivirusProfiles           = @()
                    DiskEncryptionProfiles      = @()
                    FirewallProfiles            = @()
                    EndpointDetectionProfiles   = @()
                    AttackSurfaceProfiles       = @()
                    DeploymentProfiles          = @()
                    ESPProfiles                 = @()
                    CloudPCProvisioningPolicies = @()
                    CloudPCUserSettings         = @()
                }

                # Get Device Configurations
                Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
                $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
                foreach ($config in $deviceConfigs) {
                    $directAssignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.DeviceConfigs += $config
                        }
                    }
                }

                # Get Settings Catalog Policies
                Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
                $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
                foreach ($policy in $settingsCatalog) {
                    # Exclude Endpoint Security policies from this generic Settings Catalog fetch for group view
                    if ($policy.templateReference -and $policy.templateReference.templateFamily -like "endpointSecurity*") {
                        continue
                    }
                    $directAssignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.SettingsCatalog += $policy
                        }
                    }
                }

                # Get Administrative Templates
                Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
                $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
                foreach ($template in $adminTemplates) {
                    $directAssignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.AdminTemplates += $template
                        }
                    }
                }

                # Get Compliance Policies
                Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
                $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
                foreach ($policy in $compliancePolicies) {
                    $directAssignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.CompliancePolicies += $policy
                        }
                    }
                }

                # Get App Protection Policies
                Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
                $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
                foreach ($policy in $appProtectionPolicies) {
                    $policyType = $policy.'@odata.type'
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        try {
                            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                            # For group queries, Get-IntuneAssignments will return only direct assignments/exclusions
                            $directAssignments = Get-IntuneAssignments -EntityType "deviceAppManagement/managedAppPolicies" -EntityId $policy.id -GroupId $groupId
                            if ($directAssignments.Count -gt 0) {
                                # Process all assignments for this group
                                $assignmentReasons = @()
                                foreach ($assignment in $directAssignments) {
                                    if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                        $assignmentReasons += $assignment.Reason
                                    }
                                }

                                if ($assignmentReasons.Count -gt 0) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                    $relevantPolicies.AppProtectionPolicies += $policy
                                }
                            }
                        }
                        catch {
                            Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }

                # Get App Configuration Policies
                Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
                $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
                foreach ($policy in $appConfigPolicies) {
                    $directAssignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.AppConfigurationPolicies += $policy
                        }
                    }
                }

                # Get Endpoint Security - Antivirus Policies
                Write-Host "Fetching Antivirus Policies for group..." -ForegroundColor Yellow
                $antivirusPoliciesFoundGroup = [System.Collections.ArrayList]::new()
                $processedAntivirusIdsGroup = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForAntivirusGroup = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesAntivirusGroup = $configPoliciesForAntivirusGroup | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

                # Endpoint Security Policies for the specific group
                $endpointSecurityCategories = @(
                    @{ Name = "Antivirus"; Key = "AntivirusProfiles"; TemplateFamily = "endpointSecurityAntivirus"; UserFriendlyType = "Antivirus Profile" },
                    @{ Name = "Disk Encryption"; Key = "DiskEncryptionProfiles"; TemplateFamily = "endpointSecurityDiskEncryption"; UserFriendlyType = "Disk Encryption Profile" },
                    @{ Name = "Firewall"; Key = "FirewallProfiles"; TemplateFamily = "endpointSecurityFirewall"; UserFriendlyType = "Firewall Profile" },
                    @{ Name = "Endpoint Detection and Response"; Key = "EndpointDetectionProfiles"; TemplateFamily = "endpointSecurityEndpointDetectionAndResponse"; UserFriendlyType = "EDR Profile" },
                    @{ Name = "Attack Surface Reduction"; Key = "AttackSurfaceProfiles"; TemplateFamily = "endpointSecurityAttackSurfaceReductionRules"; UserFriendlyType = "ASR Profile" }
                )

                foreach ($esCategory in $endpointSecurityCategories) {
                    Write-Host "Fetching $($esCategory.Name) Policies for group..." -ForegroundColor Yellow
                    $processedEsPolicyIds = [System.Collections.Generic.HashSet[string]]::new() # Track IDs per category to avoid duplicates from configPolicies and intents

                    # 1. Check configurationPolicies (Settings Catalog style ES policies)
                    $allConfigEsPolicies = Get-IntuneEntities -EntityType "configurationPolicies" # Fetch all, then filter
                    $matchingConfigEsPolicies = $allConfigEsPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
                    if ($matchingConfigEsPolicies) {
                        foreach ($policy in $matchingConfigEsPolicies) {
                            if ($processedEsPolicyIds.Add($policy.id)) {
                                $directAssignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id -GroupId $groupId
                                if ($directAssignments.Count -gt 0) {
                                    # Process all assignments for this group
                                    $assignmentReasons = @()
                                    foreach ($assignment in $directAssignments) {
                                        if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                            $assignmentReasons += $assignment.Reason
                                        }
                                    }

                                    if ($assignmentReasons.Count -gt 0) {
                                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                        $relevantPolicies[$esCategory.Key] += $policy
                                    }
                                }
                            }
                        }
                    }

                    # 2. Check deviceManagement/intents (Template style ES policies)
                    $allIntentEsPolicies = Get-IntuneEntities -EntityType "deviceManagement/intents" # Fetch all, then filter
                    $matchingIntentEsPolicies = $allIntentEsPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
                    if ($matchingIntentEsPolicies) {
                        foreach ($policy in $matchingIntentEsPolicies) {
                            if ($processedEsPolicyIds.Add($policy.id)) {
                                # For intents, assignments are fetched differently
                                try {
                                    $allIntentAssignments = [System.Collections.ArrayList]::new()
                                    $currentIntentAssignmentsUri = "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments"
                                    do {
                                        $intentAssignmentsResponsePage = Invoke-MgGraphRequest -Uri $currentIntentAssignmentsUri -Method Get
                                        if ($intentAssignmentsResponsePage -and $null -ne $intentAssignmentsResponsePage.value) {
                                            $allIntentAssignments.AddRange($intentAssignmentsResponsePage.value)
                                        }
                                        $currentIntentAssignmentsUri = $intentAssignmentsResponsePage.'@odata.nextLink'
                                    } while (![string]::IsNullOrEmpty($currentIntentAssignmentsUri))

                                    $directGroupAssignment = $allIntentAssignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }
                                    $directGroupExclusion = $allIntentAssignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $_.target.groupId -eq $groupId }

                                    $assignmentReason = $null
                                    if ($directGroupExclusion) {
                                        $assignmentReason = "Direct Exclusion"
                                    }
                                    elseif ($directGroupAssignment) {
                                        $assignmentReason = "Direct Assignment"
                                    }

                                    if ($assignmentReason) {
                                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                        $relevantPolicies[$esCategory.Key] += $policy
                                    }
                                }
                                catch {
                                    Write-Warning "Error fetching assignments for ES Intent $($policy.displayName) (ID: $($policy.id)): $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }

                # Fetch and process Applications
                Write-Host "Fetching Applications..." -ForegroundColor Yellow
                $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink') {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count

                foreach ($app in $allApps) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn) {
                        continue
                    }

                    $appId = $app.id
                    $allAppAssignments = [System.Collections.ArrayList]::new()
                    $currentAppAssignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    do {
                        $appAssignmentsResponsePage = Invoke-MgGraphRequest -Uri $currentAppAssignmentsUri -Method Get
                        if ($appAssignmentsResponsePage -and $null -ne $appAssignmentsResponsePage.value) {
                            $allAppAssignments.AddRange($appAssignmentsResponsePage.value)
                        }
                        $currentAppAssignmentsUri = $appAssignmentsResponsePage.'@odata.nextLink'
                    } while (![string]::IsNullOrEmpty($currentAppAssignmentsUri))
                    
                    $relevantAppAssignmentReason = $null
                    $intentForGroup = $null

                    foreach ($assignmentItem in $allAppAssignments) {
                        if ($assignmentItem.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignmentItem.target.groupId -eq $groupId) {
                            $relevantAppAssignmentReason = "Direct Assignment"
                            $intentForGroup = $assignmentItem.intent
                            break
                        }
                        elseif ($assignmentItem.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $assignmentItem.target.groupId -eq $groupId) {
                            $relevantAppAssignmentReason = "Group Exclusion"
                            $intentForGroup = $assignmentItem.intent # Intent might still be relevant for excluded apps
                            break
                        }
                    }

                    if ($relevantAppAssignmentReason) {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $relevantAppAssignmentReason -Force
                        if ($intentForGroup) {
                            switch ($intentForGroup) {
                                "required" { $relevantPolicies.AppsRequired += $appWithReason }
                                "available" { $relevantPolicies.AppsAvailable += $appWithReason }
                                "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason }
                            }
                        }
                    }
                }

                # Get Platform Scripts
                Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
                $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
                foreach ($script in $platformScripts) {
                    $directAssignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.PlatformScripts += $script
                        }
                    }
                }

                # Get Proactive Remediation Scripts
                Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
                $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
                foreach ($script in $healthScripts) {
                    $directAssignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.HealthScripts += $script
                        }
                    }
                }

                # Get Autopilot Deployment Profiles
                Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
                $autoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
                foreach ($profile in $autoProfiles) {
                    $directAssignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.DeploymentProfiles += $profile
                        }
                    }
                }

                # Get Enrollment Status Page Profiles
                Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
                $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
                $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
                foreach ($esp in $espProfiles) {
                    $directAssignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id -GroupId $groupId
                    if ($directAssignments.Count -gt 0) {
                        # Process all assignments for this group
                        $assignmentReasons = @()
                        foreach ($assignment in $directAssignments) {
                            if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                $assignmentReasons += $assignment.Reason
                            }
                        }

                        if ($assignmentReasons.Count -gt 0) {
                            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                            $relevantPolicies.ESPProfiles += $esp
                        }
                    }
                }

                # Get Windows 365 Cloud PC Provisioning Policies
                Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
                try {
                    $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
                    foreach ($policy in $cloudPCProvisioningPolicies) {
                        $directAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id -GroupId $groupId
                        if ($directAssignments.Count -gt 0) {
                            # Process all assignments for this group
                            $assignmentReasons = @()
                            foreach ($assignment in $directAssignments) {
                                if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                    $assignmentReasons += $assignment.Reason
                                }
                            }

                            if ($assignmentReasons.Count -gt 0) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                $relevantPolicies.CloudPCProvisioningPolicies += $policy
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
                }

                # Get Windows 365 Cloud PC User Settings
                Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
                try {
                    $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
                    foreach ($setting in $cloudPCUserSettings) {
                        $directAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id -GroupId $groupId
                        if ($directAssignments.Count -gt 0) {
                            # Process all assignments for this group
                            $assignmentReasons = @()
                            foreach ($assignment in $directAssignments) {
                                if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
                                    $assignmentReasons += $assignment.Reason
                                }
                            }

                            if ($assignmentReasons.Count -gt 0) {
                                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                $relevantPolicies.CloudPCUserSettings += $setting
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
                }

                # Function to format and display policy table (specific to Option 2)
                function Format-PolicyTable {
                    param (
                        [string]$Title,
                        [object[]]$Policies,
                        [scriptblock]$GetName,
                        [scriptblock]$GetExtra = { param($p) "" }
                    )
                    $localTableSeparator = "-" * 120 # Use a local variable for separator

                    # Create prominent section header
                    $headerSeparator = "-" * ($Title.Length + 16)
                    Write-Host "`n$headerSeparator" -ForegroundColor Cyan
                    Write-Host "------- $Title -------" -ForegroundColor Cyan
                    Write-Host "$headerSeparator" -ForegroundColor Cyan
                    
                    if ($Policies.Count -eq 0) {
                        Write-Host "No $Title found for this group." -ForegroundColor Gray
                        Write-Host $localTableSeparator -ForegroundColor Gray
                        Write-Host ""
                        return
                    }

                    # Create table header
                    $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f "Policy Name", "Platform", "ID", "Assignment"

                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $localTableSeparator -ForegroundColor Gray

                    # Display each policy
                    foreach ($policy in $Policies) {
                        $name = & $GetName $policy
                        $extra = & $GetExtra $policy

                        if ($name.Length -gt 42) { $name = $name.Substring(0, 39) + "..." }

                        $platform = Get-PolicyPlatform -Policy $policy
                        if ($platform.Length -gt 17) { $platform = $platform.Substring(0, 14) + "..." }

                        $id = $policy.id
                        if ($id.Length -gt 32) { $id = $id.Substring(0, 29) + "..." }

                        $assignment = if ($policy.AssignmentReason) { $policy.AssignmentReason } else { "N/A" }
                        if ($assignment.Length -gt 17) { $assignment = $assignment.Substring(0, 14) + "..." }

                        $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f $name, $platform, $id, $assignment
                        if ($assignment -eq "Direct Exclusion") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    Write-Host $localTableSeparator -ForegroundColor Gray
                }

                # Display Device Configurations
                Format-PolicyTable -Title "Device Configurations" -Policies $relevantPolicies.DeviceConfigs -GetName {
                    param($config)
                    if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                }

                # Display Settings Catalog Policies
                Format-PolicyTable -Title "Settings Catalog Policies" -Policies $relevantPolicies.SettingsCatalog -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display Administrative Templates
                Format-PolicyTable -Title "Administrative Templates" -Policies $relevantPolicies.AdminTemplates -GetName {
                    param($template)
                    if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                }

                # Display Compliance Policies
                Format-PolicyTable -Title "Compliance Policies" -Policies $relevantPolicies.CompliancePolicies -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display App Protection Policies
                Format-PolicyTable -Title "App Protection Policies" -Policies $relevantPolicies.AppProtectionPolicies -GetName {
                    param($policy)
                    $policy.displayName
                } -GetExtra {
                    param($policy)
                    @{
                        Label = 'Platform'
                        Value = switch ($policy.'@odata.type') {
                            "#microsoft.graph.androidManagedAppProtection" { "Android" }
                            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                            default { "Unknown" }
                        }
                    }
                }

                # Display App Configuration Policies
                Format-PolicyTable -Title "App Configuration Policies" -Policies $relevantPolicies.AppConfigurationPolicies -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display Platform Scripts
                Format-PolicyTable -Title "Platform Scripts" -Policies $relevantPolicies.PlatformScripts -GetName {
                    param($script)
                    if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                }

                # Display Proactive Remediation Scripts
                Format-PolicyTable -Title "Proactive Remediation Scripts" -Policies $relevantPolicies.HealthScripts -GetName {
                    param($script)
                    if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                }

                # Display Autopilot Deployment Profiles
                Format-PolicyTable -Title "Autopilot Deployment Profiles" -Policies $relevantPolicies.DeploymentProfiles -GetName {
                    param($profile)
                    if ([string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.name } else { $profile.displayName }
                }

                # Display Enrollment Status Page Profiles
                Format-PolicyTable -Title "Enrollment Status Page Profiles" -Policies $relevantPolicies.ESPProfiles -GetName {
                    param($profile)
                    if ([string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.name } else { $profile.displayName }
                }

                # Display Windows 365 Cloud PC Provisioning Policies
                Format-PolicyTable -Title "Windows 365 Cloud PC Provisioning Policies" -Policies $relevantPolicies.CloudPCProvisioningPolicies -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.name } else { $policy.displayName }
                }

                # Display Windows 365 Cloud PC User Settings
                Format-PolicyTable -Title "Windows 365 Cloud PC User Settings" -Policies $relevantPolicies.CloudPCUserSettings -GetName {
                    param($setting)
                    if ([string]::IsNullOrWhiteSpace($setting.displayName)) { $setting.name } else { $setting.displayName }
                }

                # Display Required Apps
                Format-PolicyTable -Title "Required Apps" -Policies $relevantPolicies.AppsRequired -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Available Apps
                Format-PolicyTable -Title "Available Apps" -Policies $relevantPolicies.AppsAvailable -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Uninstall Apps
                Format-PolicyTable -Title "Uninstall Apps" -Policies $relevantPolicies.AppsUninstall -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Endpoint Security - Antivirus Profiles
                Format-PolicyTable -Title "Endpoint Security - Antivirus Profiles" -Policies $relevantPolicies.AntivirusProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Disk Encryption Profiles
                Format-PolicyTable -Title "Endpoint Security - Disk Encryption Profiles" -Policies $relevantPolicies.DiskEncryptionProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Firewall Profiles
                Format-PolicyTable -Title "Endpoint Security - Firewall Profiles" -Policies $relevantPolicies.FirewallProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Endpoint Detection and Response Profiles
                Format-PolicyTable -Title "Endpoint Security - EDR Profiles" -Policies $relevantPolicies.EndpointDetectionProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Attack Surface Reduction Profiles
                Format-PolicyTable -Title "Endpoint Security - ASR Profiles" -Policies $relevantPolicies.AttackSurfaceProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }

                # Add to export data
                Add-ExportData -ExportData $exportData -Category "Device" -Items @([PSCustomObject]@{
                        displayName      = $deviceName
                        id               = $deviceInfo.Id
                        AssignmentReason = "N/A"
                    }

                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $relevantPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $relevantPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $relevantPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $relevantPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $relevantPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $relevantPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $relevantPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $relevantPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items $relevantPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items $relevantPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $relevantPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $relevantPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $relevantPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $relevantPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $relevantPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $relevantPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                )
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneDeviceAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '3' {
            Write-Host "Device selection chosen" -ForegroundColor Green

            # Get Device names from parameter or prompt
            if ($parameterMode -and $DeviceNames) {
                $deviceInput = $DeviceNames
            }
            else {
                # Prompt for one or more Device Names
                Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
                $deviceInput = Read-Host
            }

            if ([string]::IsNullOrWhiteSpace($deviceInput)) {
                Write-Host "No device name provided. Please try again." -ForegroundColor Red
                if ($parameterMode) { exit 1 } else { continue }
            }

            $deviceNames = $deviceInput -split ',' | ForEach-Object { $_.Trim() }
            $exportData = [System.Collections.ArrayList]::new()

            foreach ($deviceName in $deviceNames) {
                Write-Host "`nProcessing device: $deviceName" -ForegroundColor Yellow

                # Get Device Info
                $deviceInfo = Get-DeviceInfo -DeviceName $deviceName
                if (-not $deviceInfo.Success) {
                    Write-Host "Device not found: $deviceName" -ForegroundColor Red
                    Write-Host "Please verify the device name is correct." -ForegroundColor Yellow
                    continue
                }

                # Get Device Group Memberships
                try {
                    $groupMemberships = Get-GroupMemberships -ObjectId $deviceInfo.Id -ObjectType "Device"
                    Write-Host "Device Group Memberships: $($groupMemberships.displayName -join ', ')" -ForegroundColor Green
                }
                catch {
                    Write-Host "Error fetching group memberships for device: $deviceName" -ForegroundColor Red
                    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
                    continue
                }

                Write-Host "Fetching Intune Profiles and Applications for the device ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections for relevant policies
                $relevantPolicies = @{
                    DeviceConfigs               = @()
                    SettingsCatalog             = @()
                    AdminTemplates              = @()
                    CompliancePolicies          = @()
                    AppProtectionPolicies       = @()
                    AppConfigurationPolicies    = @()
                    AppsRequired                = @()
                    AppsAvailable               = @()
                    AppsUninstall               = @()
                    PlatformScripts             = @()
                    HealthScripts               = @()
                    AntivirusProfiles           = @()
                    DiskEncryptionProfiles      = @()
                    FirewallProfiles            = @()
                    EndpointDetectionProfiles   = @()
                    AttackSurfaceProfiles       = @()
                    CloudPCProvisioningPolicies = @()
                    CloudPCUserSettings         = @()
                }

                # Get Device Configurations
                Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
                $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
                foreach ($config in $deviceConfigs) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.DeviceConfigs += $config
                            break
                        }
                    }
                }

                # Get Settings Catalog Policies
                Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
                $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
                foreach ($policy in $settingsCatalog) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.SettingsCatalog += $policy
                            break
                        }
                    }
                }

                # Get Administrative Templates
                Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
                $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
                foreach ($template in $adminTemplates) {
                    $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.AdminTemplates += $template
                            break
                        }
                    }
                }

                # Get Compliance Policies
                Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
                $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
                foreach ($policy in $compliancePolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.CompliancePolicies += $policy
                            break
                        }
                    }
                }

                # Get App Protection Policies
                Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
                $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
                foreach ($policy in $appProtectionPolicies) {
                    $policyType = $policy.'@odata.type'
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        try {
                            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                            $assignments = @()
                            foreach ($assignment in $assignmentResponse.value) {
                                $assignmentReason = $null
                                switch ($assignment.target.'@odata.type') {
                                    '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                                        $assignmentReason = "All Users"
                                    }
                                    '#microsoft.graph.allDevicesAssignmentTarget' {
                                        $assignmentReason = "All Devices"
                                    }
                                    '#microsoft.graph.groupAssignmentTarget' {
                                        if ($groupMemberships.id -contains $assignment.target.groupId) {
                                            $assignmentReason = "Group Assignment"
                                        }
                                    }
                                    '#microsoft.graph.exclusionGroupAssignmentTarget' {
                                        if ($groupMemberships.id -contains $assignment.target.groupId) {
                                            $assignmentReason = "Group Exclusion"
                                        }
                                    }
                                }

                                if ($assignmentReason -and $assignmentReason -ne "All Users") {
                                    $assignments += @{
                                        Reason  = $assignmentReason
                                        GroupId = $assignment.target.groupId
                                    }
                                }
                            }

                            if ($assignments.Count -gt 0) {
                                $assignmentSummary = $assignments | Where-Object { $_.Reason -ne "All Users" } | ForEach-Object {
                                    if ($_.Reason -eq "Group Assignment") {
                                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                        "$($_.Reason) - $($groupInfo.DisplayName)"
                                    }
                                    else {
                                        $_.Reason
                                    }
                                }
                                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                                $relevantPolicies.AppProtectionPolicies += $policy
                            }
                        }
                        catch {
                            Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }

                # Get App Configuration Policies
                Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
                $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
                foreach ($policy in $appConfigPolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.AppConfigurationPolicies += $policy
                            break
                        }
                    }
                }

                # Get Platform Scripts
                Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
                $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
                foreach ($script in $platformScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.PlatformScripts += $script
                            break
                        }
                    }
                }

                # Get Proactive Remediation Scripts
                Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
                $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
                foreach ($script in $healthScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                    foreach ($assignment in $assignments) {
                        if ($assignment.Reason -ne "All Users" -and
                            ($assignment.Reason -eq "All Devices" -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId))) {
                            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.HealthScripts += $script
                            break
                        }
                    }
                }

                # Get Autopilot Deployment Profiles
                Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
                $autoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
                foreach ($profile in $autoProfiles) {
                    $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
                    foreach ($assignment in $assignments) {
                        if (($assignment.Reason -eq "All Devices") -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.DeploymentProfiles += $profile
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.DeploymentProfiles += $profile
                            break
                        }
                    }
                }

                # Get Enrollment Status Page Profiles
                Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
                $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
                $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
                foreach ($esp in $espProfiles) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
                    foreach ($assignment in $assignments) {
                        if (($assignment.Reason -eq "All Devices") -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                            $relevantPolicies.ESPProfiles += $esp
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                            $relevantPolicies.ESPProfiles += $esp
                            break
                        }
                    }
                }

                # Get Windows 365 Cloud PC Provisioning Policies
                Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
                try {
                    $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
                    foreach ($policy in $cloudPCProvisioningPolicies) {
                        $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
                        foreach ($assignment in $assignments) {
                            if (($assignment.Reason -eq "All Devices") -or
                                ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                                $relevantPolicies.CloudPCProvisioningPolicies += $policy
                                break
                            }
                            elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                $relevantPolicies.CloudPCProvisioningPolicies += $policy
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
                }

                # Get Windows 365 Cloud PC User Settings
                Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
                try {
                    $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
                    foreach ($setting in $cloudPCUserSettings) {
                        $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
                        foreach ($assignment in $assignments) {
                            if (($assignment.Reason -eq "All Devices") -or
                                ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignment.Reason -Force
                                $relevantPolicies.CloudPCUserSettings += $setting
                                break
                            }
                            elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                $relevantPolicies.CloudPCUserSettings += $setting
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
                }

                # Get Endpoint Security - Antivirus Policies
                Write-Host "Fetching Antivirus Policies" -ForegroundColor Yellow
                $antivirusPoliciesFoundDevice = [System.Collections.ArrayList]::new()
                $processedAntivirusIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForAntivirusDevice = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesAntivirusDevice = $configPoliciesForAntivirusDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

                if ($matchingConfigPoliciesAntivirusDevice) {
                    foreach ($policy in $matchingConfigPoliciesAntivirusDevice) {
                        if ($processedAntivirusIdsDevice.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if (($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId) -or
                                    ($assignmentDetail.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$antivirusPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$antivirusPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForAntivirusDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsAntivirusDevice = $allIntentsForAntivirusDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

                if ($matchingIntentsAntivirusDevice) {
                    foreach ($policy in $matchingIntentsAntivirusDevice) {
                        if ($processedAntivirusIdsDevice.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }

                                if (($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId) -or
                                    ($assignmentDetails.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$antivirusPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$antivirusPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.AntivirusProfiles = $antivirusPoliciesFoundDevice

                # Get Endpoint Security - Disk Encryption Policies
                Write-Host "Fetching Disk Encryption Policies." -ForegroundColor Yellow
                $diskEncryptionPoliciesFoundDevice = [System.Collections.ArrayList]::new()
                $processedDiskEncryptionIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForDiskEncDevice = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesDiskEncDevice = $configPoliciesForDiskEncDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
                
                if ($matchingConfigPoliciesDiskEncDevice) {
                    foreach ($policy in $matchingConfigPoliciesDiskEncDevice) {
                        if ($processedDiskEncryptionIdsDevice.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if (($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId) -or
                                    ($assignmentDetail.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForDiskEncDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsDiskEncDevice = $allIntentsForDiskEncDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

                if ($matchingIntentsDiskEncDevice) {
                    foreach ($policy in $matchingIntentsDiskEncDevice) {
                        if ($processedDiskEncryptionIdsDevice.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if (($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId) -or
                                    ($assignmentDetails.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.DiskEncryptionProfiles = $diskEncryptionPoliciesFoundDevice

                # Get Endpoint Security - Firewall Policies
                Write-Host "Fetching Firewall Policies" -ForegroundColor Yellow
                $firewallPoliciesFoundDevice = [System.Collections.ArrayList]::new()
                $processedFirewallIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForFirewallDevice = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesFirewallDevice = $configPoliciesForFirewallDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
                
                if ($matchingConfigPoliciesFirewallDevice) {
                    foreach ($policy in $matchingConfigPoliciesFirewallDevice) {
                        if ($processedFirewallIdsDevice.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if (($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId) -or
                                    ($assignmentDetail.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$firewallPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$firewallPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForFirewallDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsFirewallDevice = $allIntentsForFirewallDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

                if ($matchingIntentsFirewallDevice) {
                    foreach ($policy in $matchingIntentsFirewallDevice) {
                        if ($processedFirewallIdsDevice.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if (($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId) -or
                                    ($assignmentDetails.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$firewallPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$firewallPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.FirewallProfiles = $firewallPoliciesFoundDevice

                # Get Endpoint Security - Endpoint Detection and Response Policies
                Write-Host "Fetching EDR Policies" -ForegroundColor Yellow
                $edrPoliciesFoundDevice = [System.Collections.ArrayList]::new()
                $processedEDRIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForEDRDevice = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesEDRDevice = $configPoliciesForEDRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

                if ($matchingConfigPoliciesEDRDevice) {
                    foreach ($policy in $matchingConfigPoliciesEDRDevice) {
                        if ($processedEDRIdsDevice.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if (($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId) -or
                                    ($assignmentDetail.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$edrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$edrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForEDRDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsEDRDevice = $allIntentsForEDRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
                
                if ($matchingIntentsEDRDevice) {
                    foreach ($policy in $matchingIntentsEDRDevice) {
                        if ($processedEDRIdsDevice.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if (($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId) -or
                                    ($assignmentDetails.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$edrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$edrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.EndpointDetectionProfiles = $edrPoliciesFoundDevice

                # Get Endpoint Security - Attack Surface Reduction Policies
                Write-Host "Fetching ASR Policies" -ForegroundColor Yellow
                $asrPoliciesFoundDevice = [System.Collections.ArrayList]::new()
                $processedASRIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

                # 1. Check configurationPolicies
                $configPoliciesForASRDevice = Get-IntuneEntities -EntityType "configurationPolicies"
                $matchingConfigPoliciesASRDevice = $configPoliciesForASRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

                if ($matchingConfigPoliciesASRDevice) {
                    foreach ($policy in $matchingConfigPoliciesASRDevice) {
                        if ($processedASRIdsDevice.Add($policy.id)) {
                            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                            foreach ($assignmentDetail in $assignments) {
                                if (($assignmentDetail.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetail.GroupId) -or
                                    ($assignmentDetail.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetail.Reason -Force
                                    [void]$asrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetail.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetail.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$asrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }

                # 2. Check deviceManagement/intents
                $allIntentsForASRDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $matchingIntentsASRDevice = $allIntentsForASRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

                if ($matchingIntentsASRDevice) {
                    foreach ($policy in $matchingIntentsASRDevice) {
                        if ($processedASRIdsDevice.Add($policy.id)) {
                            $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                            $assignments = $assignmentsResponse.value
                            foreach ($assignment in $assignments) {
                                $assignmentDetails = @{
                                    Reason  = switch ($assignment.target.'@odata.type') {
                                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                        '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                        default { "Unknown" }
                                    }
                                    GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                                }
                                if (($assignmentDetails.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignmentDetails.GroupId) -or
                                    ($assignmentDetails.Reason -eq "All Devices")) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentDetails.Reason -Force
                                    [void]$asrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                                elseif ($assignmentDetails.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignmentDetails.GroupId) {
                                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded" -Force
                                    [void]$asrPoliciesFoundDevice.Add($policy)
                                    break
                                }
                            }
                        }
                    }
                }
                $relevantPolicies.AttackSurfaceProfiles = $asrPoliciesFoundDevice

                # Get Applications
                Write-Host "Fetching Applications..." -ForegroundColor Yellow
                # Fetch Applications
                $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink') {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count

                foreach ($app in $allApps) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn) {
                        continue
                    }

                    $appId = $app.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    $isExcluded = $false
                    $isIncluded = $false
                    $inclusionReason = ""
                    $exclusionReason = ""

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                            $groupMemberships.id -contains $assignment.target.groupId) {
                            $isExcluded = $true
                            $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                            $exclusionReason = "Excluded via group: $($groupInfo.DisplayName)"
                            break
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $isIncluded = $true
                            $inclusionReason = "All Devices"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                            $groupMemberships.id -contains $assignment.target.groupId) {
                            $isIncluded = $true
                            $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                            $inclusionReason = "Group Assignment - $($groupInfo.DisplayName)"
                        }
                    }

                    if ($isExcluded) {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $exclusionReason -Force
                        switch ($assignment.intent) {
                            "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                            "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                            "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                        }
                    }
                    elseif ($isIncluded) {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $inclusionReason -Force
                        switch ($assignment.intent) {
                            "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                            "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                            "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                        }
                    }
                }
 
                # Display results
                Write-Host "`nAssignments for Device: $deviceName" -ForegroundColor Green

                # Function to format and display policy table
                function Format-PolicyTable {
                    param (
                        [string]$Title,
                        [object[]]$Policies,
                        [scriptblock]$GetName,
                        [scriptblock]$GetExtra = { param($p) "" }
                    )
                    $tableSeparator = "-" * 120 # Define at the start for use in empty case

                    # Create prominent section header
                    $headerSeparator = "-" * ($Title.Length + 16)
                    Write-Host "`n$headerSeparator" -ForegroundColor Cyan
                    Write-Host "------- $Title -------" -ForegroundColor Cyan
                    Write-Host "$headerSeparator" -ForegroundColor Cyan
                    
                    if ($Policies.Count -eq 0) {
                        Write-Host "No $Title found for this device." -ForegroundColor Gray
                        Write-Host $tableSeparator -ForegroundColor Gray # Print bottom line for empty table
                        Write-Host ""
                        return
                    }

                    # Create table header with custom formatting (this is for when policies exist)
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "ID", "Assignment"
                    
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $tableSeparator -ForegroundColor Gray # This is the line under the headers
                    
                    # Display each policy in table format
                    foreach ($policy in $Policies) {
                        $name = & $GetName $policy
                        $extra = & $GetExtra $policy
                        
                        # Truncate long names and add ellipsis
                        if ($name.Length -gt 47) {
                            $name = $name.Substring(0, 44) + "..."
                        }
                        
                        # Format ID
                        $id = $policy.id
                        if ($id.Length -gt 37) {
                            $id = $id.Substring(0, 34) + "..."
                        }
                        
                        # Format assignment reason
                        $assignment = if ($policy.AssignmentReason) { $policy.AssignmentReason } else { "No Assignment" }
                        if ($assignment.Length -gt 27) {
                            $assignment = $assignment.Substring(0, 24) + "..."
                        }
                        
                        # Output formatted row
                        $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $name, $id, $assignment
                        if ($assignment -eq "Excluded" -or $assignment -like "*Exclusion*") {
                            Write-Host $rowFormat -ForegroundColor Red
                        }
                        else {
                            Write-Host $rowFormat -ForegroundColor White
                        }
                    }
                    
                    Write-Host $tableSeparator -ForegroundColor Gray # This is the closing line of the table
                }

                # Display Device Configurations
                Format-PolicyTable -Title "Device Configurations" -Policies $relevantPolicies.DeviceConfigs -GetName {
                    param($config)
                    if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                }

                # Display Settings Catalog Policies
                Format-PolicyTable -Title "Settings Catalog Policies" -Policies $relevantPolicies.SettingsCatalog -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display Administrative Templates
                Format-PolicyTable -Title "Administrative Templates" -Policies $relevantPolicies.AdminTemplates -GetName {
                    param($template)
                    if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                }

                # Display Compliance Policies
                Format-PolicyTable -Title "Compliance Policies" -Policies $relevantPolicies.CompliancePolicies -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display App Protection Policies
                Format-PolicyTable -Title "App Protection Policies" -Policies $relevantPolicies.AppProtectionPolicies -GetName {
                    param($policy)
                    $policy.displayName
                } -GetExtra {
                    param($policy)
                    @{
                        Label = 'Platform'
                        Value = switch ($policy.'@odata.type') {
                            "#microsoft.graph.androidManagedAppProtection" { "Android" }
                            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                            default { "Unknown" }
                        }
                    }
                }

                # Display App Configuration Policies
                Format-PolicyTable -Title "App Configuration Policies" -Policies $relevantPolicies.AppConfigurationPolicies -GetName {
                    param($policy)
                    if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                }

                # Display Platform Scripts
                Format-PolicyTable -Title "Platform Scripts" -Policies $relevantPolicies.PlatformScripts -GetName {
                    param($script)
                    if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                }

                # Display Proactive Remediation Scripts
                Format-PolicyTable -Title "Proactive Remediation Scripts" -Policies $relevantPolicies.HealthScripts -GetName {
                    param($script)
                    if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                }

                # Display Required Apps
                Format-PolicyTable -Title "Required Apps" -Policies $relevantPolicies.AppsRequired -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Available Apps
                Format-PolicyTable -Title "Available Apps" -Policies $relevantPolicies.AppsAvailable -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Uninstall Apps
                Format-PolicyTable -Title "Uninstall Apps" -Policies $relevantPolicies.AppsUninstall -GetName {
                    param($app)
                    $app.displayName
                }

                # Display Endpoint Security - Antivirus Profiles
                Format-PolicyTable -Title "Endpoint Security - Antivirus Profiles" -Policies $relevantPolicies.AntivirusProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Disk Encryption Profiles
                Format-PolicyTable -Title "Endpoint Security - Disk Encryption Profiles" -Policies $relevantPolicies.DiskEncryptionProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Firewall Profiles
                Format-PolicyTable -Title "Endpoint Security - Firewall Profiles" -Policies $relevantPolicies.FirewallProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Endpoint Detection and Response Profiles
                Format-PolicyTable -Title "Endpoint Security - EDR Profiles" -Policies $relevantPolicies.EndpointDetectionProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }
                
                # Display Endpoint Security - Attack Surface Reduction Profiles
                Format-PolicyTable -Title "Endpoint Security - ASR Profiles" -Policies $relevantPolicies.AttackSurfaceProfiles -GetName { param($profile) if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed Profile" } }

                # Add to export data
                Add-ExportData -ExportData $exportData -Category "Device" -Items @([PSCustomObject]@{
                        displayName      = $deviceName
                        id               = $deviceInfo.Id
                        AssignmentReason = "N/A"
                    }

                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $relevantPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $relevantPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $relevantPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $relevantPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $relevantPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $relevantPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $relevantPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $relevantPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $relevantPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $relevantPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $relevantPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $relevantPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $relevantPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $relevantPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }
                )
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneDeviceAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '4' {
            Write-Host "Fetching all policies and their assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for all policies
            $allPolicies = @{
                DeviceConfigs               = @()
                SettingsCatalog             = @()
                AdminTemplates              = @()
                CompliancePolicies          = @()
                AppProtectionPolicies       = @()
                AppConfigurationPolicies    = @()
                PlatformScripts             = @()
                HealthScripts               = @()
                AntivirusProfiles           = @()
                DiskEncryptionProfiles      = @()
                FirewallProfiles            = @()
                EndpointDetectionProfiles   = @()
                AttackSurfaceProfiles       = @()
                DeploymentProfiles          = @()
                ESPProfiles                 = @()
                CloudPCProvisioningPolicies = @()
                CloudPCUserSettings         = @()
            }

            # Function to process and display policy assignments
            function Process-PolicyAssignments {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$PolicyType,
                    
                    [Parameter(Mandatory = $false)] # Changed from $true
                    [object[]]$Policies,
                    
                    [Parameter(Mandatory = $true)]
                    [string]$DisplayName
                )

                if ($null -eq $Policies -or $Policies.Count -eq 0) {
                    Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
                    Write-Host "No policies found for this category." -ForegroundColor Gray
                    Write-Host ""
                    return
                }
                
                Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
                foreach ($policy in $Policies) {
                    $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Profile" }
                    Write-Host "Policy Name: $policyName" -ForegroundColor White
                    Write-Host "Policy ID: $($policy.id)" -ForegroundColor Gray
                    if ($policy.AssignmentSummary) {
                        Write-Host "Assignments: $($policy.AssignmentSummary)" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "No assignments found" -ForegroundColor Yellow
                    }
                    Write-Host ""
                }
            }

            # Get Device Configurations
            Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            foreach ($config in $deviceConfigs) {
                $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $config | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.DeviceConfigs += $config
            }

            # Get Settings Catalog Policies
            Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            foreach ($policy in $settingsCatalog) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.SettingsCatalog += $policy
            }

            # Get Administrative Templates
            Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            foreach ($template in $adminTemplates) {
                $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $template | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.AdminTemplates += $template
            }

            # Get Compliance Policies
            Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
            $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
            foreach ($policy in $compliancePolicies) {
                $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.CompliancePolicies += $policy
            }

            # Get App Protection Policies
            Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
            $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
            foreach ($policy in $appProtectionPolicies) {
                $policyType = $policy.'@odata.type'
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    try {
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                        $assignments = @()
                        foreach ($assignment in $assignmentResponse.value) {
                            $assignmentReason = $null
                            $groupId = $null
                            switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                                    $assignmentReason = "All Users"
                                }
                                '#microsoft.graph.groupAssignmentTarget' {
                                    $groupId = $assignment.target.groupId
                                    if (!$GroupId -or $groupId -eq $GroupId) {
                                        $groupInfo = Get-GroupInfo -GroupId $groupId
                                        $assignmentReason = "Group Assignment - $($groupInfo.DisplayName)"
                                    }
                                }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' {
                                    $groupId = $assignment.target.groupId
                                    if (!$GroupId -or $groupId -eq $GroupId) {
                                        $groupInfo = Get-GroupInfo -GroupId $groupId
                                        $assignmentReason = "Group Exclusion - $($groupInfo.DisplayName)"
                                    }
                                }
                            }

                            if ($assignmentReason) {
                                $assignments += $assignmentReason
                            }
                        }

                        if ($assignments.Count -gt 0) {
                            $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignments -join "; ") -Force
                            $allPolicies.AppProtectionPolicies += $policy
                        }
                    }
                    catch {
                        Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }

            # Get App Configuration Policies
            Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
            $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
            foreach ($policy in $appConfigPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.AppConfigurationPolicies += $policy
            }

            # Get Platform Scripts
            Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
            $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
            foreach ($script in $platformScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $script | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.PlatformScripts += $script
            }

            # Get Proactive Remediation Scripts
            Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
            $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
            foreach ($script in $healthScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else {
                        $_.Reason
                    }
                }
                $script | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.HealthScripts += $script
            }

            # Get Autopilot Deployment Profiles
            Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
            $autoProfilesAll = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
            foreach ($profile in $autoProfilesAll) {
                $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $profile | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.DeploymentProfiles += $profile
            }

            # Get Enrollment Status Page Profiles
            Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
            $enrollmentConfigsAll = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
            $espProfilesAll = $enrollmentConfigsAll | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
            foreach ($esp in $espProfilesAll) {
                $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $esp | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                $allPolicies.ESPProfiles += $esp
            }

            # Get Windows 365 Cloud PC Provisioning Policies
            Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
            try {
                $cloudPCProvisioningPoliciesAll = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
                foreach ($policy in $cloudPCProvisioningPoliciesAll) {
                    $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
                    $assignmentSummary = $assignments | ForEach-Object {
                        if ($_.Reason -eq "Group Assignment") {
                            $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                            "$($_.Reason) - $($groupInfo.DisplayName)"
                        }
                        else { $_.Reason }
                    }
                    $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                    $allPolicies.CloudPCProvisioningPolicies += $policy
                }
            }
            catch {
                Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
            }

            # Get Windows 365 Cloud PC User Settings
            Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
            try {
                $cloudPCUserSettingsAll = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
                foreach ($setting in $cloudPCUserSettingsAll) {
                    $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
                    $assignmentSummary = $assignments | ForEach-Object {
                        if ($_.Reason -eq "Group Assignment") {
                            $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                            "$($_.Reason) - $($groupInfo.DisplayName)"
                        }
                        else { $_.Reason }
                    }
                    $setting | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                    $allPolicies.CloudPCUserSettings += $setting
                }
            }
            catch {
                Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
            }

            # Get Endpoint Security - Antivirus Policies
            Write-Host "Fetching Antivirus Policies..." -ForegroundColor Yellow
            $antivirusPoliciesFoundAll = [System.Collections.ArrayList]::new()
            $processedAntivirusIdsAll = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForAntivirusAll = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesAntivirusAll = $configPoliciesForAntivirusAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

            if ($matchingConfigPoliciesAntivirusAll) {
                foreach ($policy in $matchingConfigPoliciesAntivirusAll) {
                    if ($processedAntivirusIdsAll.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        $assignmentSummary = $assignments | ForEach-Object {
                            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                "$($_.Reason) - $($groupInfo.DisplayName)"
                            }
                            else { $_.Reason }
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$antivirusPoliciesFoundAll.Add($policy)
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForAntivirusAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsAntivirusAll = $allIntentsForAntivirusAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
            
            if ($matchingIntentsAntivirusAll) {
                foreach ($policy in $matchingIntentsAntivirusAll) {
                    if ($processedAntivirusIdsAll.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                            $reasonText = switch ($_.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                default { "Unknown" }
                            }
                            $reasonText
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$antivirusPoliciesFoundAll.Add($policy)
                    }
                }
            }
            $allPolicies.AntivirusProfiles = $antivirusPoliciesFoundAll

            # Get Endpoint Security - Disk Encryption Policies
            Write-Host "Fetching Disk Encryption Policies..." -ForegroundColor Yellow
            $diskEncryptionPoliciesFoundAll = [System.Collections.ArrayList]::new()
            $processedDiskEncryptionIdsAll = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForDiskEncAll = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesDiskEncAll = $configPoliciesForDiskEncAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

            if ($matchingConfigPoliciesDiskEncAll) {
                foreach ($policy in $matchingConfigPoliciesDiskEncAll) {
                    if ($processedDiskEncryptionIdsAll.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        $assignmentSummary = $assignments | ForEach-Object {
                            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                "$($_.Reason) - $($groupInfo.DisplayName)"
                            }
                            else { $_.Reason }
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$diskEncryptionPoliciesFoundAll.Add($policy)
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForDiskEncAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsDiskEncAll = $allIntentsForDiskEncAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

            if ($matchingIntentsDiskEncAll) {
                foreach ($policy in $matchingIntentsDiskEncAll) {
                    if ($processedDiskEncryptionIdsAll.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                            $reasonText = switch ($_.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                default { "Unknown" }
                            }
                            $reasonText
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$diskEncryptionPoliciesFoundAll.Add($policy)
                    }
                }
            }
            $allPolicies.DiskEncryptionProfiles = $diskEncryptionPoliciesFoundAll

            # Get Endpoint Security - Firewall Policies
            Write-Host "Fetching Firewall Policies..." -ForegroundColor Yellow
            $firewallPoliciesFoundAll = [System.Collections.ArrayList]::new()
            $processedFirewallIdsAll = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForFirewallAll = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesFirewallAll = $configPoliciesForFirewallAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
            
            if ($matchingConfigPoliciesFirewallAll) {
                foreach ($policy in $matchingConfigPoliciesFirewallAll) {
                    if ($processedFirewallIdsAll.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        $assignmentSummary = $assignments | ForEach-Object {
                            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                "$($_.Reason) - $($groupInfo.DisplayName)"
                            }
                            else { $_.Reason }
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$firewallPoliciesFoundAll.Add($policy)
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForFirewallAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsFirewallAll = $allIntentsForFirewallAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

            if ($matchingIntentsFirewallAll) {
                foreach ($policy in $matchingIntentsFirewallAll) {
                    if ($processedFirewallIdsAll.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                            $reasonText = switch ($_.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                default { "Unknown" }
                            }
                            $reasonText
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$firewallPoliciesFoundAll.Add($policy)
                    }
                }
            }
            $allPolicies.FirewallProfiles = $firewallPoliciesFoundAll

            # Get Endpoint Security - Endpoint Detection and Response Policies
            Write-Host "Fetching EDR Policies..." -ForegroundColor Yellow
            $edrPoliciesFoundAll = [System.Collections.ArrayList]::new()
            $processedEDRIdsAll = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForEDRAll = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesEDRAll = $configPoliciesForEDRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

            if ($matchingConfigPoliciesEDRAll) {
                foreach ($policy in $matchingConfigPoliciesEDRAll) {
                    if ($processedEDRIdsAll.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        $assignmentSummary = $assignments | ForEach-Object {
                            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                "$($_.Reason) - $($groupInfo.DisplayName)"
                            }
                            else { $_.Reason }
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$edrPoliciesFoundAll.Add($policy)
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForEDRAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsEDRAll = $allIntentsForEDRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

            if ($matchingIntentsEDRAll) {
                foreach ($policy in $matchingIntentsEDRAll) {
                    if ($processedEDRIdsAll.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                            $reasonText = switch ($_.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                default { "Unknown" }
                            }
                            $reasonText
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$edrPoliciesFoundAll.Add($policy)
                    }
                }
            }
            $allPolicies.EndpointDetectionProfiles = $edrPoliciesFoundAll

            # Get Endpoint Security - Attack Surface Reduction Policies
            Write-Host "Fetching ASR Policies..." -ForegroundColor Yellow
            $asrPoliciesFoundAll = [System.Collections.ArrayList]::new()
            $processedASRIdsAll = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForASRAll = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesASRAll = $configPoliciesForASRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

            if ($matchingConfigPoliciesASRAll) {
                foreach ($policy in $matchingConfigPoliciesASRAll) {
                    if ($processedASRIdsAll.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        $assignmentSummary = $assignments | ForEach-Object {
                            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                "$($_.Reason) - $($groupInfo.DisplayName)"
                            }
                            else { $_.Reason }
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$asrPoliciesFoundAll.Add($policy)
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForASRAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsASRAll = $allIntentsForASRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

            if ($matchingIntentsASRAll) {
                foreach ($policy in $matchingIntentsASRAll) {
                    if ($processedASRIdsAll.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                            $reasonText = switch ($_.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                                default { "Unknown" }
                            }
                            $reasonText
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                        [void]$asrPoliciesFoundAll.Add($policy)
                    }
                }
            }
            $allPolicies.AttackSurfaceProfiles = $asrPoliciesFoundAll

            # Display all policies and their assignments
            Process-PolicyAssignments -PolicyType "deviceConfigurations" -Policies $allPolicies.DeviceConfigs -DisplayName "Device Configurations"
            Process-PolicyAssignments -PolicyType "configurationPolicies" -Policies $allPolicies.SettingsCatalog -DisplayName "Settings Catalog Policies"
            Process-PolicyAssignments -PolicyType "groupPolicyConfigurations" -Policies $allPolicies.AdminTemplates -DisplayName "Administrative Templates"
            Process-PolicyAssignments -PolicyType "deviceCompliancePolicies" -Policies $allPolicies.CompliancePolicies -DisplayName "Compliance Policies"
            Process-PolicyAssignments -PolicyType "managedAppPolicies" -Policies $allPolicies.AppProtectionPolicies -DisplayName "App Protection Policies"
            Process-PolicyAssignments -PolicyType "mobileAppConfigurations" -Policies $allPolicies.AppConfigurationPolicies -DisplayName "App Configuration Policies"
            Process-PolicyAssignments -PolicyType "deviceManagementScripts" -Policies $allPolicies.PlatformScripts -DisplayName "Platform Scripts"
            Process-PolicyAssignments -PolicyType "deviceHealthScripts" -Policies $allPolicies.HealthScripts -DisplayName "Proactive Remediation Scripts"
            Process-PolicyAssignments -PolicyType "windowsAutopilotDeploymentProfiles" -Policies $allPolicies.DeploymentProfiles -DisplayName "Autopilot Deployment Profiles"
            Process-PolicyAssignments -PolicyType "deviceEnrollmentConfigurations" -Policies $allPolicies.ESPProfiles -DisplayName "Enrollment Status Page Profiles"
            Process-PolicyAssignments -PolicyType "virtualEndpoint/provisioningPolicies" -Policies $allPolicies.CloudPCProvisioningPolicies -DisplayName "Windows 365 Cloud PC Provisioning Policies"
            Process-PolicyAssignments -PolicyType "virtualEndpoint/userSettings" -Policies $allPolicies.CloudPCUserSettings -DisplayName "Windows 365 Cloud PC User Settings"
            Process-PolicyAssignments -PolicyType "deviceManagementIntents" -Policies $allPolicies.AntivirusProfiles -DisplayName "Endpoint Security - Antivirus Profiles"
            Process-PolicyAssignments -PolicyType "deviceManagementIntents" -Policies $allPolicies.DiskEncryptionProfiles -DisplayName "Endpoint Security - Disk Encryption Profiles"
            Process-PolicyAssignments -PolicyType "deviceManagementIntents" -Policies $allPolicies.FirewallProfiles -DisplayName "Endpoint Security - Firewall Profiles"
            Process-PolicyAssignments -PolicyType "deviceManagementIntents" -Policies $allPolicies.EndpointDetectionProfiles -DisplayName "Endpoint Security - EDR Profiles"
            Process-PolicyAssignments -PolicyType "deviceManagementIntents" -Policies $allPolicies.AttackSurfaceProfiles -DisplayName "Endpoint Security - ASR Profiles"

            # Add to export data
            Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $allPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $allPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $allPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $allPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $allPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $allPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $allPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $allPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items $allPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items $allPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $allPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $allPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $allPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $allPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $allPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $allPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $allPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentSummary }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllPolicies.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '5' {
            Write-Host "Fetching all 'All Users' assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for policies with "All Users" assignments
            $allUsersAssignments = @{
                DeviceConfigs            = @()
                SettingsCatalog          = @()
                AdminTemplates           = @()
                CompliancePolicies       = @()
                AppProtectionPolicies    = @()
                AppConfigurationPolicies = @()
                PlatformScripts          = @()
                HealthScripts            = @()
                RequiredApps             = @()
                AvailableApps            = @()
                UninstallApps            = @()
                DeploymentProfiles       = @()
                ESPProfiles              = @()
            }

            # Get Device Configurations
            Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            foreach ($config in $deviceConfigs) {
                $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.DeviceConfigs += $config
                }
            }

            # Get Settings Catalog Policies
            Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            foreach ($policy in $settingsCatalog) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.SettingsCatalog += $policy
                }
            }

            # Get Administrative Templates
            Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            foreach ($template in $adminTemplates) {
                $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.AdminTemplates += $template
                }
            }

            # Get Compliance Policies
            Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
            $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
            foreach ($policy in $compliancePolicies) {
                $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.CompliancePolicies += $policy
                }
            }

            # Get App Protection Policies
            Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
            $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
            foreach ($policy in $appProtectionPolicies) {
                $policyType = $policy.'@odata.type'
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    try {
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                        $hasAllUsers = $false
                        foreach ($assignment in $assignmentResponse.value) {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                                $hasAllUsers = $true
                                break
                            }
                        }
                        if ($hasAllUsers) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            $allUsersAssignments.AppProtectionPolicies += $policy
                        }
                    }
                    catch {
                        Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }

            # Get App Configuration Policies
            Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
            $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
            foreach ($policy in $appConfigPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.AppConfigurationPolicies += $policy
                }
            }

            # Get Applications
            Write-Host "Fetching Applications..." -ForegroundColor Yellow
            # Fetch Applications
            $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $allApps = $appResponse.value
            while ($appResponse.'@odata.nextLink') {
                $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                $allApps += $appResponse.value
            }
            $totalApps = $allApps.Count

            foreach ($app in $allApps) {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn) {
                    continue
                }

                $appId = $app.id
                $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                        switch ($assignment.intent) {
                            "required" { $allUsersAssignments.RequiredApps += $appWithReason; break }
                            "available" { $allUsersAssignments.AvailableApps += $appWithReason; break }
                            "uninstall" { $allUsersAssignments.UninstallApps += $appWithReason; break }
                        }
                        break
                    }
                }
            }   

            # Get Platform Scripts
            Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
            $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
            foreach ($script in $platformScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.PlatformScripts += $script
                }
            }

            # Get Proactive Remediation Scripts
            Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
            $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
            foreach ($script in $healthScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.HealthScripts += $script
                }
            }

            # Get Endpoint Security - Antivirus Policies
            Write-Host "Fetching Antivirus Policies assigned to All Users..." -ForegroundColor Yellow
            $antivirusPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
            $processedAntivirusIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies
            $configPoliciesForAntivirus_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesAntivirus_AllUsers = $configPoliciesForAntivirus_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

            if ($matchingConfigPoliciesAntivirus_AllUsers) {
                foreach ($policy in $matchingConfigPoliciesAntivirus_AllUsers) {
                    if ($processedAntivirusIds_AllUsers.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$antivirusPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForAntivirus_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsAntivirus_AllUsers = $allIntentsForAntivirus_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

            if ($matchingIntentsAntivirus_AllUsers) {
                foreach ($policy in $matchingIntentsAntivirus_AllUsers) {
                    if ($processedAntivirusIds_AllUsers.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$antivirusPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }
            $allUsersAssignments.AntivirusProfiles = $antivirusPoliciesFound_AllUsers

            # Get Endpoint Security - Disk Encryption Policies
            Write-Host "Fetching Disk Encryption Policies assigned to All Users..." -ForegroundColor Yellow
            $diskEncryptionPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
            # Note: Re-using $processedDiskEncryptionIds_AllUsers from Antivirus for simplicity,
            # assuming policy IDs are unique across ES types or we want to process once per ID overall for this menu option.
            # If IDs can overlap meaningfully between ES types and need separate tracking, declare a new HashSet here.
            # For this context (All Users assignments), it's likely fine.
            $processedDiskEncryptionIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()


            # 1. Check configurationPolicies
            $configPoliciesForDiskEnc_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesDiskEnc_AllUsers = $configPoliciesForDiskEnc_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
            
            if ($matchingConfigPoliciesDiskEnc_AllUsers) {
                foreach ($policy in $matchingConfigPoliciesDiskEnc_AllUsers) {
                    if ($processedDiskEncryptionIds_AllUsers.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$diskEncryptionPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForDiskEnc_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsDiskEnc_AllUsers = $allIntentsForDiskEnc_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

            if ($matchingIntentsDiskEnc_AllUsers) {
                foreach ($policy in $matchingIntentsDiskEnc_AllUsers) {
                    if ($processedDiskEncryptionIds_AllUsers.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$diskEncryptionPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }
            $allUsersAssignments.DiskEncryptionProfiles = $diskEncryptionPoliciesFound_AllUsers

            # Get Endpoint Security - Firewall Policies
            Write-Host "Fetching Firewall Policies assigned to All Users..." -ForegroundColor Yellow
            $firewallPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
            $processedFirewallIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new() # Reset for this type

            # 1. Check configurationPolicies
            $configPoliciesForFirewall_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesFirewall_AllUsers = $configPoliciesForFirewall_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

            if ($matchingConfigPoliciesFirewall_AllUsers) {
                foreach ($policy in $matchingConfigPoliciesFirewall_AllUsers) {
                    if ($processedFirewallIds_AllUsers.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$firewallPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForFirewall_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsFirewall_AllUsers = $allIntentsForFirewall_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

            if ($matchingIntentsFirewall_AllUsers) {
                foreach ($policy in $matchingIntentsFirewall_AllUsers) {
                    if ($processedFirewallIds_AllUsers.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$firewallPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }
            $allUsersAssignments.FirewallProfiles = $firewallPoliciesFound_AllUsers

            # Get Endpoint Security - Endpoint Detection and Response Policies
            Write-Host "Fetching EDR Policies assigned to All Users..." -ForegroundColor Yellow
            $edrPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
            $processedEDRIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new() # Reset for this type

            # 1. Check configurationPolicies
            $configPoliciesForEDR_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesEDR_AllUsers = $configPoliciesForEDR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

            if ($matchingConfigPoliciesEDR_AllUsers) {
                foreach ($policy in $matchingConfigPoliciesEDR_AllUsers) {
                    if ($processedEDRIds_AllUsers.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$edrPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForEDR_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsEDR_AllUsers = $allIntentsForEDR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

            if ($matchingIntentsEDR_AllUsers) {
                foreach ($policy in $matchingIntentsEDR_AllUsers) {
                    if ($processedEDRIds_AllUsers.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$edrPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }
            $allUsersAssignments.EndpointDetectionProfiles = $edrPoliciesFound_AllUsers

            # Get Endpoint Security - Attack Surface Reduction Policies
            Write-Host "Fetching ASR Policies assigned to All Users..." -ForegroundColor Yellow
            $asrPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
            $processedASRIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new() # Reset for this type

            # 1. Check configurationPolicies
            $configPoliciesForASR_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesASR_AllUsers = $configPoliciesForASR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

            if ($matchingConfigPoliciesASR_AllUsers) {
                foreach ($policy in $matchingConfigPoliciesASR_AllUsers) {
                    if ($processedASRIds_AllUsers.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$asrPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents
            $allIntentsForASR_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsASR_AllUsers = $allIntentsForASR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }

            if ($matchingIntentsASR_AllUsers) {
                foreach ($policy in $matchingIntentsASR_AllUsers) {
                    if ($processedASRIds_AllUsers.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                            [void]$asrPoliciesFound_AllUsers.Add($policy)
                        }
                    }
                }
            }
            $allUsersAssignments.AttackSurfaceProfiles = $asrPoliciesFound_AllUsers
            
            # Get Autopilot Deployment Profiles
            Write-Host "Fetching Autopilot Deployment Profiles assigned to All Users..." -ForegroundColor Yellow
            $autoProfilesAU = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
            foreach ($profile in $autoProfilesAU) {
                $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.DeploymentProfiles += $profile
                }
            }

            # Get Enrollment Status Page Profiles
            Write-Host "Fetching Enrollment Status Page Profiles assigned to All Users..." -ForegroundColor Yellow
            $enrollmentConfigsAU = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
            $espProfilesAU = $enrollmentConfigsAU | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
            foreach ($esp in $espProfilesAU) {
                $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
                if ($assignments | Where-Object { $_.Reason -eq "All Users" }) {
                    $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                    $allUsersAssignments.ESPProfiles += $esp
                }
            }

            # Display results
            Write-Host "`nPolicies Assigned to All Users:" -ForegroundColor Green

            # Display Device Configurations
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            if ($allUsersAssignments.DeviceConfigs.Count -eq 0) {
                Write-Host "No Device Configurations assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($config in $allUsersAssignments.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $platform = Get-PolicyPlatform -Policy $config
                    Write-Host "Device Configuration Name: $configName, Platform: $platform, Configuration ID: $($config.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items @($config) -AssignmentReason "All Users"
                }
            }

            # Display Settings Catalog Policies
            Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
            if ($allUsersAssignments.SettingsCatalog.Count -eq 0) {
                Write-Host "No Settings Catalog Policies assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allUsersAssignments.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items @($policy) -AssignmentReason "All Users"
                }
            }

            # Display Administrative Templates
            Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AdminTemplates.Count -eq 0) {
                Write-Host "No Administrative Templates assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($template in $allUsersAssignments.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items @($template) -AssignmentReason "All Users"
                }
            }

            # Display Compliance Policies
            Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
            if ($allUsersAssignments.CompliancePolicies.Count -eq 0) {
                Write-Host "No Compliance Policies assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allUsersAssignments.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $platform = Get-PolicyPlatform -Policy $policy
                    Write-Host "Compliance Policy Name: $policyName, Platform: $platform, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items @($policy) -AssignmentReason "All Users"
                }
            }

            # Display App Protection Policies
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AppProtectionPolicies.Count -eq 0) {
                Write-Host "No App Protection Policies assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allUsersAssignments.AppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $($policy.id), Type: $policyType" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items @($policy) -AssignmentReason "All Users"
                }
            }

            # Display App Configuration Policies
            Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AppConfigurationPolicies.Count -eq 0) {
                Write-Host "No App Configuration Policies assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allUsersAssignments.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items @($policy) -AssignmentReason "All Users"
                }
            }

            # Display Platform Scripts
            Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
            if ($allUsersAssignments.PlatformScripts.Count -eq 0) {
                Write-Host "No Platform Scripts assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($script in $allUsersAssignments.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items @($script) -AssignmentReason "All Users"
                }
            }

            # Display Proactive Remediation Scripts
            Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
            if ($allUsersAssignments.HealthScripts.Count -eq 0) {
                Write-Host "No Proactive Remediation Scripts assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($script in $allUsersAssignments.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items @($script) -AssignmentReason "All Users"
                }
            }

            # Display Required Apps
            Write-Host "`n------- Required Apps -------" -ForegroundColor Cyan
            if ($allUsersAssignments.RequiredApps.Count -eq 0) {
                Write-Host "No Required Apps assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allUsersAssignments.RequiredApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Required Apps" -Items @($app) -AssignmentReason "All Users"
                }
            }

            # Display Available Apps
            Write-Host "`n------- Available Apps -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AvailableApps.Count -eq 0) {
                Write-Host "No Available Apps assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allUsersAssignments.AvailableApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Available Apps" -Items @($app) -AssignmentReason "All Users"
                }
            }

            # Display Uninstall Apps
            Write-Host "`n------- Uninstall Apps -------" -ForegroundColor Cyan
            if ($allUsersAssignments.UninstallApps.Count -eq 0) {
                Write-Host "No Uninstall Apps assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allUsersAssignments.UninstallApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Uninstall Apps" -Items @($app) -AssignmentReason "All Users"
                }
            }

            # Display Endpoint Security - Antivirus Profiles
            Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AntivirusProfiles.Count -eq 0) {
                Write-Host "No Antivirus Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.AntivirusProfiles) {
                    $profileNameForDisplay = if ($profile.displayName) { $profile.displayName } else { $profile.name }
                    Write-Host "Antivirus Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Endpoint Security - Disk Encryption Profiles
            Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.DiskEncryptionProfiles.Count -eq 0) {
                Write-Host "No Disk Encryption Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.DiskEncryptionProfiles) {
                    $profileNameForDisplay = if ($profile.displayName) { $profile.displayName } else { $profile.name }
                    Write-Host "Disk Encryption Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Endpoint Security - Firewall Profiles
            Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.FirewallProfiles.Count -eq 0) {
                Write-Host "No Firewall Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.FirewallProfiles) {
                    $profileNameForDisplay = if ($profile.displayName) { $profile.displayName } else { $profile.name }
                    Write-Host "Firewall Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Endpoint Security - Endpoint Detection and Response Profiles
            Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.EndpointDetectionProfiles.Count -eq 0) {
                Write-Host "No EDR Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.EndpointDetectionProfiles) {
                    $profileNameForDisplay = if ($profile.displayName) { $profile.displayName } else { $profile.name }
                    Write-Host "EDR Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Endpoint Security - Attack Surface Reduction Profiles
            Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.AttackSurfaceProfiles.Count -eq 0) {
                Write-Host "No ASR Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.AttackSurfaceProfiles) {
                    $profileNameForDisplay = if ($profile.displayName) { $profile.displayName } else { $profile.name }
                    Write-Host "ASR Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Autopilot Deployment Profiles
            Write-Host "`n------- Autopilot Deployment Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.DeploymentProfiles.Count -eq 0) {
                Write-Host "No Autopilot Deployment Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.DeploymentProfiles) {
                    $profileName = if ([string]::IsNullOrWhiteSpace($profile.name)) { $profile.displayName } else { $profile.name }
                    Write-Host "Autopilot Deployment Profile Name: $profileName, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Display Enrollment Status Page Profiles
            Write-Host "`n------- Enrollment Status Page Profiles -------" -ForegroundColor Cyan
            if ($allUsersAssignments.ESPProfiles.Count -eq 0) {
                Write-Host "No Enrollment Status Page Profiles assigned to All Users" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allUsersAssignments.ESPProfiles) {
                    $profileName = if ([string]::IsNullOrWhiteSpace($profile.name)) { $profile.displayName } else { $profile.name }
                    Write-Host "Enrollment Status Page Profile Name: $profileName, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page Profile" -Items @($profile) -AssignmentReason "All Users"
                }
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllUsersAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }     
        '6' {
            Write-Host "Fetching all 'All Devices' assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for policies with "All Devices" assignments
            $allDevicesAssignments = @{
                DeviceConfigs             = @()
                SettingsCatalog           = @()
                AdminTemplates            = @()
                CompliancePolicies        = @()
                AppProtectionPolicies     = @()
                AppConfigurationPolicies  = @()
                PlatformScripts           = @()
                HealthScripts             = @()
                RequiredApps              = @()
                AvailableApps             = @()
                UninstallApps             = @()
                DeploymentProfiles        = @()
                ESPProfiles               = @()
                AntivirusProfiles         = @()
                DiskEncryptionProfiles    = @()
                FirewallProfiles          = @()
                EndpointDetectionProfiles = @()
                AttackSurfaceProfiles     = @()
            }

            # Get Device Configurations
            Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            foreach ($config in $deviceConfigs) {
                $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.DeviceConfigs += $config
                }
            }

            # Get Settings Catalog Policies
            Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            foreach ($policy in $settingsCatalog) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.SettingsCatalog += $policy
                }
            }

            # Get Administrative Templates
            Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            foreach ($template in $adminTemplates) {
                $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.AdminTemplates += $template
                }
            }

            # Get Compliance Policies
            Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
            $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
            foreach ($policy in $compliancePolicies) {
                $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.CompliancePolicies += $policy
                }
            }

            # Get App Protection Policies
            Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
            $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
            foreach ($policy in $appProtectionPolicies) {
                $policyType = $policy.'@odata.type'
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    try {
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                        $hasAllDevices = $false
                        foreach ($assignment in $assignmentResponse.value) {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                                $hasAllDevices = $true
                                break
                            }
                        }
                        if ($hasAllDevices) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            $allDevicesAssignments.AppProtectionPolicies += $policy
                        }
                    }
                    catch {
                        Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }

            # Get App Configuration Policies
            Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
            $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
            foreach ($policy in $appConfigPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.AppConfigurationPolicies += $policy
                }
            }

            # Get Applications
            Write-Host "Fetching Applications..." -ForegroundColor Yellow
            $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $allApps = $appResponse.value
            while ($appResponse.'@odata.nextLink') {
                $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                $allApps += $appResponse.value
            }
            $totalApps = $allApps.Count

            foreach ($app in $allApps) {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn) {
                    continue
                }

                $appId = $app.id
                $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $appWithReason = $app.PSObject.Copy()
                        $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                        switch ($assignment.intent) {
                            "required" { $allDevicesAssignments.RequiredApps += $appWithReason; break }
                            "available" { $allDevicesAssignments.AvailableApps += $appWithReason; break }
                            "uninstall" { $allDevicesAssignments.UninstallApps += $appWithReason; break }
                        }
                        break
                    }
                }
            }

            # Get Platform Scripts
            Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
            $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
            foreach ($script in $platformScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.PlatformScripts += $script
                }
            }

            # Get Proactive Remediation Scripts
            Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
            $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
            foreach ($script in $healthScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.HealthScripts += $script
                }
            }

            # Get Autopilot Deployment Profiles
            Write-Host "Fetching Autopilot Deployment Profiles assigned to All Devices..." -ForegroundColor Yellow
            $autoProfilesAD = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
            foreach ($profile in $autoProfilesAD) {
                $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.DeploymentProfiles += $profile
                }
            }

            # Get Enrollment Status Page Profiles
            Write-Host "Fetching Enrollment Status Page Profiles assigned to All Devices..." -ForegroundColor Yellow
            $enrollmentConfigsAD = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
            $espProfilesAD = $enrollmentConfigsAD | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
            foreach ($esp in $espProfilesAD) {
                $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
                if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                    $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                    $allDevicesAssignments.ESPProfiles += $esp
                }
            }

            # Get Endpoint Security - Antivirus Policies (Dual Check)
            Write-Host "Fetching Antivirus Policies assigned to All Devices..." -ForegroundColor Yellow
            $antivirusPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
            $processedAntivirusIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies for Antivirus
            $configPoliciesForAntivirus_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesAntivirus_AllDevices = $configPoliciesForAntivirus_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
            if ($matchingConfigPoliciesAntivirus_AllDevices) {
                foreach ($policy in $matchingConfigPoliciesAntivirus_AllDevices) {
                    if ($processedAntivirusIds_AllDevices.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$antivirusPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents for Antivirus
            $allIntentsForAntivirus_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsAntivirus_AllDevices = $allIntentsForAntivirus_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
            if ($matchingIntentsAntivirus_AllDevices) {
                foreach ($policy in $matchingIntentsAntivirus_AllDevices) {
                    if ($processedAntivirusIds_AllDevices.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$antivirusPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }
            $allDevicesAssignments.AntivirusProfiles = $antivirusPoliciesFound_AllDevices

            # Get Endpoint Security - Disk Encryption Policies (Dual Check)
            Write-Host "Fetching Disk Encryption Policies assigned to All Devices..." -ForegroundColor Yellow
            $diskEncryptionPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
            $processedDiskEncryptionIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies for Disk Encryption
            $configPoliciesForDiskEnc_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesDiskEnc_AllDevices = $configPoliciesForDiskEnc_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
            if ($matchingConfigPoliciesDiskEnc_AllDevices) {
                foreach ($policy in $matchingConfigPoliciesDiskEnc_AllDevices) {
                    if ($processedDiskEncryptionIds_AllDevices.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$diskEncryptionPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents for Disk Encryption
            $allIntentsForDiskEnc_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsDiskEnc_AllDevices = $allIntentsForDiskEnc_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
            if ($matchingIntentsDiskEnc_AllDevices) {
                foreach ($policy in $matchingIntentsDiskEnc_AllDevices) {
                    if ($processedDiskEncryptionIds_AllDevices.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$diskEncryptionPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }
            $allDevicesAssignments.DiskEncryptionProfiles = $diskEncryptionPoliciesFound_AllDevices

            # Get Endpoint Security - Firewall Policies (Dual Check)
            Write-Host "Fetching Firewall Policies assigned to All Devices..." -ForegroundColor Yellow
            $firewallPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
            $processedFirewallIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies for Firewall
            $configPoliciesForFirewall_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesFirewall_AllDevices = $configPoliciesForFirewall_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
            if ($matchingConfigPoliciesFirewall_AllDevices) {
                foreach ($policy in $matchingConfigPoliciesFirewall_AllDevices) {
                    if ($processedFirewallIds_AllDevices.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$firewallPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents for Firewall
            $allIntentsForFirewall_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsFirewall_AllDevices = $allIntentsForFirewall_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
            if ($matchingIntentsFirewall_AllDevices) {
                foreach ($policy in $matchingIntentsFirewall_AllDevices) {
                    if ($processedFirewallIds_AllDevices.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$firewallPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }
            $allDevicesAssignments.FirewallProfiles = $firewallPoliciesFound_AllDevices

            # Get Endpoint Security - Endpoint Detection and Response Policies (Dual Check)
            Write-Host "Fetching EDR Policies assigned to All Devices..." -ForegroundColor Yellow
            $edrPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
            $processedEDRIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies for EDR
            $configPoliciesForEDR_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesEDR_AllDevices = $configPoliciesForEDR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
            if ($matchingConfigPoliciesEDR_AllDevices) {
                foreach ($policy in $matchingConfigPoliciesEDR_AllDevices) {
                    if ($processedEDRIds_AllDevices.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$edrPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents for EDR
            $allIntentsForEDR_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsEDR_AllDevices = $allIntentsForEDR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
            if ($matchingIntentsEDR_AllDevices) {
                foreach ($policy in $matchingIntentsEDR_AllDevices) {
                    if ($processedEDRIds_AllDevices.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$edrPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }
            $allDevicesAssignments.EndpointDetectionProfiles = $edrPoliciesFound_AllDevices

            # Get Endpoint Security - Attack Surface Reduction Policies (Dual Check)
            Write-Host "Fetching ASR Policies assigned to All Devices..." -ForegroundColor Yellow
            $asrPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
            $processedASRIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

            # 1. Check configurationPolicies for ASR
            $configPoliciesForASR_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
            $matchingConfigPoliciesASR_AllDevices = $configPoliciesForASR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }
            if ($matchingConfigPoliciesASR_AllDevices) {
                foreach ($policy in $matchingConfigPoliciesASR_AllDevices) {
                    if ($processedASRIds_AllDevices.Add($policy.id)) {
                        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                        if ($assignments | Where-Object { $_.Reason -eq "All Devices" }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$asrPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents for ASR
            $allIntentsForASR_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $matchingIntentsASR_AllDevices = $allIntentsForASR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }
            if ($matchingIntentsASR_AllDevices) {
                foreach ($policy in $matchingIntentsASR_AllDevices) {
                    if ($processedASRIds_AllDevices.Add($policy.id)) {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }) {
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                            [void]$asrPoliciesFound_AllDevices.Add($policy)
                        }
                    }
                }
            }
            $allDevicesAssignments.AttackSurfaceProfiles = $asrPoliciesFound_AllDevices

            # Display results
            Write-Host "`nPolicies Assigned to All Devices:" -ForegroundColor Green

            # Display Device Configurations
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.DeviceConfigs.Count -eq 0) {
                Write-Host "No Device Configurations assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($config in $allDevicesAssignments.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $platform = Get-PolicyPlatform -Policy $config
                    Write-Host "Device Configuration Name: $configName, Platform: $platform, Configuration ID: $($config.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items @($config) -AssignmentReason "All Devices"
                }
            }

            # Display Settings Catalog Policies
            Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.SettingsCatalog.Count -eq 0) {
                Write-Host "No Settings Catalog Policies assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allDevicesAssignments.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items @($policy) -AssignmentReason "All Devices"
                }
            }

            # Display Administrative Templates
            Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AdminTemplates.Count -eq 0) {
                Write-Host "No Administrative Templates assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($template in $allDevicesAssignments.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items @($template) -AssignmentReason "All Devices"
                }
            }

            # Display Compliance Policies
            Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.CompliancePolicies.Count -eq 0) {
                Write-Host "No Compliance Policies assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allDevicesAssignments.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $platform = Get-PolicyPlatform -Policy $policy
                    Write-Host "Compliance Policy Name: $policyName, Platform: $platform, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items @($policy) -AssignmentReason "All Devices"
                }
            }

            # Display App Protection Policies
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AppProtectionPolicies.Count -eq 0) {
                Write-Host "No App Protection Policies assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allDevicesAssignments.AppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $($policy.id), Type: $policyType" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items @($policy) -AssignmentReason "All Devices"
                }
            }

            # Display App Configuration Policies
            Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AppConfigurationPolicies.Count -eq 0) {
                Write-Host "No App Configuration Policies assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $allDevicesAssignments.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items @($policy) -AssignmentReason "All Devices"
                }
            }

            # Display Platform Scripts
            Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.PlatformScripts.Count -eq 0) {
                Write-Host "No Platform Scripts assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($script in $allDevicesAssignments.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items @($script) -AssignmentReason "All Devices"
                }
            }

            # Display Proactive Remediation Scripts
            Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.HealthScripts.Count -eq 0) {
                Write-Host "No Proactive Remediation Scripts assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($script in $allDevicesAssignments.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items @($script) -AssignmentReason "All Devices"
                }
            }

            # Display Required Apps
            Write-Host "`n------- Required Apps -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.RequiredApps.Count -eq 0) {
                Write-Host "No Required Apps assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allDevicesAssignments.RequiredApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Required Apps" -Items @($app) -AssignmentReason "All Devices"
                }
            }

            # Display Available Apps
            Write-Host "`n------- Available Apps -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AvailableApps.Count -eq 0) {
                Write-Host "No Available Apps assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allDevicesAssignments.AvailableApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Available Apps" -Items @($app) -AssignmentReason "All Devices"
                }
            }

            # Display Uninstall Apps
            Write-Host "`n------- Uninstall Apps -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.UninstallApps.Count -eq 0) {
                Write-Host "No Uninstall Apps assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($app in $allDevicesAssignments.UninstallApps) {
                    $appName = $app.displayName
                    Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Uninstall Apps" -Items @($app) -AssignmentReason "All Devices"
                }
            }

            # Display Endpoint Security - Antivirus Profiles
            Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AntivirusProfiles.Count -eq 0) {
                Write-Host "No Antivirus Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.AntivirusProfiles) {
                    Write-Host "Antivirus Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Display Endpoint Security - Disk Encryption Profiles
            Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.DiskEncryptionProfiles.Count -eq 0) {
                Write-Host "No Disk Encryption Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.DiskEncryptionProfiles) {
                    Write-Host "Disk Encryption Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Display Endpoint Security - Firewall Profiles
            Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.FirewallProfiles.Count -eq 0) {
                Write-Host "No Firewall Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.FirewallProfiles) {
                    Write-Host "Firewall Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Display Endpoint Security - Endpoint Detection and Response Profiles
            Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.EndpointDetectionProfiles.Count -eq 0) {
                Write-Host "No EDR Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.EndpointDetectionProfiles) {
                    $profileNameForDisplay = if (-not [string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($profile.name)) { $profile.name } else { "Unnamed EDR Profile" }
                    Write-Host "EDR Profile Name: $profileNameForDisplay, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Display Endpoint Security - Attack Surface Reduction Profiles
            Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.AttackSurfaceProfiles.Count -eq 0) {
                Write-Host "No ASR Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.AttackSurfaceProfiles) {
                    Write-Host "ASR Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Display Autopilot Deployment Profiles
            Write-Host "`n------- Autopilot Deployment Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.DeploymentProfiles.Count -eq 0) {
                Write-Host "No Autopilot Deployment Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.DeploymentProfiles) {
                    $profileName = if ([string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.name } else { $profile.displayName }
                    Write-Host "Deployment Profile Name: $profileName, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items @($profile) -AssignmentReason "All Devices"
                }
            }
            
            # Display Enrollment Status Page Profiles
            Write-Host "`n------- Enrollment Status Page Profiles -------" -ForegroundColor Cyan
            if ($allDevicesAssignments.ESPProfiles.Count -eq 0) {
                Write-Host "No Enrollment Status Page Profiles assigned to All Devices" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $allDevicesAssignments.ESPProfiles) {
                    $profileName = if ([string]::IsNullOrWhiteSpace($profile.displayName)) { $profile.name } else { $profile.displayName }
                    Write-Host "Enrollment Status Page Name: $profileName, Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items @($profile) -AssignmentReason "All Devices"
                }
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllDevicesAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '7' {
            Write-Host "Generating HTML Report..." -ForegroundColor Green

            # Download html-export.ps1 from GitHub
            $htmlExportUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/html-export.ps1"
            $scriptPath = Join-Path $env:TEMP 'html-export.ps1'
            
            try {
                Write-Host "Downloading html-export.ps1 from GitHub..." -ForegroundColor Yellow
                Invoke-WebRequest -Uri $htmlExportUrl -OutFile $scriptPath -UseBasicParsing
                Write-Host "Download complete." -ForegroundColor Green
                
                . $scriptPath

                # Generate the report with a fixed filename in the same directory
                $filePath = Join-Path (Get-Location) "IntuneAssignmentReport.html"
                Export-HTMLReport -FilePath $filePath

                # Ask if user wants to open the report
                $openReport = Read-Host "Would you like to open the report now? (y/n)"
                if ($openReport -eq 'y') {
                    Start-Process $filePath
                }

            }
            catch {
                Write-Host "Error: Failed to generate the HTML report. $($_.Exception.Message)" -ForegroundColor Red
            }
            finally {
                # Clean up the downloaded script
                if (Test-Path $scriptPath) {
                    Remove-Item $scriptPath -Force
                    Write-Host "Cleaned up temporary files." -ForegroundColor Gray
                }
            }
        }
        '8' {
            Write-Host "Fetching policies without assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for policies without assignments
            $unassignedPolicies = @{
                DeviceConfigs            = @()
                SettingsCatalog          = @()
                AdminTemplates           = @()
                CompliancePolicies       = @()
                AppProtectionPolicies    = @()
                AppConfigurationPolicies = @()
                PlatformScripts          = @()
                HealthScripts            = @()
            }

            # Get Device Configurations
            Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            foreach ($config in $deviceConfigs) {
                $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.DeviceConfigs += $config
                }
            }

            # Get Settings Catalog Policies
            Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            foreach ($policy in $settingsCatalog) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.SettingsCatalog += $policy
                }
            }

            # Get Administrative Templates
            Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            foreach ($template in $adminTemplates) {
                $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.AdminTemplates += $template
                }
            }

            # Get Compliance Policies
            Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
            $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
            foreach ($policy in $compliancePolicies) {
                $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.CompliancePolicies += $policy
                }
            }

            # Get App Protection Policies
            Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
            $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
            foreach ($policy in $appProtectionPolicies) {
                $policyType = $policy.'@odata.type'
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    try {
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                        if ($assignmentResponse.value.Count -eq 0) {
                            $unassignedPolicies.AppProtectionPolicies += $policy
                        }
                    }
                    catch {
                        Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }

            # Get App Configuration Policies
            Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
            $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
            foreach ($policy in $appConfigPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.AppConfigurationPolicies += $policy
                }
            }

            # Get Platform Scripts
            Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
            $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
            foreach ($script in $platformScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.PlatformScripts += $script
                }
            }

            # Get Proactive Remediation Scripts
            Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
            $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
            foreach ($script in $healthScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                if ($assignments.Count -eq 0) {
                    $unassignedPolicies.HealthScripts += $script
                }
            }

            # Get Endpoint Security - Antivirus Policies
            Write-Host "Fetching Antivirus Policies..." -ForegroundColor Yellow
            $allIntentsForAntivirusUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $antivirusPolicies = $allIntentsForAntivirusUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
            if ($antivirusPolicies) {
                foreach ($policy in $antivirusPolicies) {
                    $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    if ($assignments.value.Count -eq 0) {
                        $unassignedPolicies.AntivirusProfiles += $policy
                    }
                }
            }

            # Get Endpoint Security - Disk Encryption Policies
            Write-Host "Fetching Disk Encryption Policies..." -ForegroundColor Yellow
            $allIntentsForDiskEncUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $diskEncryptionPolicies = $allIntentsForDiskEncUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
            if ($diskEncryptionPolicies) {
                foreach ($policy in $diskEncryptionPolicies) {
                    $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    if ($assignments.value.Count -eq 0) {
                        $unassignedPolicies.DiskEncryptionProfiles += $policy
                    }
                }
            }

            # Get Endpoint Security - Firewall Policies
            Write-Host "Fetching Firewall Policies..." -ForegroundColor Yellow
            $allIntentsForFirewallUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $firewallPolicies = $allIntentsForFirewallUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
            if ($firewallPolicies) {
                foreach ($policy in $firewallPolicies) {
                    $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    if ($assignments.value.Count -eq 0) {
                        $unassignedPolicies.FirewallProfiles += $policy
                    }
                }
            }

            # Get Endpoint Security - Endpoint Detection and Response Policies
            Write-Host "Fetching EDR Policies..." -ForegroundColor Yellow
            $allIntentsForEDRUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $edrPolicies = $allIntentsForEDRUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
            if ($edrPolicies) {
                foreach ($policy in $edrPolicies) {
                    $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    if ($assignments.value.Count -eq 0) {
                        $unassignedPolicies.EndpointDetectionProfiles += $policy
                    }
                }
            }

            # Get Endpoint Security - Attack Surface Reduction Policies
            Write-Host "Fetching ASR Policies..." -ForegroundColor Yellow
            $allIntentsForASRUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
            $asrPolicies = $allIntentsForASRUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }
            if ($asrPolicies) {
                foreach ($policy in $asrPolicies) {
                    $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    if ($assignments.value.Count -eq 0) {
                        $unassignedPolicies.AttackSurfaceProfiles += $policy
                    }
                }
            }
            
            # Display results
            Write-Host "`nPolicies Without Assignments:" -ForegroundColor Green

            # Display Device Configurations
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            if ($unassignedPolicies.DeviceConfigs.Count -eq 0) {
                Write-Host "No unassigned Device Configurations found" -ForegroundColor Gray
            }
            else {
                foreach ($config in $unassignedPolicies.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $platform = Get-PolicyPlatform -Policy $config
                    Write-Host "Device Configuration Name: $configName, Platform: $platform, Configuration ID: $($config.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items @($config) -AssignmentReason "No Assignment"
                }
            }

            # Display Settings Catalog Policies
            Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
            if ($unassignedPolicies.SettingsCatalog.Count -eq 0) {
                Write-Host "No unassigned Settings Catalog Policies found" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $unassignedPolicies.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items @($policy) -AssignmentReason "No Assignment"
                }
            }

            # Display Administrative Templates
            Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
            if ($unassignedPolicies.AdminTemplates.Count -eq 0) {
                Write-Host "No unassigned Administrative Templates found" -ForegroundColor Gray
            }
            else {
                foreach ($template in $unassignedPolicies.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items @($template) -AssignmentReason "No Assignment"
                }
            }

            # Display Compliance Policies
            Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
            if ($unassignedPolicies.CompliancePolicies.Count -eq 0) {
                Write-Host "No unassigned Compliance Policies found" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $unassignedPolicies.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $platform = Get-PolicyPlatform -Policy $policy
                    Write-Host "Compliance Policy Name: $policyName, Platform: $platform, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items @($policy) -AssignmentReason "No Assignment"
                }
            }

            # Display App Protection Policies
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            if ($unassignedPolicies.AppProtectionPolicies.Count -eq 0) {
                Write-Host "No unassigned App Protection Policies found" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $unassignedPolicies.AppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $($policy.id), Type: $policyType" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items @($policy) -AssignmentReason "No Assignment"
                }
            }

            # Display App Configuration Policies
            Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
            if ($unassignedPolicies.AppConfigurationPolicies.Count -eq 0) {
                Write-Host "No unassigned App Configuration Policies found" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $unassignedPolicies.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items @($policy) -AssignmentReason "No Assignment"
                }
            }

            # Display Platform Scripts
            Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
            if ($unassignedPolicies.PlatformScripts.Count -eq 0) {
                Write-Host "No unassigned Platform Scripts found" -ForegroundColor Gray
            }
            else {
                foreach ($script in $unassignedPolicies.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items @($script) -AssignmentReason "No Assignment"
                }
            }

            # Display Proactive Remediation Scripts
            Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
            if ($unassignedPolicies.HealthScripts.Count -eq 0) {
                Write-Host "No unassigned Proactive Remediation Scripts found" -ForegroundColor Gray
            }
            else {
                foreach ($script in $unassignedPolicies.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items @($script) -AssignmentReason "No Assignment"
                }
            }

            # Display Endpoint Security - Antivirus Profiles
            Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
            if ($unassignedPolicies.AntivirusProfiles.Count -eq 0) {
                Write-Host "No unassigned Antivirus Profiles found" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $unassignedPolicies.AntivirusProfiles) {
                    Write-Host "Antivirus Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($profile) -AssignmentReason "No Assignment"
                }
            }

            # Display Endpoint Security - Disk Encryption Profiles
            Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
            if ($unassignedPolicies.DiskEncryptionProfiles.Count -eq 0) {
                Write-Host "No unassigned Disk Encryption Profiles found" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $unassignedPolicies.DiskEncryptionProfiles) {
                    Write-Host "Disk Encryption Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($profile) -AssignmentReason "No Assignment"
                }
            }

            # Display Endpoint Security - Firewall Profiles
            Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
            if ($unassignedPolicies.FirewallProfiles.Count -eq 0) {
                Write-Host "No unassigned Firewall Profiles found" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $unassignedPolicies.FirewallProfiles) {
                    Write-Host "Firewall Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($profile) -AssignmentReason "No Assignment"
                }
            }

            # Display Endpoint Security - Endpoint Detection and Response Profiles
            Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
            if ($unassignedPolicies.EndpointDetectionProfiles.Count -eq 0) {
                Write-Host "No unassigned EDR Profiles found" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $unassignedPolicies.EndpointDetectionProfiles) {
                    Write-Host "EDR Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($profile) -AssignmentReason "No Assignment"
                }
            }

            # Display Endpoint Security - Attack Surface Reduction Profiles
            Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
            if ($unassignedPolicies.AttackSurfaceProfiles.Count -eq 0) {
                Write-Host "No unassigned ASR Profiles found" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $unassignedPolicies.AttackSurfaceProfiles) {
                    Write-Host "ASR Profile Name: $($profile.displayName), Profile ID: $($profile.id)" -ForegroundColor White
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($profile) -AssignmentReason "No Assignment"
                }
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUnassignedPolicies.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
       
        '9' {
            Write-Host "Checking for policies assigned to empty groups..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Helper function to check if a group is empty
            function Test-EmptyGroup {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$GroupId
                )

                try {
                    $membersUri = "$GraphEndpoint/v1.0/groups/$GroupId/members?`$select=id"
                    $response = Invoke-MgGraphRequest -Uri $membersUri -Method Get
                    return $response.value.Count -eq 0
                }
                catch {
                    Write-Host "Error checking members for group $GroupId : $($_.Exception.Message)" -ForegroundColor Red
                    return $false
                }
            }

            # Initialize collections for policies with empty group assignments
            $emptyGroupAssignments = @{
                DeviceConfigs            = @()
                SettingsCatalog          = @()
                AdminTemplates           = @()
                CompliancePolicies       = @()
                AppProtectionPolicies    = @()
                AppConfigurationPolicies = @()
                PlatformScripts          = @()
                HealthScripts            = @()
            }

            # Get Device Configurations
            Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
            $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
            foreach ($config in $deviceConfigs) {
                $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $config | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.DeviceConfigs += $config
                            break
                        }
                    }
                }
            }

            # Get Settings Catalog Policies
            Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
            $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
            foreach ($policy in $settingsCatalog) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.SettingsCatalog += $policy
                            break
                        }
                    }
                }
            }

            # Get Administrative Templates
            Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            foreach ($template in $adminTemplates) {
                $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $template | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.AdminTemplates += $template
                            break
                        }
                    }
                }
            }

            # Get Compliance Policies
            Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
            $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
            foreach ($policy in $compliancePolicies) {
                $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.CompliancePolicies += $policy
                            break
                        }
                    }
                }
            }

            # Get App Protection Policies
            Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
            $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
            foreach ($policy in $appProtectionPolicies) {
                $policyType = $policy.'@odata.type'
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    try {
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                        $assignments = @()
                        foreach ($assignment in $assignmentResponse.value) {
                            $assignmentReason = $null
                            switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { 
                                    $assignmentReason = "All Users"
                                }
                                '#microsoft.graph.groupAssignmentTarget' {
                                    if (!$GroupId -or $assignment.target.groupId -eq $GroupId) {
                                        $assignmentReason = "Group Assignment"
                                    }
                                }
                            }

                            if ($assignmentReason) {
                                $assignments += @{
                                    Reason  = $assignmentReason
                                    GroupId = $assignment.target.groupId
                                }
                            }
                        }

                        if ($assignments.Count -gt 0) {
                            $assignmentSummary = $assignments | ForEach-Object {
                                if ($_.Reason -eq "Group Assignment") {
                                    $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                                    "$($_.Reason) - $($groupInfo.DisplayName)"
                                }
                                else {
                                    $_.Reason
                                }
                            }
                            $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                            $emptyGroupAssignments.AppProtectionPolicies += $policy
                        }
                    }
                    catch {
                        Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }

            # Get App Configuration Policies
            Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
            $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
            foreach ($policy in $appConfigPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $policy | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.AppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
            }

            # Get Platform Scripts
            Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
            $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
            foreach ($script in $platformScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $script | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.PlatformScripts += $script
                            break
                        }
                    }
                }
            }

            # Get Proactive Remediation Scripts
            Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
            $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
            foreach ($script in $healthScripts) {
                $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "Group Assignment" -and $assignment.GroupId) {
                        $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                        if ($groupInfo.Success -and (Test-EmptyGroup -GroupId $assignment.GroupId)) {
                            $script | Add-Member -NotePropertyName 'EmptyGroupInfo' -NotePropertyValue "Assigned to empty group: $($groupInfo.DisplayName)" -Force
                            $emptyGroupAssignments.HealthScripts += $script
                            break
                        }
                    }
                }
            }

            # Display results
            Write-Host "`nPolicies Assigned to Empty Groups:" -ForegroundColor Green

            # Display Device Configurations
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.DeviceConfigs.Count -eq 0) {
                Write-Host "No Device Configurations assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($config in $emptyGroupAssignments.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $platform = Get-PolicyPlatform -Policy $config
                    Write-Host "Device Configuration Name: $configName" -ForegroundColor White
                    Write-Host "Platform: $platform" -ForegroundColor Gray
                    Write-Host "Configuration ID: $($config.id)" -ForegroundColor Gray
                    Write-Host "$($config.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items @($config) -AssignmentReason $config.EmptyGroupInfo
                }
            }

            # Display Settings Catalog Policies
            Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.SettingsCatalog.Count -eq 0) {
                Write-Host "No Settings Catalog Policies assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $emptyGroupAssignments.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "Settings Catalog Policy Name: $policyName" -ForegroundColor White
                    Write-Host "Policy ID: $($policy.id)" -ForegroundColor Gray
                    Write-Host "$($policy.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items @($policy) -AssignmentReason $policy.EmptyGroupInfo
                }
            }

            # Display Administrative Templates
            Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.AdminTemplates.Count -eq 0) {
                Write-Host "No Administrative Templates assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($template in $emptyGroupAssignments.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    Write-Host "Administrative Template Name: $templateName" -ForegroundColor White
                    Write-Host "Template ID: $($template.id)" -ForegroundColor Gray
                    Write-Host "$($template.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items @($template) -AssignmentReason $template.EmptyGroupInfo
                }
            }

            # Display Compliance Policies
            Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.CompliancePolicies.Count -eq 0) {
                Write-Host "No Compliance Policies assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $emptyGroupAssignments.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $platform = Get-PolicyPlatform -Policy $policy
                    Write-Host "Compliance Policy Name: $policyName" -ForegroundColor White
                    Write-Host "Platform: $platform" -ForegroundColor Gray
                    Write-Host "Policy ID: $($policy.id)" -ForegroundColor Gray
                    Write-Host "$($policy.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items @($policy) -AssignmentReason $policy.EmptyGroupInfo
                }
            }

            # Display App Protection Policies
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.AppProtectionPolicies.Count -eq 0) {
                Write-Host "No App Protection Policies assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $emptyGroupAssignments.AppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    Write-Host "App Protection Policy Name: $policyName" -ForegroundColor White
                    Write-Host "Policy ID: $($policy.id), Type: $policyType" -ForegroundColor Gray
                    Write-Host "$($policy.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items @($policy) -AssignmentReason $policy.EmptyGroupInfo
                }
            }

            # Display App Configuration Policies
            Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.AppConfigurationPolicies.Count -eq 0) {
                Write-Host "No App Configuration Policies assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($policy in $emptyGroupAssignments.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "App Configuration Policy Name: $policyName" -ForegroundColor White
                    Write-Host "Policy ID: $($policy.id)" -ForegroundColor Gray
                    Write-Host "$($policy.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items @($policy) -AssignmentReason $policy.EmptyGroupInfo
                }
            }

            # Display Platform Scripts
            Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.PlatformScripts.Count -eq 0) {
                Write-Host "No Platform Scripts assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($script in $emptyGroupAssignments.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName" -ForegroundColor White
                    Write-Host "Script ID: $($script.id)" -ForegroundColor Gray
                    Write-Host "$($script.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items @($script) -AssignmentReason $script.EmptyGroupInfo
                }
            }

            # Display Proactive Remediation Scripts
            Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.HealthScripts.Count -eq 0) {
                Write-Host "No Proactive Remediation Scripts assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($script in $emptyGroupAssignments.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    Write-Host "Script Name: $scriptName" -ForegroundColor White
                    Write-Host "Script ID: $($script.id)" -ForegroundColor Gray
                    Write-Host "$($script.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items @($script) -AssignmentReason $script.EmptyGroupInfo
                }
            }

            # Display Endpoint Security - Antivirus Profiles
            Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.AntivirusProfiles.Count -eq 0) {
                Write-Host "No Antivirus Profiles assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $emptyGroupAssignments.AntivirusProfiles) {
                    Write-Host "Antivirus Profile Name: $($profile.displayName)" -ForegroundColor White
                    Write-Host "Profile ID: $($profile.id)" -ForegroundColor Gray
                    Write-Host "$($profile.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($profile) -AssignmentReason $profile.EmptyGroupInfo
                }
            }

            # Display Endpoint Security - Disk Encryption Profiles
            Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.DiskEncryptionProfiles.Count -eq 0) {
                Write-Host "No Disk Encryption Profiles assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $emptyGroupAssignments.DiskEncryptionProfiles) {
                    Write-Host "Disk Encryption Profile Name: $($profile.displayName)" -ForegroundColor White
                    Write-Host "Profile ID: $($profile.id)" -ForegroundColor Gray
                    Write-Host "$($profile.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($profile) -AssignmentReason $profile.EmptyGroupInfo
                }
            }

            # Display Endpoint Security - Firewall Profiles
            Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.FirewallProfiles.Count -eq 0) {
                Write-Host "No Firewall Profiles assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $emptyGroupAssignments.FirewallProfiles) {
                    Write-Host "Firewall Profile Name: $($profile.displayName)" -ForegroundColor White
                    Write-Host "Profile ID: $($profile.id)" -ForegroundColor Gray
                    Write-Host "$($profile.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($profile) -AssignmentReason $profile.EmptyGroupInfo
                }
            }

            # Display Endpoint Security - Endpoint Detection and Response Profiles
            Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.EndpointDetectionProfiles.Count -eq 0) {
                Write-Host "No EDR Profiles assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $emptyGroupAssignments.EndpointDetectionProfiles) {
                    Write-Host "EDR Profile Name: $($profile.displayName)" -ForegroundColor White
                    Write-Host "Profile ID: $($profile.id)" -ForegroundColor Gray
                    Write-Host "$($profile.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($profile) -AssignmentReason $profile.EmptyGroupInfo
                }
            }

            # Display Endpoint Security - Attack Surface Reduction Profiles
            Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
            if ($emptyGroupAssignments.AttackSurfaceProfiles.Count -eq 0) {
                Write-Host "No ASR Profiles assigned to empty groups" -ForegroundColor Gray
            }
            else {
                foreach ($profile in $emptyGroupAssignments.AttackSurfaceProfiles) {
                    Write-Host "ASR Profile Name: $($profile.displayName)" -ForegroundColor White
                    Write-Host "Profile ID: $($profile.id)" -ForegroundColor Gray
                    Write-Host "$($profile.EmptyGroupInfo)" -ForegroundColor Yellow
                    Write-Host ""
                    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($profile) -AssignmentReason $profile.EmptyGroupInfo
                }
            }

            # Export results if requested
            Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneEmptyGroupAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
        }
        '10' {
            Write-Host "Compare Group Assignments chosen" -ForegroundColor Green

            # Get Group names to compare from parameter or prompt
            if ($parameterMode -and $CompareGroupNames) {
                $groupInput = $CompareGroupNames
            }
            else {
                # Prompt for Group names or IDs
                Write-Host "Please enter Group names or Object IDs to compare, separated by commas (,): " -ForegroundColor Cyan
                Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
                $groupInput = Read-Host
            }
            
            $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }

            if ($groupInputs.Count -lt 2) {
                Write-Host "Please provide at least two groups to compare." -ForegroundColor Red
                if ($parameterMode) { exit 1 } else { continue }
            }

            # Before caching starts, initialize the group assignments hashtable
            $groupAssignments = @{}

            # Process each group input
            $resolvedGroups = @{}
            foreach ($input in $groupInputs) {
                Write-Host "`nProcessing input: $input" -ForegroundColor Yellow

                # Initialize variables
                $groupId = $null
                $groupName = $null

                # Check if input is a GUID
                if ($input -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                    try {
                        # Get group info from Graph API
                        $groupUri = "$GraphEndpoint/v1.0/groups/$input"
                        $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
                        $groupId = $groupResponse.id
                        $groupName = $groupResponse.displayName
                        $resolvedGroups[$groupId] = $groupName
                
                        # Initialize collections for this group (Add HealthScripts here)
                        $groupAssignments[$groupName] = @{
                            DeviceConfigs      = [System.Collections.ArrayList]::new()
                            SettingsCatalog    = [System.Collections.ArrayList]::new()
                            AdminTemplates     = [System.Collections.ArrayList]::new()
                            CompliancePolicies = [System.Collections.ArrayList]::new()
                            RequiredApps       = [System.Collections.ArrayList]::new()
                            AvailableApps      = [System.Collections.ArrayList]::new()
                            AppsUninstall      = [System.Collections.ArrayList]::new()
                            PlatformScripts    = [System.Collections.ArrayList]::new()
                            HealthScripts      = [System.Collections.ArrayList]::new()
                        }
                
                        Write-Host "Found group by ID: $groupName" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "No group found with ID: $input" -ForegroundColor Red
                        continue
                    }
                }
                else {
                    # Try to find group by display name
                    $groupUri = "$GraphEndpoint/v1.0/groups?`$filter=displayName eq '$input'"
                    $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get

                    if ($groupResponse.value.Count -eq 0) {
                        Write-Host "No group found with name: $input" -ForegroundColor Red
                        continue
                    }
                    elseif ($groupResponse.value.Count -gt 1) {
                        Write-Host "Multiple groups found with name: $input. Please use the Object ID instead:" -ForegroundColor Red
                        foreach ($group in $groupResponse.value) {
                            Write-Host "  - $($group.displayName) (ID: $($group.id))" -ForegroundColor Yellow
                        }
                        continue
                    }

                    $groupId = $groupResponse.value[0].id
                    $groupName = $groupResponse.value[0].displayName
                    $resolvedGroups[$groupId] = $groupName
            
                    # Initialize collections for this group (Add HealthScripts here)
                    $groupAssignments[$groupName] = @{
                        DeviceConfigs      = [System.Collections.ArrayList]::new()
                        SettingsCatalog    = [System.Collections.ArrayList]::new()
                        AdminTemplates     = [System.Collections.ArrayList]::new()
                        CompliancePolicies = [System.Collections.ArrayList]::new()
                        RequiredApps       = [System.Collections.ArrayList]::new()
                        AvailableApps      = [System.Collections.ArrayList]::new()
                        AppsUninstall      = [System.Collections.ArrayList]::new()
                        PlatformScripts    = [System.Collections.ArrayList]::new()
                        HealthScripts      = [System.Collections.ArrayList]::new()
                    }
            
                    Write-Host "Found group by name: $groupName (ID: $groupId)" -ForegroundColor Green
                }

                # Process Device Configurations
                $deviceConfigsUri = "$GraphEndpoint/beta/deviceManagement/deviceConfigurations"
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $allDeviceConfigs = $deviceConfigsResponse.value
                while ($deviceConfigsResponse.'@odata.nextLink') {
                    $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                    $allDeviceConfigs += $deviceConfigsResponse.value
                }
                $totalDeviceConfigs = $allDeviceConfigs.Count
                $currentDeviceConfig = 0
                foreach ($config in $allDeviceConfigs) {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    # Check for both inclusion and exclusion assignments
                    $hasAssignment = $assignmentResponse.value | Where-Object {
                        $_.target.groupId -eq $groupId -and
                        ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                        $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
                    }
                    if ($hasAssignment) {
                        # Check if it's an exclusion
                        $isExclusion = $hasAssignment | Where-Object {
                            $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                        }
                        $displayName = if ($isExclusion) {
                            "$($config.displayName) [EXCLUDED]"
                        }
                        else {
                            $config.displayName
                        }
                        [void]$groupAssignments[$groupName].DeviceConfigs.Add($displayName)
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Process Settings Catalog
                $settingsCatalogUri = "$GraphEndpoint/beta/deviceManagement/configurationPolicies"
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get

                foreach ($policy in $settingsCatalogResponse.value) {
                    $policyId = $policy.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    # Check for both inclusion and exclusion assignments
                    $hasAssignment = $assignmentResponse.value | Where-Object {
                        $_.target.groupId -eq $groupId -and
                        ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                        $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
                    }
                    if ($hasAssignment) {
                        # Check if it's an exclusion
                        $isExclusion = $hasAssignment | Where-Object {
                            $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                        }
                        $displayName = if ($isExclusion) {
                            "$($policy.name) [EXCLUDED]"
                        }
                        else {
                            $policy.name
                        }
                        [void]$groupAssignments[$groupName].SettingsCatalog.Add($displayName)
                    }
                }

                # Process Administrative Templates
                $adminTemplatesUri = "$GraphEndpoint/beta/deviceManagement/groupPolicyConfigurations"
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get

                foreach ($template in $adminTemplatesResponse.value) {
                    $templateId = $template.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].AdminTemplates.Add($template.displayName)
                    }
                }

                # Process Compliance Policies
                $complianceUri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies"
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get

                foreach ($policy in $complianceResponse.value) {
                    $policyId = $policy.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    # Check for both inclusion and exclusion assignments
                    $hasAssignment = $assignmentResponse.value | Where-Object {
                        $_.target.groupId -eq $groupId -and
                        ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                        $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
                    }
                    if ($hasAssignment) {
                        # Check if it's an exclusion
                        $isExclusion = $hasAssignment | Where-Object {
                            $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                        }
                        $displayName = if ($isExclusion) {
                            "$($policy.displayName) [EXCLUDED]"
                        }
                        else {
                            $policy.displayName
                        }
                        [void]$groupAssignments[$groupName].CompliancePolicies.Add($displayName)
                    }
                }

                # Process Apps
                $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get

                foreach ($app in $appResponse.value) {
                    # Skip built-in and Microsoft apps
                    if ($app.isFeatured -or $app.isBuiltIn) {
                        continue
                    }

                    $appId = $app.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.groupId -eq $groupId) {
                            switch ($assignment.intent) {
                                "required" { [void]$groupAssignments[$groupName].RequiredApps.Add($app.displayName) }
                                "available" { [void]$groupAssignments[$groupName].AvailableApps.Add($app.displayName) }
                                "uninstall" { [void]$groupAssignments[$groupName].UninstallApps.Add($app.displayName) }
                            }
                        }
                    }
                }

                # Process Platform Scripts (PowerShell)
                $scriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceManagementScripts"
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                # For PowerShell scripts, we need to check the script type
                foreach ($script in $scriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        $scriptInfo = "$($script.displayName) (PowerShell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Process Shell Scripts (macOS)
                $shellScriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceShellScripts"
                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                # For Shell scripts, we need to check the script type
                foreach ($script in $shellScriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.targetGroupId -eq $groupId }) {
                        $scriptInfo = "$($script.displayName) (Shell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                $healthScriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceHealthScripts"
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                foreach ($script in $healthScriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].HealthScripts.Add($script.displayName)
                    }
                }

                # Get Endpoint Security - Antivirus Policies
                $allIntentsForAntivirusCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $antivirusPolicies = $allIntentsForAntivirusCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
                if ($antivirusPolicies) {
                    foreach ($policy in $antivirusPolicies) {
                        $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                            [void]$groupAssignments[$groupName].AntivirusProfiles.Add($policy.displayName)
                        }
                    }
                }

                # Get Endpoint Security - Disk Encryption Policies
                $allIntentsForDiskEncCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $diskEncryptionPolicies = $allIntentsForDiskEncCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
                if ($diskEncryptionPolicies) {
                    foreach ($policy in $diskEncryptionPolicies) {
                        $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                            [void]$groupAssignments[$groupName].DiskEncryptionProfiles.Add($policy.displayName)
                        }
                    }
                }

                # Get Endpoint Security - Firewall Policies
                $allIntentsForFirewallCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $firewallPolicies = $allIntentsForFirewallCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
                if ($firewallPolicies) {
                    foreach ($policy in $firewallPolicies) {
                        $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                            [void]$groupAssignments[$groupName].FirewallProfiles.Add($policy.displayName)
                        }
                    }
                }

                # Get Endpoint Security - Endpoint Detection and Response Policies
                $allIntentsForEDRCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $edrPolicies = $allIntentsForEDRCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
                if ($edrPolicies) {
                    foreach ($policy in $edrPolicies) {
                        $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                            [void]$groupAssignments[$groupName].EndpointDetectionProfiles.Add($policy.displayName)
                        }
                    }
                }

                # Get Endpoint Security - Attack Surface Reduction Policies
                $allIntentsForASRCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
                $asrPolicies = $allIntentsForASRCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReductionRules' }
                if ($asrPolicies) {
                    foreach ($policy in $asrPolicies) {
                        $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        if ($assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                            [void]$groupAssignments[$groupName].AttackSurfaceProfiles.Add($policy.displayName)
                        }
                    }
                }
            }

            # Comparison Results section
            Write-Host "`nComparison Results:" -ForegroundColor Cyan
            Write-Host "Comparing assignments between groups:" -ForegroundColor White
            foreach ($groupName in $groupAssignments.Keys) {
                Write-Host "  • $groupName" -ForegroundColor White
            }
            Write-Host ""

            # Update categories to include "Proactive Remediation Scripts"
            $categories = @{
                "Settings Catalog"                    = "SettingsCatalog"
                "Administrative Templates"            = "AdminTemplates"
                "Compliance Policies"                 = "CompliancePolicies"
                "Available Apps"                      = "AvailableApps"
                "Required Apps"                       = "RequiredApps"
                "Platform Scripts"                    = "PlatformScripts"
                "Device Configurations"               = "DeviceConfigs"
                "Uninstall Apps"                      = "UninstallApps"
                "Proactive Remediation Scripts"       = "HealthScripts"
                "Endpoint Security - Antivirus"       = "AntivirusProfiles"
                "Endpoint Security - Disk Encryption" = "DiskEncryptionProfiles"
                "Endpoint Security - Firewall"        = "FirewallProfiles"
                "Endpoint Security - EDR"             = "EndpointDetectionProfiles"
                "Endpoint Security - ASR"             = "AttackSurfaceProfiles"
            }

            # First pass to collect all unique policies
            $uniquePolicies = [System.Collections.ArrayList]@()
            foreach ($groupName in $groupAssignments.Keys) {
                foreach ($categoryKey in $categories.Values) {
                    foreach ($policy in $groupAssignments[$groupName][$categoryKey]) {
                        if ($uniquePolicies -notcontains $policy) {
                            $null = $uniquePolicies.Add($policy)
                        }
                    }
                }
            }

            Write-Host "Found $($uniquePolicies.Count) unique policies/apps/scripts across all groups`n" -ForegroundColor Yellow

            # Display comparison for each category
            foreach ($category in $categories.Keys) {
                $categoryKey = $categories[$category]

                Write-Host "=== $category ===" -ForegroundColor Cyan
                $foundAssignments = $false

                foreach ($policy in $uniquePolicies) {
                    $assignedGroups = @()
                    foreach ($groupName in $groupAssignments.Keys) {
                        if ($groupAssignments[$groupName][$categoryKey] -contains $policy) {
                            $assignedGroups += $groupName
                        }
                    }

                    if ($assignedGroups.Count -gt 0) {
                        $foundAssignments = $true
                        Write-Host "📋 Policy: " -NoNewline -ForegroundColor White
                        Write-Host "$policy" -ForegroundColor Yellow

                        if ($assignedGroups.Count -gt 1) {
                            Write-Host "  🔗 Shared Assignment!" -ForegroundColor Magenta
                        }

                        Write-Host "  ✅ Assigned to: " -NoNewline -ForegroundColor Green
                        Write-Host "$($assignedGroups -join ', ')" -ForegroundColor White

                        $notAssignedGroups = $groupAssignments.Keys | Where-Object { $assignedGroups -notcontains $_ }
                        if ($notAssignedGroups) {
                            Write-Host "  ❌ Not assigned to: " -NoNewline -ForegroundColor Red
                            Write-Host "$($notAssignedGroups -join ', ')" -ForegroundColor White
                        }
                        Write-Host ""
                    }
                }

                if (-not $foundAssignments) {
                    Write-Host "No assignments found in this category" -ForegroundColor Gray
                    Write-Host ""
                }
            }

            # Summary section
            Write-Host "=== Summary ===" -ForegroundColor Cyan
            foreach ($groupName in $groupAssignments.Keys) {
                $totalAssignments = 0
                foreach ($categoryKey in $categories.Values) {
                    $totalAssignments += $groupAssignments[$groupName][$categoryKey].Count
                }
                Write-Host "$groupName has $totalAssignments total assignments" -ForegroundColor Yellow
            }
            Write-Host ""

            # Create comparison results
            $comparisonResults = [System.Collections.ArrayList]@()
            foreach ($category in $categories.Keys) {
                $categoryKey = $categories[$category]
                foreach ($policy in $uniquePolicies) {
                    $assignedGroups = @()
                    foreach ($groupName in $groupAssignments.Keys) {
                        if ($groupAssignments[$groupName][$categoryKey] -contains $policy) {
                            $assignedGroups += $groupName
                        }
                    }

                    if ($assignedGroups.Count -gt 0) {
                        [void]$comparisonResults.Add([PSCustomObject]@{
                                Category           = $category
                                PolicyName         = $policy
                                AssignedTo         = $assignedGroups -join '; '
                                NotAssignedTo      = ($groupAssignments.Keys | Where-Object { $assignedGroups -notcontains $_ }) -join '; '
                                IsSharedAssignment = ($assignedGroups.Count -gt 1)
                            })
                    }
                }
            }

            # Export results if requested
            if ($ExportToCSV -or -not $parameterMode) {
                $exportPath = if ($ExportPath) {
                    $ExportPath
                }
                elseif (-not $parameterMode) {
                    $export = Read-Host "Would you like to export the comparison results to CSV? (y/n)"
                    if ($export -eq 'y') {
                        Show-SaveFileDialog -DefaultFileName "IntuneGroupAssignmentComparison.csv"
                    }
                    else {
                        $null
                    }
                }
                else {
                    $null
                }
                
                if ($exportPath) {
                    $comparisonResults | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }

        '11' {
            Write-Host "Fetching all failed assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()
            
            # Get all failed assignments
            $failedAssignments = Get-AssignmentFailures
            
            if ($failedAssignments.Count -eq 0) {
                Write-Host "`nNo assignment failures found!" -ForegroundColor Green
            }
            else {
                Write-Host "`nFound $($failedAssignments.Count) assignment failures:" -ForegroundColor Yellow
                
                # Group by type for better display
                $groupedFailures = $failedAssignments | Group-Object -Property Type
                
                foreach ($group in $groupedFailures) {
                    Write-Host "`n=== $($group.Name) Failures ($($group.Count)) ===" -ForegroundColor Cyan
                    
                    foreach ($failure in $group.Group) {
                        Write-Host "`nPolicy: $($failure.PolicyName)" -ForegroundColor White
                        Write-Host "Device: $($failure.Target -replace 'Device: ', '')" -ForegroundColor Gray
                        Write-Host "Reason: $($failure.ErrorCode)" -ForegroundColor White
                        if ($failure.LastAttempt -and $failure.LastAttempt -ne "01/01/0001 00:00:00") {
                            Write-Host "Last Attempt: $($failure.LastAttempt)" -ForegroundColor Gray
                        }
                        
                        # Add to export data
                        $null = $exportData.Add([PSCustomObject]@{
                                Type             = $failure.Type
                                PolicyName       = $failure.PolicyName
                                Target           = $failure.Target
                                ErrorCode        = $failure.ErrorCode
                                ErrorDescription = $failure.ErrorDescription
                                LastAttempt      = $failure.LastAttempt
                            })
                    }
                }
                
                # Export if requested
                Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$false
            }
        }
        
        '12' {
            Write-Host "`nApp Install Summary Report" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all apps
                $appName = $null
            }
            else {
                $appName = Read-Host "Enter the app name (or press Enter to show all apps)"
            }
            
            try {
                if ($appName) {
                    Write-Host "`nSearching for app: $appName" -ForegroundColor Yellow
                    
                    # Get app install summary
                    $results = Get-AppsInstallSummaryReport -Search $appName
                    if ($results.Count -eq 0) {
                        Write-Host "`nNo app found with name: $appName" -ForegroundColor Red
                        continue
                    }
                }
                else {
                    Write-Host "`nFetching install summary for all apps..." -ForegroundColor Yellow
                    $results = Get-AppsInstallSummaryReport
                }
                
                if ($results) {
                    Write-Host "`nApp Install Summary Results:" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($result in $results) {
                        Write-Host "`nApp: $($result.DisplayName)" -ForegroundColor White
                        Write-Host "Platform: $($result.Platform_loc)" -ForegroundColor Gray
                        Write-Host "Version: $($result.AppVersion)" -ForegroundColor Gray
                        Write-Host "Total Devices: $($result.TotalCount)" -ForegroundColor White
                        Write-Host "Success Rate: $($result.SuccessRate)%" -ForegroundColor $(if ($result.SuccessRate -ge 80) { "Green" } elseif ($result.SuccessRate -ge 50) { "Yellow" } else { "Red" })
                        Write-Host "Installed: $($result.InstalledCount)" -ForegroundColor Green
                        Write-Host "Failed: $($result.FailedCount)" -ForegroundColor Red
                        Write-Host "Pending: $($result.PendingCount)" -ForegroundColor Yellow
                        Write-Host "Not Installed: $($result.NotInstalledDeviceCount)" -ForegroundColor Gray
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $results | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "AppInstallSummary.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "AppInstallSummary.csv"
                    }
                }
                else {
                    Write-Host "`nNo app install data found" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "`nError: Failed to generate app install summary - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        '13' {
            Write-Host "`nApp Install Failures Report (>60% failure rate)" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all apps
                $appName = $null
            }
            else {
                $appName = Read-Host "Enter the app name (or press Enter to show all apps)"
            }
            
            try {
                Write-Host "`nSearching for apps with high failure rates..." -ForegroundColor Yellow
                
                $failedApps = Get-AppInstallFailuresReport -Search $appName
                
                if ($failedApps -and $failedApps.Count -gt 0) {
                    Write-Host "`nApp Install Failures (>60% failure rate):" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($app in $failedApps) {
                        Write-Host "`nApp: $($app.DisplayName)" -ForegroundColor White
                        Write-Host "Platform: $($app.Platform_loc)" -ForegroundColor Gray
                        Write-Host "Version: $($app.AppVersion)" -ForegroundColor Gray
                        Write-Host "Failure Rate: $($app.FailureRate)%" -ForegroundColor Red
                        Write-Host "Total Devices: $($app.TotalCount)" -ForegroundColor White
                        Write-Host "Failed: $($app.FailedCount)" -ForegroundColor Red
                        Write-Host "Installed: $($app.InstalledCount)" -ForegroundColor Green
                        Write-Host "Pending: $($app.PendingCount)" -ForegroundColor Yellow
                        Write-Host "Not Installed: $($app.NotInstalledDeviceCount)" -ForegroundColor Gray
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $failedApps | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "AppInstallFailures.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "AppInstallFailures.csv"
                    }
                }
                else {
                    Write-Host "`nNo apps found with failure rate above 60%" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "`nError: Failed to generate app failure report - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        '14' {
            Write-Host "`nCompliance Policy Deployment Summary Report" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all policies
                $policyName = $null
            }
            else {
                $policyName = Read-Host "Enter the compliance policy name (or press Enter to show all policies)"
            }
            
            try {
                if ($policyName) {
                    Write-Host "`nSearching for compliance policy: $policyName" -ForegroundColor Yellow
                    $results = Get-CompliancePolicyDeviceSummaryReport -CompliancePolicyName $policyName
                }
                else {
                    Write-Host "`nFetching all compliance policies..." -ForegroundColor Yellow
                    $results = Get-CompliancePolicyDeviceSummaryReport -IncludeAllPolicies
                }
                
                if ($results) {
                    Write-Host "`nCompliance Policy Summary Results:" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($policy in $results) {
                        Write-Host "`nPolicy: $($policy.CompliancePolicyName)" -ForegroundColor White
                        Write-Host "Platform: $($policy.OS ?? 'All')" -ForegroundColor Gray
                        Write-Host "Compliance Rate: $($policy.ComplianceRate)%" -ForegroundColor $(if ($policy.ComplianceRate -ge 80) { 'Green' } elseif ($policy.ComplianceRate -ge 60) { 'Yellow' } else { 'Red' })
                        Write-Host "Total Devices: $($policy.TotalDevices)" -ForegroundColor White
                        Write-Host "Compliant: $($policy.NumberOfCompliantDevices)" -ForegroundColor Green
                        Write-Host "Non-Compliant: $($policy.NumberOfNonCompliantDevices)" -ForegroundColor Red
                        Write-Host "Other: $($policy.NumberOfOtherDevices)" -ForegroundColor Yellow
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $results | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "CompliancePolicySummary.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "CompliancePolicySummary.csv"
                    }
                }
                else {
                    Write-Host "`nNo compliance policy summary data found" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "`nError: Failed to generate compliance policy summary report - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        '15' {
            Write-Host "`nCompliance Policy Failures Report (>60% non-compliance)" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all policies
                $policyName = $null
            }
            else {
                $policyName = Read-Host "Enter the compliance policy name (or press Enter to show all policies)"
            }
            
            try {
                Write-Host "`nSearching for compliance policies with high non-compliance rates..." -ForegroundColor Yellow
                
                $params = @{}
                if ($policyName) { $params.CompliancePolicyName = $policyName }
                else { $params.IncludeAllObjects = $true }
                
                $failedPolicies = Get-CompliancePolicyFailuresReport @params
                
                if ($failedPolicies -and $failedPolicies.Count -gt 0) {
                    Write-Host "`nCompliance Policy Failures (>60% non-compliance):" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($policy in $failedPolicies) {
                        Write-Host "`nPolicy: $($policy.CompliancePolicyName)" -ForegroundColor White
                        Write-Host "Platform: $($policy.OS ?? 'All')" -ForegroundColor Gray
                        Write-Host "Non-Compliance Rate: $($policy.NonComplianceRate)%" -ForegroundColor Red
                        Write-Host "Total Devices: $($policy.TotalDevices)" -ForegroundColor White
                        Write-Host "Non-Compliant: $($policy.NumberOfNonCompliantDevices)" -ForegroundColor Red
                        Write-Host "Compliant: $($policy.NumberOfCompliantDevices)" -ForegroundColor Green
                        Write-Host "Other: $($policy.NumberOfOtherDevices)" -ForegroundColor Yellow
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $failedPolicies | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "CompliancePolicyFailures.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "CompliancePolicyFailures.csv"
                    }
                }
                else {
                    Write-Host "`nNo compliance policies found with non-compliance rate above 60%" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "`nError: Failed to generate compliance failure report - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        '16' {
            # This is the old section 14 - Configuration Policy Device Summary
            Write-Host "`nConfiguration Policy Device Summary Report" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all policies
                $policyName = $null
            }
            else {
                $policyName = Read-Host "Enter the configuration policy name (or press Enter to show all policies)"
            }
            
            try {
                if ($policyName) {
                    Write-Host "`nSearching for configuration policy: $policyName" -ForegroundColor Yellow
                    $results = Get-ConfigurationPolicyDeviceSummaryReport -ConfigurationPolicyName $policyName
                }
                else {
                    Write-Host "`nFetching all configuration policies..." -ForegroundColor Yellow
                    $results = Get-ConfigurationPolicyDeviceSummaryReport -IncludeAllPolicies
                }
                
                if ($results) {
                    Write-Host "`nConfiguration Policy Summary Results:" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($result in $results) {
                        Write-Host "`nPolicy: $($result.ConfigurationPolicyName)" -ForegroundColor White
                        Write-Host "Type: $($result.ConfigurationPolicyType)" -ForegroundColor Gray
                        Write-Host "Platform: $($result.UnifiedPolicyPlatformType_loc ?? 'Unknown')" -ForegroundColor Gray
                        Write-Host "Total Devices: $($result.TotalDevices)" -ForegroundColor White
                        Write-Host "Success Rate: $($result.SuccessRate)%" -ForegroundColor $(if ($result.SuccessRate -ge 80) { "Green" } elseif ($result.SuccessRate -ge 50) { "Yellow" } else { "Red" })
                        Write-Host "Compliant: $($result.CompliantCount)" -ForegroundColor Green
                        Write-Host "Non-Compliant: $($result.NonCompliantCount)" -ForegroundColor Red
                        Write-Host "Error: $($result.ErrorCount)" -ForegroundColor Red
                        Write-Host "Conflict: $($result.ConflictCount)" -ForegroundColor Yellow
                        Write-Host "In Progress: $($result.InProgressCount)" -ForegroundColor Yellow
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $results | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "ConfigurationPolicySummary.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "ConfigurationPolicySummary.csv"
                    }
                }
                else {
                    Write-Host "`nNo configuration policy data found" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "`nError: Failed to generate configuration policy summary - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        '17' {
            Write-Host "`nConfiguration Policy Failures Report (>60% failure rate)" -ForegroundColor Cyan
            Write-Host "====================================" -ForegroundColor Cyan
            
            if ($parameterMode) {
                # In parameter mode, show all policies
                $policyName = $null
            }
            else {
                $policyName = Read-Host "Enter the configuration policy name (or press Enter to show all policies)"
            }
            
            try {
                Write-Host "`nSearching for configuration policies with high failure rates..." -ForegroundColor Yellow
                
                $params = @{}
                if ($policyName) { $params.ConfigurationPolicyName = $policyName }
                else { $params.IncludeAllPolicies = $true }
                
                $failedPolicies = Get-ConfigurationPolicyFailuresReport @params
                
                if ($failedPolicies -and $failedPolicies.Count -gt 0) {
                    Write-Host "`nConfiguration Policy Failures (>60% failure rate):" -ForegroundColor Cyan
                    Write-Host "====================================" -ForegroundColor Cyan
                    
                    foreach ($policy in $failedPolicies) {
                        Write-Host "`nPolicy: $($policy.ConfigurationPolicyName)" -ForegroundColor White
                        Write-Host "Type: $($policy.ConfigurationPolicyType)" -ForegroundColor Gray
                        Write-Host "Platform: $($policy.UnifiedPolicyPlatformType_loc ?? 'Unknown')" -ForegroundColor Gray
                        Write-Host "Failure Rate: $($policy.FailureRate)%" -ForegroundColor Red
                        Write-Host "Total Devices: $($policy.TotalDevices)" -ForegroundColor White
                        Write-Host "Failed: $($policy.NonCompliantCount + $policy.ErrorCount)" -ForegroundColor Red
                        Write-Host "Success: $($policy.CompliantCount)" -ForegroundColor Green
                        Write-Host "Conflict: $($policy.ConflictCount)" -ForegroundColor Yellow
                        Write-Host "In Progress: $($policy.InProgressCount)" -ForegroundColor Yellow
                        Write-Host ("-" * 50)
                    }
                    
                    # Export if requested
                    $exportData = [System.Collections.ArrayList]::new()
                    $failedPolicies | ForEach-Object { [void]$exportData.Add($_) }
                    if ($ExportToCSV) {
                        Export-ResultsIfRequested -ExportData $exportData -ExportPath $ExportPath -ForceExport:$true -DefaultFileName "ConfigurationPolicyFailures.csv"
                    }
                    else {
                        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "ConfigurationPolicyFailures.csv"
                    }
                }
                else {
                    Write-Host "`nNo configuration policies found with failure rate above 60%" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "`nError: Failed to generate configuration failure report - $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        '0' {
            Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
            Disconnect-MgGraph | Out-Null
            Write-Host "Thank you for using IntuneAssignmentChecker! 👋" -ForegroundColor Green
            Write-Host "If you found this tool helpful, please consider:" -ForegroundColor Cyan
            Write-Host "- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor White
            Write-Host "- Supporting the project: https://github.com/sponsors/ugurkocde" -ForegroundColor White
            Write-Host ""
            exit
        }
        '98' {
            Write-Host "Opening GitHub Sponsor Page ..." -ForegroundColor Green
            Start-Process "https://github.com/sponsors/ugurkocde"
        }
        '99' {
            Write-Host "Opening GitHub Repository..." -ForegroundColor Green
            Start-Process "https://github.com/ugurkocde/IntuneAssignmentChecker"
        }
        default {
            Write-Host ("Invalid choice, please select one of: " + ($validMenuOptions -join ', ') + ".") -ForegroundColor Red
        }
    }

    # In parameter mode, exit after completing the task
    # In interactive mode, return to the menu unless exit was selected
    if ($selection -ne '0') {
        if ($parameterMode) {
            # Exit after completing the task in parameter mode
            break
        }
        else {
            # Return to menu in interactive mode
            Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
} while ($selection -ne '0')
