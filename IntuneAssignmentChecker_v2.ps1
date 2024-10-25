#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

# Intune Assignment Checker
# Author: Ugur Koc (Socials: @ugurkocde)
# Description: This script checks the assignments of Intune Configuration Policies and Device Configurations based on the groups that the user or device is a member of in Microsoft Entra (formerly Azure AD).

# Disclaimer: This script is provided AS IS without warranty of any kind. I am not responsible for any damage caused by this script. Use it at your own risk.

# You have to create an App Registration in Entra ID and grant the necessary permissions to the script.
# Note: Only Read Permissions are necessary. This script does not make any changes to the assignments or in Intune in general.
# Permissions required for the script: User.Read.All, Group.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All

################################ Prerequisites #####################################################

# Fill in your App ID, Tenant ID, and Certificate Thumbprint
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your EntraID
$certThumbprint = '<YourCertificateThumbprintHere>' # Thumbprint of the certificate associated with the App Registration
# $certName = '<YourCertificateNameHere>' # Name of the certificate associated with the App Registration

####################################################################################################

# Autoupdate function

# Version of the local script
$localVersion = "2.3.0"

# URL to the version file on GitHub
$versionUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/version_v2.txt"

# URL to the latest script on GitHub
$scriptUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/IntuneAssignmentChecker_v2.ps1"

# Determine the script path based on whether it's run as a file or from an IDE
if ($PSScriptRoot) {
    $newScriptPath = Join-Path $PSScriptRoot "IntuneAssignmentChecker_v2.ps1"
}
else {
    $currentDirectory = Get-Location
    $newScriptPath = Join-Path $currentDirectory "IntuneAssignmentChecker_v2.ps1"
}

# Flag to control auto-update behavior
$autoUpdate = $true  # Set to $false to disable auto-update

try {
    # Fetch the latest version number from GitHub
    $latestVersion = Invoke-RestMethod -Uri $versionUrl

    # Compare the local version with the latest version
    if ($localVersion -ne $latestVersion) {
        Write-Host "There is a new version available: $latestVersion. You are running $localVersion." -ForegroundColor Green

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
            Write-Host "Auto-update is disabled. Please download the latest version manually from: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "Could not check for updates. Please ensure you have an internet connection and try again. If the issue persists, please download the latest version manually from: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor Red
}


####################################################################################################

# Do not change the following code

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
            Reason     = "Needed to read device information from Azure AD"
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
            write-host "Attempting manual interactive connection (you need privileges to consent permissions)..." -ForegroundColor Yellow
            $permissionsList = ($requiredPermissions | ForEach-Object { $_.Permission }) -join ', '
            $connectionResult = Connect-MgGraph -Scopes $permissionsList -NoWelcome -ErrorAction Stop
        }
        else {
            Write-Host "Script execution cancelled by user." -ForegroundColor Red
            exit
        }
    }
    else {
        $connectionResult = Connect-MgGraph -ClientId $appid -TenantId $tenantid -CertificateThumbprint $certThumbprint -NoWelcome -ErrorAction Stop
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

##### Export Functions #####

# Function to add export data
function Add-ExportData($Category, $Items) {
    foreach ($item in $Items) {
        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }
        $assignmentReason = if ($script:defaultAssignmentReason -ne "N/A") { 
            $script:defaultAssignmentReason 
        }
        elseif ($item.AssignmentReason) { 
            $item.AssignmentReason 
        }
        else { 
            "N/A" 
        }
        $null = $exportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$itemName (ID: $($item.id))"
                AssignmentReason = $assignmentReason
            })
    }
}

# Function to add app export data
function Add-AppExportData($Category, $Apps) {
    foreach ($app in $Apps) {
        $appName = if ($app.displayName) { $app.displayName } else { $app.name }
        $assignmentReason = if ($script:defaultAssignmentReason -ne "N/A") { 
            $script:defaultAssignmentReason 
        }
        elseif ($app.AssignmentReason) { 
            $app.AssignmentReason 
        }
        else { 
            "N/A" 
        }
        $null = $exportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$appName (ID: $($app.id))"
                AssignmentReason = "$assignmentReason - $($app.AssignmentIntent)"
            })
    }
}

###### End of Export Functions ######

# Loop until the user decides to exit
do {
    # Main Menu for selection
    Write-Host "Select the type of entity you want to check the Assignments for in Intune:" -ForegroundColor Cyan
    Write-Host "1. User(s)" -ForegroundColor Yellow
    Write-Host "2. Group(s)" -ForegroundColor Yellow
    Write-Host "3. Device(s)" -ForegroundColor Yellow
    Write-Host "4. Show all 'All User' Assignments" -ForegroundColor Yellow
    Write-Host "5. Show all 'All Device' Assignments" -ForegroundColor Yellow 
    Write-Host "6. Search for Assignments by Setting Name" -ForegroundColor Yellow
    Write-Host "7. Report a Bug or Request a Feature" -ForegroundColor Yellow
    Write-Host "8. Exit" -ForegroundColor Red
    
    $selection = Read-Host "Please enter your choice (1, 2, 3, 4, 5, 6, 7 or 8)"
    switch ($selection) {

        '1' {
            Write-Host "User selection chosen" -ForegroundColor Green

            # Prompt for one or more User Principal Names
            Write-Host "Please enter User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
            $upnInput = Read-Host
            $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() }

            $exportData = [System.Collections.ArrayList]::new()

            foreach ($upn in $upns) {
                Write-Host "Checking following UPN: $upn" -ForegroundColor Yellow

                # Get User ID from Azure AD
                $userUri = "https://graph.microsoft.com/v1.0/users/$upn"
                $userResponse = Invoke-MgGraphRequest -Uri $userUri -Method Get
                $userId = $userResponse.id

                # Get User Group Memberships
                $groupsUri = "https://graph.microsoft.com/v1.0/users/$userid/transitiveMemberOf?`$select=id,displayName"
                $response = Invoke-MgGraphRequest -Uri $groupsUri -Method Get
                $groupIds = $response.value | ForEach-Object { $_.id }
                $groupNames = $response.value | ForEach-Object { $_.displayName }

                Write-Host "User Group Memberships: $($groupNames -join ', ')" -ForegroundColor Green

                Write-Host "Fetching Intune Profiles and Applications for the user ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections to hold relevant policies and applications
                $userRelevantDeviceConfigs = @()
                $userRelevantSettingsCatalog = @()
                $userRelevantAdminTemplates = @()
                $userRelevantCompliancePolicies = @()
                $userRelevantAppProtectionPolicies = @()
                $userRelevantAppConfigurationPolicies = @()
                $userRelevantAppsRequired = @()
                $userRelevantAppsAvailable = @()
                $userRelevantAppsUninstall = @()

                # Define URIs for Intune Policies and Applications
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appProtectionUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
                $appConfigurationUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

                # Fetch and process Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $totalDeviceConfigs = $deviceConfigsResponse.value.Count
                $currentDeviceConfig = 0
                foreach ($config in $deviceConfigsResponse.value) {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantDeviceConfigs += $config
                            break
                        }
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""


                # Fetch and process Settings Catalog policies
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $totalSettingsCatalog = $settingsCatalogResponse.value.Count
                $currentSettingsCatalog = 0
                foreach ($policy in $settingsCatalogResponse.value) {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantSettingsCatalog += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""

                # Fetch and process Administrative Templates
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $totalAdminTemplates = $adminTemplatesResponse.value.Count
                $currentAdminTemplate = 0
                foreach ($template in $adminTemplatesResponse.value) {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $template -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantAdminTemplates += $template
                            break
                        }
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""

                # Fetch and process Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $totalCompliancePolicies = $complianceResponse.value.Count
                $currentCompliancePolicy = 0
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $compliancepolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""

                # Fetch and process App Protection Policies
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                $totalAppProtectionPolicies = $appProtectionResponse.value.Count
                $currentAppProtectionPolicy = 0
                foreach ($policy in $appProtectionResponse.value) {
                    $currentAppProtectionPolicy++
                    Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                    $policyId = $policy.id
                    $policyType = $policy.'@odata.type'

                    # Determine the correct endpoint based on the policy type
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $policyDetails.assignments) {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                                $assignmentReason = "All Users"
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                                $assignmentReason = "Group Assignment"
                            }

                            if ($assignmentReason) {
                                Add-Member -InputObject $policyDetails -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantAppProtectionPolicies += $policyDetails
                                break
                            }
                        }
                    }
                }
                Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""

                # Fetch and process App Configuration Policies
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                $totalAppConfigurationPolicies = $appConfigurationResponse.value.Count
                $currentAppConfigurationPolicy = 0
                foreach ($policy in $appConfigurationResponse.value) {
                    $currentAppConfigurationPolicy++
                    Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantAppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $totalApps = $appResponse.value.Count
                $currentApp = 0
                foreach ($app in $appResponse.value) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' -or 
                ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)) {
                            switch ($assignment.intent) {
                                "required" { $userRelevantAppsRequired += $app; break }
                                "available" { $userRelevantAppsAvailable += $app; break }
                                "uninstall" { $userRelevantAppsUninstall += $app; break }
                            }
                            break
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                Write-Host "Intune Profiles and Apps have been successfully fetched for the user." -ForegroundColor Green

                # Generating Results for the User
                Write-Host "Generating Results for $upn..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the User: $upn" -ForegroundColor Green

                # Display the fetched Device Configurations
                Write-Host "------- Device Configurations -------" -ForegroundColor Cyan
                foreach ($config in $userRelevantDeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $assignmentInfo = if ($config.AssignmentReason) { ", Assignment Reason: $($config.AssignmentReason)" } else { "" }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Settings Catalog Policies
                Write-Host "------- Settings Catalog Policies -------" -ForegroundColor Cyan
                foreach ($policy in $userRelevantSettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Administrative Templates
                Write-Host "------- Administrative Templates -------" -ForegroundColor Cyan
                foreach ($template in $userRelevantAdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    $assignmentInfo = if ($template.AssignmentReason) { ", Assignment Reason: $($template.AssignmentReason)" } else { "" }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Compliance Policies
                Write-Host "------- Compliance Policies -------" -ForegroundColor Cyan
                foreach ($compliancepolicy in $userRelevantCompliancePolicies) {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                    $assignmentInfo = if ($compliancepolicy.AssignmentReason) { ", Assignment Reason: $($compliancepolicy.AssignmentReason)" } else { "" }
                    Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched App Protection Policies
                Write-Host "------- App Protection Policies -------" -ForegroundColor Cyan
                foreach ($policy in $userRelevantAppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyId = $policy.id
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType$assignmentInfo" -ForegroundColor White

                    Write-Host "  Protected Apps:" -ForegroundColor Yellow
                    foreach ($app in $policy.apps) {
                        $appId = if ($app.mobileAppIdentifier.windowsAppId) { $app.mobileAppIdentifier.windowsAppId } elseif ($app.mobileAppIdentifier.bundleId) { $app.mobileAppIdentifier.bundleId } else { $app.mobileAppIdentifier.packageId }
                        Write-Host "    - $appId" -ForegroundColor White
                    }
                }

                # Display the fetched App Configuration Policies
                Write-Host "------- App Configuration Policies -------" -ForegroundColor Cyan
                foreach ($policy in $userRelevantAppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Applications (Required)
                Write-Host "------- Applications (Required) -------" -ForegroundColor Cyan
                foreach ($app in $userRelevantAppsRequired) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Available)
                Write-Host "------- Applications (Available) -------" -ForegroundColor Cyan
                foreach ($app in $userRelevantAppsAvailable) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Uninstall)
                Write-Host "------- Applications (Uninstall) -------" -ForegroundColor Cyan
                foreach ($app in $userRelevantAppsUninstall) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Modify the Add-ExportData function to include the Assignment Reason
                function Add-ExportData($Category, $Items) {
                    foreach ($item in $Items) {
                        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }
                        $assignmentReason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "N/A" }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$itemName (ID: $($item.id))"
                                AssignmentReason = $assignmentReason
                            })
                    }
                }

                Add-ExportData "Device Name" @([PSCustomObject]@{displayName = $deviceName; id = $deviceId; AssignmentReason = "N/A" })
                Add-ExportData "Group Membership" ($groupNames | ForEach-Object { [PSCustomObject]@{displayName = $_; id = "N/A"; AssignmentReason = "N/A" } })

                Add-ExportData "Device Configuration" $deviceRelevantDeviceConfigs
                Add-ExportData "Settings Catalog Policy" $deviceRelevantSettingsCatalog
                Add-ExportData "Administrative Template" $deviceRelevantAdminTemplates
                Add-ExportData "Compliance Policy" $deviceRelevantCompliancePolicies
                Add-ExportData "App Protection Policy" $deviceRelevantAppProtectionPolicies
                Add-ExportData "App Configuration Policy" $deviceRelevantAppConfigurationPolicies

                Add-AppExportData "Required App" $deviceRelevantAppsRequired
                Add-AppExportData "Available App" $deviceRelevantAppsAvailable
                Add-AppExportData "Uninstall App" $deviceRelevantAppsUninstall

                # Prompt the user to export results to CSV
                $export = Read-Host "Would you like to export the results to a CSV file? (y/n)"
                if ($export -eq 'y') {
                    Add-Type -AssemblyName System.Windows.Forms
                    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                    $SaveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                    $SaveFileDialog.Title = "Save results to CSV"
                    $SaveFileDialog.ShowDialog() | Out-Null
                    $outputPath = $SaveFileDialog.FileName
                
                    if ($outputPath) {
                        # Export data to CSV
                        $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                        Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                    }
                    else {
                        Write-Host "No file selected, export cancelled." -ForegroundColor Red
                    }
                }
            }
        }

        '2' {
            Write-Host "Group selection chosen" -ForegroundColor Green

            # Prompt for one or more Group names
            Write-Host "Please enter Group name(s), separated by commas (,): " -ForegroundColor Cyan
            $groupInput = Read-Host
            $groupNames = $groupInput -split ',' | ForEach-Object { $_.Trim() }

            $exportData = [System.Collections.ArrayList]::new()

            foreach ($groupName in $groupNames) {
                Write-Host "Checking following Group: $groupName" -ForegroundColor Yellow

                # Get Group ID from Azure AD
                $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$groupName'"
                $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        
                if ($groupResponse.value.Count -eq 0) {
                    Write-Host "No group found with name: $groupName" -ForegroundColor Red
                    continue
                }
                elseif ($groupResponse.value.Count -gt 1) {
                    Write-Host "Multiple groups found with name: $groupName. Please use a more specific name." -ForegroundColor Red
                    continue
                }

                $groupId = $groupResponse.value[0].id
                Write-Host "Group Name: $groupName, Group ID: $groupId" -ForegroundColor Green

                # Fetch and display group members
                $membersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=displayName"
                $membersResponse = Invoke-MgGraphRequest -Uri $membersUri -Method Get
        
                Write-Host "Group Members:" -ForegroundColor Cyan
                foreach ($member in $membersResponse.value) {
                    Write-Host "  - $($member.displayName)" -ForegroundColor White
                }

                # Check if there are more pages of members
                while ($membersResponse.'@odata.nextLink') {
                    $membersResponse = Invoke-MgGraphRequest -Uri $membersResponse.'@odata.nextLink' -Method Get
                    foreach ($member in $membersResponse.value) {
                        Write-Host "  - $($member.displayName)" -ForegroundColor White
                    }
                }

                Write-Host "Fetching Intune Profiles and Applications for the group ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections to hold relevant policies and applications
                $groupRelevantDeviceConfigs = @()
                $groupRelevantSettingsCatalog = @()
                $groupRelevantAdminTemplates = @()
                $groupRelevantCompliancePolicies = @()
                $groupRelevantAppProtectionPolicies = @()
                $groupRelevantAppConfigurationPolicies = @()
                $groupRelevantAppsRequired = @()
                $groupRelevantAppsAvailable = @()
                $groupRelevantAppsUninstall = @()


                # Define URIs for Intune Policies and Applications
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appProtectionUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
                $appConfigurationUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

                # Fetch and process Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $totalDeviceConfigs = $deviceConfigsResponse.value.Count
                $currentDeviceConfig = 0
                foreach ($config in $deviceConfigsResponse.value) {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            $groupRelevantDeviceConfigs += $config
                            break
                        }
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Settings Catalog policies
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $totalSettingsCatalog = $settingsCatalogResponse.value.Count
                $currentSettingsCatalog = 0
                foreach ($policy in $settingsCatalogResponse.value) {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            $groupRelevantSettingsCatalog += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Administrative Templates
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $totalAdminTemplates = $adminTemplatesResponse.value.Count
                $currentAdminTemplate = 0
                foreach ($template in $adminTemplatesResponse.value) {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            $groupRelevantAdminTemplates += $template
                            break
                        }
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $totalCompliancePolicies = $complianceResponse.value.Count
                $currentCompliancePolicy = 0
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            $groupRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process App Protection Policies
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                $totalAppProtectionPolicies = $appProtectionResponse.value.Count
                $currentAppProtectionPolicy = 0
                foreach ($policy in $appProtectionResponse.value) {
                    $currentAppProtectionPolicy++
                    Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                    $policyId = $policy.id
                    $policyType = $policy.'@odata.type'

                    # Determine the correct endpoint based on the policy type
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                        foreach ($assignment in $policyDetails.assignments) {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                                $groupRelevantAppProtectionPolicies += $policyDetails
                                break
                            }
                        }
                    }
                }
                Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process App Configuration Policies
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                $totalAppConfigurationPolicies = $appConfigurationResponse.value.Count
                $currentAppConfigurationPolicy = 0
                foreach ($policy in $appConfigurationResponse.value) {
                    $currentAppConfigurationPolicy++
                    Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            $groupRelevantAppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $totalApps = $appResponse.value.Count
                $currentApp = 0
                foreach ($app in $appResponse.value) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId) {
                            switch ($assignment.intent) {
                                "required" { $groupRelevantAppsRequired += $app; break }
                                "available" { $groupRelevantAppsAvailable += $app; break }
                                "uninstall" { $groupRelevantAppsUninstall += $app; break }
                            }
                            break
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                Write-Host "Intune Profiles and Apps have been successfully fetched for the group." -ForegroundColor Green

                # Generating Results for the Group
                Write-Host "Generating Results for $groupName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the Group: $groupName" -ForegroundColor Green

                # Display the fetched Device Configurations
                Write-Host "------- Device Configurations -------" -ForegroundColor Cyan
                foreach ($config in $groupRelevantDeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
                }

                # Display the fetched Settings Catalog Policies
                Write-Host "------- Settings Catalog Policies -------" -ForegroundColor Cyan
                foreach ($policy in $groupRelevantSettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                }

                # Display the fetched Administrative Templates
                Write-Host "------- Administrative Templates -------" -ForegroundColor Cyan
                foreach ($template in $groupRelevantAdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
                }

                # Display the fetched Compliance Policies
                Write-Host "------- Compliance Policies -------" -ForegroundColor Cyan
                foreach ($compliancepolicy in $groupRelevantCompliancePolicies) {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                    Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
                }


                # Display the fetched App Protection Policies
                Write-Host "------- App Protection Policies -------" -ForegroundColor Cyan
                foreach ($policy in $groupRelevantAppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyId = $policy.id
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White
        
                    Write-Host "  Protected Apps:" -ForegroundColor Yellow
                    foreach ($app in $policy.apps) {
                        $appId = if ($app.mobileAppIdentifier.windowsAppId) { $app.mobileAppIdentifier.windowsAppId } elseif ($app.mobileAppIdentifier.bundleId) { $app.mobileAppIdentifier.bundleId } else { $app.mobileAppIdentifier.packageId }
                        Write-Host "    - $appId" -ForegroundColor White
                    }
                }

                # Display the fetched App Configuration Policies
                Write-Host "------- App Configuration Policies -------" -ForegroundColor Cyan
                foreach ($policy in $groupRelevantAppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                }

                # Display the fetched Applications (Required)
                Write-Host "------- Applications (Required) -------" -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsRequired) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Available)
                Write-Host "------- Applications (Available) -------" -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsAvailable) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Uninstall)
                Write-Host "------- Applications (Uninstall) -------" -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsUninstall) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Prepare data for export
                $exportData += [PSCustomObject]@{
                    GroupName                = $groupName
                    GroupID                  = $groupId
                    DeviceConfigurations     = ($groupRelevantDeviceConfigs | ForEach-Object { $_.displayName }) -join '; '
                    SettingsCatalogPolicies  = ($groupRelevantSettingsCatalog | ForEach-Object { $_.name }) -join '; '
                    AdministrativeTemplates  = ($groupRelevantAdminTemplates | ForEach-Object { $_.displayName }) -join '; '
                    CompliancePolicies       = ($groupRelevantCompliancePolicies | ForEach-Object { $_.displayName }) -join '; '
                    AppProtectionPolicies    = ($groupRelevantAppProtectionPolicies | ForEach-Object { "$($_.displayName) ($($_.'@odata.type'))" }) -join '; '
                    AppConfigurationPolicies = ($groupRelevantAppConfigurationPolicies | ForEach-Object { $_.displayName }) -join '; '
                    RequiredApps             = ($groupRelevantAppsRequired | ForEach-Object { $_.displayName }) -join '; '
                    AvailableApps            = ($groupRelevantAppsAvailable | ForEach-Object { $_.displayName }) -join '; '
                    UninstallApps            = ($groupRelevantAppsUninstall | ForEach-Object { $_.displayName }) -join '; '
                }
            }

            # Prompt the user to export results to CSV
            $export = Read-Host "Would you like to export the results to a CSV file? (y/n)"
            if ($export -eq 'y') {
                Add-Type -AssemblyName System.Windows.Forms
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                $SaveFileDialog.Title = "Save results to CSV"
                $SaveFileDialog.ShowDialog() | Out-Null
                $outputPath = $SaveFileDialog.FileName

                if ($outputPath) {
                    # Export data to CSV
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else {
                    Write-Host "No file selected, export cancelled." -ForegroundColor Red
                }
            }
        }


        '3' {
            Write-Host "Device selection chosen" -ForegroundColor Green

            $exportData = [System.Collections.ArrayList]::new()

            # Prompt for one or more Device Names
            Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
            $deviceNamesInput = Read-Host
            $deviceNames = $deviceNamesInput -split ',' | ForEach-Object { $_.Trim() }

            foreach ($deviceName in $deviceNames) {
                Write-Host "Checking following Device: $deviceName" -ForegroundColor Yellow

                # Get Device ID from Azure AD based on Display Name
                $deviceUri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$deviceName'"
                $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get
                $deviceId = $deviceResponse.value.id
                if ($deviceId) {
                    Write-Host "Device Found! -> Azure AD Device ID: $deviceId " -ForegroundColor Green
                }
                else {
                    Write-Host "Device Not Found: $deviceName" -ForegroundColor Red
                    continue
                }

                # Get Device Group Memberships
                $groupsUri = "https://graph.microsoft.com/v1.0/devices/$deviceId/transitiveMemberOf?`$select=id,displayName"
                $response = Invoke-MgGraphRequest -Uri $groupsUri -Method Get
                $groupIds = $response.value | ForEach-Object { $_.id }
                $groupNames = $response.value | ForEach-Object { $_.displayName }

                Write-Host "Device Group Memberships:" -ForegroundColor Cyan
                foreach ($groupName in $groupNames) {
                    Write-Host "  - $groupName" -ForegroundColor White
                }

                Write-Host "Fetching Intune Profiles and Applications for the device ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections to hold relevant policies and applications
                $deviceRelevantDeviceConfigs = @()
                $deviceRelevantSettingsCatalog = @()
                $deviceRelevantAdminTemplates = @()
                $deviceRelevantCompliancePolicies = @()
                $deviceRelevantAppProtectionPolicies = @()
                $deviceRelevantAppConfigurationPolicies = @()
                $deviceRelevantAppsRequired = @()
                $deviceRelevantAppsAvailable = @()
                $deviceRelevantAppsUninstall = @()

                # Define URIs for Intune Policies and Applications
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appProtectionUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
                $appConfigurationUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

                # Fetch and process Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $totalDeviceConfigs = $deviceConfigsResponse.value.Count
                $currentDeviceConfig = 0
                foreach ($config in $deviceConfigsResponse.value) {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantDeviceConfigs += $config
                            break
                        }
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Settings Catalog policies
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $totalSettingsCatalog = $settingsCatalogResponse.value.Count
                $currentSettingsCatalog = 0
                foreach ($policy in $settingsCatalogResponse.value) {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantSettingsCatalog += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Administrative Templates
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $totalAdminTemplates = $adminTemplatesResponse.value.Count
                $currentAdminTemplate = 0
                foreach ($template in $adminTemplatesResponse.value) {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $template -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantAdminTemplates += $template
                            break
                        }
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $totalCompliancePolicies = $complianceResponse.value.Count
                $currentCompliancePolicy = 0
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            Add-Member -InputObject $compliancepolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process App Protection Policies
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                $totalAppProtectionPolicies = $appProtectionResponse.value.Count
                $currentAppProtectionPolicy = 0
                foreach ($policy in $appProtectionResponse.value) {
                    $currentAppProtectionPolicy++
                    Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                    $policyId = $policy.id
                    $policyType = $policy.'@odata.type'

                    # Determine the correct endpoint based on the policy type
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                        default { $null }
                    }

                    if ($assignmentsUri) {
                        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                        foreach ($assignment in $policyDetails.assignments) {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
                    ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)) {
                                $deviceRelevantAppProtectionPolicies += $policyDetails
                                break
                            }
                        }
                    }
                }
                Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process App Configuration Policies
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                $totalAppConfigurationPolicies = $appConfigurationResponse.value.Count
                $currentAppConfigurationPolicy = 0
                foreach ($policy in $appConfigurationResponse.value) {
                    $currentAppConfigurationPolicy++
                    Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
                ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)) {
                            $deviceRelevantAppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Fetch and process Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $totalApps = $appResponse.value.Count
                $currentApp = 0
                foreach ($app in $appResponse.value) {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
                ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)) {
                            switch ($assignment.intent) {
                                "required" { $deviceRelevantAppsRequired += $app; break }
                                "available" { $deviceRelevantAppsAvailable += $app; break }
                                "uninstall" { $deviceRelevantAppsUninstall += $app; break }
                            }
                            break
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                Write-Host "Intune Profiles and Apps have been successfully fetched for the device." -ForegroundColor Green

                # Generating Results for the Device
                Write-Host "Generating Results for $deviceName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the Device: $deviceName" -ForegroundColor Green

                # Display the fetched Device Configurations
                Write-Host "------- Device Configurations -------" -ForegroundColor Cyan
                foreach ($config in $deviceRelevantDeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $assignmentInfo = if ($config.AssignmentReason) { ", Assignment Reason: $($config.AssignmentReason)" } else { "" }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Settings Catalog Policies
                Write-Host "------- Settings Catalog Policies -------" -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantSettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Administrative Templates
                Write-Host "------- Administrative Templates -------" -ForegroundColor Cyan
                foreach ($template in $deviceRelevantAdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    $assignmentInfo = if ($template.AssignmentReason) { ", Assignment Reason: $($template.AssignmentReason)" } else { "" }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Compliance Policies
                Write-Host "------- Compliance Policies -------" -ForegroundColor Cyan
                foreach ($compliancepolicy in $deviceRelevantCompliancePolicies) {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                    $assignmentInfo = if ($compliancepolicy.AssignmentReason) { ", Assignment Reason: $($compliancepolicy.AssignmentReason)" } else { "" }
                    Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched App Protection Policies
                Write-Host "------- App Protection Policies -------" -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantAppProtectionPolicies) {
                    $policyName = $policy.displayName
                    $policyId = $policy.id
                    $policyType = switch ($policy.'@odata.type') {
                        "#microsoft.graph.androidManagedAppProtection" { "Android" }
                        "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                        "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                        default { "Unknown" }
                    }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType$assignmentInfo" -ForegroundColor White

                    Write-Host "  Protected Apps:" -ForegroundColor Yellow
                    foreach ($app in $policy.apps) {
                        $appId = if ($app.mobileAppIdentifier.windowsAppId) { $app.mobileAppIdentifier.windowsAppId } elseif ($app.mobileAppIdentifier.bundleId) { $app.mobileAppIdentifier.bundleId } else { $app.mobileAppIdentifier.packageId }
                        Write-Host "    - $appId" -ForegroundColor White
                    }
                }

                # Display the fetched App Configuration Policies
                Write-Host "------- App Configuration Policies -------" -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantAppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Applications (Required)
                Write-Host "------- Applications (Required) -------" -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsRequired) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Available)
                Write-Host "------- Applications (Available) -------" -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsAvailable) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Uninstall)
                Write-Host "------- Applications (Uninstall) -------" -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsUninstall) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Modify the Add-ExportData function to include the Assignment Reason
                function Add-ExportData($Category, $Items) {
                    foreach ($item in $Items) {
                        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }
                        $assignmentReason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "N/A" }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$itemName (ID: $($item.id))"
                                AssignmentReason = $assignmentReason
                            })
                    }
                }

                Add-ExportData "Device Name" @([PSCustomObject]@{displayName = $deviceName; id = $deviceId; AssignmentReason = "N/A" })
                Add-ExportData "Group Membership" ($groupNames | ForEach-Object { [PSCustomObject]@{displayName = $_; id = "N/A"; AssignmentReason = "N/A" } })

                Add-ExportData "Device Configuration" $deviceRelevantDeviceConfigs
                Add-ExportData "Settings Catalog Policy" $deviceRelevantSettingsCatalog
                Add-ExportData "Administrative Template" $deviceRelevantAdminTemplates
                Add-ExportData "Compliance Policy" $deviceRelevantCompliancePolicies
                Add-ExportData "App Protection Policy" $deviceRelevantAppProtectionPolicies
                Add-ExportData "App Configuration Policy" $deviceRelevantAppConfigurationPolicies

                Add-AppExportData "Required App" $deviceRelevantAppsRequired
                Add-AppExportData "Available App" $deviceRelevantAppsAvailable
                Add-AppExportData "Uninstall App" $deviceRelevantAppsUninstall

                # Prompt the user to export results to CSV
                $export = Read-Host "Would you like to export the results to a CSV file? (y/n)"
                if ($export -eq 'y') {
                    Add-Type -AssemblyName System.Windows.Forms
                    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                    $SaveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                    $SaveFileDialog.Title = "Save results to CSV"
                    $SaveFileDialog.ShowDialog() | Out-Null
                    $outputPath = $SaveFileDialog.FileName
                
                    if ($outputPath) {
                        # Export data to CSV
                        $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                        Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                    }
                    else {
                        Write-Host "No file selected, export cancelled." -ForegroundColor Red
                    }
                }
            }
        }
        
        '4' {
            Write-Host "'Show all `All User` Assignments' chosen" -ForegroundColor Green
            $script:defaultAssignmentReason = "All Users"

            Write-Host "Fetching Intune Profiles and Applications ... (this takes a few seconds)" -ForegroundColor Yellow

            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections to hold relevant policies and applications
            $allUserDeviceConfigs = @()
            $allUserSettingsCatalog = @()
            $allUserAdminTemplates = @()
            $allUserCompliancePolicies = @()
            $allUserAppProtectionPolicies = @()
            $allUserAppConfigurationPolicies = @()
            $allUserAppsRequired = @()
            $allUserAppsAvailable = @()
            $allUserAppsUninstall = @()

            # Define URIs for Intune Policies and Applications
            $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
            $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
            $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
            $appProtectionUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
            $appConfigurationUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            $totalDeviceConfigs = $deviceConfigsResponse.value.Count
            $currentDeviceConfig = 0
            foreach ($config in $deviceConfigsResponse.value) {
                $currentDeviceConfig++
                Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                $configId = $config.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserDeviceConfigs += $config
                        break
                    }
                }
            }
            Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Settings Catalog policies
            $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
            $totalSettingsCatalog = $settingsCatalogResponse.value.Count
            $currentSettingsCatalog = 0
            foreach ($policy in $settingsCatalogResponse.value) {
                $currentSettingsCatalog++
                Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserSettingsCatalog += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Administrative Templates
            $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
            $totalAdminTemplates = $adminTemplatesResponse.value.Count
            $currentAdminTemplate = 0
            foreach ($template in $adminTemplatesResponse.value) {
                $currentAdminTemplate++
                Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                $templateId = $template.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserAdminTemplates += $template
                        break
                    }
                }
            }
            Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            $totalCompliancePolicies = $complianceResponse.value.Count
            $currentCompliancePolicy = 0
            foreach ($compliancepolicy in $complianceResponse.value) {
                $currentCompliancePolicy++
                Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                $compliancepolicyId = $compliancepolicy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserCompliancePolicies += $compliancepolicy
                        break
                    }
                }
            }
            Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process App Protection Policies
            $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
            $totalAppProtectionPolicies = $appProtectionResponse.value.Count
            $currentAppProtectionPolicy = 0
            foreach ($policy in $appProtectionResponse.value) {
                $currentAppProtectionPolicy++
                Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                $policyId = $policy.id
                $policyType = $policy.'@odata.type'

                # Determine the correct endpoint based on the policy type
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $policyDetails.assignments) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $allUserAppProtectionPolicies += $policyDetails
                            break
                        }
                    }
                }
            }
            Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process App Configuration Policies
            $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
            $totalAppConfigurationPolicies = $appConfigurationResponse.value.Count
            $currentAppConfigurationPolicy = 0
            foreach ($policy in $appConfigurationResponse.value) {
                $currentAppConfigurationPolicy++
                Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserAppConfigurationPolicies += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $totalApps = $appResponse.value.Count
            $currentApp = 0
            foreach ($app in $appResponse.value) {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                    continue
                }

                $currentApp++
                Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        switch ($assignment.intent) {
                            "required" { $allUserAppsRequired += $app; break }
                            "available" { $allUserAppsAvailable += $app; break }
                            "uninstall" { $allUserAppsUninstall += $app; break }
                        }
                        break
                    }
                }
            }
            Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            Write-Host "Intune Profiles and Apps have been successfully fetched." -ForegroundColor Green

            # Display the fetched 'All User' Device Configurations
            Write-Host "------- 'All User' Device Configurations -------" -ForegroundColor Cyan
            foreach ($config in $allUserDeviceConfigs) {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Settings Catalog Policies
            Write-Host "------- 'All User' Settings Catalog Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserSettingsCatalog) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Administrative Templates
            Write-Host "------- 'All User' Administrative Templates -------" -ForegroundColor Cyan
            foreach ($template in $allUserAdminTemplates) {
                $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Compliance Policies
            Write-Host "------- 'All User' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allUserCompliancePolicies) {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' App Protection Policies
            Write-Host "------- 'All User' App Protection Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserAppProtectionPolicies) {
                $policyName = $policy.displayName
                $policyId = $policy.id
                $policyType = switch ($policy.'@odata.type') {
                    "#microsoft.graph.androidManagedAppProtection" { "Android" }
                    "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                    "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                    default { "Unknown" }
                }
                Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White
    
                Write-Host "  Protected Apps:" -ForegroundColor Yellow
                foreach ($app in $policy.apps) {
                    $appId = if ($app.mobileAppIdentifier.windowsAppId) { $app.mobileAppIdentifier.windowsAppId } elseif ($app.mobileAppIdentifier.bundleId) { $app.mobileAppIdentifier.bundleId } else { $app.mobileAppIdentifier.packageId }
                    Write-Host "    - $appId" -ForegroundColor White
                }
            }

            # Display the fetched 'All User' App Configuration Policies
            Write-Host "------- 'All User' App Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserAppConfigurationPolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Required)
            Write-Host "------- 'All User' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsRequired) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Available)
            Write-Host "------- 'All User' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsAvailable) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Uninstall)
            Write-Host "------- 'All User' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsUninstall) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Prompt the user to export results to CSV
            $export = Read-Host "Would you like to export the results to a CSV file? (y/n)"
            if ($export -eq 'y') {
                Add-Type -AssemblyName System.Windows.Forms
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                $SaveFileDialog.Title = "Save results to CSV"
                $SaveFileDialog.ShowDialog() | Out-Null
                $outputPath = $SaveFileDialog.FileName

                if ($outputPath) {
                    Add-ExportData "Device Configuration" $allUserDeviceConfigs
                    Add-ExportData "Settings Catalog Policy" $allUserSettingsCatalog 
                    Add-ExportData "Administrative Template" $allUserAdminTemplates 
                    Add-ExportData "Compliance Policy" $allUserCompliancePolicies 
                    Add-ExportData "App Configuration Policy" $allUserAppConfigurationPolicies 

                    foreach ($policy in $allUserAppProtectionPolicies) {
                        $policyType = switch ($policy.'@odata.type') {
                            "#microsoft.graph.androidManagedAppProtection" { "Android" }
                            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                            default { "Unknown" }
                        }
                        $protectedApps = ($policy.apps | ForEach-Object { 
                                if ($_.mobileAppIdentifier.windowsAppId) { $_.mobileAppIdentifier.windowsAppId }
                                elseif ($_.mobileAppIdentifier.bundleId) { $_.mobileAppIdentifier.bundleId }
                                elseif ($_.mobileAppIdentifier.packageId) { $_.mobileAppIdentifier.packageId }
                            }) -join '; '
    
                        $exportData += [PSCustomObject]@{
                            Category      = "App Protection Policy ($policyType)"
                            Item          = "$($policy.displayName) (ID: $($policy.id))"
                            ProtectedApps = $protectedApps
                        }
                    }

                    Add-AppExportData "App (Required)" $allUserAppsRequired
                    Add-AppExportData "App (Available)" $allUserAppsAvailable
                    Add-AppExportData "App (Uninstall)" $allUserAppsUninstall

                    # Export data to CSV
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else {
                    Write-Host "No file selected, export cancelled." -ForegroundColor Red
                }
            }
        }

        '5' {
            Write-Host "'Show all `All Devices` Assignments' chosen" -ForegroundColor Green
            $script:defaultAssignmentReason = "All Devices"

            Write-Host "Fetching Intune Profiles and Applications ... (this takes a few seconds)" -ForegroundColor Yellow
            
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections to hold relevant policies and applications
            $allDeviceDeviceConfigs = @()
            $allDeviceSettingsCatalog = @()
            $allDeviceAdminTemplates = @()
            $allDeviceCompliancePolicies = @()
            $allDeviceAppProtectionPolicies = @()
            $allDeviceAppConfigurationPolicies = @()
            $allDeviceAppsRequired = @()
            $allDeviceAppsAvailable = @()
            $allDeviceAppsUninstall = @()

            # Define URIs for Intune Policies and Applications
            $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
            $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
            $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
            $appProtectionUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
            $appConfigurationUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            $totalDeviceConfigs = $deviceConfigsResponse.value.Count
            $currentDeviceConfig = 0
            foreach ($config in $deviceConfigsResponse.value) {
                $currentDeviceConfig++
                Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                $configId = $config.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDeviceDeviceConfigs += $config
                        break
                    }
                }
            }
            Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Settings Catalog policies
            $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
            $totalSettingsCatalog = $settingsCatalogResponse.value.Count
            $currentSettingsCatalog = 0
            foreach ($policy in $settingsCatalogResponse.value) {
                $currentSettingsCatalog++
                Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDeviceSettingsCatalog += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Administrative Templates
            $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
            $totalAdminTemplates = $adminTemplatesResponse.value.Count
            $currentAdminTemplate = 0
            foreach ($template in $adminTemplatesResponse.value) {
                $currentAdminTemplate++
                Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                $templateId = $template.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDeviceAdminTemplates += $template
                        break
                    }
                }
            }
            Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            $totalCompliancePolicies = $complianceResponse.value.Count
            $currentCompliancePolicy = 0
            foreach ($compliancepolicy in $complianceResponse.value) {
                $currentCompliancePolicy++
                Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                $compliancepolicyId = $compliancepolicy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDeviceCompliancePolicies += $compliancepolicy
                        break
                    }
                }
            }
            Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process App Protection Policies
            $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
            $totalAppProtectionPolicies = $appProtectionResponse.value.Count
            $currentAppProtectionPolicy = 0
            foreach ($policy in $appProtectionResponse.value) {
                $currentAppProtectionPolicy++
                Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                $policyId = $policy.id
                $policyType = $policy.'@odata.type'

                # Determine the correct endpoint based on the policy type
                $assignmentsUri = switch ($policyType) {
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" }
                    default { $null }
                }

                if ($assignmentsUri) {
                    $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $policyDetails.assignments) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $allDeviceAppProtectionPolicies += $policyDetails
                            break
                        }
                    }
                }
            }
            Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process App Configuration Policies
            $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
            $totalAppConfigurationPolicies = $appConfigurationResponse.value.Count
            $currentAppConfigurationPolicy = 0
            foreach ($policy in $appConfigurationResponse.value) {
                $currentAppConfigurationPolicy++
                Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDeviceAppConfigurationPolicies += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $totalApps = $appResponse.value.Count
            $currentApp = 0
            foreach ($app in $appResponse.value) {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                    continue
                }

                $currentApp++
                Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                $appName = $app.displayName
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        Add-Member -InputObject $app -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                        switch ($assignment.intent) {
                            "required" { $allDeviceAppsRequired += $app; break }
                            "available" { $allDeviceAppsAvailable += $app; break }
                            "uninstall" { $allDeviceAppsUninstall += $app; break }
                        }
                    }
                }
            }
            Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ""  # Move to the next line after the loop

            Write-Host "Intune Profiles and Apps have been successfully fetched." -ForegroundColor Green
        
            # Display the fetched 'All Device' Configuration Policies
            Write-Host "------- 'All Device' Device Configurations -------" -ForegroundColor Cyan
            foreach ($config in $allDeviceDeviceConfigs) {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Settings Catalog Policies
            Write-Host "------- 'All Device' Settings Catalog Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceSettingsCatalog) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Administrative Templates
            Write-Host "------- 'All Device' Administrative Templates -------" -ForegroundColor Cyan
            foreach ($template in $allDeviceAdminTemplates) {
                $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Compliance Policies
            Write-Host "------- 'All Device' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allDeviceCompliancePolicies) {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' App Protection Policies
            Write-Host "------- 'All Device' App Protection Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceAppProtectionPolicies) {
                $policyName = $policy.displayName
                $policyId = $policy.id
                $policyType = switch ($policy.'@odata.type') {
                    "#microsoft.graph.androidManagedAppProtection" { "Android" }
                    "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                    "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                    default { "Unknown" }
                }
                Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White
    
                Write-Host "  Protected Apps:" -ForegroundColor Yellow
                foreach ($app in $policy.apps) {
                    $appId = if ($app.mobileAppIdentifier.windowsAppId) { $app.mobileAppIdentifier.windowsAppId } elseif ($app.mobileAppIdentifier.bundleId) { $app.mobileAppIdentifier.bundleId } else { $app.mobileAppIdentifier.packageId }
                    Write-Host "    - $appId" -ForegroundColor White
                }
            }

            # Display the fetched 'All Device' App Configuration Policies
            Write-Host "------- 'All Device' App Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceAppConfigurationPolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Applications (Required)
            Write-Host "------- 'All Device' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsRequired) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Applications (Available)
            Write-Host "------- 'All Device' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsAvailable) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Applications (Uninstall)
            Write-Host "------- 'All Device' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsUninstall) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }
                
            # Prompt the user to export results to CSV
            $export = Read-Host "Would you like to export the results to a CSV file? (y/n)"
            if ($export -eq 'y') {
                Add-Type -AssemblyName System.Windows.Forms
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                $SaveFileDialog.Title = "Save results to CSV"
                $SaveFileDialog.ShowDialog() | Out-Null
                $outputPath = $SaveFileDialog.FileName
 
                if ($outputPath) {
                    Add-ExportData "Device Configuration" $allDeviceDeviceConfigs
                    Add-ExportData "Settings Catalog Policy" $allDeviceSettingsCatalog 
                    Add-ExportData "Administrative Template" $allDeviceAdminTemplates 
                    Add-ExportData "Compliance Policy" $allDeviceCompliancePolicies
                    Add-ExportData "App Configuration Policy" $allDeviceAppConfigurationPolicies 
 
                    foreach ($policy in $allDeviceAppProtectionPolicies) {
                        $policyType = switch ($policy.'@odata.type') {
                            "#microsoft.graph.androidManagedAppProtection" { "Android" }
                            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                            default { "Unknown" }
                        }
                        $protectedApps = ($policy.apps | ForEach-Object { 
                                if ($_.mobileAppIdentifier.windowsAppId) { $_.mobileAppIdentifier.windowsAppId }
                                elseif ($_.mobileAppIdentifier.bundleId) { $_.mobileAppIdentifier.bundleId }
                                elseif ($_.mobileAppIdentifier.packageId) { $_.mobileAppIdentifier.packageId }
                            }) -join '; '
     
                        $exportData += [PSCustomObject]@{
                            Category      = "App Protection Policy ($policyType)"
                            Item          = "$($policy.displayName) (ID: $($policy.id))"
                            ProtectedApps = $protectedApps
                        }
                    }
 
                    Add-AppExportData "App (Required)" $allDeviceAppsRequired
                    Add-AppExportData "App (Available)" $allDeviceAppsAvailable
                    Add-AppExportData "App (Uninstall)" $allDeviceAppsUninstall
 
                    # Export data to CSV
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else {
                    Write-Host "No file selected, export cancelled." -ForegroundColor Red
                }
            }
        }
        
        '6' {


            Write-Host "Search for Assignments by the Name of a Setting chosen" -ForegroundColor Green

            # Prompt for DisplayNames
            $displayNamesInput = Read-Host "Please enter the DisplayNames of the settings you want to search for (comma-separated)"
            $displayNames = $displayNamesInput -split ',' | ForEach-Object { $_.Trim() }

            # Define URIs for Intune Configuration Policies
            $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            
            # Get Intune Configuration Policies
            $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get

            $foundSettings = @()

            foreach ($policy in $policiesResponse.value) {
                $policyId = $policy.id

                # Fetch the policy name
                $policyDetailUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')"
                $policyDetailResponse = Invoke-MgGraphRequest -Uri $policyDetailUri -Method Get
                $policyName = $policyDetailResponse.name

                $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/settings?`$expand=settingDefinitions&top=1000"
                $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method Get

                foreach ($setting in $settingsResponse.value) {
                    foreach ($definition in $setting.settingDefinitions) {
                        if ($displayNames -contains $definition.displayName) {
                            # Get Policy Assignments
                            $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                            $assignments = @()
                            foreach ($assignment in $assignmentResponse.value) {
                                switch ($assignment.target.'@odata.type') {
                                    '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                                        $assignments += 'All Users'
                                    }
                                    '#microsoft.graph.allDevicesAssignmentTarget' {
                                        $assignments += 'All Devices'
                                    }
                                    default {
                                        if ($assignment.target.groupId) {
                                            $assignments += $assignment.target.groupId
                                        }
                                        else {
                                            $assignments += "Unknown"
                                        }
                                    }
                                }
                            }

                            $foundSettings += [PSCustomObject]@{
                                PolicyName              = $policyName
                                PolicyId                = $policyId
                                SettingDisplayName      = $definition.displayName
                                SettingDescription      = $definition.description
                                "Assignments (GroupID)" = $assignments -join ', '
                            }
                        }
                    }
                }
            }

            if ($foundSettings.Count -eq 0) {
                Write-Host "No settings found with the provided displayNames" -ForegroundColor Red
            }
            else {
                Write-Host "Settings found with the provided displayNames:" -ForegroundColor Green
                $foundSettings | Format-List
            }
        }

        '7' {
            Write-Host "Opening GitHub Repository..." -ForegroundColor Green
            Start-Process "https://github.com/ugurkocde/IntuneAssignmentChecker"
        }

        '8' {
            Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
            Disconnect-MgGraph | Out-Null
            Write-Host "Exiting..." -ForegroundColor Red
            exit
        }

        default {
            Write-Host "Invalid choice, please select 1, 2, 3, 4, 5, 6, 7 or 8." -ForegroundColor Red
            $script:defaultAssignmentReason = "N/A"
        }
    }

    # Pause before showing the menu again
    if ($selection -ne '8') {
        Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
} while ($selection -ne '8')
