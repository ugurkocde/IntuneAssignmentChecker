# Intune Assignment Checker
# Author: Ugur Koc (Socials: @ugurkocde)
# Description: This script checks the assignments of Intune Configuration Policies and Device Configurations based on the groups that the user or device is a member of in Microsoft Entra (formerly Azure AD).

# Disclaimer: This script is provided AS IS without warranty of any kind. I am not responsible for any damage caused by this script. Use it at your own risk.

# You have to create an App Registration in Entra ID and grant the necessary permissions to the script.
# Note: Only Read Permissions are necessary. This script does not make any changes to the assignments or in Intune in general.
# Permissions required for the script: User.Read.All, Group.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All

################################ Prerequisites #####################################################

# Fill in your App ID, Tenant ID, and Secret
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your EntraID
$secret = '<YourAppSecretHere>' # Secret of the App Registration

####################################################################################################

# Autoupdate function

# Version of the local script
$localVersion = "1.3.0"

# URL to the version file on GitHub
$versionUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/version.txt"

# URL to the latest script on GitHub
$scriptUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/v1/IntuneAssignmentChecker.ps1"

# Determine the script path based on whether it's run as a file or from an IDE
if ($PSScriptRoot) {
    $newScriptPath = Join-Path $PSScriptRoot "IntuneAssignmentChecker.ps1"
}
else {
    $currentDirectory = Get-Location
    $newScriptPath = Join-Path $currentDirectory "IntuneAssignmentChecker.ps1"
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

# Check if any of the variables are not set or contain placeholder values
if (-not $appid -or $appid -eq '<YourAppIdHere>' -or
    -not $tenantid -or $tenantid -eq '<YourTenantIdHere>' -or
    -not $secret -or $secret -eq '<YourAppSecretHere>') {
    Write-Host "App ID, Tenant ID, or Secret is missing or not set correctly. Please fill out all the necessary details." -ForegroundColor Red
    exit
}

$body = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $appid
    Client_Secret = $secret
}
 
$connection = Invoke-RestMethod `
    -Uri https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token `
    -Method POST `
    -Body $body
 
$token = $connection.access_token

$secureToken = ConvertTo-SecureString $token -AsPlainText -Force
 
Connect-MgGraph -AccessToken $secureToken -NoWelcome

# Loop until the user decides to exit
do {
    # Main Menu for selection
    Write-Host "Select the type of entity you want to check the Assignments for in Intune:" -ForegroundColor Cyan
    Write-Host "1. User(s)" -ForegroundColor Yellow
    Write-Host "2. Group(s)" -ForegroundColor Yellow
    Write-Host "3. Device(s)" -ForegroundColor Yellow
    Write-Host "4. Show all 'All User' Assignments" -ForegroundColor Yellow
    Write-Host "5. Show all 'All Device' Assignments" -ForegroundColor Yellow 
    Write-Host "6. Search for assignments by setting name" -ForegroundColor Yellow
    Write-Host "7. Check Permissions" -ForegroundColor Yellow
    Write-Host "8. Report a Bug or Request a Feature" -ForegroundColor Yellow
    Write-Host "9. Exit" -ForegroundColor Red
    
    $selection = Read-Host "Please enter your choice (1, 2, 3, 4, 5, 6, 7, 8 or 9)"
    switch ($selection) {

        '1' {
            Write-Host "User selection chosen" -ForegroundColor Green

            # User: 
            # Check groups that the user is a member of in Microsoft Entra (formerly Azure AD)

            ## User - Get Microsoft Entra User ID based on the User Principal Name (UPN)
            # Permission: User.Read.All

            # Prompt for User Principal Name (UPN)
            Write-Host "Please enter the User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
            $userPrincipalNamesInput = Read-Host
            $userPrincipalNames = $userPrincipalNamesInput -split ',' | ForEach-Object { $_.Trim() }

            $exportData = @()  # Initialize collection to hold data for export

            foreach ($userPrincipalName in $userPrincipalNames) {

                Write-Host "Checking following User: $userPrincipalName" -ForegroundColor Yellow

                # Get User ID from Microsoft Entra based on UPN
                $userDetailsUri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$userPrincipalName'"
                $userResponse = Invoke-MgGraphRequest -Uri $userDetailsUri -Method Get
                $userId = $userResponse.value.id
                if ($userId) {
                    Write-Host "User Found! -> User ID: $userId" -ForegroundColor Green
                }
                else {
                    Write-Host "User Not Found: $userPrincipalName" -ForegroundColor Red
                    return
                }

                # Get User Group Memberships
                $transitiveGroupsUri = "https://graph.microsoft.com/v1.0/users/$userId/transitiveMemberOf?$select=id,displayName"
                $groupResponse = Invoke-MgGraphRequest -Uri $transitiveGroupsUri -Method Get
                $userGroupIds = $groupResponse.value | ForEach-Object { $_.id }
                $userGroupNames = $groupResponse.value | ForEach-Object { $_.displayName }

                Write-Host "User Group Memberships: $($userGroupNames -join ', ')" -ForegroundColor Green

                Write-Host "Fetching Intune Profiles and Applications for the user ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections to hold relevant policies and applications
                $userRelevantPolicies = @()
                $userRelevantCompliancePolicies = @()
                $userRelevantAppsRequired = @()
                $userRelevantAppsAvailable = @()
                $userRelevantAppsUninstall = @()

                # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
                $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $groupPolicyUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

                # Get Intune Configuration Policies
                $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get

                # Check each configuration policy for assignments that match user's groups
                foreach ($policy in $policiesResponse.value) {
                    $policyName = $policy.name
                    $policyId = $policy.id
        
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
        
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($userGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
        
                        if ($assignmentReason) {
                            # Attach the assignment reason to the policy
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantPolicies += $policy
                            break
                        }
                    }
                }

                # Get Intune Group Policy Configurations
                $groupPoliciesResponse = Invoke-MgGraphRequest -Uri $groupPolicyUri -Method Get

                # Check each group policy for assignments that match user's groups
                foreach ($grouppolicy in $groupPoliciesResponse.value) {
                    $groupPolicyName = $grouppolicy.displayName
                    $groupPolicyId = $grouppolicy.id
        
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$groupPolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
        
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($userGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
        
                        if ($assignmentReason) {
                            Add-Member -InputObject $grouppolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantPolicies += $grouppolicy
                            break
                        }
                    }
                }

                # Get Intune Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get

                # Check each device configuration for assignments that match user's groups or all licensed users
                foreach ($config in $deviceConfigsResponse.value) {
                    $configName = $config.displayName
                    $configId = $config.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason

                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($userGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            # Attach the assignment reason to the config object
                            Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $userRelevantPolicies += $config
                            break
                        }
                    }
                }

                # Get Intune Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get

                # Check each compliance policy for assignments that match user's groups
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($userGroupIds -contains $assignment.target.groupId) {
                            $userRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
 
                # Get Intune Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
        
                # Iterate over each application
                foreach ($app in $appResponse.value) {
                    $appName = $app.displayName
                    $appId = $app.id

                    # Construct the URI to get assignments for the current app
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"

                    # Fetch the assignments for the app
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    # Iterate over each assignment to check if the user's groups are targeted
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason

                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $assignmentReason = "All Users"
                        }
                        elseif ($userGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }

                        if ($assignmentReason) {
                            # Add a new property to the app object to store the assignment reason
                            Add-Member -InputObject $app -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force

                            switch ($assignment.intent) {
                                "required" {
                                    $userRelevantAppsRequired += $app
                                    if ($assignmentReason -eq "All Users") { break }
                                }
                                "available" {
                                    $userRelevantAppsAvailable += $app
                                    if ($assignmentReason -eq "All Users") { break }
                                }
                                "uninstall" {
                                    $userRelevantAppsUninstall += $app
                                    if ($assignmentReason -eq "All Users") { break }
                                }
                            }
                        }
                    }
                }

                Write-Host "Intune Profiles and Apps have been successfully fetched for the user." -ForegroundColor Green

                # Generating Results for User
                Write-Host "Generating Results for $userPrincipalName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the User: $userPrincipalName" -ForegroundColor Green

                # Separator and heading for Assigned Profiles
                Write-Host "------- Assigned Configuration Profiles -------" -ForegroundColor Cyan

                foreach ($policy in $userRelevantPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $policyId = $policy.id
                    $assignmentReason = $policy.AssignmentReason
        
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Users") {
                        Write-Host "Configuration Profile Name: $policyName, Policy ID: $policyId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        # If the assignment reason is not "All Users", don't include the assignment reason in the output
                        Write-Host "Configuration Profile Name: $policyName, Policy ID: $policyId" -ForegroundColor White
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        UserPrincipalName = $userPrincipalName
                        Type              = "Configuration Policy"
                        Name              = $policy.displayName
                        ID                = $policy.id
                        AssignmentReason  = $assignmentReason
                    }
                }

                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan

                foreach ($compliancepolicy in $userRelevantCompliancePolicies) {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentReason = $compliancepolicy.AssignmentReason
        
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Users") {
                        Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $compliancepolicyId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $compliancepolicyId" -ForegroundColor White
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        UserPrincipalName = $userPrincipalName
                        Type              = "Compliance Policy"
                        Name              = $compliancepolicy.displayName
                        ID                = $compliancepolicy.id
                        AssignmentReason  = $assignmentReason
                    }
                }

                # Separator and heading for Assigned Apps (Required)
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan

                foreach ($app in $userRelevantAppsRequired) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
        
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Users") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        UserPrincipalName = $userPrincipalName
                        Type              = "App (Required)"
                        Name              = $app.displayName
                        ID                = $app.id
                        AssignmentReason  = $assignmentReason
                    }
                }

                # Separator and heading for Assigned Apps (Available)
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan

                foreach ($app in $userRelevantAppsAvailable) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
        
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Users") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        UserPrincipalName = $userPrincipalName
                        Type              = "App (Available)"
                        Name              = $app.displayName
                        ID                = $app.id
                        AssignmentReason  = $assignmentReason
                    }
                }

                # Separator and heading for Assigned Apps (Uninstall)
                Write-Host "------- Assigned Apps (Uninstall) -------" -ForegroundColor Cyan
        
                foreach ($app in $userRelevantAppsUninstall) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
        
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Users") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        UserPrincipalName = $userPrincipalName
                        Type              = "App (Uninstall)"
                        Name              = $app.displayName
                        ID                = $app.id
                        AssignmentReason  = $assignmentReason
                    }
                }
            }

            # Prompt the user to export results to CSV
            $export = Read-Host "Would you like to export the results to a CSV file? (yes/no)"
            if ($export -eq 'yes') {
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

        '2' {
            Write-Host "Group selection chosen" -ForegroundColor Green

            # Prompt for one or more Device Names
            Write-Host "Please enter Entra ID Group Names(s), separated by commas (,): " -ForegroundColor Cyan
            $GroupNamesInput = Read-Host
            $GroupNames = $GroupNamesInput -split ',' | ForEach-Object { $_.Trim() }

            $exportData = @()  # Initialize collection to hold data for export

            foreach ($GroupName in $GroupNames) {

                Write-Host "Checking following Group: $GroupName" -ForegroundColor Yellow

                # Get Device ID from Azure AD based on Display Name
                $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$GroupName'"
                $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
                $entragroupId = $groupResponse.value.id
                if ($entragroupId) {
                    Write-Host "Group Found! -> Microsoft Entra Group ID: $entragroupId " -ForegroundColor Green
                }
                else {
                    Write-Host "Group Not Found: $GroupName" -ForegroundColor Red
                    continue
                }

                # Get Group Members
                $transitiveGroupsUri = "https://graph.microsoft.com/v1.0/groups/$entragroupId/transitiveMembers"
                $response = Invoke-MgGraphRequest -Uri $transitiveGroupsUri -Method Get
                $entraGroupIdMembers = $response.value | ForEach-Object {
                    if ($_.userPrincipalName) {
                        # If userPrincipalName exists, it's a user, so output userPrincipalName
                        $_.userPrincipalName
                    }
                    elseif ($_.displayName) {
                        # If displayName exists but userPrincipalName doesn't, it's a device, so output displayName
                        $_.displayName
                    }
                }
        
                # Sort the array alphabetically
                $sortedMembers = $entraGroupIdMembers | Sort-Object

                # Join the sorted array into a string with each member on a new line
                $membersList = $sortedMembers -join ', '

                Write-Host "Group Members: $membersList" -ForegroundColor Green

                Write-Host "Fetching Intune Profiles and Applications for the Group ... (this takes a few seconds)" -ForegroundColor Yellow

                # Initialize collections to hold relevant policies and applications
                $GroupRelevantPolicies = @()
                $GroupRelevantCompliancePolicies = @()
                $GroupRelevantAppsRequired = @()
                $GroupRelevantAppsAvailable = @()
                $GroupRelevantAppsUninstall = @()

                # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
                $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

                # Get Intune Configuration Policies
                $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get

                # Check each configuration policy for assignments that match device groups
                foreach ($policy in $policiesResponse.value) {
                    $policyName = $policy.name
                    $policyId = $policy.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($entragroupId -contains $assignment.target.groupId) {
                            $GroupRelevantPolicies += $policy
                            break
                        }
                    }
                }

                # Get Intune Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get

                # Check each device configuration for assignments that match devices groups
                foreach ($config in $deviceConfigsResponse.value) {
                    $configName = $config.displayName
                    $configId = $config.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($entragroupId -contains $assignment.target.groupId) {
                            $GroupRelevantPolicies += $config
                            break
                        }
                    }
                }

                # Get Intune Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get

                # Check each compliance policy for assignments that match devices groups
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($entragroupId -contains $assignment.target.groupId) {
                            $GroupRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
 
                # Get Intune Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
        
                # Iterate over each application
                foreach ($app in $appResponse.value) {
                    $appName = $app.displayName
                    $appId = $app.id

                    # Construct the URI to get assignments for the current app
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"

                    # Fetch the assignments for the app
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    # Iterate over each assignment to check if the devices groups are targeted
                    foreach ($assignment in $assignmentResponse.value) {
                        if ($entragroupId -contains $assignment.target.groupId) {
                            if ($assignment.intent -eq "required") {
                                $GroupRelevantAppsRequired += $app
                                # Break out of the loop once a relevant app is found to avoid duplicates
                                break
                            }
                            elseif ($assignment.intent -eq "available") {
                                $GroupRelevantAppsAvailable += $app
                                # Continue checking in case the app has both "required" and "available" intents for different groups
                            }
                            elseif ($assignment.intent -eq "uninstall") {
                                $GroupRelevantAppsUninstall += $app
                                # Continue checking in case the app has both "required" and "available" intents for different groups
                            }
                        }
                    }
                }

                Write-Host "Intune Profiles and Apps have been successfully fetched for the group." -ForegroundColor Green

                # Generating Results for the Group
                Write-Host "Generating Results for $GroupName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the Group: $GroupName" -ForegroundColor Green

                # Separator and heading for Assigned Profiles
                Write-Host "------- Assigned Configuration Profiles -------" -ForegroundColor Cyan

                foreach ($policy in $GroupRelevantPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $policyId = $policy.id
                    Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policyId)" -ForegroundColor White

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        GroupName        = $GroupName
                        Type             = "Configuration Policy"
                        Name             = $policy.displayName
                        ID               = $policy.id
                        AssignmentReason = "Group Assignment"
                    }
                }

                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan

                foreach ($compliancepolicy in $GroupRelevantCompliancePolicies) {
                    # Check if displayName is not null or empty, otherwise use name
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id
                    Write-Host "Compliance Policy Name: $compliancepolicyName, App ID: $compliancepolicyId" -ForegroundColor White

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        GroupName        = $GroupName
                        Type             = "Compliance Policy"
                        Name             = $compliancepolicy.displayName
                        ID               = $compliancepolicy.id
                        AssignmentReason = "Group Assignment"
                    }
                }

                # Separator and heading for Assigned Apps (Required)
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan

                foreach ($app in $GroupRelevantAppsRequired) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        GroupName        = $GroupName
                        Type             = "App (Required)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = "Group Assignment"
                    }
                }

                # Separator and heading for Assigned Apps (Available)
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan

                foreach ($app in $GroupRelevantAppsAvailable) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        GroupName        = $GroupName
                        Type             = "App (Available)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = "Group Assignment"
                    }
                }

                # Separator and heading for Assigned Apps (Uninstall)
                Write-Host "------- Assigned Apps (Uninstall) -------" -ForegroundColor Cyan

                foreach ($app in $GroupRelevantAppsUninstall) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        GroupName        = $GroupName
                        Type             = "App (Uninstall)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = "Group Assignment"
                    }
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
        
            ## Devices: 
            # Check groups that the device is member of in EntraID.
        
            ## Device - Get Entra device id based on the device display name
            # Endpoint: https://graph.microsoft.com/v1.0/devices?$filter=displayName eq 'DeviceName'
            # Permission: Device.Read.All
        
            # Prompt for one or more Device Names
            Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
            $deviceNamesInput = Read-Host
            $deviceNames = $deviceNamesInput -split ',' | ForEach-Object { $_.Trim() }
        
            $exportData = @()  # Initialize collection to hold data for export
        
            foreach ($DeviceName in $deviceNames) {
        
                Write-Host "Checking following DeviceName: $DeviceName" -ForegroundColor Yellow
        
                # Get Device ID from Azure AD based on Display Name
                $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'"
                $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get
                $entradeviceId = $deviceResponse.value.azureADDeviceId
                if ($entradeviceId) {
                    Write-Host "Device Found! -> Microsoft Entra Device ID: $entradeviceId " -ForegroundColor Green
                }
                else {
                    Write-Host "Device Not Found: $DeviceName" -ForegroundColor Red
                    continue
                }
        
                # Get Device Group Memberships
                $transitiveGroupsUri = "https://graph.microsoft.com/v1.0/devices(deviceId='$entradeviceId')/transitiveMemberOf?$select=id"
                $response = Invoke-MgGraphRequest -Uri $transitiveGroupsUri -Method Get
                # Collect all group IDs
                $entradeviceGroupIds = $response.value | ForEach-Object { $_.id }
                $entradeviceGroupNames = $response.value | ForEach-Object { $_.displayName }
        
                Write-Host "Device Group Memberships: $($entradeviceGroupNames -join ', ')" -ForegroundColor Green
        
                Write-Host "Fetching Intune Profiles and Applications for the device ... (this takes a few seconds)" -ForegroundColor Yellow
        
                # Initialize collections to hold relevant policies and applications
                $deviceRelevantPolicies = @()
                $deviceRelevantCompliancePolicies = @()
                $deviceRelevantAppsRequired = @()
                $deviceRelevantAppsAvailable = @()
                $deviceRelevantAppsUninstall = @()
        
                # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
                $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
                $groupPolicyUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
        
                # Get Intune Configuration Policies
                $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get
        
                # Check each configuration policy for assignments that match the device
                foreach ($policy in $policiesResponse.value) {
                    $policyName = $policy.name
                    $policyId = $policy.id
                
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
                
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
                
                        if ($assignmentReason) {
                            # Attach the assignment reason to the policy
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantPolicies += $policy
                            break
                        }
                    }
                }
                
                # Get Intune Group Policy Configurations
                $groupPoliciesResponse = Invoke-MgGraphRequest -Uri $groupPolicyUri -Method Get
        
                # Check each group policy for assignments that match user's groups
                foreach ($grouppolicy in $groupPoliciesResponse.value) {
                    $groupPolicyName = $grouppolicy.displayName
                    $groupPolicyId = $grouppolicy.id
                
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$groupPolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
                
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
                
                        if ($assignmentReason) {
                            Add-Member -InputObject $grouppolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantPolicies += $grouppolicy
                            break
                        }
                    }
                }
        
                # Get Intune Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
        
                # Check each device configuration for assignments that match devices groups or are assigned to all users or all devices
                foreach ($config in $deviceConfigsResponse.value) {
                    $configName = $config.displayName
                    $configId = $config.id
                
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
                
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
                
                        if ($assignmentReason) {
                            # Attach the assignment reason to the config object
                            Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantPolicies += $config
                            break
                        }
                    }
                }                
        
                # Get Intune Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
        
                # Check each compliance policy for assignments that match devices groups
                foreach ($compliancepolicy in $complianceResponse.value) {
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id
        
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
        
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
        
                        if ($assignmentReason) {
                            # Attach the assignment reason to the compliance policy
                            Add-Member -InputObject $compliancepolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
        
                # Get Intune Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                
                # Iterate over each application
                foreach ($app in $appResponse.value) {
                    $appName = $app.displayName
                    $appId = $app.id
        
                    # Construct the URI to get assignments for the current app
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
        
                    # Fetch the assignments for the app
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                    # Iterate over each assignment to check if the devices groups are targeted
                    foreach ($assignment in $assignmentResponse.value) {
                        $assignmentReason = $null  # Clear previous reason
        
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $assignmentReason = "All Devices"
                        }
                        elseif ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $assignmentReason = "Group Assignment"
                        }
        
                        if ($assignmentReason) {
                            # Add a new property to the app object to store the assignment reason
                            Add-Member -InputObject $app -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
        
                            switch ($assignment.intent) {
                                "required" {
                                    $deviceRelevantAppsRequired += $app
                                    if ($assignmentReason -eq "All Devices") { break }
                                }
                                "available" {
                                    $deviceRelevantAppsAvailable += $app
                                    if ($assignmentReason -eq "All Devices") { break }
                                }
                                "uninstall" {
                                    $deviceRelevantAppsUninstall += $app
                                    if ($assignmentReason -eq "All Devices") { break }
                                }
                            }
                        }
                    }
                }
        
                Write-Host "Intune Profiles and Apps have been successfully fetched for the device." -ForegroundColor Green
        
                # Generating Results for the Device
                Write-Host "Generating Results for $DeviceName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
        
                Write-Host "Here are the Assignments for the Device: $DeviceName" -ForegroundColor Green
        
                # Separator and heading for Assigned Profiles
                Write-Host "------- Assigned Configuration Profiles -------" -ForegroundColor Cyan
        
                foreach ($policy in $deviceRelevantPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $policyId = $policy.id
                    $assignmentReason = $policy.AssignmentReason
                
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Devices") {
                        Write-Host "Configuration Profile Name: $policyName, Policy ID: $policyId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        # If the assignment reason is not "All Devices", don't include the assignment reason in the output
                        Write-Host "Configuration Profile Name: $policyName, Policy ID: $policyId" -ForegroundColor White
                    }
        
                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        DeviceName       = $DeviceName
                        Type             = "Configuration Policy"
                        Name             = $policy.displayName
                        ID               = $policy.id
                        AssignmentReason = $assignmentReason
                    }
                }
                
                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan
        
                foreach ($compliancepolicy in $deviceRelevantCompliancePolicies) {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentReason = $compliancepolicy.AssignmentReason
                
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Devices") {
                        Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $compliancepolicyId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $compliancepolicyId" -ForegroundColor White
                    }
        
                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        DeviceName       = $DeviceName
                        Type             = "Compliance Policy"
                        Name             = $compliancepolicy.displayName
                        ID               = $compliancepolicy.id
                        AssignmentReason = $assignmentReason
                    }
                }
                
                # Separator and heading for Assigned Apps (Required)
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan
                
                foreach ($app in $deviceRelevantAppsRequired) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
                
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Devices") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }
        
                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        DeviceName       = $DeviceName
                        Type             = "App (Required)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = $assignmentReason
                    }
                }
                
                # Separator and heading for Assigned Apps (Available)
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan
                
                foreach ($app in $deviceRelevantAppsAvailable) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
                
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Devices") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }
        
                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        DeviceName       = $DeviceName
                        Type             = "App (Available)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = $assignmentReason
                    }
                }
        
                # Separator and heading for Assigned Apps (Uninstall)
                Write-Host "------- Assigned Apps (Uninstall) -------" -ForegroundColor Cyan
                
                foreach ($app in $deviceRelevantAppsUninstall) {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                    $appId = $app.id
                    $assignmentReason = $app.AssignmentReason
                
                    # Output formatting based on assignment reason
                    if ($assignmentReason -eq "All Devices") {
                        Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: $assignmentReason" -ForegroundColor White
                    }
                    else {
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }
        
                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        DeviceName       = $DeviceName
                        Type             = "App (Uninstall)"
                        Name             = $app.displayName
                        ID               = $app.id
                        AssignmentReason = $assignmentReason
                    }
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
        
        
        '4' {
            Write-Host "'Show all `All User` Assignments' chosen" -ForegroundColor Green
        
            Write-Host "Fetching Intune Profiles and Applications ... (this takes a few seconds)" -ForegroundColor Yellow
        
            # Initialize collections to hold relevant policies and applications
            $allUserPolicies = @()
            $allUserDeviceConfigs = @()
            $allUserCompliancePolicies = @()
            $allUserAppsRequired = @()
            $allUserAppsAvailable = @()
            $allUserAppsUninstall = @()
        
            # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
            $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"    
            $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
        
            # Fetch and process Configuration Policies
            $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get
            foreach ($policy in $policiesResponse.value) {
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUserPolicies += $policy
                        break
                    }
                }
            }
        
            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            foreach ($config in $deviceConfigsResponse.value) {
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
        
            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            foreach ($compliancepolicy in $complianceResponse.value) {
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
        
            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            foreach ($app in $appResponse.value) {
                $appName = $app.displayName
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        Add-Member -InputObject $app -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users" -Force
                        switch ($assignment.intent) {
                            "required" { $allUserAppsRequired += $app; break }
                            "available" { $allUserAppsAvailable += $app; break }
                            "uninstall" { $allUserAppsUninstall += $app; break }
                        }
                    }
                }
            }
        
            # Display the fetched 'All User' Configuration Policies
            Write-Host "------- 'All User' Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserPolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }
        
            # Display the fetched 'All User' Compliance Policies
            Write-Host "------- 'All User' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allUserCompliancePolicies) {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }
        
            # Display the fetched 'All User' Applications (Required)
            Write-Host "------- 'All User' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsRequired) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Users" -ForegroundColor White
            }
        
            # Display the fetched 'All User' Applications (Available)
            Write-Host "------- 'All User' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsAvailable) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Users" -ForegroundColor White
            }
        
            # Display the fetched 'All User' Applications (Uninstall)
            Write-Host "------- 'All User' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsUninstall) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Users" -ForegroundColor White
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
                    # Prepare data for export
                    $exportData = @()

                    foreach ($policy in $allUserPolicies) {
                        $exportData += [PSCustomObject]@{
                            Type = "Configuration Policy"
                            Name = $policy.displayName
                            ID   = $policy.id
                        }
                    }

                    foreach ($config in $allUserDeviceConfigs) {
                        $exportData += [PSCustomObject]@{
                            Type = "Device Configuration"
                            Name = $config.displayName
                            ID   = $config.id
                        }
                    }

                    foreach ($compliancepolicy in $allUserCompliancePolicies) {
                        $exportData += [PSCustomObject]@{
                            Type = "Compliance Policy"
                            Name = $compliancepolicy.displayName
                            ID   = $compliancepolicy.id
                        }
                    }

                    foreach ($app in $allUserAppsRequired) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Required)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }

                    foreach ($app in $allUserAppsAvailable) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Available)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }

                    foreach ($app in $allUserAppsUninstall) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Uninstall)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }

                    # Export data to CSV
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else {
                    
                }
            }
        }

        '5' {
            Write-Host "'Show all `All Devices` Assignments' chosen" -ForegroundColor Green
        
            Write-Host "Fetching Intune Profiles and Applications ... (this takes a few seconds)" -ForegroundColor Yellow
        
            # Initialize collections to hold relevant policies and applications
            $allUserPolicies = @()
            $allUserDeviceConfigs = @()
            $allUserCompliancePolicies = @()
            $allUserAppsRequired = @()
            $allUserAppsAvailable = @()
            $allUserAppsUninstall = @()
        
            # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
            $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
            $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
        
            # Fetch and process Configuration Policies
            $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get
            foreach ($policy in $policiesResponse.value) {
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allUserPolicies += $policy
                        break
                    }
                }
            }
        
            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            foreach ($config in $deviceConfigsResponse.value) {
                $configId = $config.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allUserDeviceConfigs += $config
                        break
                    }
                }
            }
        
            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            foreach ($compliancepolicy in $complianceResponse.value) {
                $compliancepolicyId = $compliancepolicy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allUserCompliancePolicies += $compliancepolicy
                        break
                    }
                }
            }
        
            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            foreach ($app in $appResponse.value) {
                $appName = $app.displayName
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        Add-Member -InputObject $app -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices" -Force
                        switch ($assignment.intent) {
                            "required" { $allUserAppsRequired += $app; break }
                            "available" { $allUserAppsAvailable += $app; break }
                            "uninstall" { $allUserAppsUninstall += $app; break }
                        }
                    }
                }
            }
        
            # Display the fetched 'All Device' Configuration Policies
            Write-Host "------- 'All Device' Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserPolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Compliance Policies
            Write-Host "------- 'All Device' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allUserCompliancePolicies) {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name)) { $compliancepolicy.displayName } else { $compliancepolicy.name }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Applications (Required)
            Write-Host "------- 'All Device' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsRequired) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Devices" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Applications (Available)
            Write-Host "------- 'All Device' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsAvailable) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Devices" -ForegroundColor White
            }
        
            # Display the fetched 'All Device' Applications (Uninstall)
            Write-Host "------- 'All Device' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsUninstall) {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name)) { $app.displayName } else { $app.name }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId, Assignment Reason: All Devices" -ForegroundColor White
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
                    # Prepare data for export
                    $exportData = @()
        
                    foreach ($policy in $allUserPolicies) {
                        $exportData += [PSCustomObject]@{
                            Type = "Configuration Policy"
                            Name = $policy.displayName
                            ID   = $policy.id
                        }
                    }
        
                    foreach ($config in $allUserDeviceConfigs) {
                        $exportData += [PSCustomObject]@{
                            Type = "Device Configuration"
                            Name = $config.displayName
                            ID   = $config.id
                        }
                    }
        
                    foreach ($compliancepolicy in $allUserCompliancePolicies) {
                        $exportData += [PSCustomObject]@{
                            Type = "Compliance Policy"
                            Name = $compliancepolicy.displayName
                            ID   = $compliancepolicy.id
                        }
                    }
        
                    foreach ($app in $allUserAppsRequired) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Required)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }
        
                    foreach ($app in $allUserAppsAvailable) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Available)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }
        
                    foreach ($app in $allUserAppsUninstall) {
                        $exportData += [PSCustomObject]@{
                            Type = "App (Uninstall)"
                            Name = $app.displayName
                            ID   = $app.id
                        }
                    }
        
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
            Write-Host "Checking Permissions ..." -ForegroundColor Yellow
            # Permissions required for the script: User.Read.All, Group.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All

            # Permissions Descriptions
            $permissionDescriptions = @{
                "User.Read.All"                           = "Description: Read users' basic information";
                "Group.Read.All"                          = "Description: Read groups' basic information";
                "DeviceManagementConfiguration.Read.All"  = "Description: Read properties of Intune managed device configuration and device compliance policies and their assignment to groups.";
                "DeviceManagementManagedDevices.Read.All" = "Description: Read the properties of devices managed by Intune";
                "Device.Read.All"                         = "Description: Read devices' configuration information";
                "DeviceManagementApps.Read.All"           = "Description: Read properties of Intune mobile apps";
            }

            $testEndpoints = @{
                "User.Read.All"                           = "https://graph.microsoft.com/v1.0/users?$top=1";
                "Group.Read.All"                          = "https://graph.microsoft.com/v1.0/groups?$top=1";
                "DeviceManagementConfiguration.Read.All"  = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$top=1";
                "DeviceManagementManagedDevices.Read.All" = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?$top=1";
                "Device.Read.All"                         = "https://graph.microsoft.com/v1.0/devices?$top=1";
                "DeviceManagementApps.Read.All"           = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$top=1";
            }

            foreach ($permission in $testEndpoints.Keys) {
                try {
                    $response = Invoke-RestMethod -Headers @{Authorization = "Bearer $token" } -Uri $testEndpoints[$permission] -Method Get
                    $description = $permissionDescriptions[$permission]
                    Write-Host "Permission check for $permission ($description) - Success " -ForegroundColor Green
                }
                catch {
                    $description = $permissionDescriptions[$permission]
                    Write-Host "Permission check for $permission ($description) - Failed " -ForegroundColor Red
                }
            }

        

        }

        '7' {
            Write-Host "Opening GitHub Repository..." -ForegroundColor Green
            Start-Process "https://github.com/ugurkocde/IntuneAssignmentChecker"
        }

        '8' {
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

        '9' {
            Write-Host "Exiting..." -ForegroundColor Red
            exit
        }

        default {
            Write-Host "Invalid choice, please select 1, 2, 3, 4, 5, 6, 7 or 8." -ForegroundColor Red
        }
    }

    # Pause before showing the menu again
    if ($selection -ne '8') {
        Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
} while ($selection -ne '8')
