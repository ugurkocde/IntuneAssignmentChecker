# Intune Assignment Checker
# Author: Ugur Koc
# Version: 1.0
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
    Write-Host "4. Check Permissions" -ForegroundColor Yellow
    Write-Host "5. Exit" -ForegroundColor Red

    $selection = Read-Host "Please enter your choice (1, 2, 3, 4 or 5)"
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

                # Define URIs for Intune Configuration Policies, Device Configurations, Compliance Policies, and Applications
                $policiesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
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
                        if ($userGroupIds -contains $assignment.target.groupId) {
                            $userRelevantPolicies += $policy
                            break
                        }
                    }
                }

                # Get Intune Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get

                # Check each device configuration for assignments that match user's groups
                foreach ($config in $deviceConfigsResponse.value) {
                    $configName = $config.displayName
                    $configId = $config.id

                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value) {
                        if ($userGroupIds -contains $assignment.target.groupId) {
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
                        if ($userGroupIds -contains $assignment.target.groupId) {
                            if ($assignment.intent -eq "required") {
                                $userRelevantAppsRequired += $app
                                # Break out of the loop once a relevant app is found to avoid duplicates
                                break
                            }
                            elseif ($assignment.intent -eq "available") {
                                $userRelevantAppsAvailable += $app
                                # Continue checking in case the app has both "required" and "available" intents for different groups
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
                    Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policyId)" -ForegroundColor White
                }

                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan

                foreach ($compliancepolicy in $userRelevantCompliancePolicies) {
                    # Check if displayName is not null or empty, otherwise use name
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id
                    Write-Host "Compliance Policy Name: $compliancepolicyName, App ID: $compliancepolicyId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan

                foreach ($app in $userRelevantAppsRequired) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan

                foreach ($app in $userRelevantAppsAvailable) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

            }

        }
        '2' {
            Write-Host "Group selection chosen" -ForegroundColor Green

            # Prompt for one or more Device Names
            Write-Host "Please enter Entra ID Group Names(s), separated by commas (,): " -ForegroundColor Cyan
            $GroupNamesInput = Read-Host
            $GroupNames = $GroupNamesInput -split ',' | ForEach-Object { $_.Trim() }

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

                foreach ($policy in $GroupRelevantPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $policyId = $policy.id
                    Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policyId)" -ForegroundColor White
                }

                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan

                foreach ($compliancepolicy in $GroupRelevantCompliancePolicies) {
                    # Check if displayName is not null or empty, otherwise use name
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id
                    Write-Host "Compliance Policy Name: $compliancepolicyName, App ID: $compliancepolicyId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan

                foreach ($app in $GroupRelevantAppsRequired) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan

                foreach ($app in $GroupRelevantAppsAvailable) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
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
                        if ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            $deviceRelevantPolicies += $policy
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
                        if ($entradeviceGroupIds -contains $assignment.target.groupId) {
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
                        if ($entradeviceGroupIds -contains $assignment.target.groupId) {
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
                        if ($entradeviceGroupIds -contains $assignment.target.groupId) {
                            if ($assignment.intent -eq "required") {
                                $deviceRelevantAppsRequired += $app
                                # Break out of the loop once a relevant app is found to avoid duplicates
                                break
                            }
                            elseif ($assignment.intent -eq "available") {
                                $deviceRelevantAppsAvailable += $app
                                # Continue checking in case the app has both "required" and "available" intents for different groups
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
                    Write-Host "Configuration Profile Name: $policyName, Policy ID: $($policyId)" -ForegroundColor White
                }

                # Separator and heading for Compliance Policies
                Write-Host "------- Assigned Compliance Policies -------" -ForegroundColor Cyan

                foreach ($compliancepolicy in $deviceRelevantCompliancePolicies) {
                    # Check if displayName is not null or empty, otherwise use name
                    $compliancepolicyName = $compliancepolicy.displayName
                    $compliancepolicyId = $compliancepolicy.id
                    Write-Host "Compliance Policy Name: $compliancepolicyName, App ID: $compliancepolicyId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Required) -------" -ForegroundColor Cyan

                foreach ($app in $deviceRelevantAppsRequired) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Separator and heading for Assigned Apps
                Write-Host "------- Assigned Apps (Available) -------" -ForegroundColor Cyan

                foreach ($app in $deviceRelevantAppsAvailable) {
                    $appName = $app.displayName
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }


            }

        }


        '4' {
            Write-Host "Checking Permissions ..." -ForegroundColor Yellow
            # Permissions required for the script: User.Read.All, Group.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All

            # Permissions Descriptions
            $permissionDescriptions = @{
                "User.Read.All"                           = "Description: Read users' basic information";
                "Group.Read.All"                          = "Description: Read groups' basic information";
                "DeviceManagementConfiguration.Read.All"  = "Description: Read properties of Intune managed device configuration and device compliance policies and their assignment to groups.";
                "DeviceManagementManagedDevices.Read.All" = "Description: Read the properties of devices managed by Intune";
                "Device.Read.All"                         = "Description: Read devices' configuration information";
            }

            $testEndpoints = @{
                "User.Read.All"                           = "https://graph.microsoft.com/v1.0/users?$top=1";
                "Group.Read.All"                          = "https://graph.microsoft.com/v1.0/groups?$top=1";
                "DeviceManagementConfiguration.Read.All"  = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$top=1";
                "DeviceManagementManagedDevices.Read.All" = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?$top=1";
                "Device.Read.All"                         = "https://graph.microsoft.com/v1.0/devices?$top=1";
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
        '5' {
            Write-Host "Exiting..." -ForegroundColor Red
            exit
        }
        default {
            Write-Host "Invalid choice, please select 1, 2, 3, 4 or 5." -ForegroundColor Red
        }
    }

    # Pause before showing the menu again
    if ($selection -ne '5') {
        Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
} while ($selection -ne '4')