#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

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

#Read the configuration variables from the file below.  Change the path to suit your needs.
$secretsFile = '.\.secrets\config.json'
#Check to see if the file exists.
if (Test-Path $secretsFile)
{
    Write-Output "Reading configuration values from $secretsFile."
    #Check to make sure the file is formatted correctly.
    $secrets = Get-Content -Raw -Path $secretsFile | ConvertFrom-Json
    if (-not $secrets.appid -or -not $secrets.tenantid -or -not $secrets.certThumbprint)
    {
        Write-Host "The configuration file$secretsFile is missing one or more required values." -ForegroundColor Red
        Write-Output 'Please ensure the file is formatted as shown below and contains the correct values:'
        Write-Host "   
        {
            'appId': '<YourAppIdHere>',
            'tenantId': '<YourTenantIdHere>',
            'certThumbprint': '<YourCertificateThumbprintHere>'
        }"
        #Prompt the user to press any key to continue or press q to quit.
        $key = Read-Host "Press any key to continue with manual interactive connection or 'q' to quit."
        if ($key -eq 'q')
        {
            exit
        }
    }
    else
    {
        $appid = $secrets.appid 
        $tenantid = $secrets.tenantid 
        $certThumbprint = $secrets.certThumbprint 
    }
}
else
{
    Write-Output "The file $secretsFile is not found. Continuing to attempt manual interactive connection."
}

####################################################################################################

# Version of the local script
$localVersion = '2.6.0'

Write-Host '🔍 INTUNE ASSIGNMENT CHECKER' -ForegroundColor Cyan
Write-Host 'Made by Ugur Koc with' -NoNewline; Write-Host ' ❤️  and ☕' -NoNewline
Write-Host ' | Version' -NoNewline; Write-Host " $localVersion" -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2024-12-07' -ForegroundColor Magenta
Write-Host ''
Write-Host '📢 Feedback & Issues: ' -NoNewline -ForegroundColor Cyan
Write-Host 'https://github.com/ugurkocde/IntuneAssignmentChecker' -ForegroundColor White
Write-Host '📄 Changelog: ' -NoNewline -ForegroundColor Cyan
Write-Host 'https://github.com/ugurkocde/IntuneAssignmentChecker/releases' -ForegroundColor White
Write-Host ''
Write-Host '💝 Support this Project: ' -NoNewline -ForegroundColor Cyan
Write-Host 'https://github.com/sponsors/ugurkocde' -ForegroundColor White
Write-Host ''
Write-Host '⚠️  DISCLAIMER: This script is provided AS IS without warranty of any kind.' -ForegroundColor Yellow
Write-Host ''

####################################################################################################
# Autoupdate function

# URL to the version file on GitHub
$versionUrl = 'https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/version_v2.txt'

# URL to the latest script on GitHub
$scriptUrl = 'https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/IntuneAssignmentChecker_v2.ps1'

# Determine the script path based on whether it's run as a file or from an IDE
if ($PSScriptRoot)
{
    $newScriptPath = Join-Path $PSScriptRoot 'IntuneAssignmentChecker_v2.ps1'
}
else
{
    $currentDirectory = Get-Location
    $newScriptPath = Join-Path $currentDirectory 'IntuneAssignmentChecker_v2.ps1'
}

# Flag to control auto-update behavior
$autoUpdate = $true  # Set to $false to disable auto-update

try
{
    # Fetch the latest version number from GitHub
    $latestVersion = Invoke-RestMethod -Uri $versionUrl
    
    # Compare versions using System.Version for proper semantic versioning
    $local = [System.Version]::new($localVersion)
    $latest = [System.Version]::new($latestVersion)
    
    if ($local -lt $latest)
    {
        Write-Host "A new version is available: $latestVersion (you are running $localVersion)" -ForegroundColor Yellow
        if ($autoUpdate)
        {
            Write-Host 'AutoUpdate is enabled. Downloading the latest version...' -ForegroundColor Yellow
            try
            {
                # Download the latest version of the script
                Invoke-WebRequest -Uri $scriptUrl -OutFile $newScriptPath
                Write-Host "The latest version has been downloaded to $newScriptPath" -ForegroundColor Yellow
                Write-Host 'Please restart the script to use the updated version.' -ForegroundColor Yellow
            }
            catch
            {
                Write-Host 'An error occurred while downloading the latest version. Please download it manually from: https://github.com/ugurkocde/IntuneAssignmentChecker' -ForegroundColor Red
            }
        }
        else
        {
            Write-Host 'Auto-update is disabled. Get the latest version at:' -ForegroundColor Yellow
            Write-Host 'https://github.com/ugurkocde/IntuneAssignmentChecker' -ForegroundColor Cyan
            Write-Host '' 
        }
    }
    elseif ($local -gt $latest)
    {
        Write-Host "Note: You are running a pre-release version ($localVersion)" -ForegroundColor Magenta
        Write-Host ''
    }
}
catch
{
    Write-Host 'Unable to check for updates. Continue with current version...' -ForegroundColor Gray
}


####################################################################################################

# Do not change the following code

# Connect to Microsoft Graph using certificate-based authentication
try
{

    # Define required permissions with reasons
    $requiredPermissions = @(
        @{
            Permission = 'User.Read.All'
            Reason     = 'Required to read user profile information and check group memberships'
        },
        @{
            Permission = 'Group.Read.All'
            Reason     = 'Needed to read group information and memberships'
        },
        @{
            Permission = 'DeviceManagementConfiguration.Read.All'
            Reason     = 'Allows reading Intune device configuration policies and their assignments'
        },
        @{
            Permission = 'DeviceManagementApps.Read.All'
            Reason     = 'Necessary to read mobile app management policies and app configurations'
        },
        @{
            Permission = 'DeviceManagementManagedDevices.Read.All'
            Reason     = 'Required to read managed device information and compliance policies'
        },
        @{
            Permission = 'Device.Read.All'
            Reason     = 'Needed to read device information from Entra ID'
        }
    )

    # Check if any of the variables are not set or contain placeholder values
    if (-not $appid -or $appid -eq '<YourAppIdHere>' -or
        -not $tenantid -or $tenantid -eq '<YourTenantIdHere>' -or
        -not $certThumbprint -or $certThumbprint -eq '<YourCertificateThumbprintHere>')
    {
        Write-Host 'App ID, Tenant ID, or Certificate Thumbprint is missing or not set correctly.' -ForegroundColor Red
        $manualConnection = Read-Host 'Would you like to attempt a manual interactive connection? (y/n)'
        if ($manualConnection -eq 'y')
        {
            # Manual connection using interactive login
            Write-Host 'Attempting manual interactive connection (you need privileges to consent permissions)...' -ForegroundColor Yellow
            $permissionsList = ($requiredPermissions | ForEach-Object { $_.Permission }) -join ', '
            $connectionResult = Connect-MgGraph -Scopes $permissionsList -NoWelcome -ErrorAction Stop
        }
        else
        {
            Write-Host 'Script execution cancelled by user.' -ForegroundColor Red
            exit
        }
    }
    else
    {
        $connectionResult = Connect-MgGraph -ClientId $appid -TenantId $tenantid -CertificateThumbprint $certThumbprint -NoWelcome -ErrorAction Stop
    }
    Write-Host 'Successfully connected to Microsoft Graph' -ForegroundColor Green

    # Check and display the current permissions
    $context = Get-MgContext
    $currentPermissions = $context.Scopes

    Write-Host 'Checking required permissions:' -ForegroundColor Cyan
    $missingPermissions = @()
    foreach ($permissionInfo in $requiredPermissions)
    {
        $permission = $permissionInfo.Permission
        $reason = $permissionInfo.Reason

        # Check if either the exact permission or a "ReadWrite" version of it is granted
        $hasPermission = $currentPermissions -contains $permission -or $currentPermissions -contains $permission.Replace('.Read', '.ReadWrite')

        if ($hasPermission)
        {
            Write-Host "  [✓] $permission" -ForegroundColor Green
            Write-Host "      Reason: $reason" -ForegroundColor Gray
        }
        else
        {
            Write-Host "  [✗] $permission" -ForegroundColor Red
            Write-Host "      Reason: $reason" -ForegroundColor Gray
            $missingPermissions += $permission
        }
    }

    if ($missingPermissions.Count -eq 0)
    {
        Write-Host 'All required permissions are present.' -ForegroundColor Green
        Write-Host ''
    }
    else
    {
        Write-Host 'WARNING: The following permissions are missing:' -ForegroundColor Red
        $missingPermissions | ForEach-Object { 
            $missingPermission = $_
            $reason = ($requiredPermissions | Where-Object { $_.Permission -eq $missingPermission }).Reason
            Write-Host "  - $missingPermission" -ForegroundColor Yellow
            Write-Host "    Reason: $reason" -ForegroundColor Gray
        }
        Write-Host 'The script will continue, but it may not function correctly without these permissions.' -ForegroundColor Red
        Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
        
        $continueChoice = Read-Host 'Do you want to continue anyway? (y/n)'
        if ($continueChoice -ne 'y')
        {
            Write-Host 'Script execution cancelled by user.' -ForegroundColor Red
            exit
        }
    }
}

catch
{
    Write-Host "Failed to connect to Microsoft Graph. Error: $_" -ForegroundColor Red
    
    # Additional error handling for certificate issues
    if ($_.Exception.Message -like '*Certificate with thumbprint*was not found*')
    {
        Write-Host 'The specified certificate was not found or has expired. Please check your certificate configuration.' -ForegroundColor Yellow
    }
    
    exit
}

##### Export Functions #####

# Function to add export data
function Add-ExportData($Category, $Items)
{
    foreach ($item in $Items)
    {
        $itemName = if ($item.displayName)
        {
            $item.displayName 
        }
        else
        {
            $item.name 
        }
        $assignmentReason = if ($script:defaultAssignmentReason -ne 'N/A')
        { 
            $script:defaultAssignmentReason 
        }
        elseif ($item.AssignmentReason)
        { 
            $item.AssignmentReason 
        }
        else
        { 
            'N/A' 
        }
        $null = $exportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$itemName (ID: $($item.id))"
                AssignmentReason = $assignmentReason
            })
    }
}

# Function to add app export data
function Add-AppExportData($Category, $Apps)
{
    foreach ($app in $Apps)
    {
        $appName = if ($app.displayName)
        {
            $app.displayName 
        }
        else
        {
            $app.name 
        }
        $assignmentReason = if ($script:defaultAssignmentReason -ne 'N/A')
        { 
            $script:defaultAssignmentReason 
        }
        elseif ($app.AssignmentReason)
        { 
            $app.AssignmentReason 
        }
        else
        { 
            'N/A' 
        }
        $null = $exportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$appName (ID: $($app.id))"
                AssignmentReason = "$assignmentReason - $($app.AssignmentIntent)"
            })
    }
}

###### End of Export Functions ######

function Show-AllPoliciesAndAssignments
{
    # Initialize arrays to store policy information
    $allPolicies = @()

    Write-Host 'Fetching Configuration Profiles...' -ForegroundColor Yellow
    $configProfiles = Get-ConfigurationProfiles
    Write-Host 'Fetching Settings Catalog Policies...' -ForegroundColor Yellow
    $settingsCatalog = Get-SettingsCatalogPolicies
    Write-Host 'Fetching Compliance Policies...' -ForegroundColor Yellow
    $compliancePolicies = Get-CompliancePolicies
    Write-Host 'Fetching Administrative Templates...' -ForegroundColor Yellow
    $adminTemplates = Get-AdministrativeTemplates
    Write-Host 'Fetching Platform Scripts...' -ForegroundColor Yellow

    # Fetch PowerShell and Shell scripts
    $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
    $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
    $allScripts = $scriptsResponse.value
    while ($scriptsResponse.'@odata.nextLink')
    {
        $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
        $allScripts += $scriptsResponse.value
    }

    $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
    $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
    $allShellScripts = $shellScriptsResponse.value
    while ($shellScriptsResponse.'@odata.nextLink')
    {
        $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
        $allShellScripts += $shellScriptsResponse.value
    }

    $platformScripts = @()
    # Process all scripts
    foreach ($script in ($allScripts + $allShellScripts))
    {
        $scriptType = if ($script.'@odata.type' -eq '#microsoft.graph.deviceShellScript')
        { 
            'deviceShellScripts'
        }
        else
        {
            'deviceManagementScripts'
        }

        $assignments = Get-PolicyAssignments -PolicyId $script.id -PolicyType $scriptType
        $platform = if ($scriptType -eq 'deviceShellScripts')
        {
            'macOS' 
        }
        else
        {
            'Cross-Platform' 
        }

        $platformScripts += [PSCustomObject]@{
            PolicyType        = 'Platform Script'
            Platform          = $platform
            DisplayName       = $script.displayName
            Id                = $script.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }

    Write-Host 'Fetching Proactive Remediation Scripts...' -ForegroundColor Yellow
    $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
    $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
    $allHealthScripts = $healthScriptsResponse.value
    while ($healthScriptsResponse.'@odata.nextLink')
    {
        $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
        $allHealthScripts += $healthScriptsResponse.value
    }

    $proactiveRemediationScripts = @()
    foreach ($script in $allHealthScripts)
    {
        $assignments = Get-PolicyAssignments -PolicyId $script.id -PolicyType 'deviceHealthScripts'

        $proactiveRemediationScripts += [PSCustomObject]@{
            PolicyType        = 'Proactive Remediation Script'
            Platform          = 'Cross-Platform'
            DisplayName       = $script.displayName
            Id                = $script.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }

    # Combine and sort all policies
    $allPolicies = @($configProfiles + $settingsCatalog + $compliancePolicies + $adminTemplates + $platformScripts + $proactiveRemediationScripts)

    # Group by platform and sort
    $platformGroups = $allPolicies | Group-Object -Property Platform | Sort-Object Name

    foreach ($platformGroup in $platformGroups)
    {
        Write-Host "`n=== $($platformGroup.Name) Policies ===" -ForegroundColor Cyan

        $policies = $platformGroup.Group | Sort-Object PolicyType, DisplayName

        $policies | Format-Table -AutoSize -Property @(
            @{Label = 'Type'; Expression = { $_.PolicyType } },
            @{Label = 'Name'; Expression = { $_.DisplayName } },
            @{Label = 'Assignments'; Expression = { $_.AssignmentSummary } }
        )
    }

    # Offer to export to CSV
    $export = Read-Host 'Would you like to export this information to CSV? (y/n)'
    if ($export -eq 'y')
    {
        $exportPath = Show-SaveFileDialog -DefaultFileName 'IntuneAllPolicies.csv'
        if ($exportPath)
        {
            $allPolicies | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "Exported to $exportPath" -ForegroundColor Green
        }
    }
}
function Get-AdministrativeTemplates
{
    $policies = @()
    
    # Fetch administrative templates with pagination
    $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
    $response = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
    $policies += $response.value
    
    # Handle pagination
    while ($response.'@odata.nextLink')
    {
        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method Get
        $policies += $response.value
    }
    
    $processedPolicies = @()
    foreach ($policy in $policies)
    {
        $assignments = Get-PolicyAssignments -PolicyId $policy.id -PolicyType 'groupPolicyConfigurations'
        
        $processedPolicies += [PSCustomObject]@{
            PolicyType        = 'Administrative Template'
            Platform          = 'Windows'  # Administrative templates are Windows-only
            DisplayName       = $policy.displayName
            Id                = $policy.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }
    
    return $processedPolicies
}


function Get-SettingsCatalogPolicies
{
    $policies = @()
    
    # Fetch settings catalog policies with pagination
    $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    $response = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
    $policies += $response.value
    
    # Handle pagination
    while ($response.'@odata.nextLink')
    {
        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method Get
        $policies += $response.value
    }
    
    $processedPolicies = @()
    foreach ($policy in $policies)
    {
        $assignments = Get-PolicyAssignments -PolicyId $policy.id -PolicyType 'configurationPolicies'
        
        # Improved platform detection for Settings Catalog
        $platform = switch ($policy.platforms)
        {
            'windows10'
            {
                'Windows' 
            }
            'macOS'
            {
                'macOS' 
            }
            'iOS'
            {
                'iOS/iPadOS' 
            }
            'android'
            {
                'Android' 
            }
            default
            { 
                # If the direct match fails, try to normalize the platform string
                switch -Wildcard ($policy.platforms.ToLower())
                {
                    '*windows*'
                    {
                        'Windows' 
                    }
                    '*macos*'
                    {
                        'macOS' 
                    }
                    '*ios*'
                    {
                        'iOS/iPadOS' 
                    }
                    '*android*'
                    {
                        'Android' 
                    }
                    default
                    {
                        'Other' 
                    }
                }
            }
        }
        
        $processedPolicies += [PSCustomObject]@{
            PolicyType        = 'Settings Catalog'
            Platform          = $platform
            DisplayName       = $policy.name
            Id                = $policy.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }
    
    return $processedPolicies
}

function Get-ConfigurationProfiles
{
    $profiles = @()
    
    # Fetch device configurations
    $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    $response = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
    
    foreach ($profile in $response.value)
    {
        $assignments = Get-PolicyAssignments -PolicyId $profile.id -PolicyType 'deviceConfigurations'
        $platform = Get-PolicyPlatform -PolicyType $profile.'@odata.type'
        
        $profiles += [PSCustomObject]@{
            PolicyType        = 'Configuration Profile'
            Platform          = $platform
            DisplayName       = $profile.displayName
            Id                = $profile.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }
    
    return $profiles
}

function Get-CompliancePolicies
{
    $policies = @()
    
    # Fetch compliance policies
    $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
    $response = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
    
    foreach ($policy in $response.value)
    {
        $assignments = Get-PolicyAssignments -PolicyId $policy.id -PolicyType 'deviceCompliancePolicies'
        $platform = Get-PolicyPlatform -PolicyType $policy.'@odata.type'
        
        $policies += [PSCustomObject]@{
            PolicyType        = 'Compliance Policy'
            Platform          = $platform
            DisplayName       = $policy.displayName
            Id                = $policy.id
            AssignmentSummary = ($assignments -join '; ')
            RawAssignments    = $assignments
        }
    }
    
    return $policies
}

function Get-PolicyAssignments
{
    param (
        [string]$PolicyId,
        [string]$PolicyType
    )
    
    $assignments = @()
    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/$PolicyType('$PolicyId')/assignments"
    $response = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
    
    foreach ($assignment in $response.value)
    {
        switch ($assignment.target.'@odata.type')
        {
            '#microsoft.graph.allLicensedUsersAssignmentTarget'
            { 
                $assignments += 'All Users' 
            }
            '#microsoft.graph.allDevicesAssignmentTarget'
            { 
                $assignments += 'All Devices' 
            }
            '#microsoft.graph.groupAssignmentTarget'
            {
                $groupId = $assignment.target.groupId
                $groupName = Get-GroupName -GroupId $groupId
                $assignments += $groupName
            }
        }
    }
    
    return $assignments
}

function Get-GroupName
{
    param (
        [string]$GroupId
    )
    
    try
    {
        $groupUri = "https://graph.microsoft.com/v1.0/groups/$GroupId"
        $group = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        return $group.displayName
    }
    catch
    {
        return "Unknown Group ($GroupId)"
    }
}

function Get-PolicyPlatform
{
    param (
        [string]$PolicyType
    )
    
    switch -Wildcard ($PolicyType)
    {
        '*windows*'
        {
            return 'Windows' 
        }
        '*android*'
        {
            return 'Android' 
        }
        '*ios*'
        {
            return 'iOS/iPadOS' 
        }
        '*mac*'
        {
            return 'macOS' 
        }
        default
        {
            return 'Other' 
        }
    }
}

function Show-SaveFileDialog
{
    param (
        [string]$DefaultFileName
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $saveFileDialog.FileName = $DefaultFileName
    $saveFileDialog.Title = 'Save Policy Report'
    
    if ($saveFileDialog.ShowDialog() -eq 'OK')
    {
        return $saveFileDialog.FileName
    }
    return $null
}

function Show-PoliciesWithoutAssignments
{
    # Initialize arrays
    $unassignedPolicies = @()
    
    # Fetch all policy types
    Write-Host 'Fetching Configuration Profiles...' -ForegroundColor Yellow
    $configProfiles = Get-ConfigurationProfiles
    Write-Host 'Fetching Settings Catalog Policies...' -ForegroundColor Yellow
    $settingsCatalog = Get-SettingsCatalogPolicies
    Write-Host 'Fetching Administrative Templates...' -ForegroundColor Yellow
    $adminTemplates = Get-AdministrativeTemplates
    Write-Host 'Fetching Compliance Policies...' -ForegroundColor Yellow
    $compliancePolicies = Get-CompliancePolicies
    
    # Combine all policies
    $allPolicies = @($configProfiles + $settingsCatalog + $adminTemplates + $compliancePolicies)
    
    # Filter for unassigned policies
    $unassignedPolicies = $allPolicies | Where-Object { 
        $_.AssignmentSummary -eq '' -or 
        $null -eq $_.AssignmentSummary -or 
        $_.RawAssignments.Count -eq 0 
    }
    
    if ($unassignedPolicies.Count -eq 0)
    {
        Write-Host "`nNo unassigned policies found!" -ForegroundColor Green
        return
    }
    
    # Group by platform and policy type
    $platformGroups = $unassignedPolicies | Group-Object -Property Platform | Sort-Object Name
    
    Write-Host "`nFound $($unassignedPolicies.Count) unassigned policies:" -ForegroundColor Yellow
    
    foreach ($platformGroup in $platformGroups)
    {
        Write-Host "`n=== $($platformGroup.Name) Unassigned Policies ===" -ForegroundColor Cyan
        
        $policies = $platformGroup.Group | Sort-Object PolicyType, DisplayName
        
        $policies | Format-Table -AutoSize -Property @(
            @{Label = 'Type'; Expression = { $_.PolicyType } },
            @{Label = 'Name'; Expression = { $_.DisplayName } }
        )
    }
    
    # Offer to export to CSV
    $export = Read-Host "`nWould you like to export this information to CSV? (y/n)"
    if ($export -eq 'y')
    {
        $exportPath = Show-SaveFileDialog -DefaultFileName 'IntuneUnassignedPolicies.csv'
        if ($exportPath)
        {
            $unassignedPolicies | Select-Object PolicyType, Platform, DisplayName, Id | 
                Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "Exported to $exportPath" -ForegroundColor Green
        }
    }
}

function Show-AdministrativeTemplatesForMigration
{
    Write-Host 'Fetching Administrative Templates...' -ForegroundColor Yellow
    
    $adminTemplates = Get-AdministrativeTemplates
    
    if ($adminTemplates.Count -eq 0)
    {
        Write-Host "`nNo Administrative Templates found!" -ForegroundColor Green
        return
    }
    
    # Group templates by platform (though they should all be Windows)
    $platformGroups = $adminTemplates | Group-Object -Property Platform | Sort-Object Name
    
    foreach ($platformGroup in $platformGroups)
    {
        Write-Host "=== $($platformGroup.Name) Administrative Templates ===" -ForegroundColor Cyan
        
        $templates = $platformGroup.Group | Sort-Object DisplayName
        
        $templates | Format-Table -AutoSize -Property @(
            @{Label = 'Name'; Expression = { $_.DisplayName } },
            @{Label = 'ID'; Expression = { $_.Id } },
            @{Label = 'Assignments'; Expression = { $_.AssignmentSummary } }
        )
    }
    
    # Offer to export to CSV
    $export = Read-Host "`nWould you like to export this information to CSV? (y/n)"
    if ($export -eq 'y')
    {
        $exportPath = Show-SaveFileDialog -DefaultFileName 'IntuneAdministrativeTemplates.csv'
        if ($exportPath)
        {
            $adminTemplates | Select-Object DisplayName, Id, AssignmentSummary | 
                Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "Exported to $exportPath" -ForegroundColor Green
        }
    }
}

function Show-Menu
{    
    Write-Host 'Assignment Checks:' -ForegroundColor Cyan
    Write-Host '  [1] Check User(s) Assignments' -ForegroundColor White
    Write-Host '  [2] Check Group(s) Assignments' -ForegroundColor White
    Write-Host '  [3] Check Device(s) Assignments' -ForegroundColor White
    Write-Host ''
    
    Write-Host 'Policy Overview:' -ForegroundColor Cyan
    Write-Host '  [4] Show All Policies and Their Assignments' -ForegroundColor White
    Write-Host "  [5] Show All 'All Users' Assignments" -ForegroundColor White
    Write-Host "  [6] Show All 'All Devices' Assignments" -ForegroundColor White
    Write-Host ''
    
    Write-Host 'Advanced Options:' -ForegroundColor Cyan
    Write-Host '  [7] Search for Assignments by Setting Name' -ForegroundColor White
    Write-Host '  [8] Show Policies Without Assignments' -ForegroundColor White
    Write-Host '  [9] Check for Empty Groups in Assignments' -ForegroundColor White
    Write-Host '  [10] Show all Administrative Templates (deprecates in December 2024)' -ForegroundColor Yellow
    Write-Host '  [11] Compare Assignments Between Groups' -ForegroundColor White
    Write-Host ''
    
    Write-Host 'System:' -ForegroundColor Cyan
    Write-Host '  [0] Exit' -ForegroundColor White
    Write-Host '  [98] Support the Project 💝' -ForegroundColor Magenta
    Write-Host '  [99] Report a Bug or Request a Feature' -ForegroundColor White
    Write-Host ''
    
    Write-Host 'Select an option: ' -ForegroundColor Yellow -NoNewline
}

# Loop until the user decides to exit
do
{
    Show-Menu
    $selection = Read-Host
    switch ($selection)
    {

        '1'
        {
            Write-Host 'User selection chosen' -ForegroundColor Green

            # Prompt for one or more User Principal Names
            Write-Host 'Please enter User Principal Name(s), separated by commas (,): ' -ForegroundColor Cyan
            $upnInput = Read-Host
    
            # Validate input
            if ([string]::IsNullOrWhiteSpace($upnInput))
            {
                Write-Host 'No UPN provided. Please try again with a valid UPN.' -ForegroundColor Red
                continue
            }
    
            $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
            if ($upns.Count -eq 0)
            {
                Write-Host 'No valid UPNs provided. Please try again with at least one valid UPN.' -ForegroundColor Red
                continue
            }

            $exportData = [System.Collections.ArrayList]::new()

            foreach ($upn in $upns)
            {
                Write-Host "Checking following UPN: $upn" -ForegroundColor Yellow

                try
                {
                    # Get User ID from Entra ID
                    $userUri = "https://graph.microsoft.com/v1.0/users/$upn"
                    $userResponse = Invoke-MgGraphRequest -Uri $userUri -Method Get -ErrorAction Stop
                    $userId = $userResponse.id

                    # Get User Group Memberships
                    try
                    {
                        $groupsUri = "https://graph.microsoft.com/v1.0/users/$userId/transitiveMemberOf?`$select=id,displayName"
                        $response = Invoke-MgGraphRequest -Uri $groupsUri -Method Get -ErrorAction Stop
                        $groupIds = $response.value | ForEach-Object { $_.id }
                        $groupNames = $response.value | ForEach-Object { $_.displayName }

                        Write-Host "User Group Memberships: $($groupNames -join ', ')" -ForegroundColor Green
                    }
                    catch
                    {
                        Write-Host "Error fetching group memberships for user: $upn" -ForegroundColor Red
                        Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
                        continue
                    }

                    Write-Host 'Fetching Intune Profiles and Applications for the user ... (this takes a few seconds)' -ForegroundColor Yellow

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
                    $userRelevantPlatformScripts = @()

                    # Define URIs for Intune Policies and Applications
                    $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
                    $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
                    $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
                    $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
                    $appProtectionUri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
                    $appConfigurationUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations'
                    $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"

                    # Fetch and process Device Configurations
                    $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                    $allDeviceConfigs = $deviceConfigsResponse.value
                    while ($deviceConfigsResponse.'@odata.nextLink')
                    {
                        $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                        $allDeviceConfigs += $deviceConfigsResponse.value
                    }
                    $totalDeviceConfigs = $allDeviceConfigs.Count
                    $currentDeviceConfig = 0
                    foreach ($config in $allDeviceConfigs)
                    {
                        $currentDeviceConfig++
                        Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                        $configId = $config.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantDeviceConfigs += $config
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process Settings Catalog policies
                    $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                    $allSettingsCatalog = $settingsCatalogResponse.value
                    while ($settingsCatalogResponse.'@odata.nextLink')
                    {
                        $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                        $allSettingsCatalog += $settingsCatalogResponse.value
                    }
                    $totalSettingsCatalog = $allSettingsCatalog.Count
                    $currentSettingsCatalog = 0
            
                    foreach ($policy in $allSettingsCatalog)
                    {
                        $currentSettingsCatalog++
                        Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                        $policyId = $policy.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantSettingsCatalog += $policy
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process Administrative Templates
                    $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                    $allAdminTemplates = $adminTemplatesResponse.value
                    while ($adminTemplatesResponse.'@odata.nextLink')
                    {
                        $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                        $allAdminTemplates += $adminTemplatesResponse.value
                    }
                    $totalAdminTemplates = $allAdminTemplates.Count
                    $currentAdminTemplate = 0

                    foreach ($template in $allAdminTemplates)
                    {
                        $currentAdminTemplate++
                        Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                        $templateId = $template.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $template -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantAdminTemplates += $template
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process Compliance Policies
                    $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                    $allCompliancePolicies = $complianceResponse.value
                    while ($complianceResponse.'@odata.nextLink')
                    {
                        $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                        $allCompliancePolicies += $complianceResponse.value
                    }
                    $totalCompliancePolicies = $allCompliancePolicies.Count
                    $currentCompliancePolicy = 0

                    foreach ($compliancepolicy in $allCompliancePolicies)
                    {
                        $currentCompliancePolicy++
                        Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                        $compliancepolicyId = $compliancepolicy.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $compliancepolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantCompliancePolicies += $compliancepolicy
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process App Protection Policies
                    $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                    $allAppProtectionPolicies = $appProtectionResponse.value
                    while ($appProtectionResponse.'@odata.nextLink')
                    {
                        $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionResponse.'@odata.nextLink' -Method Get
                        $allAppProtectionPolicies += $appProtectionResponse.value
                    }
                    $totalAppProtectionPolicies = $allAppProtectionPolicies.Count
                    $currentAppProtectionPolicy = 0

                    foreach ($policy in $allAppProtectionPolicies)
                    {
                        $currentAppProtectionPolicy++
                        Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                        $policyId = $policy.id
                        $policyType = $policy.'@odata.type'

                        $assignmentsUri = switch ($policyType)
                        {
                            '#microsoft.graph.androidManagedAppProtection'
                            {
                                "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                            }
                            '#microsoft.graph.iosManagedAppProtection'
                            {
                                "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                            }
                            '#microsoft.graph.windowsManagedAppProtection'
                            {
                                "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                            }
                            default
                            {
                                $null 
                            }
                        }

                        if ($assignmentsUri)
                        {
                            $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                            foreach ($assignment in $policyDetails.assignments)
                            {
                                $assignmentReason = $null
                                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                                {
                                    $assignmentReason = 'All Users'
                                }
                                elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                                {
                                    $assignmentReason = 'Group Assignment'
                                }

                                if ($assignmentReason)
                                {
                                    Add-Member -InputObject $policyDetails -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                    $userRelevantAppProtectionPolicies += $policyDetails
                                    break
                                }
                            }
                        }
                    }
                    Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process App Configuration Policies
                    $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                    $allAppConfigPolicies = $appConfigurationResponse.value
                    while ($appConfigurationResponse.'@odata.nextLink')
                    {
                        $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationResponse.'@odata.nextLink' -Method Get
                        $allAppConfigPolicies += $appConfigurationResponse.value
                    }
                    $totalAppConfigurationPolicies = $allAppConfigPolicies.Count
                    $currentAppConfigurationPolicy = 0

                    foreach ($policy in $allAppConfigPolicies)
                    {
                        $currentAppConfigurationPolicy++
                        Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                        $policyId = $policy.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
    
                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantAppConfigurationPolicies += $policy
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''  # Move to the next line after the loop

                    # Fetch and process Applications
                    $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                    $allApps = $appResponse.value
                    while ($appResponse.'@odata.nextLink')
                    {
                        $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                        $allApps += $appResponse.value
                    }
                    $totalApps = $allApps.Count
                    $currentApp = 0

                    foreach ($app in $allApps)
                    {
                        # Filter out irrelevant apps
                        if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                        {
                            continue
                        }

                        $currentApp++
                        Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                        $appId = $app.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' -or 
                ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId))
                            {
                                switch ($assignment.intent)
                                {
                                    'required'
                                    {
                                        $userRelevantAppsRequired += $app; break 
                                    }
                                    'available'
                                    {
                                        $userRelevantAppsAvailable += $app; break 
                                    }
                                    'uninstall'
                                    {
                                        $userRelevantAppsUninstall += $app; break 
                                    }
                                }
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''  # Move to the next line after the loop

                    # Fetch and process Platform Scripts (PowerShell)
                    $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
                    $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                    $allScripts = $scriptsResponse.value
                    while ($scriptsResponse.'@odata.nextLink')
                    {
                        $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                        $allScripts += $scriptsResponse.value
                    }

                    # Add Shell Scripts
                    $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
                    $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                    $allShellScripts = $shellScriptsResponse.value
                    while ($shellScriptsResponse.'@odata.nextLink')
                    {
                        $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                        $allShellScripts += $shellScriptsResponse.value
                    }

                    $totalPlatformScripts = $allScripts.Count + $allShellScripts.Count
                    $currentPlatformScript = 0

                    foreach ($script in $allScripts)
                    {
                        $currentPlatformScript++
                        Write-Host "`rFetching Platform Script $currentPlatformScript of $totalPlatformScripts" -NoNewline
                        $scriptId = $script.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantPlatformScripts += $script
                                break
                            }
                        }
                    }

                    foreach ($script in $allShellScripts)
                    {
                        $currentPlatformScript++
                        Write-Host "`rFetching Platform Script $currentPlatformScript of $totalPlatformScripts" -NoNewline
                        $scriptId = $script.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.targetGroupId -and $groupIds -contains $assignment.targetGroupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantPlatformScripts += $script
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Platform Script $totalPlatformScripts of $totalPlatformScripts" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                    $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
                    $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                    $allHealthScripts = $healthScriptsResponse.value
                    while ($healthScriptsResponse.'@odata.nextLink')
                    {
                        $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                        $allHealthScripts += $healthScriptsResponse.value
                    }

                    $totalHealthScripts = $allHealthScripts.Count
                    $currentHealthScript = 0
                    $userRelevantHealthScripts = @()

                    foreach ($script in $allHealthScripts)
                    {
                        $currentHealthScript++
                        Write-Host "`rFetching Proactive Remediation Script $currentHealthScript of $totalHealthScripts" -NoNewline
                
                        $scriptId = $script.id
                        $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $assignmentResponse.value)
                        {
                            $assignmentReason = $null
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                            {
                                $assignmentReason = 'All Users'
                            }
                            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                            {
                                $assignmentReason = 'Group Assignment'
                            }

                            if ($assignmentReason)
                            {
                                Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                                $userRelevantHealthScripts += $script
                                break
                            }
                        }
                    }
                    Write-Host "`rFetching Proactive Remediation Script $totalHealthScripts of $totalHealthScripts" -NoNewline
                    Start-Sleep -Milliseconds 100
                    Write-Host ''

                    Write-Host 'Intune Profiles and Apps have been successfully fetched for the user.' -ForegroundColor Green

                    # Generating Results for the User
                    Write-Host "Generating Results for $upn..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1

                    Write-Host "Here are the Assignments for the User: $upn" -ForegroundColor Green

                    # Display the fetched Device Configurations
                    Write-Host '------- Device Configurations -------' -ForegroundColor Cyan
                    foreach ($config in $userRelevantDeviceConfigs)
                    {
                        $configName = if ([string]::IsNullOrWhiteSpace($config.name))
                        {
                            $config.displayName 
                        }
                        else
                        {
                            $config.name 
                        }
                        $assignmentInfo = if ($config.AssignmentReason)
                        {
                            ", Assignment Reason: $($config.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched Settings Catalog Policies
                    Write-Host '------- Settings Catalog Policies -------' -ForegroundColor Cyan
                    foreach ($policy in $userRelevantSettingsCatalog)
                    {
                        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                        {
                            $policy.displayName 
                        }
                        else
                        {
                            $policy.name 
                        }
                        $assignmentInfo = if ($policy.AssignmentReason)
                        {
                            ", Assignment Reason: $($policy.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched Administrative Templates
                    Write-Host '------- Administrative Templates -------' -ForegroundColor Cyan
                    foreach ($template in $userRelevantAdminTemplates)
                    {
                        $templateName = if ([string]::IsNullOrWhiteSpace($template.name))
                        {
                            $template.displayName 
                        }
                        else
                        {
                            $template.name 
                        }
                        $assignmentInfo = if ($template.AssignmentReason)
                        {
                            ", Assignment Reason: $($template.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched Compliance Policies
                    Write-Host '------- Compliance Policies -------' -ForegroundColor Cyan
                    foreach ($compliancepolicy in $userRelevantCompliancePolicies)
                    {
                        $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name))
                        {
                            $compliancepolicy.displayName 
                        }
                        else
                        {
                            $compliancepolicy.name 
                        }
                        $assignmentInfo = if ($compliancepolicy.AssignmentReason)
                        {
                            ", Assignment Reason: $($compliancepolicy.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched App Protection Policies
                    Write-Host '------- App Protection Policies -------' -ForegroundColor Cyan
                    foreach ($policy in $userRelevantAppProtectionPolicies)
                    {
                        $policyName = $policy.displayName
                        $policyId = $policy.id
                        $policyType = switch ($policy.'@odata.type')
                        {
                            '#microsoft.graph.androidManagedAppProtection'
                            {
                                'Android' 
                            }
                            '#microsoft.graph.iosManagedAppProtection'
                            {
                                'iOS' 
                            }
                            '#microsoft.graph.windowsManagedAppProtection'
                            {
                                'Windows' 
                            }
                            default
                            {
                                'Unknown' 
                            }
                        }
                        $assignmentInfo = if ($policy.AssignmentReason)
                        {
                            ", Assignment Reason: $($policy.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType$assignmentInfo" -ForegroundColor White

                        Write-Host '  Protected Apps:' -ForegroundColor Yellow
                        foreach ($app in $policy.apps)
                        {
                            $appId = if ($app.mobileAppIdentifier.windowsAppId)
                            {
                                $app.mobileAppIdentifier.windowsAppId 
                            }
                            elseif ($app.mobileAppIdentifier.bundleId)
                            {
                                $app.mobileAppIdentifier.bundleId 
                            }
                            else
                            {
                                $app.mobileAppIdentifier.packageId 
                            }
                            Write-Host "    - $appId" -ForegroundColor White
                        }
                    }

                    # Display the fetched App Configuration Policies
                    Write-Host '------- App Configuration Policies -------' -ForegroundColor Cyan
                    foreach ($policy in $userRelevantAppConfigurationPolicies)
                    {
                        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                        {
                            $policy.displayName 
                        }
                        else
                        {
                            $policy.name 
                        }
                        $assignmentInfo = if ($policy.AssignmentReason)
                        {
                            ", Assignment Reason: $($policy.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched Applications (Required)
                    Write-Host '------- Applications (Required) -------' -ForegroundColor Cyan
                    foreach ($app in $userRelevantAppsRequired)
                    {
                        $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                        {
                            $app.displayName 
                        }
                        else
                        {
                            $app.name 
                        }
                        $appId = $app.id
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Display the fetched Applications (Available)
                    Write-Host '------- Applications (Available) -------' -ForegroundColor Cyan
                    foreach ($app in $userRelevantAppsAvailable)
                    {
                        $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                        {
                            $app.displayName 
                        }
                        else
                        {
                            $app.name 
                        }
                        $appId = $app.id
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Display the fetched Applications (Uninstall)
                    Write-Host '------- Applications (Uninstall) -------' -ForegroundColor Cyan
                    foreach ($app in $userRelevantAppsUninstall)
                    {
                        $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                        {
                            $app.displayName 
                        }
                        else
                        {
                            $app.name 
                        }
                        $appId = $app.id
                        Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                    }

                    # Display the fetched Platform Scripts
                    Write-Host '------- Platform Scripts -------' -ForegroundColor Cyan
                    foreach ($script in $userRelevantPlatformScripts)
                    {
                        $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                        {
                            $script.displayName 
                        }
                        else
                        {
                            $script.name 
                        }
                        $assignmentInfo = if ($script.AssignmentReason)
                        {
                            ", Assignment Reason: $($script.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Display the fetched Proactive Remediation Scripts
                    Write-Host '------- Proactive Remediation Scripts -------' -ForegroundColor Cyan
                    foreach ($script in $userRelevantHealthScripts)
                    {
                        $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                        {
                            $script.displayName 
                        }
                        else
                        {
                            $script.name 
                        }
                        $assignmentInfo = if ($script.AssignmentReason)
                        {
                            ", Assignment Reason: $($script.AssignmentReason)" 
                        }
                        else
                        {
                            '' 
                        }
                        Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                    }

                    # Modify the Add-ExportData function to include the Assignment Reason
                    function Add-ExportData($Category, $Items)
                    {
                        foreach ($item in $Items)
                        {
                            $itemName = if ($item.displayName)
                            {
                                $item.displayName 
                            }
                            else
                            {
                                $item.name 
                            }
                            $assignmentReason = if ($item.AssignmentReason)
                            {
                                $item.AssignmentReason 
                            }
                            else
                            {
                                'N/A' 
                            }
                            $null = $exportData.Add([PSCustomObject]@{
                                    Category         = $Category
                                    Item             = "$itemName (ID: $($item.id))"
                                    AssignmentReason = $assignmentReason
                                })
                        }
                    }

                    # Also modify Add-AppExportData to include Assignment Reason
                    function Add-AppExportData($Category, $Apps)
                    {
                        foreach ($app in $Apps)
                        {
                            $appName = if ($app.displayName)
                            {
                                $app.displayName 
                            }
                            else
                            {
                                $app.name 
                            }
                            $assignmentReason = if ($app.AssignmentReason)
                            {
                                $app.AssignmentReason 
                            }
                            else
                            {
                                'N/A' 
                            }
                            $null = $exportData.Add([PSCustomObject]@{
                                    Category         = $Category
                                    Item             = "$appName (ID: $($app.id))"
                                    AssignmentReason = "$assignmentReason - $($app.AssignmentIntent)"
                                })
                        }
                    }

                    Add-ExportData 'User' @([PSCustomObject]@{displayName = $upn; id = $userId; AssignmentReason = 'N/A' })
                    Add-ExportData 'Group Membership' ($groupNames | ForEach-Object { [PSCustomObject]@{displayName = $_; id = 'N/A'; AssignmentReason = 'N/A' } })

                    Add-ExportData 'Device Configuration' $userRelevantDeviceConfigs
                    Add-ExportData 'Settings Catalog Policy' $userRelevantSettingsCatalog
                    Add-ExportData 'Administrative Template' $userRelevantAdminTemplates
                    Add-ExportData 'Compliance Policy' $userRelevantCompliancePolicies
                    Add-ExportData 'App Protection Policy' $userRelevantAppProtectionPolicies
                    Add-ExportData 'App Configuration Policy' $userRelevantAppConfigurationPolicies

                    Add-AppExportData 'Required App' $userRelevantAppsRequired
                    Add-AppExportData 'Available App' $userRelevantAppsAvailable
                    Add-AppExportData 'Uninstall App' $userRelevantAppsUninstall

                    Add-ExportData 'Platform Scripts' $userRelevantPlatformScripts
                    Add-ExportData 'Proactive Remediation Scripts' $userRelevantHealthScripts

                    # Prompt the user to export results to CSV
                    $export = Read-Host 'Would you like to export the results to a CSV file? (y/n)'
                    if ($export -eq 'y')
                    {
                        Add-Type -AssemblyName System.Windows.Forms
                        $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                        $SaveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                        $SaveFileDialog.Title = 'Save results to CSV'
                        $SaveFileDialog.ShowDialog() | Out-Null
                        $outputPath = $SaveFileDialog.FileName
        
                        if ($outputPath)
                        {
                            $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                            Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                        }
                        else
                        {
                            Write-Host 'No file selected, export cancelled.' -ForegroundColor Red
                        }
                    }
                }
                catch
                {
                    switch ($_.Exception.Response.StatusCode.value__)
                    {
                        404
                        { 
                            Write-Host "User not found: $upn" -ForegroundColor Red 
                            Write-Host 'Please verify the User Principal Name is correct.' -ForegroundColor Yellow
                        }
                        401
                        { 
                            Write-Host "Unauthorized access when looking up user: $upn" -ForegroundColor Red 
                            Write-Host 'Please verify your permissions are correct.' -ForegroundColor Yellow
                        }
                        403
                        { 
                            Write-Host "Forbidden access when looking up user: $upn" -ForegroundColor Red 
                            Write-Host 'Please verify your permissions are correct.' -ForegroundColor Yellow
                        }
                        429
                        { 
                            Write-Host 'Too many requests. Please try again later.' -ForegroundColor Red 
                            Write-Host 'Waiting 30 seconds before continuing...' -ForegroundColor Yellow
                            Start-Sleep -Seconds 30
                            continue
                        }
                        default
                        {
                            Write-Host "Error occurred while checking user: $upn" -ForegroundColor Red
                            Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
                            Write-Host "Error Message: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    continue
                }
            }
        }


        '2'
        {
            Write-Host 'Group selection chosen' -ForegroundColor Green

            # Prompt for Group names or IDs
            Write-Host 'Please enter Group names or Object IDs to compare, separated by commas (,): ' -ForegroundColor Cyan
            Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
            $groupInput = Read-Host
            $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }

            Write-Host "`nResolving group names..." -ForegroundColor Yellow

            $exportData = [System.Collections.ArrayList]::new()

            # Regex pattern for GUID/Object ID
            $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

            foreach ($input in $groupInputs)
            {
                if ($input -match $guidPattern)
                {
                    try
                    {
                        $groupUri = "https://graph.microsoft.com/v1.0/groups/$input"
                        $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
                        Write-Host "Group ID: $input -> Group Name: $($groupResponse.displayName)" -ForegroundColor Green
                    }
                    catch
                    {
                        Write-Host "Could not resolve group ID: $input" -ForegroundColor Red
                        continue
                    }
                }
                else
                {
                    Write-Host "Input '$input' is not a valid Group ID" -ForegroundColor Yellow
                }
            }

            Write-Host "`nFetching all Intune policies and assignments (this may take a few moments)..." -ForegroundColor Yellow

            # Process each group
            foreach ($input in $groupInputs)
            {
                Write-Host "Processing input: $input" -ForegroundColor Yellow

                # Initialize variables
                $groupId = $null
                $groupName = $null

                # Check if input is a GUID
                if ($input -match $guidPattern)
                {
                    try
                    {
                        # Try to get group info using the ID
                        $groupUri = "https://graph.microsoft.com/v1.0/groups/$input"
                        $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
                        $groupId = $groupResponse.id
                        $groupName = $groupResponse.displayName
                        Write-Host "Found group by ID: $groupName" -ForegroundColor Green
                    }
                    catch
                    {
                        Write-Host "No group found with ID: $input" -ForegroundColor Red
                        continue
                    }
                }
                else
                {
                    # Try to find group by display name
                    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$input'"
                    $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
    
                    if ($groupResponse.value.Count -eq 0)
                    {
                        Write-Host "No group found with name: $input" -ForegroundColor Red
                        continue
                    }
                    elseif ($groupResponse.value.Count -gt 1)
                    {
                        Write-Host "Multiple groups found with name: $input. Please use the Object ID instead:" -ForegroundColor Red
                        foreach ($group in $groupResponse.value)
                        {
                            Write-Host "  - $($group.displayName) (ID: $($group.id))" -ForegroundColor Yellow
                        }
                        continue
                    }

                    $groupId = $groupResponse.value[0].id
                    $groupName = $groupResponse.value[0].displayName
                    Write-Host "Found group by name: $groupName (ID: $groupId)" -ForegroundColor Green
                }

                # Get Group Members
                $groupsUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=displayName"
                $membersResponse = Invoke-MgGraphRequest -Uri $groupsUri -Method Get

                Write-Host 'Group Members:' -ForegroundColor Cyan
                foreach ($member in $membersResponse.value)
                {
                    Write-Host "  - $($member.displayName)" -ForegroundColor White
                }

                while ($membersResponse.'@odata.nextLink')
                {
                    $membersResponse = Invoke-MgGraphRequest -Uri $membersResponse.'@odata.nextLink' -Method Get
                    foreach ($member in $membersResponse.value)
                    {
                        Write-Host "  - $($member.displayName)" -ForegroundColor White
                    }
                }

                Write-Host 'Fetching Intune Profiles and Applications for the group ... (this takes a few seconds)' -ForegroundColor Yellow

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
                $groupRelevantPlatformScripts = @()
                $groupRelevantHealthScripts = @()

                # Define URIs for Intune Policies and Applications
                $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
                $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
                $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
                $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
                $appProtectionUri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
                $appConfigurationUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations'
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
                $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
                $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

                # Fetch and process Platform Scripts (PowerShell and Shell)
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                $allScripts = $scriptsResponse.value
                while ($scriptsResponse.'@odata.nextLink')
                {
                    $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                    $allScripts += $scriptsResponse.value
                }

                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                $allShellScripts = $shellScriptsResponse.value
                while ($shellScriptsResponse.'@odata.nextLink')
                {
                    $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                    $allShellScripts += $shellScriptsResponse.value
                }
                $totalScripts = $allScripts.Count + $allShellScripts.Count
                $currentScript = 0

                foreach ($script in $allScripts)
                {
                    $currentScript++
                    Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantPlatformScripts += $script
                            break
                        }
                    }
                }

                foreach ($script in $allShellScripts)
                {
                    $currentScript++
                    Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.targetGroupId -eq $groupId)
                        {
                            $groupRelevantPlatformScripts += $script
                            break
                        }
                    }
                }
                Write-Host "`rFetching Platform Script $totalScripts of $totalScripts" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $allDeviceConfigs = $deviceConfigsResponse.value
                while ($deviceConfigsResponse.'@odata.nextLink')
                {
                    $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                    $allDeviceConfigs += $deviceConfigsResponse.value
                }
                $totalDeviceConfigs = $allDeviceConfigs.Count
                $currentDeviceConfig = 0
                foreach ($config in $allDeviceConfigs)
                {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantDeviceConfigs += $config
                            break
                        }
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                # Fetch Settings Catalog policies
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $allSettingsCatalog = $settingsCatalogResponse.value
                while ($settingsCatalogResponse.'@odata.nextLink')
                {
                    $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                    $allSettingsCatalog += $settingsCatalogResponse.value
                }
                $totalSettingsCatalog = $allSettingsCatalog.Count
                $currentSettingsCatalog = 0

                foreach ($policy in $allSettingsCatalog)
                {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantSettingsCatalog += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                # Fetch Administrative Templates
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $allAdminTemplates = $adminTemplatesResponse.value
                while ($adminTemplatesResponse.'@odata.nextLink')
                {
                    $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                    $allAdminTemplates += $adminTemplatesResponse.value
                }
                $totalAdminTemplates = $allAdminTemplates.Count
                $currentAdminTemplate = 0

                foreach ($template in $allAdminTemplates)
                {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantAdminTemplates += $template
                            break
                        }
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host '' 

                # Fetch Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $allCompliancePolicies = $complianceResponse.value
                while ($complianceResponse.'@odata.nextLink')
                {
                    $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                    $allCompliancePolicies += $complianceResponse.value
                }
                $totalCompliancePolicies = $allCompliancePolicies.Count
                $currentCompliancePolicy = 0

                foreach ($compliancepolicy in $allCompliancePolicies)
                {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                # Fetch App Protection Policies
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                $allAppProtectionPolicies = $appProtectionResponse.value
                while ($appProtectionResponse.'@odata.nextLink')
                {
                    $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionResponse.'@odata.nextLink' -Method Get
                    $allAppProtectionPolicies += $appProtectionResponse.value
                }
                $totalAppProtectionPolicies = $allAppProtectionPolicies.Count
                $currentAppProtectionPolicy = 0

                foreach ($policy in $allAppProtectionPolicies)
                {
                    $currentAppProtectionPolicy++
                    Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                    $policyId = $policy.id
                    $policyType = $policy.'@odata.type'

                    $assignmentsUri = switch ($policyType)
                    {
                        '#microsoft.graph.androidManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        '#microsoft.graph.iosManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        '#microsoft.graph.windowsManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        default
                        {
                            $null 
                        }
                    }

                    if ($assignmentsUri)
                    {
                        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $policyDetails.assignments)
                        {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                            {
                                $groupRelevantAppProtectionPolicies += $policyDetails
                                break
                            }
                        }
                    }
                }
                Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host '' 

                # Fetch App Configuration Policies
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                $allAppConfigPolicies = $appConfigurationResponse.value
                while ($appConfigurationResponse.'@odata.nextLink')
                {
                    $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationResponse.'@odata.nextLink' -Method Get
                    $allAppConfigPolicies += $appConfigurationResponse.value
                }
                $totalAppConfigurationPolicies = $allAppConfigPolicies.Count
                $currentAppConfigurationPolicy = 0

                foreach ($policy in $allAppConfigPolicies)
                {
                    $currentAppConfigurationPolicy++
                    Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantAppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host '' 

                # Fetch Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink')
                {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count
                $currentApp = 0

                foreach ($app in $allApps)
                {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                    {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            switch ($assignment.intent)
                            {
                                'required'
                                {
                                    $groupRelevantAppsRequired += $app; break 
                                }
                                'available'
                                {
                                    $groupRelevantAppsAvailable += $app; break 
                                }
                                'uninstall'
                                {
                                    $groupRelevantAppsUninstall += $app; break 
                                }
                            }
                            break
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host '' 

                # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                $allHealthScripts = $healthScriptsResponse.value
                while ($healthScriptsResponse.'@odata.nextLink')
                {
                    $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                    $allHealthScripts += $healthScriptsResponse.value
                }

                $totalHealthScripts = $allHealthScripts.Count
                $currentHealthScript = 0

                foreach ($script in $allHealthScripts)
                {
                    $currentHealthScript++
                    Write-Host "`rFetching Proactive Remediation Script $currentHealthScript of $totalHealthScripts" -NoNewline
            
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $assignment.target.groupId -eq $groupId)
                        {
                            $groupRelevantHealthScripts += $script
                            break
                        }
                    }
                }
                Write-Host "`rFetching Proactive Remediation Script $totalHealthScripts of $totalHealthScripts" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                Write-Host 'Intune Profiles and Apps have been successfully fetched for the group.' -ForegroundColor Green

                # Generating Results for the Group
                Write-Host "Generating Results for $groupName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the Group: $groupName" -ForegroundColor Green

                # Display Device Configurations
                Write-Host '------- Device Configurations -------' -ForegroundColor Cyan
                foreach ($config in $groupRelevantDeviceConfigs)
                {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name))
                    {
                        $config.displayName 
                    }
                    else
                    {
                        $config.name 
                    }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
                }

                # Display Settings Catalog Policies
                Write-Host '------- Settings Catalog Policies -------' -ForegroundColor Cyan
                foreach ($policy in $groupRelevantSettingsCatalog)
                {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                    {
                        $policy.displayName 
                    }
                    else
                    {
                        $policy.name 
                    }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                }

                # Display Administrative Templates
                Write-Host '------- Administrative Templates -------' -ForegroundColor Cyan
                foreach ($template in $groupRelevantAdminTemplates)
                {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name))
                    {
                        $template.displayName 
                    }
                    else
                    {
                        $template.name 
                    }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
                }

                # Display Compliance Policies
                Write-Host '------- Compliance Policies -------' -ForegroundColor Cyan
                foreach ($compliancepolicy in $groupRelevantCompliancePolicies)
                {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name))
                    {
                        $compliancepolicy.displayName 
                    }
                    else
                    {
                        $compliancepolicy.name 
                    }
                    Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
                }

                # Display App Protection Policies
                Write-Host '------- App Protection Policies -------' -ForegroundColor Cyan
                foreach ($policy in $groupRelevantAppProtectionPolicies)
                {
                    $policyName = $policy.displayName
                    $policyId = $policy.id
                    $policyType = switch ($policy.'@odata.type')
                    {
                        '#microsoft.graph.androidManagedAppProtection'
                        {
                            'Android' 
                        }
                        '#microsoft.graph.iosManagedAppProtection'
                        {
                            'iOS' 
                        }
                        '#microsoft.graph.windowsManagedAppProtection'
                        {
                            'Windows' 
                        }
                        default
                        {
                            'Unknown' 
                        }
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White

                    Write-Host '  Protected Apps:' -ForegroundColor Yellow
                    foreach ($app in $policy.apps)
                    {
                        $appId = if ($app.mobileAppIdentifier.windowsAppId)
                        {
                            $app.mobileAppIdentifier.windowsAppId 
                        }
                        elseif ($app.mobileAppIdentifier.bundleId)
                        {
                            $app.mobileAppIdentifier.bundleId 
                        }
                        else
                        {
                            $app.mobileAppIdentifier.packageId 
                        }
                        Write-Host "    - $appId" -ForegroundColor White
                    }
                }

                # Display App Configuration Policies
                Write-Host '------- App Configuration Policies -------' -ForegroundColor Cyan
                foreach ($policy in $groupRelevantAppConfigurationPolicies)
                {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                    {
                        $policy.displayName 
                    }
                    else
                    {
                        $policy.name 
                    }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
                }

                # Display Applications (Required)
                Write-Host '------- Applications (Required) -------' -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsRequired)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display Applications (Available)
                Write-Host '------- Applications (Available) -------' -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsAvailable)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.displayName 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display Applications (Uninstall)
                Write-Host '------- Applications (Uninstall) -------' -ForegroundColor Cyan
                foreach ($app in $GroupRelevantAppsUninstall)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display Platform Scripts
                Write-Host '------- Platform Scripts -------' -ForegroundColor Cyan
                foreach ($script in $groupRelevantPlatformScripts)
                {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                    {
                        $script.displayName 
                    }
                    else
                    {
                        $script.name 
                    }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                }

                # Display Proactive Remediation Scripts
                Write-Host '------- Proactive Remediation Scripts -------' -ForegroundColor Cyan
                foreach ($script in $groupRelevantHealthScripts)
                {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                    {
                        $script.displayName 
                    }
                    else
                    {
                        $script.name 
                    }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
                }

                # Prepare data for export
                function Add-ExportData($Category, $Items)
                {
                    foreach ($item in $Items)
                    {
                        $itemName = if ($item.displayName)
                        {
                            $item.displayName 
                        }
                        else
                        {
                            $item.name 
                        }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$itemName (ID: $($item.id))"
                                AssignmentReason = 'N/A'
                            })
                    }
                }

                function Add-AppExportData($Category, $Apps)
                {
                    foreach ($app in $Apps)
                    {
                        $appName = if ($app.displayName)
                        {
                            $app.displayName 
                        }
                        else
                        {
                            $app.name 
                        }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$appName (ID: $($app.id))"
                                AssignmentReason = 'N/A'
                            })
                    }
                }

                Add-ExportData 'Group Name' @([PSCustomObject]@{displayName = $groupName; id = $groupId; AssignmentReason = 'N/A' })

                Add-ExportData 'Device Configuration' $groupRelevantDeviceConfigs
                Add-ExportData 'Settings Catalog Policy' $groupRelevantSettingsCatalog
                Add-ExportData 'Administrative Template' $groupRelevantAdminTemplates
                Add-ExportData 'Compliance Policy' $groupRelevantCompliancePolicies
                Add-ExportData 'App Configuration Policy' $groupRelevantAppConfigurationPolicies

                foreach ($policy in $groupRelevantAppProtectionPolicies)
                {
                    $policyType = switch ($policy.'@odata.type')
                    {
                        '#microsoft.graph.androidManagedAppProtection'
                        {
                            'Android' 
                        }
                        '#microsoft.graph.iosManagedAppProtection'
                        {
                            'iOS' 
                        }
                        '#microsoft.graph.windowsManagedAppProtection'
                        {
                            'Windows' 
                        }
                        default
                        {
                            'Unknown' 
                        }
                    }
                    $protectedApps = ($policy.apps | ForEach-Object { 
                            if ($_.mobileAppIdentifier.windowsAppId)
                            {
                                $_.mobileAppIdentifier.windowsAppId 
                            }
                            elseif ($_.mobileAppIdentifier.bundleId)
                            {
                                $_.mobileAppIdentifier.bundleId 
                            }
                            elseif ($_.mobileAppIdentifier.packageId)
                            {
                                $_.mobileAppIdentifier.packageId 
                            }
                        }) -join '; '

                    $exportData += [PSCustomObject]@{
                        Category         = "App Protection Policy ($policyType)"
                        Item             = "$($policy.displayName) (ID: $($policy.id))"
                        AssignmentReason = 'N/A'
                    }
                }

                Add-AppExportData 'App (Required)' $groupRelevantAppsRequired
                Add-AppExportData 'App (Available)' $groupRelevantAppsAvailable
                Add-AppExportData 'App (Uninstall)' $groupRelevantAppsUninstall

                Add-ExportData 'Platform Scripts' $groupRelevantPlatformScripts
                Add-ExportData 'Proactive Remediation Scripts' $groupRelevantHealthScripts

                # Prompt the user to export results to CSV
                $export = Read-Host 'Would you like to export the results to a CSV file? (y/n)'
                if ($export -eq 'y')
                {
                    Add-Type -AssemblyName System.Windows.Forms
                    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                    $SaveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                    $SaveFileDialog.Title = 'Save results to CSV'
                    $SaveFileDialog.ShowDialog() | Out-Null
                    $outputPath = $SaveFileDialog.FileName

                    if ($outputPath)
                    {
                        $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                        Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host 'No file selected, export cancelled.' -ForegroundColor Red
                    }
                }
            }
        }



        '3'
        {
            Write-Host 'Device selection chosen' -ForegroundColor Green

            $exportData = [System.Collections.ArrayList]::new()

            # Prompt for one or more Device Names
            Write-Host 'Please enter Device Name(s), separated by commas (,): ' -ForegroundColor Cyan
            $deviceNamesInput = Read-Host
            $deviceNames = $deviceNamesInput -split ',' | ForEach-Object { $_.Trim() }

            foreach ($deviceName in $deviceNames)
            {
                Write-Host "Checking following Device: $deviceName" -ForegroundColor Yellow

                # Get Device ID from Entra ID based on Display Name
                $deviceUri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$deviceName'"
                $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get
                $deviceId = $deviceResponse.value.id
                if ($deviceId)
                {
                    Write-Host "Device Found! -> Entra ID Device ID: $deviceId " -ForegroundColor Green
                }
                else
                {
                    Write-Host "Device Not Found: $deviceName" -ForegroundColor Red
                    continue
                }

                # Get Device Group Memberships
                $groupsUri = "https://graph.microsoft.com/v1.0/devices/$deviceId/transitiveMemberOf?`$select=id,displayName"
                $response = Invoke-MgGraphRequest -Uri $groupsUri -Method Get
                $groupIds = $response.value | ForEach-Object { $_.id }
                $groupNames = $response.value | ForEach-Object { $_.displayName }

                Write-Host 'Device Group Memberships:' -ForegroundColor Cyan
                foreach ($groupName in $groupNames)
                {
                    Write-Host "  - $groupName" -ForegroundColor White
                }

                Write-Host 'Fetching Intune Profiles and Applications for the device ... (this takes a few seconds)' -ForegroundColor Yellow

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
                $deviceRelevantPlatformScripts = @()
                $deviceRelevantHealthScripts = @()

                # Define URIs for Intune Policies and Applications
                $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
                $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
                $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
                $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
                $appProtectionUri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
                $appConfigurationUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations'
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
                $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
                $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

                # Fetch and process Device Configurations
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $allDeviceConfigs = $deviceConfigsResponse.value
                while ($deviceConfigsResponse.'@odata.nextLink')
                {
                    $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                    $allDeviceConfigs += $deviceConfigsResponse.value
                }
                $totalDeviceConfigs = $allDeviceConfigs.Count
                $currentDeviceConfig = 0
                foreach ($config in $allDeviceConfigs)
                {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $config -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantDeviceConfigs += $config
                            break
                        }
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process Settings Catalog policies
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $allSettingsCatalog = $settingsCatalogResponse.value
                while ($settingsCatalogResponse.'@odata.nextLink')
                {
                    $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                    $allSettingsCatalog += $settingsCatalogResponse.value
                }
                $totalSettingsCatalog = $allSettingsCatalog.Count
                $currentSettingsCatalog = 0

                foreach ($policy in $allSettingsCatalog)
                {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $policy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantSettingsCatalog += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process Administrative Templates
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $allAdminTemplates = $adminTemplatesResponse.value
                while ($adminTemplatesResponse.'@odata.nextLink')
                {
                    $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                    $allAdminTemplates += $adminTemplatesResponse.value
                }
                $totalAdminTemplates = $allAdminTemplates.Count
                $currentAdminTemplate = 0

                foreach ($template in $allAdminTemplates)
                {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $template -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantAdminTemplates += $template
                            break
                        }
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process Compliance Policies
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $allCompliancePolicies = $complianceResponse.value
                while ($complianceResponse.'@odata.nextLink')
                {
                    $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                    $allCompliancePolicies += $complianceResponse.value
                }
                $totalCompliancePolicies = $allCompliancePolicies.Count
                $currentCompliancePolicy = 0

                foreach ($compliancepolicy in $allCompliancePolicies)
                {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $compliancepolicyId = $compliancepolicy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $compliancepolicy -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantCompliancePolicies += $compliancepolicy
                            break
                        }
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process App Protection Policies
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
                $allAppProtectionPolicies = $appProtectionResponse.value
                while ($appProtectionResponse.'@odata.nextLink')
                {
                    $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionResponse.'@odata.nextLink' -Method Get
                    $allAppProtectionPolicies += $appProtectionResponse.value
                }
                $totalAppProtectionPolicies = $allAppProtectionPolicies.Count
                $currentAppProtectionPolicy = 0

                foreach ($policy in $allAppProtectionPolicies)
                {
                    $currentAppProtectionPolicy++
                    Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                    $policyId = $policy.id
                    $policyType = $policy.'@odata.type'

                    $assignmentsUri = switch ($policyType)
                    {
                        '#microsoft.graph.androidManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        '#microsoft.graph.iosManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        '#microsoft.graph.windowsManagedAppProtection'
                        {
                            "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                        }
                        default
                        {
                            $null 
                        }
                    }

                    if ($assignmentsUri)
                    {
                        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                        foreach ($assignment in $policyDetails.assignments)
                        {
                            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
                ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId))
                            {
                                $deviceRelevantAppProtectionPolicies += $policyDetails
                                break
                            }
                        }
                    }
                }
                Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process App Configuration Policies
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
                $allAppConfigPolicies = $appConfigurationResponse.value
                while ($appConfigurationResponse.'@odata.nextLink')
                {
                    $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationResponse.'@odata.nextLink' -Method Get
                    $allAppConfigPolicies += $appConfigurationResponse.value
                }
                $totalAppConfigurationPolicies = $allAppConfigPolicies.Count
                $currentAppConfigurationPolicy = 0

                foreach ($policy in $allAppConfigPolicies)
                {
                    $currentAppConfigurationPolicy++
                    Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
            ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId))
                        {
                            $deviceRelevantAppConfigurationPolicies += $policy
                            break
                        }
                    }
                }
                Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Fetch and process Applications
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink')
                {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count
                $currentApp = 0

                foreach ($app in $allApps)
                {
                    # Filter out irrelevant apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                    {
                        continue
                    }

                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' -or 
            ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId))
                        {
                            switch ($assignment.intent)
                            {
                                'required'
                                {
                                    $deviceRelevantAppsRequired += $app; break 
                                }
                                'available'
                                {
                                    $deviceRelevantAppsAvailable += $app; break 
                                }
                                'uninstall'
                                {
                                    $deviceRelevantAppsUninstall += $app; break 
                                }
                            }
                            break
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                # Fetch and process Platform Scripts (PowerShell and Shell)
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                $allScripts = $scriptsResponse.value
                while ($scriptsResponse.'@odata.nextLink')
                {
                    $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                    $allScripts += $scriptsResponse.value
                }

                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                $allShellScripts = $shellScriptsResponse.value
                while ($shellScriptsResponse.'@odata.nextLink')
                {
                    $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                    $allShellScripts += $shellScriptsResponse.value
                }

                $totalPlatformScripts = $allScripts.Count + $allShellScripts.Count
                $currentPlatformScript = 0

                foreach ($script in $allScripts)
                {
                    $currentPlatformScript++
                    Write-Host "`rFetching Platform Script $currentPlatformScript of $totalPlatformScripts" -NoNewline
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantPlatformScripts += $script
                            break
                        }
                    }
                }

                foreach ($script in $allShellScripts)
                {
                    $currentPlatformScript++
                    Write-Host "`rFetching Platform Script $currentPlatformScript of $totalPlatformScripts" -NoNewline
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($groupIds -contains $assignment.targetGroupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantPlatformScripts += $script
                            break
                        }
                    }
                }
                Write-Host "`rFetching Platform Script $totalPlatformScripts of $totalPlatformScripts" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                $allHealthScripts = $healthScriptsResponse.value
                while ($healthScriptsResponse.'@odata.nextLink')
                {
                    $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                    $allHealthScripts += $healthScriptsResponse.value
                }

                $totalHealthScripts = $allHealthScripts.Count
                $currentHealthScript = 0

                foreach ($script in $allHealthScripts)
                {
                    $currentHealthScript++
                    Write-Host "`rFetching Proactive Remediation Script $currentHealthScript of $totalHealthScripts" -NoNewline
            
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $assignmentResponse.value)
                    {
                        $assignmentReason = $null
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $assignmentReason = 'All Devices'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $assignmentReason = 'All Users'
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $groupIds -contains $assignment.target.groupId)
                        {
                            $assignmentReason = 'Group Assignment'
                        }

                        if ($assignmentReason)
                        {
                            Add-Member -InputObject $script -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                            $deviceRelevantHealthScripts += $script
                            break
                        }
                    }
                }
                Write-Host "`rFetching Proactive Remediation Script $totalHealthScripts of $totalHealthScripts" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''

                Write-Host 'Intune Profiles and Apps have been successfully fetched for the device.' -ForegroundColor Green

                # Generating Results for the Device
                Write-Host "Generating Results for $deviceName..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1

                Write-Host "Here are the Assignments for the Device: $deviceName" -ForegroundColor Green

                # Display the fetched Device Configurations
                Write-Host '------- Device Configurations -------' -ForegroundColor Cyan
                foreach ($config in $deviceRelevantDeviceConfigs)
                {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name))
                    {
                        $config.displayName 
                    }
                    else
                    {
                        $config.name 
                    }
                    $assignmentInfo = if ($config.AssignmentReason)
                    {
                        ", Assignment Reason: $($config.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Settings Catalog Policies
                Write-Host '------- Settings Catalog Policies -------' -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantSettingsCatalog)
                {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                    {
                        $policy.displayName 
                    }
                    else
                    {
                        $policy.name 
                    }
                    $assignmentInfo = if ($policy.AssignmentReason)
                    {
                        ", Assignment Reason: $($policy.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Administrative Templates
                Write-Host '------- Administrative Templates -------' -ForegroundColor Cyan
                foreach ($template in $deviceRelevantAdminTemplates)
                {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name))
                    {
                        $template.displayName 
                    }
                    else
                    {
                        $template.name 
                    }
                    $assignmentInfo = if ($template.AssignmentReason)
                    {
                        ", Assignment Reason: $($template.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Compliance Policies
                Write-Host '------- Compliance Policies -------' -ForegroundColor Cyan
                foreach ($compliancepolicy in $deviceRelevantCompliancePolicies)
                {
                    $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name))
                    {
                        $compliancepolicy.displayName 
                    }
                    else
                    {
                        $compliancepolicy.name 
                    }
                    $assignmentInfo = if ($compliancepolicy.AssignmentReason)
                    {
                        ", Assignment Reason: $($compliancepolicy.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched App Protection Policies
                Write-Host '------- App Protection Policies -------' -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantAppProtectionPolicies)
                {
                    $policyName = $policy.displayName
                    $policyId = $policy.id
                    $policyType = switch ($policy.'@odata.type')
                    {
                        '#microsoft.graph.androidManagedAppProtection'
                        {
                            'Android' 
                        }
                        '#microsoft.graph.iosManagedAppProtection'
                        {
                            'iOS' 
                        }
                        '#microsoft.graph.windowsManagedAppProtection'
                        {
                            'Windows' 
                        }
                        default
                        {
                            'Unknown' 
                        }
                    }
                    $assignmentInfo = if ($policy.AssignmentReason)
                    {
                        ", Assignment Reason: $($policy.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType$assignmentInfo" -ForegroundColor White

                    Write-Host '  Protected Apps:' -ForegroundColor Yellow
                    foreach ($app in $policy.apps)
                    {
                        $appId = if ($app.mobileAppIdentifier.windowsAppId)
                        {
                            $app.mobileAppIdentifier.windowsAppId 
                        }
                        elseif ($app.mobileAppIdentifier.bundleId)
                        {
                            $app.mobileAppIdentifier.bundleId 
                        }
                        else
                        {
                            $app.mobileAppIdentifier.packageId 
                        }
                        Write-Host "    - $appId" -ForegroundColor White
                    }
                }

                # Display the fetched App Configuration Policies
                Write-Host '------- App Configuration Policies -------' -ForegroundColor Cyan
                foreach ($policy in $deviceRelevantAppConfigurationPolicies)
                {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                    {
                        $policy.displayName 
                    }
                    else
                    {
                        $policy.name 
                    }
                    $assignmentInfo = if ($policy.AssignmentReason)
                    {
                        ", Assignment Reason: $($policy.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Applications (Required)
                Write-Host '------- Applications (Required) -------' -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsRequired)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Available)
                Write-Host '------- Applications (Available) -------' -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsAvailable)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Applications (Uninstall)
                Write-Host '------- Applications (Uninstall) -------' -ForegroundColor Cyan
                foreach ($app in $deviceRelevantAppsUninstall)
                {
                    $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $appId = $app.id
                    Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
                }

                # Display the fetched Platform Scripts
                Write-Host '------- Platform Scripts -------' -ForegroundColor Cyan
                foreach ($script in $deviceRelevantPlatformScripts)
                {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                    {
                        $script.displayName 
                    }
                    else
                    {
                        $script.name 
                    }
                    $scriptType = if ($script.'@odata.type' -eq '#microsoft.graph.deviceShellScript')
                    {
                        'Shell' 
                    }
                    else
                    {
                        'PowerShell' 
                    }
                    $assignmentInfo = if ($script.AssignmentReason)
                    {
                        ", Assignment Reason: $($script.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Script Name: $scriptName, Type: $scriptType, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                }

                # Display the fetched Proactive Remediation Scripts
                Write-Host '------- Proactive Remediation Scripts -------' -ForegroundColor Cyan
                foreach ($script in $deviceRelevantHealthScripts)
                {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                    {
                        $script.displayName 
                    }
                    else
                    {
                        $script.name 
                    }
                    $assignmentInfo = if ($script.AssignmentReason)
                    {
                        ", Assignment Reason: $($script.AssignmentReason)" 
                    }
                    else
                    {
                        '' 
                    }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                }

                # Modify the Add-ExportData function to include the Assignment Reason
                function Add-ExportData($Category, $Items)
                {
                    foreach ($item in $Items)
                    {
                        $itemName = if ($item.displayName)
                        {
                            $item.displayName 
                        }
                        else
                        {
                            $item.name 
                        }
                        $assignmentReason = if ($item.AssignmentReason)
                        {
                            $item.AssignmentReason 
                        }
                        else
                        {
                            'N/A' 
                        }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$itemName (ID: $($item.id))"
                                AssignmentReason = $assignmentReason
                            })
                    }
                }

                function Add-AppExportData($Category, $Apps)
                {
                    foreach ($app in $Apps)
                    {
                        $appName = if ($app.displayName)
                        {
                            $app.displayName 
                        }
                        else
                        {
                            $app.name 
                        }
                        $assignmentReason = if ($app.AssignmentReason)
                        {
                            $app.AssignmentReason 
                        }
                        else
                        {
                            'N/A' 
                        }
                        $null = $exportData.Add([PSCustomObject]@{
                                Category         = $Category
                                Item             = "$appName (ID: $($app.id))"
                                AssignmentReason = "$assignmentReason - $($app.AssignmentIntent)"
                            })
                    }
                }

                Add-ExportData 'Device Name' @([PSCustomObject]@{displayName = $deviceName; id = $deviceId; AssignmentReason = 'N/A' })
                Add-ExportData 'Group Membership' ($groupNames | ForEach-Object { [PSCustomObject]@{displayName = $_; id = 'N/A'; AssignmentReason = 'N/A' } })

                Add-ExportData 'Device Configuration' $deviceRelevantDeviceConfigs
                Add-ExportData 'Settings Catalog Policy' $deviceRelevantSettingsCatalog
                Add-ExportData 'Administrative Template' $deviceRelevantAdminTemplates
                Add-ExportData 'Compliance Policy' $deviceRelevantCompliancePolicies
                Add-ExportData 'App Protection Policy' $deviceRelevantAppProtectionPolicies
                Add-ExportData 'App Configuration Policy' $deviceRelevantAppConfigurationPolicies

                Add-AppExportData 'Required App' $deviceRelevantAppsRequired
                Add-AppExportData 'Available App' $deviceRelevantAppsAvailable
                Add-AppExportData 'Uninstall App' $deviceRelevantAppsUninstall

                Add-ExportData 'Platform Scripts' $deviceRelevantPlatformScripts
                Add-ExportData 'Proactive Remediation Scripts' $deviceRelevantHealthScripts

                # Prompt the user to export results to CSV
                $export = Read-Host 'Would you like to export the results to a CSV file? (y/n)'
                if ($export -eq 'y')
                {
                    Add-Type -AssemblyName System.Windows.Forms
                    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                    $SaveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                    $SaveFileDialog.Title = 'Save results to CSV'
                    $SaveFileDialog.ShowDialog() | Out-Null
                    $outputPath = $SaveFileDialog.FileName

                    if ($outputPath)
                    {
                        $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                        Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host 'No file selected, export cancelled.' -ForegroundColor Red
                    }
                }
            }
        }


        '4'
        {
            Write-Host 'Fetching all policies and their assignments...' -ForegroundColor Green
            Show-AllPoliciesAndAssignments
        }
        
        '5'
        {
            Write-Host "'Show all `All User` Assignments' chosen" -ForegroundColor Green
            $script:defaultAssignmentReason = 'All Users'

            Write-Host 'Fetching Intune Profiles and Applications ... (this takes a few seconds)' -ForegroundColor Yellow
    
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
            $allUserPlatformScripts = @()
            $allUserHealthScripts = @()

            # Define URIs for Intune Policies and Applications
            $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
            $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
            $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
            $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
            $appProtectionUri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
            $appConfigurationUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations'
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
            $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
            $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
            $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            $allDeviceConfigs = $deviceConfigsResponse.value
            while ($deviceConfigsResponse.'@odata.nextLink')
            {
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                $allDeviceConfigs += $deviceConfigsResponse.value
            }
            $totalDeviceConfigs = $allDeviceConfigs.Count
            $currentDeviceConfig = 0
            foreach ($config in $allDeviceConfigs)
            {
                $currentDeviceConfig++
                Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                $configId = $config.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserDeviceConfigs += $config
                        break
                    }
                }
            }
            Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Settings Catalog policies
            $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
            $allSettingsCatalogPolicies = $settingsCatalogResponse.value
            while ($settingsCatalogResponse.'@odata.nextLink')
            {
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                $allSettingsCatalogPolicies += $settingsCatalogResponse.value
            }
            $totalSettingsCatalog = $allSettingsCatalogPolicies.Count
            $currentSettingsCatalog = 0

            foreach ($policy in $allSettingsCatalogPolicies)
            {
                $currentSettingsCatalog++
                Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserSettingsCatalog += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Administrative Templates
            $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
            $allAdminTemplatesPolicies = $adminTemplatesResponse.value
            while ($adminTemplatesResponse.'@odata.nextLink')
            {
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                $allAdminTemplatesPolicies += $adminTemplatesResponse.value
            }
            $totalAdminTemplates = $allAdminTemplatesPolicies.Count
            $currentAdminTemplate = 0

            foreach ($template in $allAdminTemplatesPolicies)
            {
                $currentAdminTemplate++
                Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                $templateId = $template.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserAdminTemplates += $template
                        break
                    }
                }
            }
            Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            $allCompliancePoliciesPolicies = $complianceResponse.value
            while ($complianceResponse.'@odata.nextLink')
            {
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                $allCompliancePoliciesPolicies += $complianceResponse.value
            }
            $totalCompliancePolicies = $allCompliancePoliciesPolicies.Count
            $currentCompliancePolicy = 0

            foreach ($compliancepolicy in $allCompliancePoliciesPolicies)
            {
                $currentCompliancePolicy++
                Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                $compliancepolicyId = $compliancepolicy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserCompliancePolicies += $compliancepolicy
                        break
                    }
                }
            }
            Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process App Protection Policies
            $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
            $allAppProtectionPoliciesPolicies = $appProtectionResponse.value
            while ($appProtectionResponse.'@odata.nextLink')
            {
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionResponse.'@odata.nextLink' -Method Get
                $allAppProtectionPoliciesPolicies += $appProtectionResponse.value
            }
            $totalAppProtectionPolicies = $allAppProtectionPoliciesPolicies.Count
            $currentAppProtectionPolicy = 0

            foreach ($policy in $allAppProtectionPoliciesPolicies)
            {
                $currentAppProtectionPolicy++
                Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                $policyId = $policy.id
                $policyType = $policy.'@odata.type'

                $assignmentsUri = switch ($policyType)
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    default
                    {
                        $null 
                    }
                }

                if ($assignmentsUri)
                {
                    $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $policyDetails.assignments)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                        {
                            $allUserAppProtectionPolicies += $policyDetails
                            break
                        }
                    }
                }
            }
            Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process App Configuration Policies
            $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
            $allAppConfigPolicies = $appConfigurationResponse.value
            while ($appConfigurationResponse.'@odata.nextLink')
            {
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationResponse.'@odata.nextLink' -Method Get
                $allAppConfigPolicies += $appConfigurationResponse.value
            }
            $totalAppConfigurationPolicies = $allAppConfigPolicies.Count
            $currentAppConfigurationPolicy = 0

            foreach ($policy in $allAppConfigPolicies)
            {
                $currentAppConfigurationPolicy++
                Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserAppConfigurationPolicies += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $allApps = $appResponse.value
            while ($appResponse.'@odata.nextLink')
            {
                $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                $allApps += $appResponse.value
            }
            $totalApps = $allApps.Count
            $currentApp = 0

            foreach ($app in $allApps)
            {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                {
                    continue
                }

                $currentApp++
                Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        switch ($assignment.intent)
                        {
                            'required'
                            {
                                $allUserAppsRequired += $app; break 
                            }
                            'available'
                            {
                                $allUserAppsAvailable += $app; break 
                            }
                            'uninstall'
                            {
                                $allUserAppsUninstall += $app; break 
                            }
                        }
                        break
                    }
                }
            }
            Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Platform Scripts (PowerShell and Shell)
            $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
            $allScripts = $scriptsResponse.value
            while ($scriptsResponse.'@odata.nextLink')
            {
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                $allScripts += $scriptsResponse.value
            }

            $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
            $allShellScripts = $shellScriptsResponse.value
            while ($shellScriptsResponse.'@odata.nextLink')
            {
                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                $allShellScripts += $shellScriptsResponse.value
            }

            $totalScripts = $allScripts.Count + $allShellScripts.Count
            $currentScript = 0

            foreach ($script in $allScripts)
            {
                $currentScript++
                Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserPlatformScripts += $script
                        break
                    }
                }
            }
            foreach ($script in $allShellScripts)
            {
                $currentScript++
                Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    # Shell scripts use targetGroupId
                    # For All Users scenario, shell scripts won't be assigned via All Users target. So no "All Users" for Shell scripts specifically.
                    # Shell scripts can't be assigned to "All Users" directly (no allLicensedUsersAssignmentTarget support there)
                    # Hence, no match here. We just keep this logic consistent.
                    if ($assignment.targetGroupId -eq $null)
                    {
                        # no direct all users scenario
                        # no action required
                    }
                }
            }
            Write-Host "`rFetching Platform Script $totalScripts of $totalScripts" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
            $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
            $allHealthScripts = $healthScriptsResponse.value
            while ($healthScriptsResponse.'@odata.nextLink')
            {
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                $allHealthScripts += $healthScriptsResponse.value
            }

            $totalHealthScripts = $allHealthScripts.Count
            $currentHealthScript = 0

            foreach ($script in $allHealthScripts)
            {
                $currentHealthScript++
                Write-Host "`rFetching Proactive Remediation Script $currentHealthScript of $totalHealthScripts" -NoNewline

                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
                    {
                        $allUserHealthScripts += $script
                        break
                    }
                }
            }
            Write-Host "`rFetching Proactive Remediation Script $totalHealthScripts of $totalHealthScripts" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            Write-Host 'Intune Profiles and Apps have been successfully fetched.' -ForegroundColor Green

            # Display the fetched 'All User' Device Configurations
            Write-Host "------- 'All User' Device Configurations -------" -ForegroundColor Cyan
            foreach ($config in $allUserDeviceConfigs)
            {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name))
                {
                    $config.displayName 
                }
                else
                {
                    $config.name 
                }
                Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Settings Catalog Policies
            Write-Host "------- 'All User' Settings Catalog Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserSettingsCatalog)
            {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                {
                    $policy.displayName 
                }
                else
                {
                    $policy.name 
                }
                Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Administrative Templates
            Write-Host "------- 'All User' Administrative Templates -------" -ForegroundColor Cyan
            foreach ($template in $allUserAdminTemplates)
            {
                $templateName = if ([string]::IsNullOrWhiteSpace($template.name))
                {
                    $template.displayName 
                }
                else
                {
                    $template.name 
                }
                Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Compliance Policies
            Write-Host "------- 'All User' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allUserCompliancePolicies)
            {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name))
                {
                    $compliancepolicy.displayName 
                }
                else
                {
                    $compliancepolicy.name 
                }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' App Protection Policies
            Write-Host "------- 'All User' App Protection Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserAppProtectionPolicies)
            {
                $policyName = $policy.displayName
                $policyId = $policy.id
                $policyType = switch ($policy.'@odata.type')
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        'Android' 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        'iOS' 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        'Windows' 
                    }
                    default
                    {
                        'Unknown' 
                    }
                }
                Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White

                Write-Host '  Protected Apps:' -ForegroundColor Yellow
                foreach ($app in $policy.apps)
                {
                    $appId = if ($app.mobileAppIdentifier.windowsAppId)
                    {
                        $app.mobileAppIdentifier.windowsAppId 
                    }
                    elseif ($app.mobileAppIdentifier.bundleId)
                    {
                        $app.mobileAppIdentifier.bundleId 
                    }
                    else
                    {
                        $app.mobileAppIdentifier.packageId 
                    }
                    Write-Host "    - $appId" -ForegroundColor White
                }
            }

            # Display the fetched 'All User' App Configuration Policies
            Write-Host "------- 'All User' App Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allUserAppConfigurationPolicies)
            {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                {
                    $policy.displayName 
                }
                else
                {
                    $policy.name 
                }
                Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Required)
            Write-Host "------- 'All User' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsRequired)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.name 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Available)
            Write-Host "------- 'All User' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsAvailable)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.displayName 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All User' Applications (Uninstall)
            Write-Host "------- 'All User' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allUserAppsUninstall)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.name 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All User' Platform Scripts
            Write-Host "------- 'All User' Platform Scripts -------" -ForegroundColor Cyan
            foreach ($script in $allUserPlatformScripts)
            {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                {
                    $script.displayName 
                }
                else
                {
                    $script.name 
                }
                Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
            }

            # Display the fetched 'All User' Proactive Remediation Scripts
            Write-Host "------- 'All User' Proactive Remediation Scripts -------" -ForegroundColor Cyan
            foreach ($script in $allUserHealthScripts)
            {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                {
                    $script.displayName 
                }
                else
                {
                    $script.name 
                }
                Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
            }

            # Prepare export functions
            function Add-ExportData($Category, $Items)
            {
                foreach ($item in $Items)
                {
                    $itemName = if ($item.displayName)
                    {
                        $item.displayName 
                    }
                    else
                    {
                        $item.name 
                    }
                    $null = $exportData.Add([PSCustomObject]@{
                            Category         = $Category
                            Item             = "$itemName (ID: $($item.id))"
                            AssignmentReason = 'All Users'
                        })
                }
            }

            function Add-AppExportData($Category, $Apps)
            {
                foreach ($app in $Apps)
                {
                    $appName = if ($app.displayName)
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $null = $exportData.Add([PSCustomObject]@{
                            Category         = $Category
                            Item             = "$appName (ID: $($app.id))"
                            AssignmentReason = "All Users - $($app.AssignmentIntent)"
                        })
                }
            }

            Add-ExportData 'Device Configuration' $allUserDeviceConfigs
            Add-ExportData 'Settings Catalog Policy' $allUserSettingsCatalog
            Add-ExportData 'Administrative Template' $allUserAdminTemplates
            Add-ExportData 'Compliance Policy' $allUserCompliancePolicies
            Add-ExportData 'App Configuration Policy' $allUserAppConfigurationPolicies 

            foreach ($policy in $allUserAppProtectionPolicies)
            {
                $policyType = switch ($policy.'@odata.type')
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        'Android' 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        'iOS' 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        'Windows' 
                    }
                    default
                    {
                        'Unknown' 
                    }
                }
                $exportData += [PSCustomObject]@{
                    Category         = "App Protection Policy ($policyType)"
                    Item             = "$($policy.displayName) (ID: $($policy.id))"
                    AssignmentReason = 'All Users'
                }
            }

            Add-AppExportData 'App (Required)' $allUserAppsRequired
            Add-AppExportData 'App (Available)' $allUserAppsAvailable
            Add-AppExportData 'App (Uninstall)' $allUserAppsUninstall

            Add-ExportData 'Platform Scripts' $allUserPlatformScripts
            Add-ExportData 'Proactive Remediation Scripts' $allUserHealthScripts

            # Prompt the user to export results to CSV
            $export = Read-Host 'Would you like to export the results to a CSV file? (y/n)'
            if ($export -eq 'y')
            {
                Add-Type -AssemblyName System.Windows.Forms
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                $SaveFileDialog.Title = 'Save results to CSV'
                $SaveFileDialog.ShowDialog() | Out-Null
                $outputPath = $SaveFileDialog.FileName

                if ($outputPath)
                {
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else
                {
                    Write-Host 'No file selected, export cancelled.' -ForegroundColor Red
                }
            }
        }


        '6'
        {
            Write-Host "'Show all `All Devices` Assignments' chosen" -ForegroundColor Green
            $script:defaultAssignmentReason = 'All Devices'

            Write-Host 'Fetching Intune Profiles and Applications ... (this takes a few seconds)' -ForegroundColor Yellow
    
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
            $allDevicePlatformScripts = @()
            $allDeviceHealthScripts = @()

            # Define URIs for Intune Policies and Applications
            $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
            $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
            $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
            $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
            $appProtectionUri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
            $appConfigurationUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations'
            $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
            $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
            $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
            $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

            # Fetch and process Device Configurations
            $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
            $allDeviceConfigsData = $deviceConfigsResponse.value
            while ($deviceConfigsResponse.'@odata.nextLink')
            {
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                $allDeviceConfigsData += $deviceConfigsResponse.value
            }
            $totalDeviceConfigs = $allDeviceConfigsData.Count
            $currentDeviceConfig = 0
            foreach ($config in $allDeviceConfigsData)
            {
                $currentDeviceConfig++
                Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                $configId = $config.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceDeviceConfigs += $config
                        break
                    }
                }
            }
            Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Settings Catalog policies
            $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
            $allSettingsCatalogPolicies = $settingsCatalogResponse.value
            while ($settingsCatalogResponse.'@odata.nextLink')
            {
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                $allSettingsCatalogPolicies += $settingsCatalogResponse.value
            }
            $totalSettingsCatalog = $allSettingsCatalogPolicies.Count
            $currentSettingsCatalog = 0

            foreach ($policy in $allSettingsCatalogPolicies)
            {
                $currentSettingsCatalog++
                Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceSettingsCatalog += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Administrative Templates
            $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
            $allAdminTemplatesPolicies = $adminTemplatesResponse.value
            while ($adminTemplatesResponse.'@odata.nextLink')
            {
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                $allAdminTemplatesPolicies += $adminTemplatesResponse.value
            }
            $totalAdminTemplates = $allAdminTemplatesPolicies.Count
            $currentAdminTemplate = 0

            foreach ($template in $allAdminTemplatesPolicies)
            {
                $currentAdminTemplate++
                Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                $templateId = $template.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceAdminTemplates += $template
                        break
                    }
                }
            }
            Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Compliance Policies
            $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
            $allCompliancePoliciesPolicies = $complianceResponse.value
            while ($complianceResponse.'@odata.nextLink')
            {
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                $allCompliancePoliciesPolicies += $complianceResponse.value
            }
            $totalCompliancePolicies = $allCompliancePoliciesPolicies.Count
            $currentCompliancePolicy = 0

            foreach ($compliancepolicy in $allCompliancePoliciesPolicies)
            {
                $currentCompliancePolicy++
                Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                $compliancepolicyId = $compliancepolicy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$compliancepolicyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceCompliancePolicies += $compliancepolicy
                        break
                    }
                }
            }
            Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process App Protection Policies
            $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionUri -Method Get
            $allAppProtectionPoliciesPolicies = $appProtectionResponse.value
            while ($appProtectionResponse.'@odata.nextLink')
            {
                $appProtectionResponse = Invoke-MgGraphRequest -Uri $appProtectionResponse.'@odata.nextLink' -Method Get
                $allAppProtectionPoliciesPolicies += $appProtectionResponse.value
            }
            $totalAppProtectionPolicies = $allAppProtectionPoliciesPolicies.Count
            $currentAppProtectionPolicy = 0

            foreach ($policy in $allAppProtectionPoliciesPolicies)
            {
                $currentAppProtectionPolicy++
                Write-Host "`rFetching App Protection Policy $currentAppProtectionPolicy of $totalAppProtectionPolicies" -NoNewline
                $policyId = $policy.id
                $policyType = $policy.'@odata.type'

                $assignmentsUri = switch ($policyType)
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$policyId')?`$expand=apps,assignments" 
                    }
                    default
                    {
                        $null 
                    }
                }

                if ($assignmentsUri)
                {
                    $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    foreach ($assignment in $policyDetails.assignments)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                        {
                            $allDeviceAppProtectionPolicies += $policyDetails
                            break
                        }
                    }
                }
            }
            Write-Host "`rFetching App Protection Policy $totalAppProtectionPolicies of $totalAppProtectionPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process App Configuration Policies
            $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationUri -Method Get
            $allAppConfigPolicies = $appConfigurationResponse.value
            while ($appConfigurationResponse.'@odata.nextLink')
            {
                $appConfigurationResponse = Invoke-MgGraphRequest -Uri $appConfigurationResponse.'@odata.nextLink' -Method Get
                $allAppConfigPolicies += $appConfigurationResponse.value
            }
            $totalAppConfigurationPolicies = $allAppConfigPolicies.Count
            $currentAppConfigurationPolicy = 0

            foreach ($policy in $allAppConfigPolicies)
            {
                $currentAppConfigurationPolicy++
                Write-Host "`rFetching App Configuration Policy $currentAppConfigurationPolicy of $totalAppConfigurationPolicies" -NoNewline
                $policyId = $policy.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$policyId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceAppConfigurationPolicies += $policy
                        break
                    }
                }
            }
            Write-Host "`rFetching App Configuration Policy $totalAppConfigurationPolicies of $totalAppConfigurationPolicies" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Applications
            $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
            $allApps = $appResponse.value
            while ($appResponse.'@odata.nextLink')
            {
                $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                $allApps += $appResponse.value
            }
            $totalApps = $allApps.Count
            $currentApp = 0

            foreach ($app in $allApps)
            {
                # Filter out irrelevant apps
                if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                {
                    continue
                }

                $currentApp++
                Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                $appId = $app.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        switch ($assignment.intent)
                        {
                            'required'
                            {
                                $allDeviceAppsRequired += $app; break 
                            }
                            'available'
                            {
                                $allDeviceAppsAvailable += $app; break 
                            }
                            'uninstall'
                            {
                                $allDeviceAppsUninstall += $app; break 
                            }
                        }
                        break
                    }
                }
            }
            Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Platform Scripts (PowerShell and Shell)
            $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
            $allScripts = $scriptsResponse.value
            while ($scriptsResponse.'@odata.nextLink')
            {
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                $allScripts += $scriptsResponse.value
            }

            $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
            $allShellScripts = $shellScriptsResponse.value
            while ($shellScriptsResponse.'@odata.nextLink')
            {
                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                $allShellScripts += $shellScriptsResponse.value
            }

            $totalScripts = $allScripts.Count + $allShellScripts.Count
            $currentScript = 0

            foreach ($script in $allScripts)
            {
                $currentScript++
                Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDevicePlatformScripts += $script
                        break
                    }
                }
            }

            foreach ($script in $allShellScripts)
            {
                $currentScript++
                Write-Host "`rFetching Platform Script $currentScript of $totalScripts" -NoNewline
                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    # Shell scripts use targetGroupId and do not support allDevices directly
                    # Hence, no direct "All Devices" scenario for shell scripts.
                }
            }
            Write-Host "`rFetching Platform Script $totalScripts of $totalScripts" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
            $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
            $allHealthScriptsData = $healthScriptsResponse.value
            while ($healthScriptsResponse.'@odata.nextLink')
            {
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                $allHealthScriptsData += $healthScriptsResponse.value
            }

            $totalHealthScripts = $allHealthScriptsData.Count
            $currentHealthScript = 0

            foreach ($script in $allHealthScriptsData)
            {
                $currentHealthScript++
                Write-Host "`rFetching Proactive Remediation Script $currentHealthScript of $totalHealthScripts" -NoNewline

                $scriptId = $script.id
                $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                foreach ($assignment in $assignmentResponse.value)
                {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')
                    {
                        $allDeviceHealthScripts += $script
                        break
                    }
                }
            }
            Write-Host "`rFetching Proactive Remediation Script $totalHealthScripts of $totalHealthScripts" -NoNewline
            Start-Sleep -Milliseconds 100
            Write-Host ''

            Write-Host 'Intune Profiles and Apps have been successfully fetched.' -ForegroundColor Green

            # Display the fetched 'All Device' Configuration Policies
            Write-Host "------- 'All Device' Device Configurations -------" -ForegroundColor Cyan
            foreach ($config in $allDeviceDeviceConfigs)
            {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name))
                {
                    $config.displayName 
                }
                else
                {
                    $config.name 
                }
                Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Settings Catalog Policies
            Write-Host "------- 'All Device' Settings Catalog Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceSettingsCatalog)
            {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                {
                    $policy.displayName 
                }
                else
                {
                    $policy.name 
                }
                Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Administrative Templates
            Write-Host "------- 'All Device' Administrative Templates -------" -ForegroundColor Cyan
            foreach ($template in $allDeviceAdminTemplates)
            {
                $templateName = if ([string]::IsNullOrWhiteSpace($template.name))
                {
                    $template.displayName 
                }
                else
                {
                    $template.name 
                }
                Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Compliance Policies
            Write-Host "------- 'All Device' Compliance Policies -------" -ForegroundColor Cyan
            foreach ($compliancepolicy in $allDeviceCompliancePolicies)
            {
                $compliancepolicyName = if ([string]::IsNullOrWhiteSpace($compliancepolicy.name))
                {
                    $compliancepolicy.displayName 
                }
                else
                {
                    $compliancepolicy.name 
                }
                Write-Host "Compliance Policy Name: $compliancepolicyName, Policy ID: $($compliancepolicy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' App Protection Policies
            Write-Host "------- 'All Device' App Protection Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceAppProtectionPolicies)
            {
                $policyName = $policy.displayName
                $policyId = $policy.id
                $policyType = switch ($policy.'@odata.type')
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        'Android' 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        'iOS' 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        'Windows' 
                    }
                    default
                    {
                        'Unknown' 
                    }
                }
                Write-Host "App Protection Policy Name: $policyName, Policy ID: $policyId, Type: $policyType" -ForegroundColor White

                Write-Host '  Protected Apps:' -ForegroundColor Yellow
                foreach ($app in $policy.apps)
                {
                    $appId = if ($app.mobileAppIdentifier.windowsAppId)
                    {
                        $app.mobileAppIdentifier.windowsAppId 
                    }
                    elseif ($app.mobileAppIdentifier.bundleId)
                    {
                        $app.mobileAppIdentifier.bundleId 
                    }
                    else
                    {
                        $app.mobileAppIdentifier.packageId 
                    }
                    Write-Host "    - $appId" -ForegroundColor White
                }
            }

            # Display the fetched 'All Device' App Configuration Policies
            Write-Host "------- 'All Device' App Configuration Policies -------" -ForegroundColor Cyan
            foreach ($policy in $allDeviceAppConfigurationPolicies)
            {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name))
                {
                    $policy.displayName 
                }
                else
                {
                    $policy.name 
                }
                Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Applications (Required)
            Write-Host "------- 'All Device' Applications (Required) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsRequired)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.name 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All Device' Applications (Available)
            Write-Host "------- 'All Device' Applications (Available) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsAvailable)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.displayName 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All Device' Applications (Uninstall)
            Write-Host "------- 'All Device' Applications (Uninstall) -------" -ForegroundColor Cyan
            foreach ($app in $allDeviceAppsUninstall)
            {
                $appName = if ([string]::IsNullOrWhiteSpace($app.name))
                {
                    $app.displayName 
                }
                else
                {
                    $app.name 
                }
                $appId = $app.id
                Write-Host "App Name: $appName, App ID: $appId" -ForegroundColor White
            }

            # Display the fetched 'All Device' Platform Scripts
            Write-Host "------- 'All Device' Platform Scripts -------" -ForegroundColor Cyan
            foreach ($script in $allDevicePlatformScripts)
            {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                {
                    $script.displayName 
                }
                else
                {
                    $script.name 
                }
                Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
            }

            # Display the fetched 'All Device' Proactive Remediation Scripts
            Write-Host "------- 'All Device' Proactive Remediation Scripts -------" -ForegroundColor Cyan
            foreach ($script in $allDeviceHealthScripts)
            {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name))
                {
                    $script.displayName 
                }
                else
                {
                    $script.name 
                }
                Write-Host "Script Name: $scriptName, Script ID: $($script.id)" -ForegroundColor White
            }

            # Prepare export functions
            function Add-ExportData($Category, $Items)
            {
                foreach ($item in $Items)
                {
                    $itemName = if ($item.displayName)
                    {
                        $item.displayName 
                    }
                    else
                    {
                        $item.name 
                    }
                    $null = $exportData.Add([PSCustomObject]@{
                            Category         = $Category
                            Item             = "$itemName (ID: $($item.id))"
                            AssignmentReason = 'All Devices'
                        })
                }
            }

            function Add-AppExportData($Category, $Apps)
            {
                foreach ($app in $Apps)
                {
                    $appName = if ($app.displayName)
                    {
                        $app.displayName 
                    }
                    else
                    {
                        $app.name 
                    }
                    $null = $exportData.Add([PSCustomObject]@{
                            Category         = $Category
                            Item             = "$appName (ID: $($app.id))"
                            AssignmentReason = "All Devices - $($app.AssignmentIntent)"
                        })
                }
            }

            Add-ExportData 'Device Configuration' $allDeviceDeviceConfigs
            Add-ExportData 'Settings Catalog Policy' $allDeviceSettingsCatalog 
            Add-ExportData 'Administrative Template' $allDeviceAdminTemplates 
            Add-ExportData 'Compliance Policy' $allDeviceCompliancePolicies
            Add-ExportData 'App Configuration Policy' $allDeviceAppConfigurationPolicies 

            foreach ($policy in $allDeviceAppProtectionPolicies)
            {
                $policyType = switch ($policy.'@odata.type')
                {
                    '#microsoft.graph.androidManagedAppProtection'
                    {
                        'Android' 
                    }
                    '#microsoft.graph.iosManagedAppProtection'
                    {
                        'iOS' 
                    }
                    '#microsoft.graph.windowsManagedAppProtection'
                    {
                        'Windows' 
                    }
                    default
                    {
                        'Unknown' 
                    }
                }
                $exportData += [PSCustomObject]@{
                    Category         = "App Protection Policy ($policyType)"
                    Item             = "$($policy.displayName) (ID: $($policy.id))"
                    AssignmentReason = 'All Devices'
                }
            }

            Add-AppExportData 'App (Required)' $allDeviceAppsRequired
            Add-AppExportData 'App (Available)' $allDeviceAppsAvailable
            Add-AppExportData 'App (Uninstall)' $allDeviceAppsUninstall

            Add-ExportData 'Platform Scripts' $allDevicePlatformScripts
            Add-ExportData 'Proactive Remediation Scripts' $allDeviceHealthScripts

            # Prompt the user to export results to CSV
            $export = Read-Host 'Would you like to export the results to a CSV file? (y/n)'
            if ($export -eq 'y')
            {
                Add-Type -AssemblyName System.Windows.Forms
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                $SaveFileDialog.Title = 'Save results to CSV'
                $SaveFileDialog.ShowDialog() | Out-Null
                $outputPath = $SaveFileDialog.FileName

                if ($outputPath)
                {
                    $exportData | Export-Csv -Path $outputPath -NoTypeInformation
                    Write-Host "Results have been exported to $outputPath" -ForegroundColor Green
                }
                else
                {
                    Write-Host 'No file selected, export cancelled.' -ForegroundColor Red
                }
            }
        }

        
        '7'
        {


            Write-Host 'Search for Assignments by the Name of a Setting chosen' -ForegroundColor Green

            # Prompt for DisplayNames
            $displayNamesInput = Read-Host 'Please enter the DisplayNames of the settings you want to search for (comma-separated)'
            $displayNames = $displayNamesInput -split ',' | ForEach-Object { $_.Trim() }

            # Define URIs for Intune Configuration Policies
            $policiesUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
            
            # Get Intune Configuration Policies
            $policiesResponse = Invoke-MgGraphRequest -Uri $policiesUri -Method Get

            $foundSettings = @()

            foreach ($policy in $policiesResponse.value)
            {
                $policyId = $policy.id

                # Fetch the policy name
                $policyDetailUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')"
                $policyDetailResponse = Invoke-MgGraphRequest -Uri $policyDetailUri -Method Get
                $policyName = $policyDetailResponse.name

                $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/settings?`$expand=settingDefinitions&top=1000"
                $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method Get

                foreach ($setting in $settingsResponse.value)
                {
                    foreach ($definition in $setting.settingDefinitions)
                    {
                        if ($displayNames -contains $definition.displayName)
                        {
                            # Get Policy Assignments
                            $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                            $assignments = @()
                            foreach ($assignment in $assignmentResponse.value)
                            {
                                switch ($assignment.target.'@odata.type')
                                {
                                    '#microsoft.graph.allLicensedUsersAssignmentTarget'
                                    {
                                        $assignments += 'All Users'
                                    }
                                    '#microsoft.graph.allDevicesAssignmentTarget'
                                    {
                                        $assignments += 'All Devices'
                                    }
                                    default
                                    {
                                        if ($assignment.target.groupId)
                                        {
                                            $assignments += $assignment.target.groupId
                                        }
                                        else
                                        {
                                            $assignments += 'Unknown'
                                        }
                                    }
                                }
                            }

                            $foundSettings += [PSCustomObject]@{
                                PolicyName              = $policyName
                                PolicyId                = $policyId
                                SettingDisplayName      = $definition.displayName
                                SettingDescription      = $definition.description
                                'Assignments (GroupID)' = $assignments -join ', '
                            }
                        }
                    }
                }
            }

            if ($foundSettings.Count -eq 0)
            {
                Write-Host 'No settings found with the provided displayNames' -ForegroundColor Red
            }
            else
            {
                Write-Host 'Settings found with the provided displayNames:' -ForegroundColor Green
                $foundSettings | Format-List
            }
        }

        '8'
        {
            Write-Host 'Checking for policies without assignments...' -ForegroundColor Green
            Show-PoliciesWithoutAssignments
        }

        '9'
        {
            Write-Host 'Checking for empty groups in assignments...' -ForegroundColor Yellow
            
            # Initialize array to store policies with empty group assignments
            $emptyGroupAssignments = @()
            
            # Function to check if a group is empty
            function Get-GroupMemberCount
            {
                param (
                    [string]$GroupId
                )
                try
                {
                    $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$count"
                    $count = Invoke-MgGraphRequest -Uri $membersUri -Method Get -Headers @{'ConsistencyLevel' = 'eventual' } -OutputType PSObject
                    return [int]$count
                }
                catch
                {
                    Write-Host "Error checking members for group $GroupId" -ForegroundColor Red
                    return -1
                }
            }
            
            # Function to process assignments for a policy
            function Process-PolicyAssignments
            {
                param (
                    [string]$PolicyType,
                    [string]$PolicyId,
                    [string]$PolicyName
                )
                                
                try
                {
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/$PolicyType('$PolicyId')/assignments"
                    $assignments = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                    
                    foreach ($assignment in $assignments.value)
                    {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget')
                        {
                            $groupId = $assignment.target.groupId
                            
                            try
                            {
                                $memberCount = Get-GroupMemberCount -GroupId $groupId
                                
                                if ($memberCount -eq 0)
                                {
                                    $groupInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId" -Method Get
                                    
                                    $script:emptyGroupAssignments += [PSCustomObject]@{
                                        PolicyType = $PolicyType
                                        PolicyName = $PolicyName
                                        PolicyId   = $PolicyId
                                        GroupName  = $groupInfo.displayName
                                        GroupId    = $groupId
                                    }
                                }
                            }
                            catch
                            {
                                Write-Host "  Error processing group $groupId : $_" -ForegroundColor Red
                            }
                        }
                    }
                }
                catch
                {
                    Write-Host "Error fetching assignments for policy $PolicyName : $_" -ForegroundColor Red
                }
            }
            
            Write-Host 'Fetching Configuration Profiles...' -ForegroundColor Yellow
            $deviceConfigs = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' -Method Get
            foreach ($config in $deviceConfigs.value)
            {
                Process-PolicyAssignments -PolicyType 'deviceConfigurations' -PolicyId $config.id -PolicyName $config.displayName
            }
            
            Write-Host 'Fetching Settings Catalog Policies...' -ForegroundColor Yellow
            $settingsCatalog = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Method Get
            foreach ($policy in $settingsCatalog.value)
            {
                Process-PolicyAssignments -PolicyType 'configurationPolicies' -PolicyId $policy.id -PolicyName $policy.name
            }
            
            Write-Host 'Fetching Compliance Policies...' -ForegroundColor Yellow
            $compliancePolicies = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies' -Method Get
            foreach ($policy in $compliancePolicies.value)
            {
                Process-PolicyAssignments -PolicyType 'deviceCompliancePolicies' -PolicyId $policy.id -PolicyName $policy.displayName
            }
            
            # Display results
            if ($emptyGroupAssignments.Count -eq 0)
            {
                Write-Host "`nNo empty groups found in policy assignments!" -ForegroundColor Green
            }
            else
            {
                Write-Host "`nFound $($emptyGroupAssignments.Count) policies with empty group assignments:" -ForegroundColor Yellow
                $emptyGroupAssignments | Format-Table -AutoSize -Property PolicyName, GroupName, GroupId
                
                # Offer to export to CSV
                $export = Read-Host "`nWould you like to export this information to CSV? (y/n)"
                if ($export -eq 'y')
                {
                    $exportPath = Show-SaveFileDialog -DefaultFileName 'IntuneEmptyGroupAssignments.csv'
                    if ($exportPath)
                    {
                        $emptyGroupAssignments | Export-Csv -Path $exportPath -NoTypeInformation
                        Write-Host "Exported to $exportPath" -ForegroundColor Green
                    }
                }
            }
        }

        '10'
        {
            Show-AdministrativeTemplatesForMigration
        }

        '11'
        {
            Write-Host 'Compare Group Assignments chosen' -ForegroundColor Green

            # Prompt for Group names or IDs
            Write-Host 'Please enter Group names or Object IDs to compare, separated by commas (,): ' -ForegroundColor Cyan
            Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
            $groupInput = Read-Host
            $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }

            if ($groupInputs.Count -lt 2)
            {
                Write-Host 'Please provide at least two groups to compare.' -ForegroundColor Red
                continue
            }

            # Before caching starts, initialize the group assignments hashtable
            $groupAssignments = @{}

            # Process each group input
            $resolvedGroups = @{}
            foreach ($input in $groupInputs)
            {
                Write-Host "`nProcessing input: $input" -ForegroundColor Yellow

                # Initialize variables
                $groupId = $null
                $groupName = $null

                # Check if input is a GUID
                if ($input -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
                {
                    try
                    {
                        # Get group info from Graph API
                        $groupUri = "https://graph.microsoft.com/v1.0/groups/$input"
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
                            UninstallApps      = [System.Collections.ArrayList]::new()
                            PlatformScripts    = [System.Collections.ArrayList]::new()
                            HealthScripts      = [System.Collections.ArrayList]::new()
                        }
                
                        Write-Host "Found group by ID: $groupName" -ForegroundColor Green
                    }
                    catch
                    {
                        Write-Host "No group found with ID: $input" -ForegroundColor Red
                        continue
                    }
                }
                else
                {
                    # Try to find group by display name
                    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$input'"
                    $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get

                    if ($groupResponse.value.Count -eq 0)
                    {
                        Write-Host "No group found with name: $input" -ForegroundColor Red
                        continue
                    }
                    elseif ($groupResponse.value.Count -gt 1)
                    {
                        Write-Host "Multiple groups found with name: $input. Please use the Object ID instead:" -ForegroundColor Red
                        foreach ($group in $groupResponse.value)
                        {
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
                        UninstallApps      = [System.Collections.ArrayList]::new()
                        PlatformScripts    = [System.Collections.ArrayList]::new()
                        HealthScripts      = [System.Collections.ArrayList]::new()
                    }
            
                    Write-Host "Found group by name: $groupName (ID: $groupId)" -ForegroundColor Green
                }

                # Process Device Configurations
                $deviceConfigsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
                $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsUri -Method Get
                $allDeviceConfigs = $deviceConfigsResponse.value
                while ($deviceConfigsResponse.'@odata.nextLink')
                {
                    $deviceConfigsResponse = Invoke-MgGraphRequest -Uri $deviceConfigsResponse.'@odata.nextLink' -Method Get
                    $allDeviceConfigs += $deviceConfigsResponse.value
                }
                $totalDeviceConfigs = $allDeviceConfigs.Count
                $currentDeviceConfig = 0
                foreach ($config in $allDeviceConfigs)
                {
                    $currentDeviceConfig++
                    Write-Host "`rFetching Device Configuration $currentDeviceConfig of $totalDeviceConfigs" -NoNewline
                    $configId = $config.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId })
                    {
                        [void]$groupAssignments[$groupName].DeviceConfigs.Add($config.displayName)
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Process Settings Catalog
                $settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get
                $allSettingsCatalog = $settingsCatalogResponse.value
                while ($settingsCatalogResponse.'@odata.nextLink')
                {
                    $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogResponse.'@odata.nextLink' -Method Get
                    $allSettingsCatalog += $settingsCatalogResponse.value
                }
                $totalSettingsCatalog = $allSettingsCatalog.Count
                $currentSettingsCatalog = 0
                foreach ($policy in $allSettingsCatalog)
                {
                    $currentSettingsCatalog++
                    Write-Host "`rFetching Settings Catalog Policy $currentSettingsCatalog of $totalSettingsCatalog" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId })
                    {
                        [void]$groupAssignments[$groupName].SettingsCatalog.Add($policy.name)
                    }
                }
                Write-Host "`rFetching Settings Catalog Policy $totalSettingsCatalog of $totalSettingsCatalog" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Process Administrative Templates
                $adminTemplatesUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get
                $allAdminTemplates = $adminTemplatesResponse.value
                while ($adminTemplatesResponse.'@odata.nextLink')
                {
                    $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesResponse.'@odata.nextLink' -Method Get
                    $allAdminTemplates += $adminTemplatesResponse.value
                }
                $totalAdminTemplates = $allAdminTemplates.Count
                $currentAdminTemplate = 0
                foreach ($template in $allAdminTemplates)
                {
                    $currentAdminTemplate++
                    Write-Host "`rFetching Administrative Template $currentAdminTemplate of $totalAdminTemplates" -NoNewline
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId })
                    {
                        [void]$groupAssignments[$groupName].AdminTemplates.Add($template.displayName)
                    }
                }
                Write-Host "`rFetching Administrative Template $totalAdminTemplates of $totalAdminTemplates" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Process Compliance Policies
                $complianceUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get
                $allCompliancePolicies = $complianceResponse.value
                while ($complianceResponse.'@odata.nextLink')
                {
                    $complianceResponse = Invoke-MgGraphRequest -Uri $complianceResponse.'@odata.nextLink' -Method Get
                    $allCompliancePolicies += $complianceResponse.value
                }
                $totalCompliancePolicies = $allCompliancePolicies.Count
                $currentCompliancePolicy = 0
                foreach ($policy in $allCompliancePolicies)
                {
                    $currentCompliancePolicy++
                    Write-Host "`rFetching Compliance Policy $currentCompliancePolicy of $totalCompliancePolicies" -NoNewline
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId })
                    {
                        [void]$groupAssignments[$groupName].CompliancePolicies.Add($policy.displayName)
                    }
                }
                Write-Host "`rFetching Compliance Policy $totalCompliancePolicies of $totalCompliancePolicies" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Process Apps
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
                $allApps = $appResponse.value
                while ($appResponse.'@odata.nextLink')
                {
                    $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
                    $allApps += $appResponse.value
                }
                $totalApps = $allApps.Count
                $currentApp = 0
                foreach ($app in $allApps)
                {
                    $currentApp++
                    Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
                    # Skip built-in and Microsoft apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq 'Microsoft Corporation')
                    {
                        continue
                    }

                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    foreach ($assignment in $assignmentResponse.value)
                    {
                        if ($assignment.target.groupId -eq $groupId)
                        {
                            switch ($assignment.intent)
                            {
                                'required'
                                {
                                    [void]$groupAssignments[$groupName].RequiredApps.Add($app.displayName) 
                                }
                                'available'
                                {
                                    [void]$groupAssignments[$groupName].AvailableApps.Add($app.displayName) 
                                }
                                'uninstall'
                                {
                                    [void]$groupAssignments[$groupName].UninstallApps.Add($app.displayName) 
                                }
                            }
                        }
                    }
                }
                Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ''  # Move to the next line after the loop

                # Process Platform Scripts (PowerShell)
                $scriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                $allScripts = $scriptsResponse.value
                while ($scriptsResponse.'@odata.nextLink')
                {
                    $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsResponse.'@odata.nextLink' -Method Get
                    $allScripts += $scriptsResponse.value
                }

                foreach ($script in $allScripts)
                {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId })
                    {
                        $scriptInfo = "$($script.displayName) (PowerShell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Process Shell Scripts (macOS)
                $shellScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts'
                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                $allShellScripts = $shellScriptsResponse.value
                while ($shellScriptsResponse.'@odata.nextLink')
                {
                    $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsResponse.'@odata.nextLink' -Method Get
                    $allShellScripts += $shellScriptsResponse.value
                }

                foreach ($script in $allShellScripts)
                {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.targetGroupId -eq $groupId })
                    {
                        $scriptInfo = "$($script.displayName) (Shell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                $healthScriptsUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                $allHealthScripts = $healthScriptsResponse.value
                while ($healthScriptsResponse.'@odata.nextLink')
                {
                    $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsResponse.'@odata.nextLink' -Method Get
                    $allHealthScripts += $healthScriptsResponse.value
                }

                foreach ($script in $allHealthScripts)
                {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId })
                    {
                        [void]$groupAssignments[$groupName].HealthScripts.Add($script.displayName)
                    }
                }

            }

            # Comparison Results section
            Write-Host "`nComparison Results:" -ForegroundColor Cyan
            Write-Host 'Comparing assignments between groups:' -ForegroundColor White
            foreach ($groupName in $groupAssignments.Keys)
            {
                Write-Host "  • $groupName" -ForegroundColor White
            }
            Write-Host ''

            # Update categories to include "Proactive Remediation Scripts"
            $categories = @{
                'Settings Catalog'              = 'SettingsCatalog'
                'Administrative Templates'      = 'AdminTemplates'
                'Compliance Policies'           = 'CompliancePolicies'
                'Available Apps'                = 'AvailableApps'
                'Required Apps'                 = 'RequiredApps'
                'Platform Scripts'              = 'PlatformScripts'
                'Device Configurations'         = 'DeviceConfigs'
                'Uninstall Apps'                = 'UninstallApps'
                'Proactive Remediation Scripts' = 'HealthScripts'
            }

            # First pass to collect all unique policies
            $uniquePolicies = [System.Collections.ArrayList]@()
            foreach ($groupName in $groupAssignments.Keys)
            {
                foreach ($categoryKey in $categories.Values)
                {
                    foreach ($policy in $groupAssignments.$groupName.$categoryKey)
                    {
                        if ($uniquePolicies -notcontains $policy)
                        {
                            $null = $uniquePolicies.Add($policy)
                        }
                    }
                }
            }

            Write-Host "Found $($uniquePolicies.Count) unique policies/apps/scripts across all groups`n" -ForegroundColor Yellow

            # Display comparison for each category
            foreach ($category in $categories.Keys)
            {
                $categoryKey = $categories[$category]

                Write-Host "=== $category ===" -ForegroundColor Cyan
                $foundAssignments = $false

                foreach ($policy in $uniquePolicies)
                {
                    $assignedGroups = @()
                    foreach ($groupName in $groupAssignments.Keys)
                    {
                        if ($groupAssignments.$groupName.$categoryKey -contains $policy)
                        {
                            $assignedGroups += $groupName
                        }
                    }

                    if ($assignedGroups.Count -gt 0)
                    {
                        $foundAssignments = $true
                        Write-Host '📋 Policy: ' -NoNewline -ForegroundColor White
                        Write-Host "$policy" -ForegroundColor Yellow

                        if ($assignedGroups.Count -gt 1)
                        {
                            Write-Host '  🔗 Shared Assignment!' -ForegroundColor Magenta
                        }

                        Write-Host '  ✅ Assigned to: ' -NoNewline -ForegroundColor Green
                        Write-Host "$($assignedGroups -join ', ')" -ForegroundColor White

                        $notAssignedGroups = $groupAssignments.Keys | Where-Object { $assignedGroups -notcontains $_ }
                        if ($notAssignedGroups)
                        {
                            Write-Host '  ❌ Not assigned to: ' -NoNewline -ForegroundColor Red
                            Write-Host "$($notAssignedGroups -join ', ')" -ForegroundColor White
                        }
                        Write-Host ''
                    }
                }

                if (-not $foundAssignments)
                {
                    Write-Host 'No assignments found in this category' -ForegroundColor Gray
                    Write-Host ''
                }
            }

            # Summary section
            Write-Host '=== Summary ===' -ForegroundColor Cyan
            foreach ($groupName in $groupAssignments.Keys)
            {
                $totalAssignments = 0
                foreach ($categoryKey in $categories.Values)
                {
                    $totalAssignments += $groupAssignments.$groupName.$categoryKey.Count
                }
                Write-Host "$groupName has $totalAssignments total assignments" -ForegroundColor Yellow
            }
            Write-Host ''

            # Offer to export results
            $export = Read-Host 'Would you like to export the comparison results to CSV? (y/n)'
            if ($export -eq 'y')
            {
                $exportPath = Show-SaveFileDialog -DefaultFileName 'IntuneGroupAssignmentComparison.csv'
                if ($exportPath)
                {
                    $comparisonResults = [System.Collections.ArrayList]@()
                    foreach ($category in $categories.Keys)
                    {
                        $categoryKey = $categories[$category]
                        foreach ($policy in $uniquePolicies)
                        {
                            $assignedGroups = @()
                            foreach ($groupName in $groupAssignments.Keys)
                            {
                                if ($groupAssignments.$groupName.$categoryKey -contains $policy)
                                {
                                    $assignedGroups += $groupName
                                }
                            }

                            if ($assignedGroups.Count -gt 0)
                            {
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
                    $comparisonResults | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }

        
        '0'
        {
            Write-Host 'Disconnecting from Microsoft Graph...' -ForegroundColor Yellow
            Disconnect-MgGraph | Out-Null
            Write-Host 'Thank you for using IntuneAssignmentChecker! 👋' -ForegroundColor Green
            Write-Host 'If you found this tool helpful, please consider:' -ForegroundColor Cyan
            Write-Host '- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker' -ForegroundColor White
            Write-Host '- Supporting the project: https://github.com/sponsors/ugurkocde' -ForegroundColor White
            Write-Host ''
            exit
        }

        '98'
        {
            Write-Host 'Opening GitHub Sponsor Page ...' -ForegroundColor Green
            Start-Process 'https://github.com/sponsors/ugurkocde'
        }

        '99'
        {
            Write-Host 'Opening GitHub Repository...' -ForegroundColor Green
            Start-Process 'https://github.com/ugurkocde/IntuneAssignmentChecker'
        }

        default
        {
            Write-Host 'Invalid choice, please select 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 or 11.' -ForegroundColor Red
            $script:defaultAssignmentReason = 'N/A'
        }
    }

    # Pause before showing the menu again
    if ($selection -ne '0')
    {
        Write-Host 'Press any key to return to the main menu...' -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    
} while ($selection -ne '0')
