# [Previous content truncated due to length limit. The content was successfully written but is too long to display in full.]
Write-Host "🚧 PREVIEW VERSION 3.0 🚧" -ForegroundColor Magenta
Write-Host ""
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
$versionUrl = "https://raw.githubusercontent.com/ugurkocde/IntuneAssignmentChecker/main/version_v3.txt"

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

    # Handle special cases for App Protection Policies
    $assignmentsUri = if ($EntityType -eq "deviceAppManagement/managedAppPolicies") {
        # For App Protection Policies, we need to determine the specific policy type first
        $policyUri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies/$EntityId"
        $policy = Invoke-MgGraphRequest -Uri $policyUri -Method Get
        $policyType = switch ($policy.'@odata.type') {
            "#microsoft.graph.androidManagedAppProtection" { "androidManagedAppProtections" }
            "#microsoft.graph.iosManagedAppProtection" { "iosManagedAppProtections" }
            "#microsoft.graph.windowsManagedAppProtection" { "windowsManagedAppProtections" }
            default { return $null }
        }
        if ($policyType) {
            "https://graph.microsoft.com/beta/deviceAppManagement/$policyType('$EntityId')/assignments"
        }
        else {
            $null
        }
    }
    else {
        "https://graph.microsoft.com/beta/deviceManagement/$EntityType('$EntityId')/assignments"
    }
    # For App Protection Policies that use $expand, the response structure is different
    $isAppProtectionPolicy = $EntityType -like "deviceAppManagement/*" -and ($EntityType -like "*ManagedAppProtections")
    
    if ($isAppProtectionPolicy) {
        $policyDetails = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        $assignments = @()
        
        foreach ($assignment in $policyDetails.assignments) {
            $assignmentReason = $null
            
            switch ($assignment.target.'@odata.type') {
                '#microsoft.graph.allLicensedUsersAssignmentTarget' { 
                    $assignmentReason = "All Users"
                }
                '#microsoft.graph.groupAssignmentTarget' {
                    if ($assignment.target.groupId -eq $GroupId) {
                        $assignmentReason = "Direct Assignment"
                    }
                }
            }

            if ($assignmentReason) {
                $assignments += @{
                    Reason  = $assignmentReason
                    GroupId = $assignment.target.groupId
                    Apps    = $policyDetails.apps
                }
            }
        }
    }
    else {
        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
        $assignments = @()

        $assignmentList = if ($EntityType -like "deviceAppManagement/*") { $assignmentResponse } else { $assignmentResponse.value }
        
        foreach ($assignment in $assignmentList) {
            $assignmentReason = $null
        
            # Only process group assignments when GroupId is provided
            if ($GroupId) {
                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                    $assignment.target.groupId -eq $GroupId) {
                    $assignmentReason = "Direct Assignment"
                }
            }
            else {
                $assignmentReason = switch ($assignment.target.'@odata.type') {
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                    '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                    '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                }
            }

            if ($assignmentReason) {
                $assignments += @{
                    Reason  = $assignmentReason
                    GroupId = $assignment.target.groupId
                    Apps    = if ($isAppProtectionPolicy) { $policyDetails.apps } else { $null }
                }
            }
        }
    }

    return $assignments
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

    # Handle special cases for app management endpoints
    $baseUri = if ($EntityType -like "deviceAppManagement/*") {
        "https://graph.microsoft.com/beta"
    }
    else {
        "https://graph.microsoft.com/beta/deviceManagement"
    }
    
    # Extract the actual entity type from full path if needed
    $actualEntityType = if ($EntityType -like "deviceAppManagement/*") {
        $EntityType
    }
    else {
        "$EntityType"
    }
    
    $uri = "$baseUri/$actualEntityType"
    if ($Filter) { $uri += "?`$filter=$Filter" }
    if ($Select) { $uri += $(if ($Filter) { "&" }else { "?" }) + "`$select=$Select" }
    if ($Expand) { $uri += $(if ($Filter -or $Select) { "&" }else { "?" }) + "`$expand=$Expand" }

    $response = Invoke-MgGraphRequest -Uri $uri -Method Get
    $entities = $response.value

    while ($response.'@odata.nextLink') {
        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method Get
        $entities += $response.value
    }

    return $entities
}

function Get-GroupInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    try {
        $groupUri = "https://graph.microsoft.com/v1.0/groups/$GroupId"
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

    $deviceUri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$DeviceName'"
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
        $userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
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

    $uri = "https://graph.microsoft.com/v1.0/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf?`$select=id,displayName"
    $response = Invoke-MgGraphRequest -Uri $uri -Method Get
    
    return $response.value
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

function Show-SaveFileDialog {
    param (
        [string]$DefaultFileName
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Excel files (*.xlsx)|*.xlsx|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $saveFileDialog.FileName = $DefaultFileName
    $saveFileDialog.Title = "Save Policy Report"
    
    if ($saveFileDialog.ShowDialog() -eq 'OK') {
        return $saveFileDialog.FileName
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
    Write-Host "  [10] Show all Administrative Templates (deprecates in December 2024)" -ForegroundColor Yellow
    Write-Host "  [11] Compare Assignments Between Groups" -ForegroundColor White
    Write-Host ""
    
    Write-Host "System:" -ForegroundColor Cyan
    Write-Host "  [0] Exit" -ForegroundColor White
    Write-Host "  [98] Support the Project 💝" -ForegroundColor Magenta
    Write-Host "  [99] Report a Bug or Request a Feature" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline
}

# Main script logic
do {
    Show-Menu
    $selection = Read-Host

    switch ($selection) {
        '1' {
            Write-Host "User selection chosen" -ForegroundColor Green

            # Prompt for one or more User Principal Names
            Write-Host "Please enter User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
            $upnInput = Read-Host
    
            # Validate input
            if ([string]::IsNullOrWhiteSpace($upnInput)) {
                Write-Host "No UPN provided. Please try again with a valid UPN." -ForegroundColor Red
                continue
            }
    
            $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
            if ($upns.Count -eq 0) {
                Write-Host "No valid UPNs provided. Please try again with at least one valid UPN." -ForegroundColor Red
                continue
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
                    DeviceConfigs            = @()
                    SettingsCatalog          = @()
                    AdminTemplates           = @()
                    CompliancePolicies       = @()
                    AppProtectionPolicies    = @()
                    AppConfigurationPolicies = @()
                    AppsRequired             = @()
                    AppsAvailable            = @()
                    AppsUninstall            = @()
                    PlatformScripts          = @()
                    HealthScripts            = @()
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
                    }
                }

                # Get App Protection Policies
                Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
                $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
                foreach ($policy in $appProtectionPolicies) {
                    $policyType = $policy.'@odata.type'
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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

                # Display results
                Write-Host "`nAssignments for User: $upn" -ForegroundColor Green

                # Display Device Configurations
                Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
                foreach ($config in $relevantPolicies.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $assignmentInfo = if ($config.AssignmentReason) { ", Assignment Reason: $($config.AssignmentReason)" } else { "" }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Settings Catalog Policies
                Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Administrative Templates
                Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
                foreach ($template in $relevantPolicies.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    $assignmentInfo = if ($template.AssignmentReason) { ", Assignment Reason: $($template.AssignmentReason)" } else { "" }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Compliance Policies
                Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Compliance Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display App Protection Policies
                Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.AppProtectionPolicies) {
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
                }

                # Display App Configuration Policies
                Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Platform Scripts
                Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
                foreach ($script in $relevantPolicies.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    $assignmentInfo = if ($script.AssignmentReason) { ", Assignment Reason: $($script.AssignmentReason)" } else { "" }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Proactive Remediation Scripts
                Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
                foreach ($script in $relevantPolicies.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    $assignmentInfo = if ($script.AssignmentReason) { ", Assignment Reason: $($script.AssignmentReason)" } else { "" }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
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
                )
            }

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneUserAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
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
                    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$input'"
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
                    DeviceConfigs            = @()
                    SettingsCatalog          = @()
                    AdminTemplates           = @()
                    CompliancePolicies       = @()
                    AppProtectionPolicies    = @()
                    AppConfigurationPolicies = @()
                    AppsRequired             = @()
                    AppsAvailable            = @()
                    AppsUninstall            = @()
                    PlatformScripts          = @()
                    HealthScripts            = @()
                }

                # Get Device Configurations
                Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
                $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
                foreach ($config in $deviceConfigs) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.DeviceConfigs += $config
                    }
                }

                # Get Settings Catalog Policies
                Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
                $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
                foreach ($policy in $settingsCatalog) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.SettingsCatalog += $policy
                    }
                }

                # Get Administrative Templates
                Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
                $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
                foreach ($template in $adminTemplates) {
                    $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $template | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.AdminTemplates += $template
                    }
                }

                # Get Compliance Policies
                Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
                $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
                foreach ($policy in $compliancePolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.CompliancePolicies += $policy
                    }
                }

                # Get App Protection Policies
                Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
                $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
                foreach ($policy in $appProtectionPolicies) {
                    $policyType = $policy.'@odata.type'
                    $assignmentsUri = switch ($policyType) {
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                                        if (!$GroupId -or $assignment.target.groupId -eq $groupId) {
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
                    $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.AppConfigurationPolicies += $policy
                    }
                }

                # Get Platform Scripts
                Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
                $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
                foreach ($script in $platformScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.PlatformScripts += $script
                    }
                }

                # Get Proactive Remediation Scripts
                Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
                $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
                foreach ($script in $healthScripts) {
                    $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id -GroupId $groupId
                    if ($assignments) {
                        $assignmentReason = if ($assignments[0].Reason -eq "Group Assignment") {
                            if ($assignments[0].GroupId -eq $groupId) {
                                "Direct Assignment"
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $assignments[0].GroupId
                                "$($assignments[0].Reason) - $($groupInfo.DisplayName)"
                            }
                        }
                        else {
                            $assignments[0].Reason
                        }
                        $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $assignmentReason -Force
                        $relevantPolicies.HealthScripts += $script
                    }
                }

                # Display results
                Write-Host "`nAssignments for Group: $groupName" -ForegroundColor Green

                # Display Device Configurations
                Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
                foreach ($config in $relevantPolicies.DeviceConfigs) {
                    $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                    $assignmentInfo = if ($config.AssignmentReason) { ", Assignment Reason: $($config.AssignmentReason)" } else { "" }
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Settings Catalog Policies
                Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.SettingsCatalog) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Administrative Templates
                Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
                foreach ($template in $relevantPolicies.AdminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { $template.displayName } else { $template.name }
                    $assignmentInfo = if ($template.AssignmentReason) { ", Assignment Reason: $($template.AssignmentReason)" } else { "" }
                    Write-Host "Administrative Template Name: $templateName, Template ID: $($template.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Compliance Policies
                Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.CompliancePolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "Compliance Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display App Protection Policies
                Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.AppProtectionPolicies) {
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
                }

                # Display App Configuration Policies
                Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
                foreach ($policy in $relevantPolicies.AppConfigurationPolicies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                    $assignmentInfo = if ($policy.AssignmentReason) { ", Assignment Reason: $($policy.AssignmentReason)" } else { "" }
                    Write-Host "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Platform Scripts
                Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
                foreach ($script in $relevantPolicies.PlatformScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    $assignmentInfo = if ($script.AssignmentReason) { ", Assignment Reason: $($script.AssignmentReason)" } else { "" }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                }

                # Display Proactive Remediation Scripts
                Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
                foreach ($script in $relevantPolicies.HealthScripts) {
                    $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                    $assignmentInfo = if ($script.AssignmentReason) { ", Assignment Reason: $($script.AssignmentReason)" } else { "" }
                    Write-Host "Script Name: $scriptName, Script ID: $($script.id)$assignmentInfo" -ForegroundColor White
                }

                # Add to export data
                Add-ExportData -ExportData $exportData -Category "Group" -Items @([PSCustomObject]@{
                        displayName      = $groupName
                        id               = $groupId
                        AssignmentReason = "Direct Assignment"
                    }

                    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $relevantPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $relevantPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $relevantPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $relevantPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $relevantPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
                    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $relevantPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $relevantPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
                    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $relevantPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
                )
            }

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneGroupAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }
        '3' {
            Write-Host "Device selection chosen" -ForegroundColor Green

            # Prompt for one or more Device Names
            Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
            $deviceInput = Read-Host

            if ([string]::IsNullOrWhiteSpace($deviceInput)) {
                Write-Host "No device name provided. Please try again." -ForegroundColor Red
                continue
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
                    DeviceConfigs            = @()
                    SettingsCatalog          = @()
                    AdminTemplates           = @()
                    CompliancePolicies       = @()
                    AppProtectionPolicies    = @()
                    AppConfigurationPolicies = @()
                    AppsRequired             = @()
                    AppsAvailable            = @()
                    AppsUninstall            = @()
                    PlatformScripts          = @()
                    HealthScripts            = @()
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
                        "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                        "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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

                    if ($Policies.Count -eq 0) {
                        return
                    }

                    # Create prominent section header
                    $headerSeparator = "-" * ($Title.Length + 16)  # 16 accounts for the added spaces and dashes
                    Write-Host "`n$headerSeparator" -ForegroundColor Cyan
                    Write-Host "------- $Title -------" -ForegroundColor Cyan
                    Write-Host "$headerSeparator" -ForegroundColor Cyan
                    
                    # Create table header with custom formatting
                    $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "ID", "Assignment"
                    $tableSeparator = "-" * 120
                    
                    Write-Host $headerFormat -ForegroundColor Yellow
                    Write-Host $separator -ForegroundColor Gray
                    
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
                        Write-Host $rowFormat -ForegroundColor White
                    }
                    
                    Write-Host $separator -ForegroundColor Gray
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
                )
            }

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneDeviceAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }
        '4' {
            Write-Host "Fetching all policies and their assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for all policies
            $allPolicies = @{
                DeviceConfigs            = @()
                SettingsCatalog          = @()
                AdminTemplates           = @()
                CompliancePolicies       = @()
                AppProtectionPolicies    = @()
                AppConfigurationPolicies = @()
                PlatformScripts          = @()
                HealthScripts            = @()
            }

            # Function to process and display policy assignments
            function Process-PolicyAssignments {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$PolicyType,
                    
                    [Parameter(Mandatory = $true)]
                    [object[]]$Policies,
                    
                    [Parameter(Mandatory = $true)]
                    [string]$DisplayName
                )
                
                Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
                foreach ($policy in $Policies) {
                    $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    if ($_.Reason -eq "Group Assignment") {
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
                    if ($_.Reason -eq "Group Assignment") {
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

            # Display all policies and their assignments
            Process-PolicyAssignments -PolicyType "deviceConfigurations" -Policies $allPolicies.DeviceConfigs -DisplayName "Device Configurations"
            Process-PolicyAssignments -PolicyType "configurationPolicies" -Policies $allPolicies.SettingsCatalog -DisplayName "Settings Catalog Policies"
            Process-PolicyAssignments -PolicyType "groupPolicyConfigurations" -Policies $allPolicies.AdminTemplates -DisplayName "Administrative Templates"
            Process-PolicyAssignments -PolicyType "deviceCompliancePolicies" -Policies $allPolicies.CompliancePolicies -DisplayName "Compliance Policies"
            Process-PolicyAssignments -PolicyType "managedAppPolicies" -Policies $allPolicies.AppProtectionPolicies -DisplayName "App Protection Policies"
            Process-PolicyAssignments -PolicyType "mobileAppConfigurations" -Policies $allPolicies.AppConfigurationPolicies -DisplayName "App Configuration Policies"
            Process-PolicyAssignments -PolicyType "deviceManagementScripts" -Policies $allPolicies.PlatformScripts -DisplayName "Platform Scripts"
            Process-PolicyAssignments -PolicyType "deviceHealthScripts" -Policies $allPolicies.HealthScripts -DisplayName "Proactive Remediation Scripts"

            # Add to export data
            Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $allPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $allPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items $allPolicies.AdminTemplates -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $allPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $allPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $allPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $allPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $allPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentSummary }

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneAllPolicies.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
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
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
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
                    Write-Host "Compliance Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
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

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneAllUsersAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }     
        '6' {
            Write-Host "Fetching all 'All Devices' assignments..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Initialize collections for policies with "All Devices" assignments
            $allDevicesAssignments = @{
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
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
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
                    Write-Host "Compliance Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
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

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneAllDevicesAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }
        '7' {
            Write-Host "Generating HTML Report..." -ForegroundColor Green

            # Download the html-export.ps1 from github and Save the script in the same directory as this script
            #$downloadurl = "https://raw.githubusercontent.com/ugurkocde/Intune/refs/heads/main/html-export.ps1"

            try {
                # Download and save the script content
                #$htmlExportScript = (Invoke-WebRequest -Uri $downloadurl -UseBasicParsing).Content
                $scriptPath = ".\html-export.ps1"
                #Set-Content -Path $scriptPath -Value $htmlExportScript

                # Import the script
                . $scriptPath

                # Generate the report with a fixed filename in the same directory
                $filePath = Join-Path (Get-Location) "IntuneAssignmentReport.html"
                Export-HTMLReport -FilePath $filePath

                # Ask if user wants to open the report
                $openReport = Read-Host "Would you like to open the report now? (y/n)"
                if ($openReport -eq 'y') {
                    Start-Process $filePath
                }

                # Clean up - remove the downloaded script
                if (Test-Path $scriptPath) {
                    #Remove-Item -Path $scriptPath -Force
                    continue
                }
            }
            catch {
                Write-Host "Error: Failed to download or process the HTML export script. $($_.Exception.Message)" -ForegroundColor Red
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
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                    Write-Host "Device Configuration Name: $configName, Configuration ID: $($config.id)" -ForegroundColor White
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
                    Write-Host "Compliance Policy Name: $policyName, Policy ID: $($policy.id)" -ForegroundColor White
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

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneUnassignedPolicies.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
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
                    $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$filter=id&`$top=1"
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
                    "#microsoft.graph.androidManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.iosManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                    "#microsoft.graph.windowsManagedAppProtection" { "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                    Write-Host "Device Configuration Name: $configName" -ForegroundColor White
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
                    Write-Host "Compliance Policy Name: $policyName" -ForegroundColor White
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

            # Offer to export results
            $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneEmptyGroupAssignments.csv"
                if ($exportPath) {
                    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
            }
        }
        '10' {
            Write-Host "⚠️  WARNING: Administrative Templates will be deprecated in December 2024" -ForegroundColor Yellow
            Write-Host "Microsoft recommends migrating to Settings Catalog" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Fetching all Administrative Templates..." -ForegroundColor Green
            $exportData = [System.Collections.ArrayList]::new()

            # Get Administrative Templates
            $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
            
            if ($adminTemplates.Count -eq 0) {
                Write-Host "No Administrative Templates found" -ForegroundColor Gray
            }
            else {
                # Process each template and its assignments
                foreach ($template in $adminTemplates) {
                    $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
                    $assignmentSummary = $assignments | ForEach-Object {
                        if ($_.Reason -eq "Group Assignment") {
                            $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                            "$($_.Reason) - $($groupInfo.DisplayName)"
                        }
                        else {
                            $_.Reason
                        }
                    }
                    $template | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                }

                # Display results in a table format
                Write-Host "`n------- Administrative Templates -------" -ForegroundColor Cyan
                
                # Create table header
                $headerFormat = "{0,-50} {1,-40} {2,-50}" -f "Template Name", "Template ID", "Assignments"
                $separator = "-" * 140
                
                Write-Host $separator
                Write-Host $headerFormat -ForegroundColor Yellow
                Write-Host $separator
                
                foreach ($template in $adminTemplates) {
                    $templateName = if ([string]::IsNullOrWhiteSpace($template.name)) { 
                        $template.displayName 
                    }
                    else { 
                        $template.name 
                    }
                    
                    # Truncate long names and add ellipsis
                    if ($templateName.Length -gt 47) {
                        $templateName = $templateName.Substring(0, 44) + "..."
                    }
                    
                    # Format ID
                    $id = $template.id
                    if ($id.Length -gt 37) {
                        $id = $id.Substring(0, 34) + "..."
                    }
                    
                    # Format assignment summary
                    $assignments = if ($template.AssignmentSummary) { 
                        $template.AssignmentSummary 
                    }
                    else { 
                        "No Assignments" 
                    }
                    if ($assignments.Length -gt 47) {
                        $assignments = $assignments.Substring(0, 44) + "..."
                    }
                    
                    # Output formatted row
                    $rowFormat = "{0,-50} {1,-40} {2,-50}" -f $templateName, $id, $assignments
                    Write-Host $rowFormat -ForegroundColor White
                    
                    # Add to export data
                    Add-ExportData -ExportData $exportData -Category "Administrative Template" -Items @($template) -AssignmentReason $template.AssignmentSummary
                }
                
                Write-Host $separator
                
                # Display summary
                Write-Host "`nSummary:" -ForegroundColor Cyan
                Write-Host "Total Administrative Templates: $($adminTemplates.Count)" -ForegroundColor White
                $assignedCount = ($adminTemplates | Where-Object { $_.AssignmentSummary }).Count
                $unassignedCount = $adminTemplates.Count - $assignedCount
                Write-Host "Templates with assignments: $assignedCount" -ForegroundColor White
                Write-Host "Templates without assignments: $unassignedCount" -ForegroundColor White
                
                # Offer to export results
                $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
                if ($export -eq 'y') {
                    $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneAdministrativeTemplates.csv"
                    if ($exportPath) {
                        $exportData | Export-Csv -Path $exportPath -NoTypeInformation
                        Write-Host "Results exported to $exportPath" -ForegroundColor Green
                    }
                }
            }
        }
        '11' {
            Write-Host "Compare Group Assignments chosen" -ForegroundColor Green

            # Prompt for Group names or IDs
            Write-Host "Please enter Group names or Object IDs to compare, separated by commas (,): " -ForegroundColor Cyan
            Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
            $groupInput = Read-Host
            $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }

            if ($groupInputs.Count -lt 2) {
                Write-Host "Please provide at least two groups to compare." -ForegroundColor Red
                continue
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
                    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$input'"
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
                $deviceConfigsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
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
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            
                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].DeviceConfigs.Add($config.displayName)
                    }
                }
                Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""  # Move to the next line after the loop

                # Process Settings Catalog
                $settingsCatalogUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get

                foreach ($policy in $settingsCatalogResponse.value) {
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].SettingsCatalog.Add($policy.name)
                    }
                }

                # Process Administrative Templates
                $adminTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
                $adminTemplatesResponse = Invoke-MgGraphRequest -Uri $adminTemplatesUri -Method Get

                foreach ($template in $adminTemplatesResponse.value) {
                    $templateId = $template.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$templateId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].AdminTemplates.Add($template.displayName)
                    }
                }

                # Process Compliance Policies
                $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
                $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get

                foreach ($policy in $complianceResponse.value) {
                    $policyId = $policy.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$policyId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].CompliancePolicies.Add($policy.displayName)
                    }
                }

                # Process Apps
                $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
                $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get

                foreach ($app in $appResponse.value) {
                    # Skip built-in and Microsoft apps
                    if ($app.isFeatured -or $app.isBuiltIn -or $app.publisher -eq "Microsoft Corporation") {
                        continue
                    }

                    $appId = $app.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$appId')/assignments"
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
                $scriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"
                $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
                # For PowerShell scripts, we need to check the script type
                foreach ($script in $scriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.groupId -eq $groupId }) {
                        $scriptInfo = "$($script.displayName) (PowerShell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Process Shell Scripts (macOS)
                $shellScriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts"
                $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
                # For Shell scripts, we need to check the script type
                foreach ($script in $shellScriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.targetGroupId -eq $groupId }) {
                        $scriptInfo = "$($script.displayName) (Shell)"
                        [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
                    }
                }

                # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
                $healthScriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"
                $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
                foreach ($script in $healthScriptsResponse.value) {
                    $scriptId = $script.id
                    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
                    $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

                    if ($assignmentResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $groupId }) {
                        [void]$groupAssignments[$groupName].HealthScripts.Add($script.displayName)
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
                "Settings Catalog"              = "SettingsCatalog"
                "Administrative Templates"      = "AdminTemplates"
                "Compliance Policies"           = "CompliancePolicies"
                "Available Apps"                = "AvailableApps"
                "Required Apps"                 = "RequiredApps"
                "Platform Scripts"              = "PlatformScripts"
                "Device Configurations"         = "DeviceConfigs"
                "Uninstall Apps"                = "UninstallApps"
                "Proactive Remediation Scripts" = "HealthScripts"
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

            # Offer to export results
            $export = Read-Host "Would you like to export the comparison results to CSV? (y/n)"
            if ($export -eq 'y') {
                $exportPath = Show-SaveFileDialog -DefaultFileName "IntuneGroupAssignmentComparison.csv"
                if ($exportPath) {
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
                    $comparisonResults | Export-Csv -Path $exportPath -NoTypeInformation
                    Write-Host "Results exported to $exportPath" -ForegroundColor Green
                }
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
            Write-Host "Invalid choice, please select 1-11, 98, 99, or 0." -ForegroundColor Red
        }
    }

    if ($selection -ne '0') {
        Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} while ($selection -ne '0')
