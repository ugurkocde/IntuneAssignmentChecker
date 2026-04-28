function Get-IntuneUserDeviceAssignment {
    <#
    .SYNOPSIS
    Shows the full effective set of Intune policies and apps that would apply to a specific User on a specific Device.

    .DESCRIPTION
    Combines the user's group memberships with the device's group memberships and evaluates every policy/app
    category as if both subjects were present at the same time. This mirrors what Intune actually does for an
    Autopilot deployment where User X is assigned to Device Y, without requiring you to test by reprovisioning.

    Assignment filters (Include/Exclude) are listed but their rule expressions are not evaluated against device
    properties. Filter evaluation is performed by the Intune service itself at deployment time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "User Principal Name")]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false, HelpMessage = "Device display name or Object ID")]
        [string]$DeviceName,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter
    )

    Write-Host "What-If: User on Device - effective policy preview" -ForegroundColor Green

    # ── Resolve User and Device ──────────────────────────────────────────────
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        Write-Host "Please enter the User Principal Name: " -NoNewline -ForegroundColor Cyan
        $UserPrincipalName = Read-Host
    }
    if ([string]::IsNullOrWhiteSpace($DeviceName)) {
        Write-Host "Please enter the Device name: " -NoNewline -ForegroundColor Cyan
        $DeviceName = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -or [string]::IsNullOrWhiteSpace($DeviceName)) {
        Write-Host "Both a User Principal Name and a Device name are required." -ForegroundColor Red
        return
    }

    $upn = ($UserPrincipalName -split ',')[0].Trim()
    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Host "Invalid UPN format: '$upn'. Expected: user@domain.com" -ForegroundColor Red
        return
    }
    $devName = ($DeviceName -split ',')[0].Trim()

    Write-Host "Looking up user: $upn" -ForegroundColor Yellow
    $userInfo = Get-UserInfo -UserPrincipalName $upn
    if (-not $userInfo.Success) {
        Write-Host "User not found: $upn" -ForegroundColor Red
        return
    }

    Write-Host "Looking up device: $devName" -ForegroundColor Yellow
    $deviceInfo = $null
    if ($devName -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        try {
            $selectProps = "id,displayName,operatingSystem,operatingSystemVersion"
            $directDevice = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/devices/$($devName)?`$select=$selectProps" -Method Get
            $deviceInfo = @{
                Id              = $directDevice.id
                DisplayName     = $directDevice.displayName
                OperatingSystem = $directDevice.operatingSystem
                Success         = $true
                MultipleFound   = $false
            }
        }
        catch {
            Write-Host "No device found with Object ID: $devName" -ForegroundColor Red
            return
        }
    }
    else {
        $deviceInfo = Get-DeviceInfo -DeviceName $devName
        if (-not $deviceInfo.Success) {
            Write-Host "Device not found: $devName" -ForegroundColor Red
            return
        }
        if ($deviceInfo.MultipleFound) {
            Write-Host "Multiple devices match name '$devName'. Use the Object ID instead:" -ForegroundColor Red
            foreach ($d in $deviceInfo.AllDevices) {
                Write-Host "  - $($d.displayName) (ID: $($d.id), OS: $($d.operatingSystem))" -ForegroundColor Yellow
            }
            return
        }
    }

    Write-Host "Resolved: $($userInfo.UserPrincipalName) + $($deviceInfo.DisplayName) (OS: $($deviceInfo.OperatingSystem))" -ForegroundColor Green

    # ── Group memberships ────────────────────────────────────────────────────
    $userGroupIds   = @()
    $deviceGroupIds = @()
    try {
        $uGroups = Get-GroupMemberships -ObjectId $userInfo.Id   -ObjectType "User"
        $dGroups = Get-GroupMemberships -ObjectId $deviceInfo.Id -ObjectType "Device"
        $userGroupIds   = @($uGroups | Where-Object { $_.id } | ForEach-Object { $_.id })
        $deviceGroupIds = @($dGroups | Where-Object { $_.id } | ForEach-Object { $_.id })
    }
    catch {
        Write-Host "Error fetching group memberships: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $combinedGroupIds = @(($userGroupIds + $deviceGroupIds) | Select-Object -Unique)
    $deviceOS = $deviceInfo.OperatingSystem
    $includeReasons = @("All Users", "All Devices")

    # ── Helper: classify the source of a winning assignment ──────────────────
    # Returns @{ Reason = '...'; Source = 'All Users'|'All Devices'|'User group'|'Device group'|'User+Device group'|'Excluded' }
    $classify = {
        param($assignments, $reasonString)

        if (-not $reasonString) { return $null }

        $source = if ($reasonString -like 'Excluded*')    { 'Excluded' }
                  elseif ($reasonString -like 'All Users*')   { 'All Users' }
                  elseif ($reasonString -like 'All Devices*') { 'All Devices' }
                  else { $null }

        if (-not $source) {
            # Group Assignment - find the matching assignment to learn its GroupId
            foreach ($a in $assignments) {
                if ($a.Reason -eq 'Group Assignment') {
                    $inUser   = $userGroupIds   -contains $a.GroupId
                    $inDevice = $deviceGroupIds -contains $a.GroupId
                    if ($inUser -and $inDevice) { $source = 'User+Device group'; break }
                    elseif ($inUser)            { $source = 'User group';        break }
                    elseif ($inDevice)          { $source = 'Device group';      break }
                }
            }
            if (-not $source) { $source = 'Group' }
        }

        return @{ Reason = $reasonString; Source = $source }
    }

    Write-Host "Fetching effective policies and apps..." -ForegroundColor Yellow

    $relevantPolicies = @{
        DeviceConfigs               = [System.Collections.ArrayList]::new()
        SettingsCatalog             = [System.Collections.ArrayList]::new()
        CompliancePolicies          = [System.Collections.ArrayList]::new()
        AppProtectionPolicies       = [System.Collections.ArrayList]::new()
        AppConfigurationPolicies    = [System.Collections.ArrayList]::new()
        AppsRequired                = [System.Collections.ArrayList]::new()
        AppsAvailable               = [System.Collections.ArrayList]::new()
        AppsUninstall               = [System.Collections.ArrayList]::new()
        PlatformScripts             = [System.Collections.ArrayList]::new()
        HealthScripts               = [System.Collections.ArrayList]::new()
        AntivirusProfiles           = [System.Collections.ArrayList]::new()
        DiskEncryptionProfiles      = [System.Collections.ArrayList]::new()
        FirewallProfiles            = [System.Collections.ArrayList]::new()
        EndpointDetectionProfiles   = [System.Collections.ArrayList]::new()
        AttackSurfaceProfiles       = [System.Collections.ArrayList]::new()
        AccountProtectionProfiles   = [System.Collections.ArrayList]::new()
        DeploymentProfiles          = [System.Collections.ArrayList]::new()
        ESPProfiles                 = [System.Collections.ArrayList]::new()
        CloudPCProvisioningPolicies = [System.Collections.ArrayList]::new()
        CloudPCUserSettings         = [System.Collections.ArrayList]::new()
    }

    # Helper: standard fetch -> resolve -> classify pattern for generic categories
    $processGeneric = {
        param($entityType, $bucketKey, [switch]$SkipPlatformCheck)

        $items = Get-IntuneEntities -EntityType $entityType
        foreach ($item in $items) {
            $assignments = Get-IntuneAssignments -EntityType $entityType -EntityId $item.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
            if (-not $reason) { continue }
            if (-not $SkipPlatformCheck -and -not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $item)) { continue }
            $info = & $classify $assignments $reason
            $item | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
            $item | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
            [void]$relevantPolicies[$bucketKey].Add($item)
        }
    }

    # Helper: ES intents-based fetch
    $processIntent = {
        param($templateFamily, $bucketKey, $processedSet)

        # configurationPolicies branch
        $configPolicies = Get-IntuneEntities -EntityType "configurationPolicies"
        $matching = $configPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $templateFamily }
        foreach ($policy in $matching) {
            if (-not $processedSet.Add($policy.id)) { continue }
            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
            if (-not $reason) { continue }
            if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) { continue }
            $info = & $classify $assignments $reason
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
            $policy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
            [void]$relevantPolicies[$bucketKey].Add($policy)
        }

        # deviceManagement/intents branch
        $intents = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $intents
        $matchingIntents = $intents | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $templateFamily }
        foreach ($policy in $matchingIntents) {
            if (-not $processedSet.Add($policy.id)) { continue }
            $resp = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
            $assignmentList = foreach ($a in $resp.value) {
                [PSCustomObject]@{
                    Reason  = switch ($a.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget'      { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget'           { "Group Assignment" }
                        '#microsoft.graph.exclusionGroupAssignmentTarget'  { "Group Exclusion" }
                        default { "Unknown" }
                    }
                    GroupId = if ($a.target.'@odata.type' -match "groupAssignmentTarget") { $a.target.groupId } else { $null }
                }
            }
            $reason = Resolve-AssignmentReason -Assignments $assignmentList -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
            if (-not $reason) { continue }
            if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) { continue }
            $info = & $classify $assignmentList $reason
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
            $policy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
            [void]$relevantPolicies[$bucketKey].Add($policy)
        }
    }

    # ── Generic categories ───────────────────────────────────────────────────
    Write-Host "  Device Configurations..." -ForegroundColor Yellow
    & $processGeneric "deviceConfigurations" "DeviceConfigs"

    Write-Host "  Settings Catalog Policies..." -ForegroundColor Yellow
    $allConfigPolicies = Get-IntuneEntities -EntityType "configurationPolicies"
    foreach ($policy in $allConfigPolicies) {
        # Skip endpoint-security templates - they're handled separately
        if ($policy.templateReference -and $policy.templateReference.templateFamily -like 'endpointSecurity*') { continue }
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
        if (-not $reason) { continue }
        if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) { continue }
        $info = & $classify $assignments $reason
        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
        $policy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
        [void]$relevantPolicies.SettingsCatalog.Add($policy)
    }

    Write-Host "  Compliance Policies..." -ForegroundColor Yellow
    & $processGeneric "deviceCompliancePolicies" "CompliancePolicies"

    Write-Host "  App Configuration Policies..." -ForegroundColor Yellow
    $appConfigs = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
    foreach ($policy in $appConfigs) {
        $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
        $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
        if (-not $reason) { continue }
        if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) { continue }
        $info = & $classify $assignments $reason
        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
        $policy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
        [void]$relevantPolicies.AppConfigurationPolicies.Add($policy)
    }

    Write-Host "  Platform Scripts..." -ForegroundColor Yellow
    & $processGeneric "deviceManagementScripts" "PlatformScripts"

    Write-Host "  Proactive Remediation Scripts..." -ForegroundColor Yellow
    & $processGeneric "deviceHealthScripts" "HealthScripts"

    if (-not $deviceOS -or $deviceOS -eq "Windows") {
        Write-Host "  Autopilot Deployment Profiles..." -ForegroundColor Yellow
        & $processGeneric "windowsAutopilotDeploymentProfiles" "DeploymentProfiles" -SkipPlatformCheck

        Write-Host "  Enrollment Status Page Profiles..." -ForegroundColor Yellow
        $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
        $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
        foreach ($esp in $espProfiles) {
            $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
            if (-not $reason) { continue }
            $info = & $classify $assignments $reason
            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
            $esp | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
            [void]$relevantPolicies.ESPProfiles.Add($esp)
        }

        Write-Host "  Cloud PC Provisioning / User Settings..." -ForegroundColor Yellow
        try {
            & $processGeneric "virtualEndpoint/provisioningPolicies" "CloudPCProvisioningPolicies" -SkipPlatformCheck
            & $processGeneric "virtualEndpoint/userSettings" "CloudPCUserSettings" -SkipPlatformCheck
        }
        catch { Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant" }
    }

    # ── App Protection (per-platform endpoints, user-targeted only) ──────────
    Write-Host "  App Protection Policies..." -ForegroundColor Yellow
    $appProt = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
    foreach ($policy in $appProt) {
        if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) { continue }
        $assignmentsUri = switch ($policy.'@odata.type') {
            "#microsoft.graph.androidManagedAppProtection" { "$script:GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
            "#microsoft.graph.iosManagedAppProtection"     { "$script:GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
            "#microsoft.graph.windowsManagedAppProtection" { "$script:GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
            default { $null }
        }
        if (-not $assignmentsUri) { continue }
        try {
            $resp = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
            $assignmentList = foreach ($a in $resp.value) {
                [PSCustomObject]@{
                    Reason  = switch ($a.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.groupAssignmentTarget'           { "Group Assignment" }
                        '#microsoft.graph.exclusionGroupAssignmentTarget'  { "Group Exclusion" }
                        default { "Unknown" }
                    }
                    GroupId = if ($a.target.'@odata.type' -match "groupAssignmentTarget") { $a.target.groupId } else { $null }
                }
            }
            $reason = Resolve-AssignmentReason -Assignments $assignmentList -GroupMembershipIds $combinedGroupIds -IncludeReasons $includeReasons
            if (-not $reason) { continue }
            $info = & $classify $assignmentList $reason
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $info.Reason -Force
            $policy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $info.Source -Force
            [void]$relevantPolicies.AppProtectionPolicies.Add($policy)
        }
        catch {
            Write-Host "Error fetching assignments for App Protection $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ── Endpoint Security categories (templated) ─────────────────────────────
    $esFamilies = @(
        @{ Family = 'endpointSecurityAntivirus';                    Bucket = 'AntivirusProfiles'         }
        @{ Family = 'endpointSecurityDiskEncryption';               Bucket = 'DiskEncryptionProfiles'    }
        @{ Family = 'endpointSecurityFirewall';                     Bucket = 'FirewallProfiles'          }
        @{ Family = 'endpointSecurityEndpointDetectionAndResponse'; Bucket = 'EndpointDetectionProfiles' }
        @{ Family = 'endpointSecurityAttackSurfaceReduction';       Bucket = 'AttackSurfaceProfiles'     }
        @{ Family = 'endpointSecurityAccountProtection';            Bucket = 'AccountProtectionProfiles' }
    )
    foreach ($f in $esFamilies) {
        Write-Host "  Endpoint Security: $($f.Family)..." -ForegroundColor Yellow
        $processed = [System.Collections.Generic.HashSet[string]]::new()
        & $processIntent $f.Family $f.Bucket $processed
    }

    # ── Applications ─────────────────────────────────────────────────────────
    Write-Host "  Applications..." -ForegroundColor Yellow
    $appUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
    $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
    $allApps = $appResponse.value
    while ($appResponse.'@odata.nextLink') {
        $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
        $allApps += $appResponse.value
    }

    foreach ($app in $allApps) {
        if ($app.isFeatured -or $app.isBuiltIn) { continue }
        if (-not (Test-AppPlatformCompatibility -DeviceOS $deviceOS -App $app)) { continue }

        try {
            $assignmentsUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps('$($app.id)')/assignments"
            $resp = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            # Single pass: capture exclusion membership, the winning include, and the intent.
            # We need the intent from an inclusion to know which app bucket to route into,
            # even when an exclusion ultimately wins.
            $isExcluded = $false
            $excludingTarget = $null
            $winningIncludeTarget = $null
            $winningIncludeReason = $null
            $winningIncludeGroupId = $null
            $intent = $null

            foreach ($a in $resp.value) {
                $t = $a.target.'@odata.type'
                $g = $a.target.groupId

                if ($t -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $combinedGroupIds -contains $g) {
                    if (-not $isExcluded) { $excludingTarget = $a.target }
                    $isExcluded = $true
                    continue
                }

                # Inclusion paths
                $isIncludeMatch = $false
                $matchReason = $null
                if ($t -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                    $isIncludeMatch = $true; $matchReason = "All Users"
                }
                elseif ($t -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                    $isIncludeMatch = $true; $matchReason = "All Devices"
                }
                elseif ($t -eq '#microsoft.graph.groupAssignmentTarget' -and $combinedGroupIds -contains $g) {
                    $isIncludeMatch = $true; $matchReason = "Group Assignment"
                }

                if ($isIncludeMatch) {
                    if (-not $intent) { $intent = $a.intent }
                    if (-not $winningIncludeTarget) {
                        $winningIncludeTarget  = $a.target
                        $winningIncludeReason  = $matchReason
                        $winningIncludeGroupId = if ($matchReason -eq "Group Assignment") { $g } else { $null }
                    }
                }
            }

            # If neither an exclusion nor an inclusion applies, skip this app entirely.
            if (-not $isExcluded -and -not $winningIncludeTarget) { continue }
            # If exclusion applies but no inclusion would have matched, the exclusion is irrelevant.
            if ($isExcluded -and -not $winningIncludeTarget) { continue }

            if ($isExcluded) {
                $suffix = Format-AssignmentFilter -FilterId $excludingTarget.deviceAndAppManagementAssignmentFilterId -FilterType $excludingTarget.deviceAndAppManagementAssignmentFilterType
                $appCopy = $app.PSObject.Copy()
                $appCopy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                $appCopy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue 'Excluded' -Force
                $appCopy | Add-Member -NotePropertyName 'AssignmentIntent' -NotePropertyValue $intent -Force
            }
            else {
                $suffix = Format-AssignmentFilter -FilterId $winningIncludeTarget.deviceAndAppManagementAssignmentFilterId -FilterType $winningIncludeTarget.deviceAndAppManagementAssignmentFilterType
                $source = if ($winningIncludeReason -eq "All Users") { 'All Users' }
                          elseif ($winningIncludeReason -eq "All Devices") { 'All Devices' }
                          else {
                              $inUser   = $userGroupIds   -contains $winningIncludeGroupId
                              $inDevice = $deviceGroupIds -contains $winningIncludeGroupId
                              if ($inUser -and $inDevice) { 'User+Device group' }
                              elseif ($inUser)            { 'User group' }
                              elseif ($inDevice)          { 'Device group' }
                              else                        { 'Group' }
                          }
                $appCopy = $app.PSObject.Copy()
                $appCopy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$winningIncludeReason$suffix" -Force
                $appCopy | Add-Member -NotePropertyName 'Source'           -NotePropertyValue $source -Force
                $appCopy | Add-Member -NotePropertyName 'AssignmentIntent' -NotePropertyValue $intent -Force
            }

            switch ($intent) {
                "required"  { [void]$relevantPolicies.AppsRequired.Add($appCopy) }
                "available" { [void]$relevantPolicies.AppsAvailable.Add($appCopy) }
                "uninstall" { [void]$relevantPolicies.AppsUninstall.Add($appCopy) }
            }
        }
        catch {
            Write-Host "Error fetching assignments for app $($app.displayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ── Apply scope tag filter ───────────────────────────────────────────────
    if ($ScopeTagFilter) {
        foreach ($key in @($relevantPolicies.Keys)) {
            $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # ── Display ──────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow
    Write-Host "  WHAT-IF: User on Device - Effective Policies" -ForegroundColor Yellow
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow
    Write-Host "  User:   $upn" -ForegroundColor White
    Write-Host "  Device: $($deviceInfo.DisplayName) (OS: $deviceOS)" -ForegroundColor White
    Write-Host "  Note:   Assignment filter rules are listed but not evaluated against device properties." -ForegroundColor DarkGray
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow

    $categoryDisplay = [ordered]@{
        DeviceConfigs               = "Device Configurations"
        SettingsCatalog             = "Settings Catalog Policies"
        CompliancePolicies          = "Compliance Policies"
        AppProtectionPolicies       = "App Protection Policies"
        AppConfigurationPolicies    = "App Configuration Policies"
        AppsRequired                = "Required Apps"
        AppsAvailable               = "Available Apps"
        AppsUninstall               = "Uninstall Apps"
        PlatformScripts             = "Platform Scripts"
        HealthScripts               = "Proactive Remediation Scripts"
        AntivirusProfiles           = "Endpoint Security - Antivirus"
        DiskEncryptionProfiles      = "Endpoint Security - Disk Encryption"
        FirewallProfiles            = "Endpoint Security - Firewall"
        EndpointDetectionProfiles   = "Endpoint Security - EDR"
        AttackSurfaceProfiles       = "Endpoint Security - ASR"
        AccountProtectionProfiles   = "Endpoint Security - Account Protection"
        DeploymentProfiles          = "Autopilot Deployment Profiles"
        ESPProfiles                 = "Enrollment Status Page Profiles"
        CloudPCProvisioningPolicies = "Cloud PC Provisioning"
        CloudPCUserSettings         = "Cloud PC User Settings"
    }

    $totalEffective = 0
    foreach ($key in $categoryDisplay.Keys) {
        $items = $relevantPolicies[$key]
        if ($items.Count -eq 0) { continue }
        $totalEffective += $items.Count
        Write-Host "`n------- $($categoryDisplay[$key]) ($($items.Count)) -------" -ForegroundColor Cyan
        $headerFormat = "{0,-45} {1,-22} {2,-30} {3,-20}" -f "Name", "Source", "Reason", "ID"
        $sep = Get-Separator
        Write-Host $sep
        Write-Host $headerFormat -ForegroundColor Yellow
        Write-Host $sep

        foreach ($item in $items) {
            $name = if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } else { $item.name }
            if (-not $name) { $name = "Unnamed" }
            if ($name.Length -gt 42) { $name = $name.Substring(0, 39) + "..." }

            $src = if ($item.Source) { $item.Source } else { "-" }
            if ($src.Length -gt 19) { $src = $src.Substring(0, 16) + "..." }

            $reason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "-" }
            if ($reason.Length -gt 27) { $reason = $reason.Substring(0, 24) + "..." }

            $id = if ($item.id) { $item.id } else { "-" }
            if ($id.Length -gt 17) { $id = $id.Substring(0, 14) + "..." }

            $color = if ($src -eq 'Excluded') { 'Red' } else { 'White' }
            Write-Host ("{0,-45} {1,-22} {2,-30} {3,-20}" -f $name, $src, $reason, $id) -ForegroundColor $color
        }
        Write-Host $sep
    }

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    if ($totalEffective -eq 0) {
        Write-Host "  No effective policies or apps for this user/device combination." -ForegroundColor Yellow
    }
    else {
        Write-Host "  $totalEffective effective policy/app assignments found across $((($categoryDisplay.Keys | Where-Object { $relevantPolicies[$_].Count -gt 0 })).Count) categories." -ForegroundColor Green
    }

    # ── Export ───────────────────────────────────────────────────────────────
    $exportData = [System.Collections.ArrayList]::new()
    $null = $exportData.Add([PSCustomObject]@{
        Category         = "What-If Subject"
        Item             = "User: $upn + Device: $($deviceInfo.DisplayName) (ID: $($deviceInfo.Id), OS: $deviceOS)"
        ScopeTags        = ""
        AssignmentReason = "Effective Policy Preview"
    })

    Add-ExportData -ExportData $exportData -Category "Device Configuration"                  -Items $relevantPolicies.DeviceConfigs               -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy"               -Items $relevantPolicies.SettingsCatalog             -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Compliance Policy"                     -Items $relevantPolicies.CompliancePolicies          -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "App Protection Policy"                 -Items $relevantPolicies.AppProtectionPolicies       -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "App Configuration Policy"              -Items $relevantPolicies.AppConfigurationPolicies    -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Required App"                          -Items $relevantPolicies.AppsRequired                -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Available App"                         -Items $relevantPolicies.AppsAvailable               -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Uninstall App"                         -Items $relevantPolicies.AppsUninstall               -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Platform Script"                       -Items $relevantPolicies.PlatformScripts             -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Script"          -Items $relevantPolicies.HealthScripts               -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus"         -Items $relevantPolicies.AntivirusProfiles           -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption"   -Items $relevantPolicies.DiskEncryptionProfiles      -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall"          -Items $relevantPolicies.FirewallProfiles            -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR"               -Items $relevantPolicies.EndpointDetectionProfiles   -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR"               -Items $relevantPolicies.AttackSurfaceProfiles       -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items $relevantPolicies.AccountProtectionProfiles  -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile"          -Items $relevantPolicies.DeploymentProfiles          -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page Profile"        -Items $relevantPolicies.ESPProfiles                 -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Cloud PC Provisioning Policy"          -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }
    Add-ExportData -ExportData $exportData -Category "Cloud PC User Setting"                 -Items $relevantPolicies.CloudPCUserSettings         -AssignmentReason { param($i) "$($i.Source) | $($i.AssignmentReason)" }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUserDeviceAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
