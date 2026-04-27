function Get-IntuneDeviceAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DeviceNames,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter
    )

    Write-Host "Device selection chosen" -ForegroundColor Green

    # Get Device names from parameter or prompt
    if ($DeviceNames) {
        $deviceInput = $DeviceNames
    }
    else {
        # Prompt for one or more Device Names
        Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
        $deviceInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($deviceInput)) {
        Write-Host "No device name provided. Please try again." -ForegroundColor Red
        return
    }

    $deviceNames = $deviceInput -split ',' | ForEach-Object { $_.Trim() }
    $exportData = [System.Collections.ArrayList]::new()

    foreach ($deviceName in $deviceNames) {
        Write-Host "`nProcessing device: $deviceName" -ForegroundColor Yellow

        # Check if input is a GUID (Object ID)
        $deviceInfo = $null
        if ($deviceName -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            try {
                $selectProps = "id,displayName,operatingSystem,operatingSystemVersion,managementType,deviceOwnership,trustType,isCompliant,isManaged,approximateLastSignInDateTime,manufacturer,model,enrollmentProfileName"
                $directDevice = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/devices/$($deviceName)?`$select=$selectProps" -Method Get
                $deviceInfo = @{
                    Id              = $directDevice.id
                    DisplayName     = $directDevice.displayName
                    OperatingSystem = $directDevice.operatingSystem
                    Success         = $true
                    MultipleFound   = $false
                    AllDevices      = $null
                }
            }
            catch {
                Write-Host "No device found with Object ID: $deviceName" -ForegroundColor Red
                continue
            }
        }
        else {
            # Get Device Info by display name
            $deviceInfo = Get-DeviceInfo -DeviceName $deviceName
        }

        # Handle multiple devices found
        if ($deviceInfo.MultipleFound) {
            if ($DeviceNames) {
                Write-Host "Multiple devices found with name '$deviceName'. Please use the Object ID instead:" -ForegroundColor Red
                foreach ($d in $deviceInfo.AllDevices) {
                    $lastSignIn = if ($d.approximateLastSignInDateTime) { ([datetime]$d.approximateLastSignInDateTime).ToString("yyyy-MM-dd") } else { "N/A" }
                    Write-Host "  - $($d.displayName) | OS: $($d.operatingSystem) $($d.operatingSystemVersion) | Trust: $($d.trustType) | Ownership: $($d.deviceOwnership) | Last sign-in: $lastSignIn | ID: $($d.id)" -ForegroundColor Yellow
                }
                continue
            }

            Write-Host "`nMultiple devices found with name '$deviceName':" -ForegroundColor Yellow
            Write-Host ""
            for ($i = 0; $i -lt $deviceInfo.AllDevices.Count; $i++) {
                $d = $deviceInfo.AllDevices[$i]
                $lastSignIn = if ($d.approximateLastSignInDateTime) { ([datetime]$d.approximateLastSignInDateTime).ToString("yyyy-MM-dd") } else { "N/A" }
                $managedStatus = if ($d.isManaged) { "Managed" } else { "Not managed" }
                $compliantStatus = if ($d.isCompliant) { "Compliant" } else { "Not compliant" }
                Write-Host "  [$($i + 1)] $($d.displayName)" -ForegroundColor Cyan
                Write-Host "      OS: $($d.operatingSystem) $($d.operatingSystemVersion) | Trust: $($d.trustType) | Ownership: $($d.deviceOwnership)" -ForegroundColor Gray
                Write-Host "      $managedStatus | $compliantStatus | Last sign-in: $lastSignIn" -ForegroundColor Gray
                Write-Host "      Object ID: $($d.id)" -ForegroundColor Gray
            }
            Write-Host "  [0] Skip this device" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Select a device (1-$($deviceInfo.AllDevices.Count)) or 0 to skip: " -ForegroundColor Cyan -NoNewline
            $selection = Read-Host

            if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $deviceInfo.AllDevices.Count) {
                $selectedDevice = $deviceInfo.AllDevices[[int]$selection - 1]
                $deviceInfo = @{
                    Id              = $selectedDevice.id
                    DisplayName     = $selectedDevice.displayName
                    OperatingSystem = $selectedDevice.operatingSystem
                    Success         = $true
                    MultipleFound   = $false
                    AllDevices      = $null
                }
            }
            else {
                Write-Host "Skipping device: $deviceName" -ForegroundColor Yellow
                continue
            }
        }

        if (-not $deviceInfo.Success) {
            Write-Host "Device not found: $deviceName" -ForegroundColor Red
            Write-Host "Please verify the device name is correct." -ForegroundColor Yellow
            continue
        }

        $deviceOS = $deviceInfo.OperatingSystem
        if ($deviceOS) {
            Write-Host "Device OS: $deviceOS" -ForegroundColor Green
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

        Write-Host "Fetching Intune Profiles and Applications for the device..." -ForegroundColor Yellow

        # Initialize collections for relevant policies
        $relevantPolicies = @{
            DeviceConfigs               = @()
            SettingsCatalog             = @()
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
            AccountProtectionProfiles   = @()
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
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $config)) {
                $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.DeviceConfigs += $config
            }
        }

        # Get Settings Catalog Policies
        Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
        $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
        foreach ($policy in $settingsCatalog) {
            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.SettingsCatalog += $policy
            }
        }

        # Get Compliance Policies
        Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
        $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
        foreach ($policy in $compliancePolicies) {
            $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.CompliancePolicies += $policy
            }
        }

        # Get App Protection Policies
        Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
        $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
        foreach ($policy in $appProtectionPolicies) {
            if (-not (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                continue
            }
            $policyType = $policy.'@odata.type'
            $assignmentsUri = switch ($policyType) {
                "#microsoft.graph.androidManagedAppProtection" { "$script:GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
                "#microsoft.graph.iosManagedAppProtection" { "$script:GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
                "#microsoft.graph.windowsManagedAppProtection" { "$script:GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
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
                            $rawFilterId   = $assignment.target.deviceAndAppManagementAssignmentFilterId
                            $rawFilterType = $assignment.target.deviceAndAppManagementAssignmentFilterType
                            $effFilterId   = $null
                            $effFilterType = $null
                            if ($rawFilterType -and $rawFilterType -ne 'none' -and $rawFilterId -and $rawFilterId -ne '00000000-0000-0000-0000-000000000000') {
                                $effFilterId   = $rawFilterId
                                $effFilterType = $rawFilterType
                            }
                            $assignments += @{
                                Reason     = $assignmentReason
                                GroupId    = $assignment.target.groupId
                                FilterId   = $effFilterId
                                FilterType = $effFilterType
                            }
                        }
                    }

                    if ($assignments.Count -gt 0) {
                        $assignmentSummary = $assignments | Where-Object { $_.Reason -ne "All Users" } | ForEach-Object {
                            Format-AssignmentSummaryLine -Assignment ([PSCustomObject]$_)
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
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.AppConfigurationPolicies += $policy
            }
        }

        # Get Platform Scripts
        Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
        $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
        foreach ($script in $platformScripts) {
            $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $script)) {
                $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.PlatformScripts += $script
            }
        }

        # Get Proactive Remediation Scripts
        Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
        $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
        foreach ($script in $healthScripts) {
            $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $script)) {
                $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.HealthScripts += $script
            }
        }

        # Get Autopilot Deployment Profiles (Windows-only)
        if (-not $deviceOS -or $deviceOS -eq "Windows") {
            Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
            $autoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
            foreach ($policyProfile in $autoProfiles) {
                $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policyProfile.id
                foreach ($assignment in $assignments) {
                    if (($assignment.Reason -eq "All Devices") -or
                        ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $policyProfile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                        $relevantPolicies.DeploymentProfiles += $policyProfile
                        break
                    }
                    elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $policyProfile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                        $relevantPolicies.DeploymentProfiles += $policyProfile
                        break
                    }
                }
            }
        }

        # Get Enrollment Status Page Profiles (Windows-only)
        if (-not $deviceOS -or $deviceOS -eq "Windows") {
            Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
            $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
            $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
            foreach ($esp in $espProfiles) {
                $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
                foreach ($assignment in $assignments) {
                    if (($assignment.Reason -eq "All Devices") -or
                        ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                        $relevantPolicies.ESPProfiles += $esp
                        break
                    }
                    elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                        $relevantPolicies.ESPProfiles += $esp
                        break
                    }
                }
            }
        }

        # Get Windows 365 Cloud PC Provisioning Policies (Windows-only)
        if (-not $deviceOS -or $deviceOS -eq "Windows") {
            Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
            try {
                $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
                foreach ($policy in $cloudPCProvisioningPolicies) {
                    $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
                    foreach ($assignment in $assignments) {
                        if (($assignment.Reason -eq "All Devices") -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                            $relevantPolicies.CloudPCProvisioningPolicies += $policy
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                            $relevantPolicies.CloudPCProvisioningPolicies += $policy
                            break
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant"
            }
        }

        # Get Windows 365 Cloud PC User Settings (Windows-only)
        if (-not $deviceOS -or $deviceOS -eq "Windows") {
            Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
            try {
                $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
                foreach ($setting in $cloudPCUserSettings) {
                    $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
                    foreach ($assignment in $assignments) {
                        if (($assignment.Reason -eq "All Devices") -or
                            ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                            $relevantPolicies.CloudPCUserSettings += $setting
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                            $relevantPolicies.CloudPCUserSettings += $setting
                            break
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant"
            }
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
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$antivirusPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForAntivirusDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirusDevice
        $matchingIntentsAntivirusDevice = $allIntentsForAntivirusDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

        if ($matchingIntentsAntivirusDevice) {
            foreach ($policy in $matchingIntentsAntivirusDevice) {
                if ($processedAntivirusIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$antivirusPoliciesFoundDevice.Add($policy)
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
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForDiskEncDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEncDevice
        $matchingIntentsDiskEncDevice = $allIntentsForDiskEncDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

        if ($matchingIntentsDiskEncDevice) {
            foreach ($policy in $matchingIntentsDiskEncDevice) {
                if ($processedDiskEncryptionIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$diskEncryptionPoliciesFoundDevice.Add($policy)
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
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$firewallPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForFirewallDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewallDevice
        $matchingIntentsFirewallDevice = $allIntentsForFirewallDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

        if ($matchingIntentsFirewallDevice) {
            foreach ($policy in $matchingIntentsFirewallDevice) {
                if ($processedFirewallIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$firewallPoliciesFoundDevice.Add($policy)
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
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$edrPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForEDRDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDRDevice
        $matchingIntentsEDRDevice = $allIntentsForEDRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

        if ($matchingIntentsEDRDevice) {
            foreach ($policy in $matchingIntentsEDRDevice) {
                if ($processedEDRIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$edrPoliciesFoundDevice.Add($policy)
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
        $matchingConfigPoliciesASRDevice = $configPoliciesForASRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

        if ($matchingConfigPoliciesASRDevice) {
            foreach ($policy in $matchingConfigPoliciesASRDevice) {
                if ($processedASRIdsDevice.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$asrPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForASRDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASRDevice
        $matchingIntentsASRDevice = $allIntentsForASRDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

        if ($matchingIntentsASRDevice) {
            foreach ($policy in $matchingIntentsASRDevice) {
                if ($processedASRIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$asrPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.AttackSurfaceProfiles = $asrPoliciesFoundDevice

        # Get Endpoint Security - Account Protection Policies
        Write-Host "Fetching Account Protection Policies" -ForegroundColor Yellow
        $accountProtectionPoliciesFoundDevice = [System.Collections.ArrayList]::new()
        $processedAccountProtectionIdsDevice = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForAccountProtectionDevice = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesAccountProtectionDevice = $configPoliciesForAccountProtectionDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

        if ($matchingConfigPoliciesAccountProtectionDevice) {
            foreach ($policy in $matchingConfigPoliciesAccountProtectionDevice) {
                if ($processedAccountProtectionIdsDevice.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$accountProtectionPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForAccountProtectionDevice = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtectionDevice
        $matchingIntentsAccountProtectionDevice = $allIntentsForAccountProtectionDevice | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

        if ($matchingIntentsAccountProtectionDevice) {
            foreach ($policy in $matchingIntentsAccountProtectionDevice) {
                if ($processedAccountProtectionIdsDevice.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allDevicesAssignmentTarget'     { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget'          { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
                    if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $policy)) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$accountProtectionPoliciesFoundDevice.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.AccountProtectionProfiles = $accountProtectionPoliciesFoundDevice

        # Get Applications
        Write-Host "Fetching Applications..." -ForegroundColor Yellow
        # Fetch Applications
        $appUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
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

            if (-not (Test-AppPlatformCompatibility -DeviceOS $deviceOS -App $app)) {
                continue
            }

            $appId = $app.id
            $assignmentsUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            $isExcluded = $false
            $isIncluded = $false
            $inclusionReason = ""
            $exclusionReason = ""
            $inclusionAssignment = $null
            $exclusionAssignment = $null

            foreach ($assignment in $assignmentResponse.value) {
                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                    $groupMemberships.id -contains $assignment.target.groupId) {
                    $isExcluded = $true
                    $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                    $exclusionReason = "Excluded via group: $($groupInfo.DisplayName)"
                    $exclusionAssignment = $assignment
                    break
                }
                elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                    if (-not $isIncluded) { $inclusionAssignment = $assignment }
                    $isIncluded = $true
                    $inclusionReason = "All Devices"
                }
                elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                    $groupMemberships.id -contains $assignment.target.groupId) {
                    if (-not $isIncluded) { $inclusionAssignment = $assignment }
                    $isIncluded = $true
                    $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                    $inclusionReason = "Group Assignment - $($groupInfo.DisplayName)"
                }
            }

            if ($isExcluded) {
                $suffix = Format-AssignmentFilter `
                    -FilterId   $exclusionAssignment.target.deviceAndAppManagementAssignmentFilterId `
                    -FilterType $exclusionAssignment.target.deviceAndAppManagementAssignmentFilterType
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$exclusionReason$suffix" -Force
                switch ($assignment.intent) {
                    "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                    "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                    "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                }
            }
            elseif ($isIncluded) {
                $suffix = ''
                if ($inclusionAssignment) {
                    $suffix = Format-AssignmentFilter `
                        -FilterId   $inclusionAssignment.target.deviceAndAppManagementAssignmentFilterId `
                        -FilterType $inclusionAssignment.target.deviceAndAppManagementAssignmentFilterType
                }
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$inclusionReason$suffix" -Force
                switch ($assignment.intent) {
                    "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                    "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                    "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                }
            }
        }

        # Apply scope tag filter if specified
        if ($ScopeTagFilter) {
            foreach ($key in @($relevantPolicies.Keys)) {
                $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
            }
        }

        # Display results
        Write-Host "`nAssignments for Device: $deviceName" -ForegroundColor Green

        # Function to format and display policy table
        function Format-PolicyTable {
            param (
                [string]$Title,
                [object[]]$Policies,
                [scriptblock]$GetName
            )
            $tableSeparator = Get-Separator

            # Create prominent section header
            $headerSeparator = "-" * ($Title.Length + 16)
            Write-Host "`n$headerSeparator" -ForegroundColor Cyan
            Write-Host "------- $Title -------" -ForegroundColor Cyan
            Write-Host "$headerSeparator" -ForegroundColor Cyan

            if ($Policies.Count -eq 0) {
                Write-Host "No $Title found for this device." -ForegroundColor Gray
                Write-Host $tableSeparator -ForegroundColor Gray
                Write-Host ""
                return
            }

            # Create table header
            $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-30}" -f "Policy Name", "Scope Tags", "ID", "Assignment"

            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $tableSeparator -ForegroundColor Gray

            # Display each policy in table format
            foreach ($policy in $Policies) {
                $name = & $GetName $policy

                if ($name.Length -gt 42) {
                    $name = $name.Substring(0, 39) + "..."
                }

                $scopeTags = Get-ScopeTagNames -ScopeTagIds $policy.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
                if ($scopeTags.Length -gt 17) { $scopeTags = $scopeTags.Substring(0, 14) + "..." }

                $id = $policy.id
                if ($id.Length -gt 32) {
                    $id = $id.Substring(0, 29) + "..."
                }

                $assignment = if ($policy.AssignmentReason) { $policy.AssignmentReason } else { "No Assignment" }
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-30}" -f $name, $scopeTags, $id, $assignment
                if ($assignment -like "Excluded*" -or $assignment -like "*Exclusion*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }

            Write-Host $tableSeparator -ForegroundColor Gray
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
            param($policyProfile)
            if ([string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.name } else { $policyProfile.displayName }
        }

        # Display Enrollment Status Page Profiles
        Format-PolicyTable -Title "Enrollment Status Page Profiles" -Policies $relevantPolicies.ESPProfiles -GetName {
            param($esp)
            if ([string]::IsNullOrWhiteSpace($esp.displayName)) { $esp.name } else { $esp.displayName }
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
        Format-PolicyTable -Title "Endpoint Security - Antivirus Profiles" -Policies $relevantPolicies.AntivirusProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Display Endpoint Security - Disk Encryption Profiles
        Format-PolicyTable -Title "Endpoint Security - Disk Encryption Profiles" -Policies $relevantPolicies.DiskEncryptionProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Display Endpoint Security - Firewall Profiles
        Format-PolicyTable -Title "Endpoint Security - Firewall Profiles" -Policies $relevantPolicies.FirewallProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Display Endpoint Security - Endpoint Detection and Response Profiles
        Format-PolicyTable -Title "Endpoint Security - EDR Profiles" -Policies $relevantPolicies.EndpointDetectionProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Display Endpoint Security - Attack Surface Reduction Profiles
        Format-PolicyTable -Title "Endpoint Security - ASR Profiles" -Policies $relevantPolicies.AttackSurfaceProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Display Endpoint Security - Account Protection Profiles
        Format-PolicyTable -Title "Endpoint Security - Account Protection Profiles" -Policies $relevantPolicies.AccountProtectionProfiles -GetName { param($policyProfile) if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" } }

        # Add to export data
        Add-ExportData -ExportData $exportData -Category "Device" -Items @([PSCustomObject]@{
                displayName      = $deviceName
                id               = $deviceInfo.Id
                AssignmentReason = "N/A"
            }

            Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $relevantPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $relevantPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $relevantPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $relevantPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
            Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $relevantPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $relevantPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $relevantPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items $relevantPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items $relevantPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $relevantPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $relevantPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $relevantPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $relevantPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $relevantPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items $relevantPolicies.AccountProtectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $relevantPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Required Apps" -Items $relevantPolicies.AppsRequired -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Available Apps" -Items $relevantPolicies.AppsAvailable -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Uninstall Apps" -Items $relevantPolicies.AppsUninstall -AssignmentReason { param($item) $item.AssignmentReason }
        )
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneDeviceAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
