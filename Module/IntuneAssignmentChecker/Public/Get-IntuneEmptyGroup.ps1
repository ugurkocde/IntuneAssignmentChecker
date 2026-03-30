function Get-IntuneEmptyGroup {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

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
        DeviceConfigs             = @()
        SettingsCatalog           = @()
        CompliancePolicies        = @()
        AppProtectionPolicies     = @()
        AppConfigurationPolicies  = @()
        PlatformScripts           = @()
        HealthScripts             = @()
        AntivirusProfiles         = @()
        DiskEncryptionProfiles    = @()
        FirewallProfiles          = @()
        EndpointDetectionProfiles = @()
        AttackSurfaceProfiles     = @()
        AccountProtectionProfiles = @()
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
        foreach ($policyProfile in $emptyGroupAssignments.AntivirusProfiles) {
            Write-Host "Antivirus Profile Name: $($policyProfile.displayName)" -ForegroundColor White
            Write-Host "Profile ID: $($policyProfile.id)" -ForegroundColor Gray
            Write-Host "$($policyProfile.EmptyGroupInfo)" -ForegroundColor Yellow
            Write-Host ""
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($policyProfile) -AssignmentReason $policyProfile.EmptyGroupInfo
        }
    }

    # Display Endpoint Security - Disk Encryption Profiles
    Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
    if ($emptyGroupAssignments.DiskEncryptionProfiles.Count -eq 0) {
        Write-Host "No Disk Encryption Profiles assigned to empty groups" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $emptyGroupAssignments.DiskEncryptionProfiles) {
            Write-Host "Disk Encryption Profile Name: $($policyProfile.displayName)" -ForegroundColor White
            Write-Host "Profile ID: $($policyProfile.id)" -ForegroundColor Gray
            Write-Host "$($policyProfile.EmptyGroupInfo)" -ForegroundColor Yellow
            Write-Host ""
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($policyProfile) -AssignmentReason $policyProfile.EmptyGroupInfo
        }
    }

    # Display Endpoint Security - Firewall Profiles
    Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
    if ($emptyGroupAssignments.FirewallProfiles.Count -eq 0) {
        Write-Host "No Firewall Profiles assigned to empty groups" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $emptyGroupAssignments.FirewallProfiles) {
            Write-Host "Firewall Profile Name: $($policyProfile.displayName)" -ForegroundColor White
            Write-Host "Profile ID: $($policyProfile.id)" -ForegroundColor Gray
            Write-Host "$($policyProfile.EmptyGroupInfo)" -ForegroundColor Yellow
            Write-Host ""
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($policyProfile) -AssignmentReason $policyProfile.EmptyGroupInfo
        }
    }

    # Display Endpoint Security - Endpoint Detection and Response Profiles
    Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
    if ($emptyGroupAssignments.EndpointDetectionProfiles.Count -eq 0) {
        Write-Host "No EDR Profiles assigned to empty groups" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $emptyGroupAssignments.EndpointDetectionProfiles) {
            Write-Host "EDR Profile Name: $($policyProfile.displayName)" -ForegroundColor White
            Write-Host "Profile ID: $($policyProfile.id)" -ForegroundColor Gray
            Write-Host "$($policyProfile.EmptyGroupInfo)" -ForegroundColor Yellow
            Write-Host ""
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($policyProfile) -AssignmentReason $policyProfile.EmptyGroupInfo
        }
    }

    # Display Endpoint Security - Attack Surface Reduction Profiles
    Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
    if ($emptyGroupAssignments.AttackSurfaceProfiles.Count -eq 0) {
        Write-Host "No ASR Profiles assigned to empty groups" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $emptyGroupAssignments.AttackSurfaceProfiles) {
            Write-Host "ASR Profile Name: $($policyProfile.displayName)" -ForegroundColor White
            Write-Host "Profile ID: $($policyProfile.id)" -ForegroundColor Gray
            Write-Host "$($policyProfile.EmptyGroupInfo)" -ForegroundColor Yellow
            Write-Host ""
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($policyProfile) -AssignmentReason $policyProfile.EmptyGroupInfo
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneEmptyGroupAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
