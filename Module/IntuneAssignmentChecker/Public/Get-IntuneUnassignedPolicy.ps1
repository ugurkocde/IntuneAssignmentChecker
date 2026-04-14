function Get-IntuneUnassignedPolicy {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching policies without assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Initialize collections for policies without assignments
    $unassignedPolicies = @{
        DeviceConfigs            = @()
        SettingsCatalog          = @()
        CompliancePolicies       = @()
        AppProtectionPolicies    = @()
        AppConfigurationPolicies = @()
        PlatformScripts          = @()
        HealthScripts            = @()
        Apps                     = @()
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
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirusUnassigned
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
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEncUnassigned
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
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewallUnassigned
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
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDRUnassigned
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
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASRUnassigned
    $asrPolicies = $allIntentsForASRUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
    if ($asrPolicies) {
        foreach ($policy in $asrPolicies) {
            $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
            if ($assignments.value.Count -eq 0) {
                $unassignedPolicies.AttackSurfaceProfiles += $policy
            }
        }
    }

    # Get Endpoint Security - Account Protection Policies
    Write-Host "Fetching Account Protection Policies..." -ForegroundColor Yellow
    $allIntentsForAccountProtectionUnassigned = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtectionUnassigned
    $accountProtectionPolicies = $allIntentsForAccountProtectionUnassigned | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
    if ($accountProtectionPolicies) {
        foreach ($policy in $accountProtectionPolicies) {
            $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
            if ($assignments.value.Count -eq 0) {
                $unassignedPolicies.AccountProtectionProfiles += $policy
            }
        }
    }

    # Get Unassigned Apps
    Write-Host "Fetching Unassigned Apps..." -ForegroundColor Yellow
    $unassignedAppUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq false"
    $unassignedAppResponse = Invoke-MgGraphRequest -Uri $unassignedAppUri -Method Get
    $unassignedApps = $unassignedAppResponse.value
    while ($unassignedAppResponse.'@odata.nextLink') {
        $unassignedAppResponse = Invoke-MgGraphRequest -Uri $unassignedAppResponse.'@odata.nextLink' -Method Get
        $unassignedApps += $unassignedAppResponse.value
    }
    $unassignedApps = $unassignedApps | Where-Object { -not $_.isFeatured -and -not $_.isBuiltIn }
    $unassignedPolicies.Apps = $unassignedApps

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($unassignedPolicies.Keys)) {
            $unassignedPolicies[$key] = @(Filter-ByScopeTag -Items $unassignedPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # Display results
    Write-Host "`nPolicies and Apps Without Assignments:" -ForegroundColor Green

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
        foreach ($policyProfile in $unassignedPolicies.AntivirusProfiles) {
            Write-Host "Antivirus Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Endpoint Security - Disk Encryption Profiles
    Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
    if ($unassignedPolicies.DiskEncryptionProfiles.Count -eq 0) {
        Write-Host "No unassigned Disk Encryption Profiles found" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $unassignedPolicies.DiskEncryptionProfiles) {
            Write-Host "Disk Encryption Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Endpoint Security - Firewall Profiles
    Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
    if ($unassignedPolicies.FirewallProfiles.Count -eq 0) {
        Write-Host "No unassigned Firewall Profiles found" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $unassignedPolicies.FirewallProfiles) {
            Write-Host "Firewall Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Endpoint Security - Endpoint Detection and Response Profiles
    Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
    if ($unassignedPolicies.EndpointDetectionProfiles.Count -eq 0) {
        Write-Host "No unassigned EDR Profiles found" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $unassignedPolicies.EndpointDetectionProfiles) {
            Write-Host "EDR Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Endpoint Security - Attack Surface Reduction Profiles
    Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
    if ($unassignedPolicies.AttackSurfaceProfiles.Count -eq 0) {
        Write-Host "No unassigned ASR Profiles found" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $unassignedPolicies.AttackSurfaceProfiles) {
            Write-Host "ASR Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Endpoint Security - Account Protection Profiles
    Write-Host "`n------- Endpoint Security - Account Protection Profiles -------" -ForegroundColor Cyan
    if ($unassignedPolicies.AccountProtectionProfiles.Count -eq 0) {
        Write-Host "No unassigned Account Protection Profiles found" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $unassignedPolicies.AccountProtectionProfiles) {
            Write-Host "Account Protection Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items @($policyProfile) -AssignmentReason "No Assignment"
        }
    }

    # Display Applications
    Write-Host "`n------- Applications -------" -ForegroundColor Cyan
    if ($unassignedPolicies.Apps.Count -eq 0) {
        Write-Host "No unassigned Apps found" -ForegroundColor Gray
    }
    else {
        foreach ($app in $unassignedPolicies.Apps) {
            $appType = if ($app.'@odata.type') { ($app.'@odata.type' -replace '#microsoft\.graph\.', '') } else { "Unknown" }
            Write-Host "App Name: $($app.displayName), Type: $appType, App ID: $($app.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Apps" -Items @($app) -AssignmentReason "No Assignment"
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUnassignedPolicies.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
