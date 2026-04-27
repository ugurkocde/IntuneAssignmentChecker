function Get-IntuneAllDevicesAssignment {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching all 'All Devices' assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Initialize collections for policies with "All Devices" assignments
    $allDevicesAssignments = @{
        DeviceConfigs             = @()
        SettingsCatalog           = @()
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
        EndpointDetectionProfiles    = @()
        AttackSurfaceProfiles        = @()
        AccountProtectionProfiles    = @()
    }

    # Get Device Configurations
    Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
    $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
    foreach ($config in $deviceConfigs) {
        $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allDevicesAssignments.DeviceConfigs += $config
        }
    }

    # Get Settings Catalog Policies
    Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
    $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
    foreach ($policy in $settingsCatalog) {
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allDevicesAssignments.SettingsCatalog += $policy
        }
    }

    # Get Compliance Policies
    Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
    $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    foreach ($policy in $compliancePolicies) {
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
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
                $allDevicesTarget = $null
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        $allDevicesTarget = $assignment.target
                        break
                    }
                }
                if ($allDevicesTarget) {
                    $suffix = Format-AssignmentFilter -FilterId $allDevicesTarget.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$suffix" -Force
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
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
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
                $suffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$suffix" -Force
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
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allDevicesAssignments.PlatformScripts += $script
        }
    }

    # Get Proactive Remediation Scripts
    Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
    $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
    foreach ($script in $healthScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allDevicesAssignments.HealthScripts += $script
        }
    }

    # Get Autopilot Deployment Profiles
    Write-Host "Fetching Autopilot Deployment Profiles assigned to All Devices..." -ForegroundColor Yellow
    $autoProfilesAD = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    foreach ($policyProfile in $autoProfilesAD) {
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policyProfile.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $policyProfile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allDevicesAssignments.DeploymentProfiles += $policyProfile
        }
    }

    # Get Enrollment Status Page Profiles
    Write-Host "Fetching Enrollment Status Page Profiles assigned to All Devices..." -ForegroundColor Yellow
    $enrollmentConfigsAD = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $espProfilesAD = $enrollmentConfigsAD | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    foreach ($esp in $espProfilesAD) {
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
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
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$antivirusPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for Antivirus
    $allIntentsForAntivirus_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirus_AllDevices
    $matchingIntentsAntivirus_AllDevices = $allIntentsForAntivirus_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
    if ($matchingIntentsAntivirus_AllDevices) {
        foreach ($policy in $matchingIntentsAntivirus_AllDevices) {
            if ($processedAntivirusIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
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
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$diskEncryptionPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for Disk Encryption
    $allIntentsForDiskEnc_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEnc_AllDevices
    $matchingIntentsDiskEnc_AllDevices = $allIntentsForDiskEnc_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
    if ($matchingIntentsDiskEnc_AllDevices) {
        foreach ($policy in $matchingIntentsDiskEnc_AllDevices) {
            if ($processedDiskEncryptionIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
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
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$firewallPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for Firewall
    $allIntentsForFirewall_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewall_AllDevices
    $matchingIntentsFirewall_AllDevices = $allIntentsForFirewall_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
    if ($matchingIntentsFirewall_AllDevices) {
        foreach ($policy in $matchingIntentsFirewall_AllDevices) {
            if ($processedFirewallIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
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
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$edrPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for EDR
    $allIntentsForEDR_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDR_AllDevices
    $matchingIntentsEDR_AllDevices = $allIntentsForEDR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
    if ($matchingIntentsEDR_AllDevices) {
        foreach ($policy in $matchingIntentsEDR_AllDevices) {
            if ($processedEDRIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
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
    $matchingConfigPoliciesASR_AllDevices = $configPoliciesForASR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
    if ($matchingConfigPoliciesASR_AllDevices) {
        foreach ($policy in $matchingConfigPoliciesASR_AllDevices) {
            if ($processedASRIds_AllDevices.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$asrPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for ASR
    $allIntentsForASR_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASR_AllDevices
    $matchingIntentsASR_AllDevices = $allIntentsForASR_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
    if ($matchingIntentsASR_AllDevices) {
        foreach ($policy in $matchingIntentsASR_AllDevices) {
            if ($processedASRIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
                    [void]$asrPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }
    $allDevicesAssignments.AttackSurfaceProfiles = $asrPoliciesFound_AllDevices

    # Get Endpoint Security - Account Protection Policies (Dual Check)
    Write-Host "Fetching Account Protection Policies assigned to All Devices..." -ForegroundColor Yellow
    $accountProtectionPoliciesFound_AllDevices = [System.Collections.ArrayList]::new()
    $processedAccountProtectionIds_AllDevices = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies for Account Protection
    $configPoliciesForAccountProtection_AllDevices = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesAccountProtection_AllDevices = $configPoliciesForAccountProtection_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
    if ($matchingConfigPoliciesAccountProtection_AllDevices) {
        foreach ($policy in $matchingConfigPoliciesAccountProtection_AllDevices) {
            if ($processedAccountProtectionIds_AllDevices.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Devices")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$accountProtectionPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents for Account Protection
    $allIntentsForAccountProtection_AllDevices = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtection_AllDevices
    $matchingIntentsAccountProtection_AllDevices = $allIntentsForAccountProtection_AllDevices | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
    if ($matchingIntentsAccountProtection_AllDevices) {
        foreach ($policy in $matchingIntentsAccountProtection_AllDevices) {
            if ($processedAccountProtectionIds_AllDevices.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allDevicesTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } | Select-Object -First 1
                if ($allDevicesTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$intentSuffix" -Force
                    [void]$accountProtectionPoliciesFound_AllDevices.Add($policy)
                }
            }
        }
    }
    $allDevicesAssignments.AccountProtectionProfiles = $accountProtectionPoliciesFound_AllDevices

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allDevicesAssignments.Keys)) {
            $allDevicesAssignments[$key] = @(Filter-ByScopeTag -Items $allDevicesAssignments[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
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
        foreach ($policyProfile in $allDevicesAssignments.AntivirusProfiles) {
            Write-Host "Antivirus Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Endpoint Security - Disk Encryption Profiles
    Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.DiskEncryptionProfiles.Count -eq 0) {
        Write-Host "No Disk Encryption Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.DiskEncryptionProfiles) {
            Write-Host "Disk Encryption Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Endpoint Security - Firewall Profiles
    Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.FirewallProfiles.Count -eq 0) {
        Write-Host "No Firewall Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.FirewallProfiles) {
            Write-Host "Firewall Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Endpoint Security - Endpoint Detection and Response Profiles
    Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.EndpointDetectionProfiles.Count -eq 0) {
        Write-Host "No EDR Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.EndpointDetectionProfiles) {
            $profileNameForDisplay = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed EDR Profile" }
            Write-Host "EDR Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Endpoint Security - Attack Surface Reduction Profiles
    Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.AttackSurfaceProfiles.Count -eq 0) {
        Write-Host "No ASR Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.AttackSurfaceProfiles) {
            Write-Host "ASR Profile Name: $($policyProfile.displayName), Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Endpoint Security - Account Protection Profiles
    Write-Host "`n------- Endpoint Security - Account Protection Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.AccountProtectionProfiles.Count -eq 0) {
        Write-Host "No Account Protection Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.AccountProtectionProfiles) {
            $profileNameForDisplay = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Account Protection Profile" }
            Write-Host "Account Protection Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Autopilot Deployment Profiles
    Write-Host "`n------- Autopilot Deployment Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.DeploymentProfiles.Count -eq 0) {
        Write-Host "No Autopilot Deployment Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.DeploymentProfiles) {
            $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.name } else { $policyProfile.displayName }
            Write-Host "Deployment Profile Name: $profileName, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Display Enrollment Status Page Profiles
    Write-Host "`n------- Enrollment Status Page Profiles -------" -ForegroundColor Cyan
    if ($allDevicesAssignments.ESPProfiles.Count -eq 0) {
        Write-Host "No Enrollment Status Page Profiles assigned to All Devices" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allDevicesAssignments.ESPProfiles) {
            $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.name } else { $policyProfile.displayName }
            Write-Host "Enrollment Status Page Name: $profileName, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items @($policyProfile) -AssignmentReason "All Devices"
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllDevicesAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
