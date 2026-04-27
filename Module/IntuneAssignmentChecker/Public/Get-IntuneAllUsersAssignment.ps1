function Get-IntuneAllUsersAssignment {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching all 'All Users' assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Initialize collections for policies with "All Users" assignments
    $allUsersAssignments = @{
        DeviceConfigs            = @()
        SettingsCatalog          = @()
        CompliancePolicies       = @()
        AppProtectionPolicies    = @()
        AppConfigurationPolicies = @()
        PlatformScripts          = @()
        HealthScripts            = @()
        RequiredApps             = @()
        AvailableApps            = @()
        UninstallApps                = @()
        AntivirusProfiles            = @()
        DiskEncryptionProfiles       = @()
        FirewallProfiles             = @()
        EndpointDetectionProfiles    = @()
        AttackSurfaceProfiles        = @()
        AccountProtectionProfiles    = @()
        DeploymentProfiles           = @()
        ESPProfiles                  = @()
    }

    # Get Device Configurations
    Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
    $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
    foreach ($config in $deviceConfigs) {
        $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.DeviceConfigs += $config
        }
    }

    # Get Settings Catalog Policies
    Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
    $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
    foreach ($policy in $settingsCatalog) {
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.SettingsCatalog += $policy
        }
    }

    # Get Compliance Policies
    Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
    $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    foreach ($policy in $compliancePolicies) {
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.CompliancePolicies += $policy
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
                $allUsersTarget = $null
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                        $allUsersTarget = $assignment.target
                        break
                    }
                }
                if ($allUsersTarget) {
                    $suffix = Format-AssignmentFilter -FilterId $allUsersTarget.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$suffix" -Force
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
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.AppConfigurationPolicies += $policy
        }
    }

    # Get Applications
    Write-Host "Fetching Applications..." -ForegroundColor Yellow
    # Fetch Applications
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
            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $suffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$suffix" -Force
                switch ($assignment.intent) {
                    "required" { $allUsersAssignments.RequiredApps += $appWithReason; break }
                    "available" { $allUsersAssignments.AvailableApps += $appWithReason; break }
                    "uninstall" { $allUsersAssignments.UninstallApps += $appWithReason; break }
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
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.PlatformScripts += $script
        }
    }

    # Get Proactive Remediation Scripts
    Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
    $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
    foreach ($script in $healthScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.HealthScripts += $script
        }
    }

    # Get Endpoint Security - Antivirus Policies
    Write-Host "Fetching Antivirus Policies assigned to All Users..." -ForegroundColor Yellow
    $antivirusPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedAntivirusIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForAntivirus_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesAntivirus_AllUsers = $configPoliciesForAntivirus_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

    if ($matchingConfigPoliciesAntivirus_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesAntivirus_AllUsers) {
            if ($processedAntivirusIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$antivirusPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForAntivirus_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirus_AllUsers
    $matchingIntentsAntivirus_AllUsers = $allIntentsForAntivirus_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

    if ($matchingIntentsAntivirus_AllUsers) {
        foreach ($policy in $matchingIntentsAntivirus_AllUsers) {
            if ($processedAntivirusIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$antivirusPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.AntivirusProfiles = $antivirusPoliciesFound_AllUsers

    # Get Endpoint Security - Disk Encryption Policies
    Write-Host "Fetching Disk Encryption Policies assigned to All Users..." -ForegroundColor Yellow
    $diskEncryptionPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedDiskEncryptionIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForDiskEnc_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesDiskEnc_AllUsers = $configPoliciesForDiskEnc_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

    if ($matchingConfigPoliciesDiskEnc_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesDiskEnc_AllUsers) {
            if ($processedDiskEncryptionIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$diskEncryptionPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForDiskEnc_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEnc_AllUsers
    $matchingIntentsDiskEnc_AllUsers = $allIntentsForDiskEnc_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

    if ($matchingIntentsDiskEnc_AllUsers) {
        foreach ($policy in $matchingIntentsDiskEnc_AllUsers) {
            if ($processedDiskEncryptionIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$diskEncryptionPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.DiskEncryptionProfiles = $diskEncryptionPoliciesFound_AllUsers

    # Get Endpoint Security - Firewall Policies
    Write-Host "Fetching Firewall Policies assigned to All Users..." -ForegroundColor Yellow
    $firewallPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedFirewallIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForFirewall_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesFirewall_AllUsers = $configPoliciesForFirewall_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

    if ($matchingConfigPoliciesFirewall_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesFirewall_AllUsers) {
            if ($processedFirewallIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$firewallPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForFirewall_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewall_AllUsers
    $matchingIntentsFirewall_AllUsers = $allIntentsForFirewall_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

    if ($matchingIntentsFirewall_AllUsers) {
        foreach ($policy in $matchingIntentsFirewall_AllUsers) {
            if ($processedFirewallIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$firewallPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.FirewallProfiles = $firewallPoliciesFound_AllUsers

    # Get Endpoint Security - Endpoint Detection and Response Policies
    Write-Host "Fetching EDR Policies assigned to All Users..." -ForegroundColor Yellow
    $edrPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedEDRIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForEDR_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesEDR_AllUsers = $configPoliciesForEDR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

    if ($matchingConfigPoliciesEDR_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesEDR_AllUsers) {
            if ($processedEDRIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$edrPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForEDR_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDR_AllUsers
    $matchingIntentsEDR_AllUsers = $allIntentsForEDR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

    if ($matchingIntentsEDR_AllUsers) {
        foreach ($policy in $matchingIntentsEDR_AllUsers) {
            if ($processedEDRIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$edrPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.EndpointDetectionProfiles = $edrPoliciesFound_AllUsers

    # Get Endpoint Security - Attack Surface Reduction Policies
    Write-Host "Fetching ASR Policies assigned to All Users..." -ForegroundColor Yellow
    $asrPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedASRIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForASR_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesASR_AllUsers = $configPoliciesForASR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

    if ($matchingConfigPoliciesASR_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesASR_AllUsers) {
            if ($processedASRIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$asrPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForASR_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASR_AllUsers
    $matchingIntentsASR_AllUsers = $allIntentsForASR_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

    if ($matchingIntentsASR_AllUsers) {
        foreach ($policy in $matchingIntentsASR_AllUsers) {
            if ($processedASRIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$asrPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.AttackSurfaceProfiles = $asrPoliciesFound_AllUsers

    # Get Endpoint Security - Account Protection Policies
    Write-Host "Fetching Account Protection Policies assigned to All Users..." -ForegroundColor Yellow
    $accountProtectionPoliciesFound_AllUsers = [System.Collections.ArrayList]::new()
    $processedAccountProtectionIds_AllUsers = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForAccountProtection_AllUsers = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesAccountProtection_AllUsers = $configPoliciesForAccountProtection_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

    if ($matchingConfigPoliciesAccountProtection_AllUsers) {
        foreach ($policy in $matchingConfigPoliciesAccountProtection_AllUsers) {
            if ($processedAccountProtectionIds_AllUsers.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    [void]$accountProtectionPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForAccountProtection_AllUsers = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtection_AllUsers
    $matchingIntentsAccountProtection_AllUsers = $allIntentsForAccountProtection_AllUsers | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

    if ($matchingIntentsAccountProtection_AllUsers) {
        foreach ($policy in $matchingIntentsAccountProtection_AllUsers) {
            if ($processedAccountProtectionIds_AllUsers.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $allUsersTarget = $assignmentsResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' } | Select-Object -First 1
                if ($allUsersTarget) {
                    $intentSuffix = Format-AssignmentFilter -FilterId $allUsersTarget.target.deviceAndAppManagementAssignmentFilterId -FilterType $allUsersTarget.target.deviceAndAppManagementAssignmentFilterType
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$intentSuffix" -Force
                    [void]$accountProtectionPoliciesFound_AllUsers.Add($policy)
                }
            }
        }
    }
    $allUsersAssignments.AccountProtectionProfiles = $accountProtectionPoliciesFound_AllUsers

    # Get Autopilot Deployment Profiles
    Write-Host "Fetching Autopilot Deployment Profiles assigned to All Users..." -ForegroundColor Yellow
    $autoProfilesAU = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    foreach ($policyProfile in $autoProfilesAU) {
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policyProfile.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $policyProfile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.DeploymentProfiles += $policyProfile
        }
    }

    # Get Enrollment Status Page Profiles
    Write-Host "Fetching Enrollment Status Page Profiles assigned to All Users..." -ForegroundColor Yellow
    $enrollmentConfigsAU = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $espProfilesAU = $enrollmentConfigsAU | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    foreach ($esp in $espProfilesAU) {
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
        if (($reason = Get-AllTargetReason -Assignments $assignments -TargetReason "All Users")) {
            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $allUsersAssignments.ESPProfiles += $esp
        }
    }

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allUsersAssignments.Keys)) {
            $allUsersAssignments[$key] = @(Filter-ByScopeTag -Items $allUsersAssignments[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
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
            $platform = Get-PolicyPlatform -Policy $config
            Write-Host "Device Configuration Name: $configName, Platform: $platform, Configuration ID: $($config.id)" -ForegroundColor White
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

    # Display Compliance Policies
    Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
    if ($allUsersAssignments.CompliancePolicies.Count -eq 0) {
        Write-Host "No Compliance Policies assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policy in $allUsersAssignments.CompliancePolicies) {
            $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
            $platform = Get-PolicyPlatform -Policy $policy
            Write-Host "Compliance Policy Name: $policyName, Platform: $platform, Policy ID: $($policy.id)" -ForegroundColor White
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

    # Display Required Apps
    Write-Host "`n------- Required Apps -------" -ForegroundColor Cyan
    if ($allUsersAssignments.RequiredApps.Count -eq 0) {
        Write-Host "No Required Apps assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($app in $allUsersAssignments.RequiredApps) {
            $appName = $app.displayName
            Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Required Apps" -Items @($app) -AssignmentReason "All Users"
        }
    }

    # Display Available Apps
    Write-Host "`n------- Available Apps -------" -ForegroundColor Cyan
    if ($allUsersAssignments.AvailableApps.Count -eq 0) {
        Write-Host "No Available Apps assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($app in $allUsersAssignments.AvailableApps) {
            $appName = $app.displayName
            Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Available Apps" -Items @($app) -AssignmentReason "All Users"
        }
    }

    # Display Uninstall Apps
    Write-Host "`n------- Uninstall Apps -------" -ForegroundColor Cyan
    if ($allUsersAssignments.UninstallApps.Count -eq 0) {
        Write-Host "No Uninstall Apps assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($app in $allUsersAssignments.UninstallApps) {
            $appName = $app.displayName
            Write-Host "App Name: $appName, App ID: $($app.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Uninstall Apps" -Items @($app) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Antivirus Profiles
    Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.AntivirusProfiles.Count -eq 0) {
        Write-Host "No Antivirus Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.AntivirusProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Antivirus Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Disk Encryption Profiles
    Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.DiskEncryptionProfiles.Count -eq 0) {
        Write-Host "No Disk Encryption Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.DiskEncryptionProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Disk Encryption Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Firewall Profiles
    Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.FirewallProfiles.Count -eq 0) {
        Write-Host "No Firewall Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.FirewallProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Firewall Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Endpoint Detection and Response Profiles
    Write-Host "`n------- Endpoint Security - EDR Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.EndpointDetectionProfiles.Count -eq 0) {
        Write-Host "No EDR Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.EndpointDetectionProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "EDR Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Attack Surface Reduction Profiles
    Write-Host "`n------- Endpoint Security - ASR Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.AttackSurfaceProfiles.Count -eq 0) {
        Write-Host "No ASR Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.AttackSurfaceProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "ASR Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Endpoint Security - Account Protection Profiles
    Write-Host "`n------- Endpoint Security - Account Protection Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.AccountProtectionProfiles.Count -eq 0) {
        Write-Host "No Account Protection Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.AccountProtectionProfiles) {
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Account Protection Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Autopilot Deployment Profiles
    Write-Host "`n------- Autopilot Deployment Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.DeploymentProfiles.Count -eq 0) {
        Write-Host "No Autopilot Deployment Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.DeploymentProfiles) {
            $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Autopilot Deployment Profile Name: $profileName, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Display Enrollment Status Page Profiles
    Write-Host "`n------- Enrollment Status Page Profiles -------" -ForegroundColor Cyan
    if ($allUsersAssignments.ESPProfiles.Count -eq 0) {
        Write-Host "No Enrollment Status Page Profiles assigned to All Users" -ForegroundColor Gray
    }
    else {
        foreach ($policyProfile in $allUsersAssignments.ESPProfiles) {
            $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.displayName } else { $policyProfile.name }
            Write-Host "Enrollment Status Page Profile Name: $profileName, Profile ID: $($policyProfile.id)" -ForegroundColor White
            Add-ExportData -ExportData $exportData -Category "Enrollment Status Page Profile" -Items @($policyProfile) -AssignmentReason "All Users"
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllUsersAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
