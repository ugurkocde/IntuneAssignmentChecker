function Get-IntuneAllPolicies {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching all policies and their assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Initialize collections for all policies
    $allPolicies = @{
        DeviceConfigs               = @()
        SettingsCatalog             = @()
        CompliancePolicies          = @()
        AppProtectionPolicies       = @()
        AppConfigurationPolicies    = @()
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

    # Function to process and display policy assignments
    function Invoke-PolicyAssignments {
        param (
            [Parameter(Mandatory = $false)]
            [object[]]$Policies,

            [Parameter(Mandatory = $true)]
            [string]$DisplayName
        )

        if ($null -eq $Policies -or $Policies.Count -eq 0) {
            Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
            Write-Host "No policies found for this category." -ForegroundColor Gray
            Write-Host ""
            return
        }

        Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
        foreach ($policy in $Policies) {
            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Profile" }
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
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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

    # Get Compliance Policies
    Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
    $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    foreach ($policy in $compliancePolicies) {
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        $assignmentSummary = $assignments | ForEach-Object {
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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
                    $groupId = $null
                    switch ($assignment.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                            $assignmentReason = "All Users"
                        }
                        '#microsoft.graph.groupAssignmentTarget' {
                            $groupId = $assignment.target.groupId
                            if (!$GroupId -or $groupId -eq $GroupId) {
                                $groupInfo = Get-GroupInfo -GroupId $groupId
                                $assignmentReason = "Group Assignment - $($groupInfo.DisplayName)"
                            }
                        }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' {
                            $groupId = $assignment.target.groupId
                            if (!$GroupId -or $groupId -eq $GroupId) {
                                $groupInfo = Get-GroupInfo -GroupId $groupId
                                $assignmentReason = "Group Exclusion - $($groupInfo.DisplayName)"
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
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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
            if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
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

    # Get Autopilot Deployment Profiles
    Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
    $autoProfilesAll = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    foreach ($policyProfile in $autoProfilesAll) {
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policyProfile.id
        $assignmentSummary = $assignments | ForEach-Object {
            if ($_.Reason -eq "Group Assignment") {
                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                "$($_.Reason) - $($groupInfo.DisplayName)"
            }
            else { $_.Reason }
        }
        $policyProfile | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
        $allPolicies.DeploymentProfiles += $policyProfile
    }

    # Get Enrollment Status Page Profiles
    Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
    $enrollmentConfigsAll = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $espProfilesAll = $enrollmentConfigsAll | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    foreach ($esp in $espProfilesAll) {
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
        $assignmentSummary = $assignments | ForEach-Object {
            if ($_.Reason -eq "Group Assignment") {
                $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                "$($_.Reason) - $($groupInfo.DisplayName)"
            }
            else { $_.Reason }
        }
        $esp | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
        $allPolicies.ESPProfiles += $esp
    }

    # Get Windows 365 Cloud PC Provisioning Policies
    Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
    try {
        $cloudPCProvisioningPoliciesAll = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
        foreach ($policy in $cloudPCProvisioningPoliciesAll) {
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
            $assignmentSummary = $assignments | ForEach-Object {
                if ($_.Reason -eq "Group Assignment") {
                    $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                    "$($_.Reason) - $($groupInfo.DisplayName)"
                }
                else { $_.Reason }
            }
            $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
            $allPolicies.CloudPCProvisioningPolicies += $policy
        }
    }
    catch {
        Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
    }

    # Get Windows 365 Cloud PC User Settings
    Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
    try {
        $cloudPCUserSettingsAll = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
        foreach ($setting in $cloudPCUserSettingsAll) {
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
            $assignmentSummary = $assignments | ForEach-Object {
                if ($_.Reason -eq "Group Assignment") {
                    $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                    "$($_.Reason) - $($groupInfo.DisplayName)"
                }
                else { $_.Reason }
            }
            $setting | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
            $allPolicies.CloudPCUserSettings += $setting
        }
    }
    catch {
        Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
    }

    # Get Endpoint Security - Antivirus Policies
    Write-Host "Fetching Antivirus Policies..." -ForegroundColor Yellow
    $antivirusPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedAntivirusIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForAntivirusAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesAntivirusAll = $configPoliciesForAntivirusAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

    if ($matchingConfigPoliciesAntivirusAll) {
        foreach ($policy in $matchingConfigPoliciesAntivirusAll) {
            if ($processedAntivirusIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$antivirusPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForAntivirusAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirusAll
    $matchingIntentsAntivirusAll = $allIntentsForAntivirusAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

    if ($matchingIntentsAntivirusAll) {
        foreach ($policy in $matchingIntentsAntivirusAll) {
            if ($processedAntivirusIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$antivirusPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.AntivirusProfiles = $antivirusPoliciesFoundAll

    # Get Endpoint Security - Disk Encryption Policies
    Write-Host "Fetching Disk Encryption Policies..." -ForegroundColor Yellow
    $diskEncryptionPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedDiskEncryptionIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForDiskEncAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesDiskEncAll = $configPoliciesForDiskEncAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

    if ($matchingConfigPoliciesDiskEncAll) {
        foreach ($policy in $matchingConfigPoliciesDiskEncAll) {
            if ($processedDiskEncryptionIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$diskEncryptionPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForDiskEncAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEncAll
    $matchingIntentsDiskEncAll = $allIntentsForDiskEncAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

    if ($matchingIntentsDiskEncAll) {
        foreach ($policy in $matchingIntentsDiskEncAll) {
            if ($processedDiskEncryptionIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$diskEncryptionPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.DiskEncryptionProfiles = $diskEncryptionPoliciesFoundAll

    # Get Endpoint Security - Firewall Policies
    Write-Host "Fetching Firewall Policies..." -ForegroundColor Yellow
    $firewallPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedFirewallIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForFirewallAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesFirewallAll = $configPoliciesForFirewallAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

    if ($matchingConfigPoliciesFirewallAll) {
        foreach ($policy in $matchingConfigPoliciesFirewallAll) {
            if ($processedFirewallIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$firewallPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForFirewallAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewallAll
    $matchingIntentsFirewallAll = $allIntentsForFirewallAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

    if ($matchingIntentsFirewallAll) {
        foreach ($policy in $matchingIntentsFirewallAll) {
            if ($processedFirewallIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$firewallPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.FirewallProfiles = $firewallPoliciesFoundAll

    # Get Endpoint Security - Endpoint Detection and Response Policies
    Write-Host "Fetching EDR Policies..." -ForegroundColor Yellow
    $edrPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedEDRIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForEDRAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesEDRAll = $configPoliciesForEDRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

    if ($matchingConfigPoliciesEDRAll) {
        foreach ($policy in $matchingConfigPoliciesEDRAll) {
            if ($processedEDRIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$edrPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForEDRAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDRAll
    $matchingIntentsEDRAll = $allIntentsForEDRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

    if ($matchingIntentsEDRAll) {
        foreach ($policy in $matchingIntentsEDRAll) {
            if ($processedEDRIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$edrPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.EndpointDetectionProfiles = $edrPoliciesFoundAll

    # Get Endpoint Security - Attack Surface Reduction Policies
    Write-Host "Fetching ASR Policies..." -ForegroundColor Yellow
    $asrPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedASRIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForASRAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesASRAll = $configPoliciesForASRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

    if ($matchingConfigPoliciesASRAll) {
        foreach ($policy in $matchingConfigPoliciesASRAll) {
            if ($processedASRIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$asrPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForASRAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASRAll
    $matchingIntentsASRAll = $allIntentsForASRAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

    if ($matchingIntentsASRAll) {
        foreach ($policy in $matchingIntentsASRAll) {
            if ($processedASRIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$asrPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.AttackSurfaceProfiles = $asrPoliciesFoundAll

    # Get Endpoint Security - Account Protection Policies
    Write-Host "Fetching Account Protection Policies..." -ForegroundColor Yellow
    $accountProtectionPoliciesFoundAll = [System.Collections.ArrayList]::new()
    $processedAccountProtectionIdsAll = [System.Collections.Generic.HashSet[string]]::new()

    # 1. Check configurationPolicies
    $configPoliciesForAccountProtectionAll = Get-IntuneEntities -EntityType "configurationPolicies"
    $matchingConfigPoliciesAccountProtectionAll = $configPoliciesForAccountProtectionAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

    if ($matchingConfigPoliciesAccountProtectionAll) {
        foreach ($policy in $matchingConfigPoliciesAccountProtectionAll) {
            if ($processedAccountProtectionIdsAll.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $assignmentSummary = $assignments | ForEach-Object {
                    if ($_.Reason -eq "Group Assignment" -or $_.Reason -eq "Group Exclusion") {
                        $groupInfo = Get-GroupInfo -GroupId $_.GroupId
                        "$($_.Reason) - $($groupInfo.DisplayName)"
                    }
                    else { $_.Reason }
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$accountProtectionPoliciesFoundAll.Add($policy)
            }
        }
    }

    # 2. Check deviceManagement/intents
    $allIntentsForAccountProtectionAll = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtectionAll
    $matchingIntentsAccountProtectionAll = $allIntentsForAccountProtectionAll | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

    if ($matchingIntentsAccountProtectionAll) {
        foreach ($policy in $matchingIntentsAccountProtectionAll) {
            if ($processedAccountProtectionIdsAll.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentSummary = $assignmentsResponse.value | ForEach-Object {
                    $reasonText = switch ($_.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget'       { "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget'            { "Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        '#microsoft.graph.exclusionGroupAssignmentTarget'   { "Exclude Group: " + (Get-GroupInfo -GroupId $_.target.groupId).DisplayName }
                        default { "Unknown" }
                    }
                    $reasonText
                }
                $policy | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                [void]$accountProtectionPoliciesFoundAll.Add($policy)
            }
        }
    }
    $allPolicies.AccountProtectionProfiles = $accountProtectionPoliciesFoundAll

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allPolicies.Keys)) {
            $allPolicies[$key] = @(Filter-ByScopeTag -Items $allPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # Display all policies and their assignments
    Invoke-PolicyAssignments -Policies $allPolicies.DeviceConfigs -DisplayName "Device Configurations"
    Invoke-PolicyAssignments -Policies $allPolicies.SettingsCatalog -DisplayName "Settings Catalog Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.CompliancePolicies -DisplayName "Compliance Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.AppProtectionPolicies -DisplayName "App Protection Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.AppConfigurationPolicies -DisplayName "App Configuration Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.PlatformScripts -DisplayName "Platform Scripts"
    Invoke-PolicyAssignments -Policies $allPolicies.HealthScripts -DisplayName "Proactive Remediation Scripts"
    Invoke-PolicyAssignments -Policies $allPolicies.DeploymentProfiles -DisplayName "Autopilot Deployment Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.ESPProfiles -DisplayName "Enrollment Status Page Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.CloudPCProvisioningPolicies -DisplayName "Windows 365 Cloud PC Provisioning Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.CloudPCUserSettings -DisplayName "Windows 365 Cloud PC User Settings"
    Invoke-PolicyAssignments -Policies $allPolicies.AntivirusProfiles -DisplayName "Endpoint Security - Antivirus Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.DiskEncryptionProfiles -DisplayName "Endpoint Security - Disk Encryption Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.FirewallProfiles -DisplayName "Endpoint Security - Firewall Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.EndpointDetectionProfiles -DisplayName "Endpoint Security - EDR Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.AttackSurfaceProfiles -DisplayName "Endpoint Security - ASR Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.AccountProtectionProfiles -DisplayName "Endpoint Security - Account Protection Profiles"

    # Add to export data
    Add-ExportData -ExportData $exportData -Category "Device Configuration" -Items $allPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Settings Catalog Policy" -Items $allPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Compliance Policy" -Items $allPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "App Protection Policy" -Items $allPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "App Configuration Policy" -Items $allPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Platform Scripts" -Items $allPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Proactive Remediation Scripts" -Items $allPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Autopilot Deployment Profile" -Items $allPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Enrollment Status Page" -Items $allPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $allPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $allPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $allPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $allPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $allPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $allPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $allPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentSummary }
    Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items $allPolicies.AccountProtectionProfiles -AssignmentReason { param($item) $item.AssignmentSummary }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllPolicies.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
