function Get-IntuneUserAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalNames,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter
    )

    Write-Host "User selection chosen" -ForegroundColor Green

    # Get User Principal Names from parameter or prompt
    if ($UserPrincipalNames) {
        $upnInput = $UserPrincipalNames
    }
    else {
        # Prompt for one or more User Principal Names
        Write-Host "Please enter User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
        $upnInput = Read-Host
    }

    # Validate input
    if ([string]::IsNullOrWhiteSpace($upnInput)) {
        Write-Host "No UPN provided. Please try again with a valid UPN." -ForegroundColor Red
        return
    }

    $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($upns.Count -eq 0) {
        Write-Host "No valid UPNs provided. Please try again with at least one valid UPN." -ForegroundColor Red
        return
    }

    # Validate UPN format
    $upnRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    $invalidUpns = @($upns | Where-Object { $_ -notmatch $upnRegex })
    if ($invalidUpns.Count -gt 0) {
        foreach ($badUpn in $invalidUpns) {
            Write-Host "Invalid UPN format: '$badUpn'. Expected: user@domain.com" -ForegroundColor Red
        }
        $upns = @($upns | Where-Object { $_ -match $upnRegex })
        if ($upns.Count -eq 0) {
            Write-Host "No valid UPNs remaining. Please try again." -ForegroundColor Red
            return
        }
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

        Write-Host "Fetching Intune Profiles and Applications for the user..." -ForegroundColor Yellow

        $totalCategories = 16
        $currentCategory = 0

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
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Device Configurations..." -ForegroundColor Yellow
        $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
        foreach ($config in $deviceConfigs) {
            $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.DeviceConfigs += $config
            }
        }

        # Get Settings Catalog Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Settings Catalog Policies..." -ForegroundColor Yellow
        $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
        foreach ($policy in $settingsCatalog) {
            $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.SettingsCatalog += $policy
            }
        }

        # Get Compliance Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Compliance Policies..." -ForegroundColor Yellow
        $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
        foreach ($policy in $compliancePolicies) {
            $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.CompliancePolicies += $policy
            }
        }

        # Get App Protection Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching App Protection Policies..." -ForegroundColor Yellow
        $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
        foreach ($policy in $appProtectionPolicies) {
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
                            '#microsoft.graph.groupAssignmentTarget' {
                                if (!$GroupId -or $assignment.target.groupId -eq $GroupId) {
                                    $assignmentReason = "Group Assignment"
                                }
                            }
                            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                                if (!$GroupId -or $assignment.target.groupId -eq $GroupId) {
                                    $assignmentReason = "Group Exclusion"
                                }
                            }
                        }

                        if ($assignmentReason) {
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
                        $assignmentSummary = $assignments | ForEach-Object {
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
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching App Configuration Policies..." -ForegroundColor Yellow
        $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
        foreach ($policy in $appConfigPolicies) {
            $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.AppConfigurationPolicies += $policy
            }
        }

        # Fetch and process Applications
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Applications..." -ForegroundColor Yellow
        $appUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
        $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
        $allApps = $appResponse.value
        while ($appResponse.'@odata.nextLink') {
            $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
            $allApps += $appResponse.value
        }
        $totalApps = $allApps.Count
        $currentApp = 0

        foreach ($app in $allApps) {
            # Filter out irrelevant apps
            if ($app.isFeatured -or $app.isBuiltIn) {
                continue
            }

            $currentApp++
            Write-Host "`rFetching Application $currentApp of $totalApps" -NoNewline
            $appId = $app.id
            $assignmentsUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            $isExcluded = $false
            $isIncluded = $false
            $winningAssignment = $null

            foreach ($assignment in $assignmentResponse.value) {
                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                    $groupMemberships.id -contains $assignment.target.groupId) {
                    $isExcluded = $true
                    $winningAssignment = $assignment
                    break
                }
                elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' -or
                    ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                    $groupMemberships.id -contains $assignment.target.groupId)) {
                    if (-not $isIncluded) { $winningAssignment = $assignment }
                    $isIncluded = $true
                }
            }

            $filterSuffix = ''
            if ($winningAssignment) {
                $filterSuffix = Format-AssignmentFilter `
                    -FilterId   $winningAssignment.target.deviceAndAppManagementAssignmentFilterId `
                    -FilterType $winningAssignment.target.deviceAndAppManagementAssignmentFilterType
            }

            if ($isIncluded -and -not $isExcluded) {
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Included$filterSuffix" -Force
                switch ($assignment.intent) {
                    "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                    "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                    "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                }
            }
            elseif ($isExcluded) {
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$filterSuffix" -Force
                switch ($assignment.intent) {
                    "required" { $relevantPolicies.AppsRequired += $appWithReason; break }
                    "available" { $relevantPolicies.AppsAvailable += $appWithReason; break }
                    "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason; break }
                }
            }
        }
        Write-Host "`rFetching Application $totalApps of $totalApps" -NoNewline
        Start-Sleep -Milliseconds 100
        Write-Host ""  # Move to the next line after the loop

        # Get Platform Scripts
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Platform Scripts..." -ForegroundColor Yellow
        $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
        foreach ($script in $platformScripts) {
            $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.PlatformScripts += $script
            }
        }

        # Get Proactive Remediation Scripts
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
        $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
        foreach ($script in $healthScripts) {
            $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
            $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
            if ($reason) {
                $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $relevantPolicies.HealthScripts += $script
            }
        }

        # Get Endpoint Security - Antivirus Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Antivirus Policies..." -ForegroundColor Yellow
        $antivirusPoliciesFound = [System.Collections.ArrayList]::new()
        $processedAntivirusIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForAntivirus = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesAntivirus = $configPoliciesForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

        if ($matchingConfigPoliciesAntivirus) {
            foreach ($policy in $matchingConfigPoliciesAntivirus) {
                if ($processedAntivirusIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$antivirusPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForAntivirus = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirus
        $matchingIntentsAntivirus = $allIntentsForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }

        if ($matchingIntentsAntivirus) {
            foreach ($policy in $matchingIntentsAntivirus) {
                if ($processedAntivirusIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$antivirusPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.AntivirusProfiles = $antivirusPoliciesFound

        # Get Endpoint Security - Disk Encryption Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Disk Encryption Policies..." -ForegroundColor Yellow
        $diskEncryptionPoliciesFound = [System.Collections.ArrayList]::new()
        $processedDiskEncryptionIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForDiskEncryption = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesDiskEnc = $configPoliciesForDiskEncryption | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

        if ($matchingConfigPoliciesDiskEnc) {
            foreach ($policy in $matchingConfigPoliciesDiskEnc) {
                if ($processedDiskEncryptionIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$diskEncryptionPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents (excluding those already found)
        $allIntentsForDiskEncryption = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEncryption
        $matchingIntentsDiskEnc = $allIntentsForDiskEncryption | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }

        if ($matchingIntentsDiskEnc) {
            foreach ($policy in $matchingIntentsDiskEnc) {
                if ($processedDiskEncryptionIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$diskEncryptionPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.DiskEncryptionProfiles = $diskEncryptionPoliciesFound

        # Get Endpoint Security - Firewall Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Firewall Policies..." -ForegroundColor Yellow
        $firewallPoliciesFound = [System.Collections.ArrayList]::new()
        $processedFirewallIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForFirewall = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesFirewall = $configPoliciesForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

        if ($matchingConfigPoliciesFirewall) {
            foreach ($policy in $matchingConfigPoliciesFirewall) {
                if ($processedFirewallIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$firewallPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForFirewall = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewall
        $matchingIntentsFirewall = $allIntentsForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }

        if ($matchingIntentsFirewall) {
            foreach ($policy in $matchingIntentsFirewall) {
                if ($processedFirewallIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$firewallPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.FirewallProfiles = $firewallPoliciesFound

        # Get Endpoint Security - Endpoint Detection and Response Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Endpoint Detection and Response Policies..." -ForegroundColor Yellow
        $edrPoliciesFound = [System.Collections.ArrayList]::new()
        $processedEDRIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForEDR = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesEDR = $configPoliciesForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

        if ($matchingConfigPoliciesEDR) {
            foreach ($policy in $matchingConfigPoliciesEDR) {
                if ($processedEDRIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$edrPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForEDR = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDR
        $matchingIntentsEDR = $allIntentsForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }

        if ($matchingIntentsEDR) {
            foreach ($policy in $matchingIntentsEDR) {
                if ($processedEDRIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$edrPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.EndpointDetectionProfiles = $edrPoliciesFound

        # Get Endpoint Security - Attack Surface Reduction Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Attack Surface Reduction Policies..." -ForegroundColor Yellow
        $asrPoliciesFound = [System.Collections.ArrayList]::new()
        $processedASRIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForASR = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesASR = $configPoliciesForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

        if ($matchingConfigPoliciesASR) {
            foreach ($policy in $matchingConfigPoliciesASR) {
                if ($processedASRIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$asrPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForASR = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASR
        $matchingIntentsASR = $allIntentsForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }

        if ($matchingIntentsASR) {
            foreach ($policy in $matchingIntentsASR) {
                if ($processedASRIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$asrPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.AttackSurfaceProfiles = $asrPoliciesFound

        # Get Endpoint Security - Account Protection Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Account Protection Policies..." -ForegroundColor Yellow
        $accountProtectionPoliciesFound = [System.Collections.ArrayList]::new()
        $processedAccountProtectionIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies
        $configPoliciesForAccountProtection = Get-IntuneEntities -EntityType "configurationPolicies"
        $matchingConfigPoliciesAccountProtection = $configPoliciesForAccountProtection | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

        if ($matchingConfigPoliciesAccountProtection) {
            foreach ($policy in $matchingConfigPoliciesAccountProtection) {
                if ($processedAccountProtectionIds.Add($policy.id)) {
                    $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$accountProtectionPoliciesFound.Add($policy)
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents
        $allIntentsForAccountProtection = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtection
        $matchingIntentsAccountProtection = $allIntentsForAccountProtection | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }

        if ($matchingIntentsAccountProtection) {
            foreach ($policy in $matchingIntentsAccountProtection) {
                if ($processedAccountProtectionIds.Add($policy.id)) {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $assignments = $assignmentsResponse.value
                    $assignmentDetailsList = foreach ($assignment in $assignments) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    $reason = Resolve-AssignmentReason -Assignments $assignmentDetailsList -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Users")
                    if ($reason) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                        [void]$accountProtectionPoliciesFound.Add($policy)
                    }
                }
            }
        }
        $relevantPolicies.AccountProtectionProfiles = $accountProtectionPoliciesFound

        # Get Windows 365 Cloud PC Provisioning Policies
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
        try {
            $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
            foreach ($policy in $cloudPCProvisioningPolicies) {
                $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "All Users" -or
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

        # Get Windows 365 Cloud PC User Settings
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
        try {
            $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
            foreach ($setting in $cloudPCUserSettings) {
                $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
                foreach ($assignment in $assignments) {
                    if ($assignment.Reason -eq "All Users" -or
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

        # Apply scope tag filter if specified
        if ($ScopeTagFilter) {
            foreach ($key in @($relevantPolicies.Keys)) {
                $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
            }
        }

        # Display results
        Write-Host "`nAssignments for User: $upn" -ForegroundColor Green

        # Calculate category summary
        $categoryNames = @('DeviceConfigs', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies', 'AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'AppsRequired', 'AppsAvailable', 'AppsUninstall', 'AntivirusProfiles', 'DiskEncryptionProfiles', 'FirewallProfiles', 'EndpointDetectionProfiles', 'AttackSurfaceProfiles', 'AccountProtectionProfiles', 'CloudPCProvisioningPolicies', 'CloudPCUserSettings')
        $nonEmptyCount = ($categoryNames | Where-Object { $relevantPolicies[$_].Count -gt 0 }).Count
        $totalDisplayCategories = $categoryNames.Count
        Write-Host "`nFound assignments in $nonEmptyCount of $totalDisplayCategories categories." -ForegroundColor Cyan

        # Display Device Configurations
        if ($relevantPolicies.DeviceConfigs.Count -gt 0) {
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f "Configuration Name", "Platform", "Configuration ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($config in $relevantPolicies.DeviceConfigs) {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                if ($configName.Length -gt 42) {
                    $configName = $configName.Substring(0, 39) + "..."
                }

                $platform = Get-PolicyPlatform -Policy $config
                if ($platform.Length -gt 17) {
                    $platform = $platform.Substring(0, 14) + "..."
                }

                $configId = $config.id
                if ($configId.Length -gt 32) {
                    $configId = $configId.Substring(0, 29) + "..."
                }

                $assignment = $config.AssignmentReason
                if ($assignment.Length -gt 17) {
                    $assignment = $assignment.Substring(0, 14) + "..."
                }

                $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f $configName, $platform, $configId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Settings Catalog Policies
        if ($relevantPolicies.SettingsCatalog.Count -gt 0) {
            Write-Host "`n------- Settings Catalog Policies -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policy in $relevantPolicies.SettingsCatalog) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                if ($policyName.Length -gt 47) {
                    $policyName = $policyName.Substring(0, 44) + "..."
                }

                $policyId = $policy.id
                if ($policyId.Length -gt 37) {
                    $policyId = $policyId.Substring(0, 34) + "..."
                }

                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Compliance Policies
        if ($relevantPolicies.CompliancePolicies.Count -gt 0) {
            Write-Host "`n------- Compliance Policies -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policy in $relevantPolicies.CompliancePolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                if ($policyName.Length -gt 47) {
                    $policyName = $policyName.Substring(0, 44) + "..."
                }

                $policyId = $policy.id
                if ($policyId.Length -gt 37) {
                    $policyId = $policyId.Substring(0, 34) + "..."
                }

                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display App Protection Policies
        if ($relevantPolicies.AppProtectionPolicies.Count -gt 0) {
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f "Policy Name", "Policy ID", "Type", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policy in $relevantPolicies.AppProtectionPolicies) {
                $policyName = $policy.displayName
                if ($policyName.Length -gt 37) {
                    $policyName = $policyName.Substring(0, 34) + "..."
                }

                $policyId = $policy.id
                if ($policyId.Length -gt 27) {
                    $policyId = $policyId.Substring(0, 24) + "..."
                }

                $policyType = switch ($policy.'@odata.type') {
                    "#microsoft.graph.androidManagedAppProtection" { "Android" }
                    "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                    "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                    default { "Unknown" }
                }

                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f $policyName, $policyId, $policyType, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display App Configuration Policies
        if ($relevantPolicies.AppConfigurationPolicies.Count -gt 0) {
            Write-Host "`n------- App Configuration Policies -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policy in $relevantPolicies.AppConfigurationPolicies) {
                $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
                if ($policyName.Length -gt 47) {
                    $policyName = $policyName.Substring(0, 44) + "..."
                }

                $policyId = $policy.id
                if ($policyId.Length -gt 37) {
                    $policyId = $policyId.Substring(0, 34) + "..."
                }

                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Platform Scripts
        if ($relevantPolicies.PlatformScripts.Count -gt 0) {
            Write-Host "`n------- Platform Scripts -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Script Name", "Script ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($script in $relevantPolicies.PlatformScripts) {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                if ($scriptName.Length -gt 47) {
                    $scriptName = $scriptName.Substring(0, 44) + "..."
                }

                $scriptId = $script.id
                if ($scriptId.Length -gt 37) {
                    $scriptId = $scriptId.Substring(0, 34) + "..."
                }

                $assignment = $script.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $scriptName, $scriptId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Proactive Remediation Scripts
        if ($relevantPolicies.HealthScripts.Count -gt 0) {
            Write-Host "`n------- Proactive Remediation Scripts -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Script Name", "Script ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($script in $relevantPolicies.HealthScripts) {
                $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
                if ($scriptName.Length -gt 47) {
                    $scriptName = $scriptName.Substring(0, 44) + "..."
                }

                $scriptId = $script.id
                if ($scriptId.Length -gt 37) {
                    $scriptId = $scriptId.Substring(0, 34) + "..."
                }

                $assignment = $script.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $scriptName, $scriptId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Required Apps
        if ($relevantPolicies.AppsRequired.Count -gt 0) {
            Write-Host "`n------- Required Apps -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($app in $relevantPolicies.AppsRequired) {
                $appName = $app.displayName
                if ($appName.Length -gt 47) {
                    $appName = $appName.Substring(0, 44) + "..."
                }

                $appId = $app.id
                if ($appId.Length -gt 37) {
                    $appId = $appId.Substring(0, 34) + "..."
                }

                $assignment = $app.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                if ($assignment -like "*Exclusion*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Available Apps
        if ($relevantPolicies.AppsAvailable.Count -gt 0) {
            Write-Host "`n------- Available Apps -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($app in $relevantPolicies.AppsAvailable) {
                $appName = $app.displayName
                if ($appName.Length -gt 47) {
                    $appName = $appName.Substring(0, 44) + "..."
                }

                $appId = $app.id
                if ($appId.Length -gt 37) {
                    $appId = $appId.Substring(0, 34) + "..."
                }

                $assignment = $app.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                if ($assignment -like "*Exclusion*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Uninstall Apps
        if ($relevantPolicies.AppsUninstall.Count -gt 0) {
            Write-Host "`n------- Uninstall Apps -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "App Name", "App ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($app in $relevantPolicies.AppsUninstall) {
                $appName = $app.displayName
                if ($appName.Length -gt 47) {
                    $appName = $appName.Substring(0, 44) + "..."
                }

                $appId = $app.id
                if ($appId.Length -gt 37) {
                    $appId = $appId.Substring(0, 34) + "..."
                }

                $assignment = $app.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $appName, $appId, $assignment
                if ($assignment -like "*Exclusion*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Antivirus Profiles
        if ($relevantPolicies.AntivirusProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Antivirus Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.AntivirusProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Disk Encryption Profiles
        if ($relevantPolicies.DiskEncryptionProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Disk Encryption Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.DiskEncryptionProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Firewall Profiles
        if ($relevantPolicies.FirewallProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Firewall Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.FirewallProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Endpoint Detection and Response Profiles
        if ($relevantPolicies.EndpointDetectionProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Endpoint Detection and Response Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.EndpointDetectionProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Attack Surface Reduction Profiles
        if ($relevantPolicies.AttackSurfaceProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Attack Surface Reduction Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.AttackSurfaceProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Endpoint Security - Account Protection Profiles
        if ($relevantPolicies.AccountProtectionProfiles.Count -gt 0) {
            Write-Host "`n------- Endpoint Security - Account Protection Profiles -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Profile Name", "Profile ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policyProfile in $relevantPolicies.AccountProtectionProfiles) {
                $profileName = if (-not [string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.name } else { "Unnamed Profile" }
                if ($profileName.Length -gt 47) {
                    $profileName = $profileName.Substring(0, 44) + "..."
                }

                $profileId = $policyProfile.id
                if ($profileId.Length -gt 37) {
                    $profileId = $profileId.Substring(0, 34) + "..."
                }

                $assignment = $policyProfile.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $profileName, $profileId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Windows 365 Cloud PC Provisioning Policies
        if ($relevantPolicies.CloudPCProvisioningPolicies.Count -gt 0) {
            Write-Host "`n------- Windows 365 Cloud PC Provisioning Policies -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($policy in $relevantPolicies.CloudPCProvisioningPolicies) {
                $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Policy" }
                if ($policyName.Length -gt 47) {
                    $policyName = $policyName.Substring(0, 44) + "..."
                }

                $policyId = $policy.id
                if ($policyId.Length -gt 37) {
                    $policyId = $policyId.Substring(0, 34) + "..."
                }

                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $policyName, $policyId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Display Windows 365 Cloud PC User Settings
        if ($relevantPolicies.CloudPCUserSettings.Count -gt 0) {
            Write-Host "`n------- Windows 365 Cloud PC User Settings -------" -ForegroundColor Cyan
            # Create table header
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Setting Name", "Setting ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($setting in $relevantPolicies.CloudPCUserSettings) {
                $settingName = if (-not [string]::IsNullOrWhiteSpace($setting.displayName)) { $setting.displayName } elseif (-not [string]::IsNullOrWhiteSpace($setting.name)) { $setting.name } else { "Unnamed Setting" }
                if ($settingName.Length -gt 47) {
                    $settingName = $settingName.Substring(0, 44) + "..."
                }

                $settingId = $setting.id
                if ($settingId.Length -gt 37) {
                    $settingId = $settingId.Substring(0, 34) + "..."
                }

                $assignment = $setting.AssignmentReason
                if ($assignment.Length -gt 27) {
                    $assignment = $assignment.Substring(0, 24) + "..."
                }

                $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $settingName, $settingId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Add all data to export
        Add-ExportData -ExportData $exportData -Category "User" -Items @([PSCustomObject]@{
                displayName      = $upn
                id               = $userInfo.Id
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
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC Provisioning Policy" -Items $relevantPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Windows 365 Cloud PC User Setting" -Items $relevantPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Antivirus" -Items $relevantPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Disk Encryption" -Items $relevantPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Firewall" -Items $relevantPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - EDR" -Items $relevantPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - ASR" -Items $relevantPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Endpoint Security - Account Protection" -Items $relevantPolicies.AccountProtectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Required Apps" -Items $relevantPolicies.AppsRequired -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Available Apps" -Items $relevantPolicies.AppsAvailable -AssignmentReason { param($item) $item.AssignmentReason }
            Add-ExportData -ExportData $exportData -Category "Uninstall Apps" -Items $relevantPolicies.AppsUninstall -AssignmentReason { param($item) $item.AssignmentReason }
        )
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUserAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
