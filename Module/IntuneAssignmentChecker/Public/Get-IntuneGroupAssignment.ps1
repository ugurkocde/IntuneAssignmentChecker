function Get-IntuneGroupAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GroupNames,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNestedGroups,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter
    )

    Write-Host "Group selection chosen" -ForegroundColor Green

    # Get Group names from parameter or prompt
    if ($GroupNames) {
        $groupInput = $GroupNames
    }
    else {
        # Prompt for Group names or IDs
        Write-Host "Please enter Group names or Object IDs, separated by commas (,): " -ForegroundColor Cyan
        Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
        $groupInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($groupInput)) {
        Write-Host "No group information provided. Please try again." -ForegroundColor Red
        return
    }

    $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }
    $exportData = [System.Collections.ArrayList]::new()

    # Determine if nested group checking should be enabled
    $checkNestedGroups = $false
    if ($IncludeNestedGroups) {
        $checkNestedGroups = $true
    }
    else {
        $nestedPrompt = Read-Host "Include assignments inherited from parent groups? (y/n)"
        if ($nestedPrompt -match '^[Yy]') {
            $checkNestedGroups = $true
        }
    }

    foreach ($groupInput in $groupInputs) {
        Write-Host "`nProcessing input: $groupInput" -ForegroundColor Yellow

        # Initialize variables
        $groupId = $null
        $groupName = $null

        # Check if input is a GUID
        if ($groupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $groupInfo = Get-GroupInfo -GroupId $groupInput
            if (-not $groupInfo.Success) {
                Write-Host "No group found with ID: $groupInput" -ForegroundColor Red
                continue
            }
            $groupId = $groupInfo.Id
            $groupName = $groupInfo.DisplayName
        }
        else {
            # Try to find group by display name
            $groupUri = "$script:GraphEndpoint/v1.0/groups?`$filter=displayName eq '$groupInput'"
            $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get

            if ($groupResponse.value.Count -eq 0) {
                Write-Host "No group found with name: $groupInput" -ForegroundColor Red
                continue
            }
            elseif ($groupResponse.value.Count -gt 1) {
                Write-Host "Multiple groups found with name: $groupInput. Please use the Object ID instead:" -ForegroundColor Red
                foreach ($group in $groupResponse.value) {
                    Write-Host "  - $($group.displayName) (ID: $($group.id))" -ForegroundColor Yellow
                }
                continue
            }

            $groupId = $groupResponse.value[0].id
            $groupName = $groupResponse.value[0].displayName
        }

        Write-Host "Found group: $groupName (ID: $groupId)" -ForegroundColor Green

        # Build effective group IDs list (direct + parent groups if nested checking enabled)
        $allGroupIds = @($groupId)
        $parentGroupMap = @{}
        if ($checkNestedGroups) {
            Write-Host "Checking parent group memberships..." -ForegroundColor Yellow
            $parentGroups = Get-TransitiveGroupMembership -GroupId $groupId
            if ($parentGroups.Count -gt 0) {
                foreach ($pg in $parentGroups) {
                    $allGroupIds += $pg.id
                    $parentGroupMap[$pg.id] = $pg.displayName
                }
                Write-Host "Found $($parentGroups.Count) parent group(s): $($parentGroups.displayName -join ', ')" -ForegroundColor Green
            }
            else {
                Write-Host "No parent groups found." -ForegroundColor Gray
            }
        }

        Write-Host "Fetching Intune Profiles and Applications for the group..." -ForegroundColor Yellow

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
            # Endpoint Security profiles
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
            $directAssignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.DeviceConfigs += $config
                }
            }
        }

        # Get Settings Catalog Policies
        Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
        $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
        foreach ($policy in $settingsCatalog) {
            # Exclude Windows-only Endpoint Security policies from this generic Settings Catalog fetch
            # Allow macOS and cross-platform endpoint security policies through
            if ($policy.templateReference -and $policy.templateReference.templateFamily -like "endpointSecurity*") {
                $platforms = $policy.platforms
                # Only skip if this is a Windows-only policy (not macOS or other platforms)
                if ($platforms -and
                    (($platforms -contains "windows10" -or $platforms -contains "windows10AndLater") -and
                     $platforms -notcontains "macOS")) {
                    continue
                }
            }
            $directAssignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.SettingsCatalog += $policy
                }
            }
        }

        # Get Compliance Policies
        Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
        $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
        foreach ($policy in $compliancePolicies) {
            $directAssignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.CompliancePolicies += $policy
                }
            }
        }

        # Get App Protection Policies
        Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
        $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
        foreach ($policy in $appProtectionPolicies) {
            # Get-IntuneAssignments handles App Protection policy type resolution internally
            try {
                $directAssignments = Get-IntuneAssignments -EntityType "deviceAppManagement/managedAppPolicies" -EntityId $policy.id -GroupIds $allGroupIds
                if ($directAssignments.Count -gt 0) {
                    $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                    if ($assignmentReasons.Count -gt 0) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                        $relevantPolicies.AppProtectionPolicies += $policy
                    }
                }
            }
            catch {
                Write-Host "Error fetching assignments for App Protection policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Get App Configuration Policies
        Write-Host "Fetching App Configuration Policies..." -ForegroundColor Yellow
        $appConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
        foreach ($policy in $appConfigPolicies) {
            $directAssignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.AppConfigurationPolicies += $policy
                }
            }
        }

        # Endpoint Security Policies for the specific group
        $endpointSecurityCategories = @(
            @{ Name = "Antivirus"; Key = "AntivirusProfiles"; TemplateFamily = "endpointSecurityAntivirus"; UserFriendlyType = "Antivirus Profile" },
            @{ Name = "Disk Encryption"; Key = "DiskEncryptionProfiles"; TemplateFamily = "endpointSecurityDiskEncryption"; UserFriendlyType = "Disk Encryption Profile" },
            @{ Name = "Firewall"; Key = "FirewallProfiles"; TemplateFamily = "endpointSecurityFirewall"; UserFriendlyType = "Firewall Profile" },
            @{ Name = "Endpoint Detection and Response"; Key = "EndpointDetectionProfiles"; TemplateFamily = "endpointSecurityEndpointDetectionAndResponse"; UserFriendlyType = "EDR Profile" },
            @{ Name = "Attack Surface Reduction"; Key = "AttackSurfaceProfiles"; TemplateFamily = "endpointSecurityAttackSurfaceReduction"; UserFriendlyType = "ASR Profile" },
            @{ Name = "Account Protection"; Key = "AccountProtectionProfiles"; TemplateFamily = "endpointSecurityAccountProtection"; UserFriendlyType = "Account Protection Profile" }
        )

        foreach ($esCategory in $endpointSecurityCategories) {
            Write-Host "Fetching $($esCategory.Name) Policies for group..." -ForegroundColor Yellow
            $processedEsPolicyIds = [System.Collections.Generic.HashSet[string]]::new() # Track IDs per category to avoid duplicates from configPolicies and intents

            # 1. Check configurationPolicies (Settings Catalog style ES policies)
            $allConfigEsPolicies = Get-IntuneEntities -EntityType "configurationPolicies" # Fetch all, then filter
            $matchingConfigEsPolicies = $allConfigEsPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
            if ($matchingConfigEsPolicies) {
                foreach ($policy in $matchingConfigEsPolicies) {
                    if ($processedEsPolicyIds.Add($policy.id)) {
                        $directAssignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id -GroupIds $allGroupIds
                        if ($directAssignments.Count -gt 0) {
                            $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                            if ($assignmentReasons.Count -gt 0) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                $relevantPolicies[$esCategory.Key] += $policy
                            }
                        }
                    }
                }
            }

            # 2. Check deviceManagement/intents (Template style ES policies)
            $allIntentEsPolicies = Get-IntuneEntities -EntityType "deviceManagement/intents" # Fetch all, then filter
            Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentEsPolicies
            $matchingIntentEsPolicies = $allIntentEsPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
            if ($matchingIntentEsPolicies) {
                foreach ($policy in $matchingIntentEsPolicies) {
                    if ($processedEsPolicyIds.Add($policy.id)) {
                        # For intents, assignments are fetched differently
                        try {
                            $allIntentAssignments = [System.Collections.ArrayList]::new()
                            $currentIntentAssignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments"
                            do {
                                $intentAssignmentsResponsePage = Invoke-MgGraphRequest -Uri $currentIntentAssignmentsUri -Method Get
                                if ($intentAssignmentsResponsePage -and $null -ne $intentAssignmentsResponsePage.value) {
                                    $allIntentAssignments.AddRange($intentAssignmentsResponsePage.value)
                                }
                                $currentIntentAssignmentsUri = $intentAssignmentsResponsePage.'@odata.nextLink'
                            } while (![string]::IsNullOrEmpty($currentIntentAssignmentsUri))

                            $assignmentReasons = @()
                            foreach ($intentAssignment in $allIntentAssignments) {
                                $targetGid = $intentAssignment.target.groupId
                                $reasonText = $null
                                if ($intentAssignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $allGroupIds -contains $targetGid) {
                                    if ($targetGid -eq $groupId) {
                                        $reasonText = "Direct Exclusion"
                                    }
                                    elseif ($parentGroupMap.ContainsKey($targetGid)) {
                                        $reasonText = "Inherited Exclusion (via $($parentGroupMap[$targetGid]))"
                                    }
                                }
                                elseif ($intentAssignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $targetGid) {
                                    if ($targetGid -eq $groupId) {
                                        $reasonText = "Direct Assignment"
                                    }
                                    elseif ($parentGroupMap.ContainsKey($targetGid)) {
                                        $reasonText = "Inherited (via $($parentGroupMap[$targetGid]))"
                                    }
                                }
                                if ($reasonText) {
                                    $suffix = Format-AssignmentFilter -FilterId $intentAssignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $intentAssignment.target.deviceAndAppManagementAssignmentFilterType
                                    $assignmentReasons += "$reasonText$suffix"
                                }
                            }

                            if ($assignmentReasons.Count -gt 0) {
                                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                                $relevantPolicies[$esCategory.Key] += $policy
                            }
                        }
                        catch {
                            Write-Warning "Error fetching assignments for ES Intent $($policy.displayName) (ID: $($policy.id)): $($_.Exception.Message)"
                        }
                    }
                }
            }
        }

        # Fetch and process Applications
        Write-Host "Fetching Applications..." -ForegroundColor Yellow
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

            $appId = $app.id
            $allAppAssignments = [System.Collections.ArrayList]::new()
            $currentAppAssignmentsUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            do {
                $appAssignmentsResponsePage = Invoke-MgGraphRequest -Uri $currentAppAssignmentsUri -Method Get
                if ($appAssignmentsResponsePage -and $null -ne $appAssignmentsResponsePage.value) {
                    $allAppAssignments.AddRange($appAssignmentsResponsePage.value)
                }
                $currentAppAssignmentsUri = $appAssignmentsResponsePage.'@odata.nextLink'
            } while (![string]::IsNullOrEmpty($currentAppAssignmentsUri))

            $relevantAppAssignmentReasons = @()
            $intentForGroup = $null

            foreach ($assignmentItem in $allAppAssignments) {
                $appTargetGid = $assignmentItem.target.groupId
                $reasonText = $null
                if ($assignmentItem.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $appTargetGid) {
                    if ($appTargetGid -eq $groupId) {
                        $reasonText = "Direct Assignment"
                    }
                    elseif ($parentGroupMap.ContainsKey($appTargetGid)) {
                        $reasonText = "Inherited (via $($parentGroupMap[$appTargetGid]))"
                    }
                    if (-not $intentForGroup) { $intentForGroup = $assignmentItem.intent }
                }
                elseif ($assignmentItem.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $allGroupIds -contains $appTargetGid) {
                    if ($appTargetGid -eq $groupId) {
                        $reasonText = "Group Exclusion"
                    }
                    elseif ($parentGroupMap.ContainsKey($appTargetGid)) {
                        $reasonText = "Inherited Exclusion (via $($parentGroupMap[$appTargetGid]))"
                    }
                }
                if ($reasonText) {
                    $suffix = Format-AssignmentFilter -FilterId $assignmentItem.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignmentItem.target.deviceAndAppManagementAssignmentFilterType
                    $relevantAppAssignmentReasons += "$reasonText$suffix"
                }
            }

            if ($relevantAppAssignmentReasons.Count -gt 0) {
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($relevantAppAssignmentReasons -join "; ") -Force
                if ($intentForGroup) {
                    switch ($intentForGroup) {
                        "required" { $relevantPolicies.AppsRequired += $appWithReason }
                        "available" { $relevantPolicies.AppsAvailable += $appWithReason }
                        "uninstall" { $relevantPolicies.AppsUninstall += $appWithReason }
                    }
                }
            }
        }

        # Get Platform Scripts
        Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
        $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
        foreach ($script in $platformScripts) {
            $directAssignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.PlatformScripts += $script
                }
            }
        }

        # Get Proactive Remediation Scripts
        Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
        $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
        foreach ($script in $healthScripts) {
            $directAssignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.HealthScripts += $script
                }
            }
        }

        # Get Autopilot Deployment Profiles
        Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
        $autoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
        foreach ($policyProfile in $autoProfiles) {
            $directAssignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policyProfile.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $policyProfile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.DeploymentProfiles += $policyProfile
                }
            }
        }

        # Get Enrollment Status Page Profiles
        Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
        $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
        $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
        foreach ($esp in $espProfiles) {
            $directAssignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id -GroupIds $allGroupIds
            if ($directAssignments.Count -gt 0) {
                $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                if ($assignmentReasons.Count -gt 0) {
                    $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                    $relevantPolicies.ESPProfiles += $esp
                }
            }
        }

        # Get Windows 365 Cloud PC Provisioning Policies
        Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
        try {
            $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
            foreach ($policy in $cloudPCProvisioningPolicies) {
                $directAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id -GroupIds $allGroupIds
                if ($directAssignments.Count -gt 0) {
                    $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                    if ($assignmentReasons.Count -gt 0) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                        $relevantPolicies.CloudPCProvisioningPolicies += $policy
                    }
                }
            }
        }
        catch {
            Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant"
        }

        # Get Windows 365 Cloud PC User Settings
        Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
        try {
            $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
            foreach ($setting in $cloudPCUserSettings) {
                $directAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id -GroupIds $allGroupIds
                if ($directAssignments.Count -gt 0) {
                    $assignmentReasons = Get-GroupAssignmentReasons -Assignments $directAssignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap
                    if ($assignmentReasons.Count -gt 0) {
                        $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                        $relevantPolicies.CloudPCUserSettings += $setting
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

        # Function to format and display policy table (specific to Option 2)
        function Format-PolicyTable {
            param (
                [string]$Title,
                [object[]]$Policies,
                [scriptblock]$GetName
            )
            $localTableSeparator = Get-Separator

            # Create prominent section header
            $headerSeparator = "-" * ($Title.Length + 16)
            Write-Host "`n$headerSeparator" -ForegroundColor Cyan
            Write-Host "------- $Title -------" -ForegroundColor Cyan
            Write-Host "$headerSeparator" -ForegroundColor Cyan

            if ($Policies.Count -eq 0) {
                Write-Host "No $Title found for this group." -ForegroundColor Gray
                Write-Host $localTableSeparator -ForegroundColor Gray
                Write-Host ""
                return
            }

            # Create table header
            $headerFormat = "{0,-40} {1,-15} {2,-20} {3,-30} {4,-35}" -f "Policy Name", "Platform", "Scope Tags", "ID", "Assignment"

            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $localTableSeparator -ForegroundColor Gray

            # Display each policy
            foreach ($policy in $Policies) {
                $name = & $GetName $policy

                if ($name.Length -gt 37) { $name = $name.Substring(0, 34) + "..." }

                $platform = Get-PolicyPlatform -Policy $policy
                if ($platform.Length -gt 12) { $platform = $platform.Substring(0, 9) + "..." }

                $scopeTags = Get-ScopeTagNames -ScopeTagIds $policy.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
                if ($scopeTags.Length -gt 17) { $scopeTags = $scopeTags.Substring(0, 14) + "..." }

                $id = $policy.id
                if ($id.Length -gt 27) { $id = $id.Substring(0, 24) + "..." }

                $assignment = if ($policy.AssignmentReason) { $policy.AssignmentReason } else { "N/A" }
                if ($assignment.Length -gt 32) { $assignment = $assignment.Substring(0, 29) + "..." }

                $rowFormat = "{0,-40} {1,-15} {2,-20} {3,-30} {4,-35}" -f $name, $platform, $scopeTags, $id, $assignment
                if ($assignment -match "Inherited Exclusion") {
                    Write-Host $rowFormat -ForegroundColor Magenta
                }
                elseif ($assignment -match "Direct Exclusion") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                elseif ($assignment -match "Inherited") {
                    Write-Host $rowFormat -ForegroundColor DarkYellow
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $localTableSeparator -ForegroundColor Gray
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
            param($policyProfile)
            if ([string]::IsNullOrWhiteSpace($policyProfile.displayName)) { $policyProfile.name } else { $policyProfile.displayName }
        }

        # Display Windows 365 Cloud PC Provisioning Policies
        Format-PolicyTable -Title "Windows 365 Cloud PC Provisioning Policies" -Policies $relevantPolicies.CloudPCProvisioningPolicies -GetName {
            param($policy)
            if ([string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.name } else { $policy.displayName }
        }

        # Display Windows 365 Cloud PC User Settings
        Format-PolicyTable -Title "Windows 365 Cloud PC User Settings" -Policies $relevantPolicies.CloudPCUserSettings -GetName {
            param($setting)
            if ([string]::IsNullOrWhiteSpace($setting.displayName)) { $setting.name } else { $setting.displayName }
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
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneGroupAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
