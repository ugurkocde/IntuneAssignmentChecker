function Compare-IntuneGroupAssignment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$CompareGroupNames,

        [Parameter()]
        [switch]$IncludeNestedGroups,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

    Write-Host "Compare Group Assignments chosen" -ForegroundColor Green

    # Get Group names to compare from parameter or prompt
    if ($CompareGroupNames) {
        $groupInput = $CompareGroupNames
    }
    else {
        # Prompt for Group names or IDs
        Write-Host "Please enter Group names or Object IDs to compare, separated by commas (,): " -ForegroundColor Cyan
        Write-Host "Example: 'Marketing Team, 12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
        $groupInput = Read-Host
    }

    $groupInputs = $groupInput -split ',' | ForEach-Object { $_.Trim() }

    if ($groupInputs.Count -lt 2) {
        Write-Host "Please provide at least two groups to compare." -ForegroundColor Red
        return
    }

    # Determine if nested group checking should be enabled
    $checkNestedGroupsCompare = $false
    if ($IncludeNestedGroups) {
        $checkNestedGroupsCompare = $true
    }
    elseif (-not $CompareGroupNames) {
        $nestedPromptCompare = Read-Host "Include assignments inherited from parent groups? (y/n)"
        if ($nestedPromptCompare -match '^[Yy]') {
            $checkNestedGroupsCompare = $true
        }
    }

    # Before caching starts, initialize the group assignments hashtable
    $groupAssignments = [ordered]@{}

    # Process each group input
    $resolvedGroups = @{}
    foreach ($groupInput in $groupInputs) {
        Write-Host "`nProcessing input: $groupInput" -ForegroundColor Yellow

        # Initialize variables
        $groupId = $null
        $groupName = $null
        $allGroupIds = @()
        $parentGroupMap = @{}

        # Check if input is a GUID
        if ($groupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            try {
                # Get group info from Graph API
                $groupUri = "$GraphEndpoint/v1.0/groups/$groupInput"
                $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method Get
                $groupId = $groupResponse.id
                $groupName = $groupResponse.displayName
                $resolvedGroups[$groupId] = $groupName

                # Initialize collections for this group
                $groupAssignments[$groupName] = @{
                    DeviceConfigs              = [System.Collections.ArrayList]::new()
                    SettingsCatalog            = [System.Collections.ArrayList]::new()
                    CompliancePolicies         = [System.Collections.ArrayList]::new()
                    RequiredApps               = [System.Collections.ArrayList]::new()
                    AvailableApps              = [System.Collections.ArrayList]::new()
                    UninstallApps              = [System.Collections.ArrayList]::new()
                    PlatformScripts            = [System.Collections.ArrayList]::new()
                    HealthScripts              = [System.Collections.ArrayList]::new()
                    AntivirusProfiles          = [System.Collections.ArrayList]::new()
                    DiskEncryptionProfiles     = [System.Collections.ArrayList]::new()
                    FirewallProfiles           = [System.Collections.ArrayList]::new()
                    EndpointDetectionProfiles  = [System.Collections.ArrayList]::new()
                    AttackSurfaceProfiles      = [System.Collections.ArrayList]::new()
                    AccountProtectionProfiles  = [System.Collections.ArrayList]::new()
                }

                Write-Host "Found group by ID: $groupName" -ForegroundColor Green

                # Build effective group IDs for nested group support
                $allGroupIds = @($groupId)
                $parentGroupMap = @{}
                if ($checkNestedGroupsCompare) {
                    $parentGroups = Get-TransitiveGroupMembership -GroupId $groupId
                    if ($parentGroups.Count -gt 0) {
                        foreach ($pg in $parentGroups) {
                            $allGroupIds += $pg.id
                            $parentGroupMap[$pg.id] = $pg.displayName
                        }
                        Write-Host "  Found $($parentGroups.Count) parent group(s)" -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Host "No group found with ID: $groupInput" -ForegroundColor Red
                continue
            }
        }
        else {
            # Try to find group by display name
            $groupUri = "$GraphEndpoint/v1.0/groups?`$filter=displayName eq '$groupInput'"
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
            $resolvedGroups[$groupId] = $groupName

            # Initialize collections for this group
            $groupAssignments[$groupName] = @{
                DeviceConfigs              = [System.Collections.ArrayList]::new()
                SettingsCatalog            = [System.Collections.ArrayList]::new()
                CompliancePolicies         = [System.Collections.ArrayList]::new()
                RequiredApps               = [System.Collections.ArrayList]::new()
                AvailableApps              = [System.Collections.ArrayList]::new()
                UninstallApps              = [System.Collections.ArrayList]::new()
                PlatformScripts            = [System.Collections.ArrayList]::new()
                HealthScripts              = [System.Collections.ArrayList]::new()
                AntivirusProfiles          = [System.Collections.ArrayList]::new()
                DiskEncryptionProfiles     = [System.Collections.ArrayList]::new()
                FirewallProfiles           = [System.Collections.ArrayList]::new()
                EndpointDetectionProfiles  = [System.Collections.ArrayList]::new()
                AttackSurfaceProfiles      = [System.Collections.ArrayList]::new()
                AccountProtectionProfiles  = [System.Collections.ArrayList]::new()
            }

            Write-Host "Found group by name: $groupName (ID: $groupId)" -ForegroundColor Green

            # Build effective group IDs for nested group support
            $allGroupIds = @($groupId)
            $parentGroupMap = @{}
            if ($checkNestedGroupsCompare) {
                $parentGroups = Get-TransitiveGroupMembership -GroupId $groupId
                if ($parentGroups.Count -gt 0) {
                    foreach ($pg in $parentGroups) {
                        $allGroupIds += $pg.id
                        $parentGroupMap[$pg.id] = $pg.displayName
                    }
                    Write-Host "  Found $($parentGroups.Count) parent group(s)" -ForegroundColor Green
                }
            }
        }

        # Process Device Configurations
        $deviceConfigsUri = "$GraphEndpoint/beta/deviceManagement/deviceConfigurations"
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
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceConfigurations('$configId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            # Check for both inclusion and exclusion assignments
            $hasAssignment = $assignmentResponse.value | Where-Object {
                $allGroupIds -contains $_.target.groupId -and
                ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
            }
            if ($hasAssignment) {
                $isExclusion = $hasAssignment | Where-Object {
                    $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                }
                $isInherited = $hasAssignment | Where-Object {
                    $_.target.groupId -ne $groupId
                }
                $suffix = ""
                if ($isExclusion) { $suffix += " [EXCLUDED]" }
                if ($isInherited) { $suffix += " [INHERITED]" }
                $displayName = "$($config.displayName)$suffix"
                [void]$groupAssignments[$groupName].DeviceConfigs.Add($displayName)
            }
        }
        Write-Host "`rFetching Device Configuration $totalDeviceConfigs of $totalDeviceConfigs" -NoNewline
        Start-Sleep -Milliseconds 100
        Write-Host ""  # Move to the next line after the loop

        # Process Settings Catalog
        $settingsCatalogUri = "$GraphEndpoint/beta/deviceManagement/configurationPolicies"
        $settingsCatalogResponse = Invoke-MgGraphRequest -Uri $settingsCatalogUri -Method Get

        foreach ($policy in $settingsCatalogResponse.value) {
            $policyId = $policy.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/configurationPolicies('$policyId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            # Check for both inclusion and exclusion assignments
            $hasAssignment = $assignmentResponse.value | Where-Object {
                $allGroupIds -contains $_.target.groupId -and
                ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
            }
            if ($hasAssignment) {
                $isExclusion = $hasAssignment | Where-Object {
                    $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                }
                $isInherited = $hasAssignment | Where-Object {
                    $_.target.groupId -ne $groupId
                }
                $suffix = ""
                if ($isExclusion) { $suffix += " [EXCLUDED]" }
                if ($isInherited) { $suffix += " [INHERITED]" }
                $displayName = "$($policy.name)$suffix"
                [void]$groupAssignments[$groupName].SettingsCatalog.Add($displayName)
            }
        }

        # Process Compliance Policies
        $complianceUri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies"
        $complianceResponse = Invoke-MgGraphRequest -Uri $complianceUri -Method Get

        foreach ($policy in $complianceResponse.value) {
            $policyId = $policy.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies('$policyId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            # Check for both inclusion and exclusion assignments
            $hasAssignment = $assignmentResponse.value | Where-Object {
                $allGroupIds -contains $_.target.groupId -and
                ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -or
                $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
            }
            if ($hasAssignment) {
                $isExclusion = $hasAssignment | Where-Object {
                    $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                }
                $isInherited = $hasAssignment | Where-Object {
                    $_.target.groupId -ne $groupId
                }
                $suffix = ""
                if ($isExclusion) { $suffix += " [EXCLUDED]" }
                if ($isInherited) { $suffix += " [INHERITED]" }
                $displayName = "$($policy.displayName)$suffix"
                [void]$groupAssignments[$groupName].CompliancePolicies.Add($displayName)
            }
        }

        # Process Apps
        $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
        $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get

        foreach ($app in $appResponse.value) {
            # Skip built-in and Microsoft apps
            if ($app.isFeatured -or $app.isBuiltIn) {
                continue
            }

            $appId = $app.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            foreach ($assignment in $assignmentResponse.value) {
                if ($allGroupIds -contains $assignment.target.groupId) {
                    $inheritedSuffix = if ($assignment.target.groupId -ne $groupId) { " [INHERITED]" } else { "" }
                    switch ($assignment.intent) {
                        "required" { [void]$groupAssignments[$groupName].RequiredApps.Add("$($app.displayName)$inheritedSuffix") }
                        "available" { [void]$groupAssignments[$groupName].AvailableApps.Add("$($app.displayName)$inheritedSuffix") }
                        "uninstall" { [void]$groupAssignments[$groupName].UninstallApps.Add("$($app.displayName)$inheritedSuffix") }
                    }
                }
            }
        }

        # Process Platform Scripts (PowerShell)
        $scriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceManagementScripts"
        $scriptsResponse = Invoke-MgGraphRequest -Uri $scriptsUri -Method Get
        # For PowerShell scripts, we need to check the script type
        foreach ($script in $scriptsResponse.value) {
            $scriptId = $script.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceManagementScripts('$scriptId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            $hasAssignment = $assignmentResponse.value | Where-Object { $allGroupIds -contains $_.target.groupId }
            if ($hasAssignment) {
                $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                $scriptInfo = "$($script.displayName) (PowerShell)$suffix"
                [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
            }
        }

        # Process Shell Scripts (macOS)
        $shellScriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceShellScripts"
        $shellScriptsResponse = Invoke-MgGraphRequest -Uri $shellScriptsUri -Method Get
        # For Shell scripts, we need to check the script type
        foreach ($script in $shellScriptsResponse.value) {
            $scriptId = $script.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceShellScripts('$scriptId')/groupAssignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            $hasAssignment = $assignmentResponse.value | Where-Object { $allGroupIds -contains $_.targetGroupId }
            if ($hasAssignment) {
                $isInherited = $hasAssignment | Where-Object { $_.targetGroupId -ne $groupId }
                $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                $scriptInfo = "$($script.displayName) (Shell)$suffix"
                [void]$groupAssignments[$groupName].PlatformScripts.Add($scriptInfo)
            }
        }

        # Fetch and process Proactive Remediation Scripts (deviceHealthScripts)
        $healthScriptsUri = "$GraphEndpoint/beta/deviceManagement/deviceHealthScripts"
        $healthScriptsResponse = Invoke-MgGraphRequest -Uri $healthScriptsUri -Method Get
        foreach ($script in $healthScriptsResponse.value) {
            $scriptId = $script.id
            $assignmentsUri = "$GraphEndpoint/beta/deviceManagement/deviceHealthScripts('$scriptId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            $hasAssignment = $assignmentResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
            if ($hasAssignment) {
                $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                [void]$groupAssignments[$groupName].HealthScripts.Add("$($script.displayName)$suffix")
            }
        }

        # Get Endpoint Security - Antivirus Policies
        $allIntentsForAntivirusCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAntivirusCompare
        $antivirusPolicies = $allIntentsForAntivirusCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
        if ($antivirusPolicies) {
            foreach ($policy in $antivirusPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].AntivirusProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }

        # Get Endpoint Security - Disk Encryption Policies
        $allIntentsForDiskEncCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForDiskEncCompare
        $diskEncryptionPolicies = $allIntentsForDiskEncCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
        if ($diskEncryptionPolicies) {
            foreach ($policy in $diskEncryptionPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].DiskEncryptionProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }

        # Get Endpoint Security - Firewall Policies
        $allIntentsForFirewallCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForFirewallCompare
        $firewallPolicies = $allIntentsForFirewallCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
        if ($firewallPolicies) {
            foreach ($policy in $firewallPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].FirewallProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }

        # Get Endpoint Security - Endpoint Detection and Response Policies
        $allIntentsForEDRCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForEDRCompare
        $edrPolicies = $allIntentsForEDRCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
        if ($edrPolicies) {
            foreach ($policy in $edrPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].EndpointDetectionProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }

        # Get Endpoint Security - Attack Surface Reduction Policies
        $allIntentsForASRCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForASRCompare
        $asrPolicies = $allIntentsForASRCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
        if ($asrPolicies) {
            foreach ($policy in $asrPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].AttackSurfaceProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }

        # Get Endpoint Security - Account Protection Policies
        $allIntentsForAccountProtectionCompare = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentsForAccountProtectionCompare
        $accountProtectionPolicies = $allIntentsForAccountProtectionCompare | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
        if ($accountProtectionPolicies) {
            foreach ($policy in $accountProtectionPolicies) {
                $assignments = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $hasAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $allGroupIds -contains $_.target.groupId }
                if ($hasAssignment) {
                    $isInherited = $hasAssignment | Where-Object { $_.target.groupId -ne $groupId }
                    $suffix = if ($isInherited) { " [INHERITED]" } else { "" }
                    [void]$groupAssignments[$groupName].AccountProtectionProfiles.Add("$($policy.displayName)$suffix")
                }
            }
        }
    }

    # Comparison Results section
    Write-Host "`nComparison Results:" -ForegroundColor Cyan
    Write-Host "Comparing assignments between groups:" -ForegroundColor White
    foreach ($groupName in $groupAssignments.Keys) {
        Write-Host "  * $groupName" -ForegroundColor White
    }
    Write-Host ""

    # Update categories to include "Proactive Remediation Scripts"
    $categories = [ordered]@{
        "Device Configurations"               = "DeviceConfigs"
        "Settings Catalog"                    = "SettingsCatalog"
        "Compliance Policies"                 = "CompliancePolicies"
        "Required Apps"                       = "RequiredApps"
        "Available Apps"                      = "AvailableApps"
        "Uninstall Apps"                      = "UninstallApps"
        "Platform Scripts"                    = "PlatformScripts"
        "Proactive Remediation Scripts"       = "HealthScripts"
        "Endpoint Security - Antivirus"       = "AntivirusProfiles"
        "Endpoint Security - Disk Encryption" = "DiskEncryptionProfiles"
        "Endpoint Security - Firewall"        = "FirewallProfiles"
        "Endpoint Security - EDR"             = "EndpointDetectionProfiles"
        "Endpoint Security - ASR"             = "AttackSurfaceProfiles"
        "Endpoint Security - Account Protection" = "AccountProtectionProfiles"
    }

    # Collect all unique base policy names (strip tag suffixes for deduplication)
    $uniqueBasePolicies = [System.Collections.ArrayList]@()
    foreach ($groupName in $groupAssignments.Keys) {
        foreach ($categoryKey in $categories.Values) {
            foreach ($policy in $groupAssignments[$groupName][$categoryKey]) {
                $baseName = $policy -replace ' \[(EXCLUDED|INHERITED)\]', ''
                $baseName = $baseName.Trim()
                if ($uniqueBasePolicies -notcontains $baseName) {
                    $null = $uniqueBasePolicies.Add($baseName)
                }
            }
        }
    }

    Write-Host "Found $($uniqueBasePolicies.Count) unique policies/apps/scripts across all groups`n" -ForegroundColor Yellow

    $groupNames = @($groupAssignments.Keys)

    # Display comparison for each category in table format
    foreach ($category in $categories.Keys) {
        $categoryKey = $categories[$category]

        # Collect base policy names that belong to this category
        $categoryPolicies = [System.Collections.ArrayList]@()
        foreach ($baseName in $uniqueBasePolicies) {
            $isInCategory = $false
            foreach ($g in $groupNames) {
                $matchFound = $groupAssignments[$g][$categoryKey] | Where-Object {
                    ($_ -replace ' \[(EXCLUDED|INHERITED)\]', '').Trim() -eq $baseName
                }
                if ($matchFound) {
                    $isInCategory = $true
                    break
                }
            }
            if ($isInCategory) {
                $null = $categoryPolicies.Add($baseName)
            }
        }

        Write-Host "=== $category ===" -ForegroundColor Cyan

        if ($categoryPolicies.Count -eq 0) {
            Write-Host "No assignments found in this category" -ForegroundColor Gray
            Write-Host ""
            continue
        }

        # Calculate column widths
        $maxPolicyLen = ($categoryPolicies | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        $maxPolicyLen = [Math]::Max($maxPolicyLen, 6)   # min width for "Policy" header
        $maxPolicyLen = [Math]::Min($maxPolicyLen, 50)  # cap at 50 chars

        $groupColWidths = @{}
        foreach ($g in $groupNames) {
            $groupColWidths[$g] = [Math]::Max($g.Length, 10)
        }

        # Header row
        $header = ("Policy".PadRight($maxPolicyLen + 2))
        foreach ($g in $groupNames) {
            $header += ($g.PadRight($groupColWidths[$g] + 2))
        }
        Write-Host $header -ForegroundColor White

        # Separator row
        $sep = ("-" * ($maxPolicyLen + 2))
        foreach ($g in $groupNames) {
            $sep += ("-" * ($groupColWidths[$g] + 2))
        }
        Write-Host $sep -ForegroundColor Gray

        # Data rows
        foreach ($baseName in $categoryPolicies) {
            $displayName = if ($baseName.Length -gt 50) { $baseName.Substring(0, 47) + "..." } else { $baseName }
            $row = $displayName.PadRight($maxPolicyLen + 2)

            foreach ($g in $groupNames) {
                $assignments = $groupAssignments[$g][$categoryKey]
                # Find all matching entries for this base name
                $matchingEntries = $assignments | Where-Object {
                    ($_ -replace ' \[(EXCLUDED|INHERITED)\]', '').Trim() -eq $baseName
                }
                $cell = ""
                if ($matchingEntries) {
                    $hasExcluded = $matchingEntries | Where-Object { $_ -match '\[EXCLUDED\]' }
                    $hasInherited = $matchingEntries | Where-Object { $_ -match '\[INHERITED\]' }
                    if ($hasExcluded -and $hasInherited) {
                        $cell = "IE"
                    }
                    elseif ($hasExcluded) {
                        $cell = "E"
                    }
                    elseif ($hasInherited) {
                        $cell = "I"
                    }
                    else {
                        $cell = "X"
                    }
                }
                $row += $cell.PadRight($groupColWidths[$g] + 2)
            }
            Write-Host $row -ForegroundColor Yellow
        }
        Write-Host ""
    }

    # Legend
    Write-Host "Legend: X = Included, E = Excluded, I = Inherited, IE = Inherited+Excluded" -ForegroundColor Gray
    Write-Host ""

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

    # Create comparison results with one column per group
    $comparisonResults = [System.Collections.ArrayList]@()
    foreach ($category in $categories.Keys) {
        $categoryKey = $categories[$category]
        foreach ($baseName in $uniqueBasePolicies) {
            # Check if this policy belongs to this category
            $isInCategory = $false
            foreach ($g in $groupNames) {
                $matchFound = $groupAssignments[$g][$categoryKey] | Where-Object {
                    ($_ -replace ' \[(EXCLUDED|INHERITED)\]', '').Trim() -eq $baseName
                }
                if ($matchFound) {
                    $isInCategory = $true
                    break
                }
            }
            if (-not $isInCategory) { continue }

            $props = [ordered]@{
                Category   = $category
                PolicyName = $baseName
            }
            foreach ($g in $groupNames) {
                $matchingEntries = $groupAssignments[$g][$categoryKey] | Where-Object {
                    ($_ -replace ' \[(EXCLUDED|INHERITED)\]', '').Trim() -eq $baseName
                }
                $val = ""
                if ($matchingEntries) {
                    $hasExcluded = $matchingEntries | Where-Object { $_ -match '\[EXCLUDED\]' }
                    $hasInherited = $matchingEntries | Where-Object { $_ -match '\[INHERITED\]' }
                    if ($hasExcluded -and $hasInherited) {
                        $val = "Inherited+Excluded"
                    }
                    elseif ($hasExcluded) {
                        $val = "Excluded"
                    }
                    elseif ($hasInherited) {
                        $val = "Inherited"
                    }
                    else {
                        $val = "Included"
                    }
                }
                $props[$g] = $val
            }
            [void]$comparisonResults.Add([PSCustomObject]$props)
        }
    }

    # Export results if requested
    if ($ExportToCSV) {
        $csvExportPath = if ($ExportPath) {
            $ExportPath
        }
        else {
            $null
        }

        if ($csvExportPath) {
            $comparisonResults | Export-Csv -Path $csvExportPath -NoTypeInformation
            Write-Host "Results exported to $csvExportPath" -ForegroundColor Green
        }
    }
    elseif (-not $CompareGroupNames) {
        $export = Read-Host "Would you like to export the comparison results to CSV? (y/n)"
        if ($export -match '^[Yy]') {
            $csvExportPath = Show-SaveFileDialog -DefaultFileName "IntuneGroupAssignmentComparison.csv"
            if ($csvExportPath) {
                $comparisonResults | Export-Csv -Path $csvExportPath -NoTypeInformation
                Write-Host "Results exported to $csvExportPath" -ForegroundColor Green
            }
        }
    }
}
