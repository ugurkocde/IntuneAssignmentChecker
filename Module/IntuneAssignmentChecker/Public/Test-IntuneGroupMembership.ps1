function Test-IntuneGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserPrincipalNames,

        [Parameter()]
        [string]$SimulateTargetGroup,

        [Parameter()]
        [string]$GroupNames,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Group Membership Impact Analysis selected" -ForegroundColor Green

    # Get User Principal Name
    if ($UserPrincipalNames) {
        $simUpnInput = $UserPrincipalNames
    }
    else {
        Write-Host "Please enter the User Principal Name: " -ForegroundColor Cyan
        $simUpnInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($simUpnInput)) {
        Write-Host "No UPN provided. Please try again with a valid UPN." -ForegroundColor Red
        return
    }

    $simUpn = ($simUpnInput -split ',')[0].Trim()

    # Validate UPN format
    if ($simUpn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Host "Invalid UPN format: '$simUpn'. Expected: user@domain.com" -ForegroundColor Red
        return
    }

    # Get Target Group - SimulateTargetGroup takes precedence over GroupNames
    if ($SimulateTargetGroup) {
        $simGroupInput = $SimulateTargetGroup
    }
    elseif ($GroupNames) {
        $simGroupInput = $GroupNames
    }
    else {
        Write-Host "Please enter the Target Group name or Object ID: " -ForegroundColor Cyan
        Write-Host "Example: 'Marketing Team' or '12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
        $simGroupInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($simGroupInput)) {
        Write-Host "No group provided. Please try again." -ForegroundColor Red
        return
    }

    $simGroupInput = ($simGroupInput -split ',')[0].Trim()

    # Resolve user
    Write-Host "Looking up user: $simUpn" -ForegroundColor Yellow
    $simUserInfo = Get-UserInfo -UserPrincipalName $simUpn
    if (-not $simUserInfo.Success) {
        Write-Host "User not found: $simUpn" -ForegroundColor Red
        return
    }

    # Resolve target group
    Write-Host "Looking up group: $simGroupInput" -ForegroundColor Yellow
    $simTargetGroupId = $null
    $simTargetGroupName = $null

    if ($simGroupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        $simGroupInfo = Get-GroupInfo -GroupId $simGroupInput
        if (-not $simGroupInfo.Success) {
            Write-Host "No group found with ID: $simGroupInput" -ForegroundColor Red
            return
        }
        $simTargetGroupId = $simGroupInfo.Id
        $simTargetGroupName = $simGroupInfo.DisplayName
    }
    else {
        $simGroupUri = "$GraphEndpoint/v1.0/groups?`$filter=displayName eq '$simGroupInput'"
        $simGroupResponse = Invoke-MgGraphRequest -Uri $simGroupUri -Method Get

        if ($simGroupResponse.value.Count -eq 0) {
            Write-Host "No group found with name: $simGroupInput" -ForegroundColor Red
            return
        }
        elseif ($simGroupResponse.value.Count -gt 1) {
            Write-Host "Multiple groups found with name: $simGroupInput. Please use the Object ID instead:" -ForegroundColor Red
            foreach ($g in $simGroupResponse.value) {
                Write-Host "  - $($g.displayName) (ID: $($g.id))" -ForegroundColor Yellow
            }
            return
        }

        $simTargetGroupId = $simGroupResponse.value[0].id
        $simTargetGroupName = $simGroupResponse.value[0].displayName
    }

    Write-Host "Target group: $simTargetGroupName (ID: $simTargetGroupId)" -ForegroundColor Green

    # Get user's current group memberships
    try {
        $simUserGroups = Get-GroupMemberships -ObjectId $simUserInfo.Id -ObjectType "User"
        $simCurrentGroupIds = @($simUserGroups | Where-Object { $_.id } | ForEach-Object { $_.id })
    }
    catch {
        Write-Host "Error fetching group memberships: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Check if user is already in the target group
    $alreadyMember = $simCurrentGroupIds -contains $simTargetGroupId
    if ($alreadyMember) {
        Write-Host "`nNote: User is already a member of '$simTargetGroupName'. Showing policies received via this group." -ForegroundColor Yellow
    }

    # Get target group's parent groups (transitive)
    $simTargetParentGroups = Get-TransitiveGroupMembership -GroupId $simTargetGroupId
    $simTargetAllGroupIds = @($simTargetGroupId)
    if ($simTargetParentGroups) {
        $simTargetAllGroupIds += $simTargetParentGroups.id
    }

    # Build simulated group set (current + target + target's parents, deduplicated)
    $simSimulatedGroupIds = @($simCurrentGroupIds + $simTargetAllGroupIds | Select-Object -Unique)

    Write-Host "Analyzing impact..." -ForegroundColor Yellow

    $totalCategories = 18
    $currentCategory = 0

    # Initialize delta collections
    $deltaPolicies = @{
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
    $conflictPolicies = [System.Collections.ArrayList]::new()

    # --- Device Configurations ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Device Configurations..." -ForegroundColor Yellow
    $simDeviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
    foreach ($config in $simDeviceConfigs) {
        $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $config | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.DeviceConfigs.Add($config)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Device Configuration"; PolicyName = if ($config.displayName) { $config.displayName } else { $config.name }; PolicyId = $config.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Settings Catalog ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Settings Catalog Policies..." -ForegroundColor Yellow
    $simSettingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
    foreach ($policy in $simSettingsCatalog) {
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.SettingsCatalog.Add($policy)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Settings Catalog"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Compliance Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Compliance Policies..." -ForegroundColor Yellow
    $simCompliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    foreach ($policy in $simCompliancePolicies) {
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.CompliancePolicies.Add($policy)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Compliance Policy"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- App Protection Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching App Protection Policies..." -ForegroundColor Yellow
    $simAppProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
    foreach ($policy in $simAppProtectionPolicies) {
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
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { $assignmentReason = "All Users" }
                        '#microsoft.graph.groupAssignmentTarget' { $assignmentReason = "Group Assignment" }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' { $assignmentReason = "Group Exclusion" }
                    }
                    if ($assignmentReason) {
                        $assignments += @{ Reason = $assignmentReason; GroupId = $assignment.target.groupId }
                    }
                }

                if ($assignments.Count -gt 0) {
                    $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                    if ($delta.IsNewPolicy) {
                        $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                        [void]$deltaPolicies.AppProtectionPolicies.Add($policy)
                    }
                    elseif ($delta.IsConflict) {
                        [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "App Protection Policy"; PolicyName = $policy.displayName; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                    }
                }
            }
            catch {
                Write-Host "Error fetching assignments for policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # --- App Configuration Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching App Configuration Policies..." -ForegroundColor Yellow
    $simAppConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
    foreach ($policy in $simAppConfigPolicies) {
        $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.AppConfigurationPolicies.Add($policy)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "App Configuration Policy"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Applications ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Applications..." -ForegroundColor Yellow
    $simAppUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
    $simAppResponse = Invoke-MgGraphRequest -Uri $simAppUri -Method Get
    $simAllApps = $simAppResponse.value
    while ($simAppResponse.'@odata.nextLink') {
        $simAppResponse = Invoke-MgGraphRequest -Uri $simAppResponse.'@odata.nextLink' -Method Get
        $simAllApps += $simAppResponse.value
    }
    $simTotalApps = $simAllApps.Count
    $simCurrentApp = 0

    foreach ($app in $simAllApps) {
        if ($app.isFeatured -or $app.isBuiltIn) { continue }

        $simCurrentApp++
        Write-Host "`rFetching Application $simCurrentApp of $simTotalApps" -NoNewline
        $appId = $app.id

        try {
            $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            # Check current assignment status
            $currentExcluded = $false
            $currentIncluded = $false
            $simExcluded = $false
            $simIncluded = $false
            $appIntent = $null

            foreach ($assignment in $assignmentResponse.value) {
                $targetType = $assignment.target.'@odata.type'
                $targetGroupId = $assignment.target.groupId

                if ($targetType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    if ($simCurrentGroupIds -contains $targetGroupId) { $currentExcluded = $true }
                    if ($simSimulatedGroupIds -contains $targetGroupId) { $simExcluded = $true }
                }
                elseif ($targetType -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                    $currentIncluded = $true
                    $simIncluded = $true
                    $appIntent = $assignment.intent
                }
                elseif ($targetType -eq '#microsoft.graph.groupAssignmentTarget') {
                    if ($simCurrentGroupIds -contains $targetGroupId) { $currentIncluded = $true; $appIntent = $assignment.intent }
                    if ($simSimulatedGroupIds -contains $targetGroupId) { $simIncluded = $true; $appIntent = $assignment.intent }
                }
            }

            $currentHasApp = $currentIncluded -and -not $currentExcluded
            $simHasApp = $simIncluded -and -not $simExcluded

            if ($simHasApp -and -not $currentHasApp) {
                $appWithReason = $app.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Group Assignment" -Force
                $appWithReason | Add-Member -NotePropertyName 'AssignmentIntent' -NotePropertyValue $appIntent -Force
                switch ($appIntent) {
                    "required" { [void]$deltaPolicies.AppsRequired.Add($appWithReason) }
                    "available" { [void]$deltaPolicies.AppsAvailable.Add($appWithReason) }
                    "uninstall" { [void]$deltaPolicies.AppsUninstall.Add($appWithReason) }
                }
            }
            elseif ($currentExcluded -and $simExcluded) {
                # Check if target group specifically includes this app while user is excluded
                foreach ($assignment in $assignmentResponse.value) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                        $simTargetAllGroupIds -contains $assignment.target.groupId -and
                        $simCurrentGroupIds -notcontains $assignment.target.groupId) {
                        $appName = if ($app.displayName) { $app.displayName } else { $app.name }
                        [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Application ($($assignment.intent))"; PolicyName = $appName; PolicyId = $app.id; ConflictType = "Currently excluded; target group includes it" })
                        break
                    }
                }
            }
        }
        catch {
            Write-Host "`nError fetching assignments for app $($app.displayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "`rFetching Application $simTotalApps of $simTotalApps" -NoNewline
    Start-Sleep -Milliseconds 100
    Write-Host ""

    # --- Platform Scripts ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Platform Scripts..." -ForegroundColor Yellow
    $simPlatformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
    foreach ($script in $simPlatformScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.PlatformScripts.Add($script)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Platform Script"; PolicyName = if ($script.displayName) { $script.displayName } else { $script.name }; PolicyId = $script.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Proactive Remediation Scripts ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
    $simHealthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
    foreach ($script in $simHealthScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $script | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.HealthScripts.Add($script)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Proactive Remediation Script"; PolicyName = if ($script.displayName) { $script.displayName } else { $script.name }; PolicyId = $script.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Endpoint Security: Antivirus ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Antivirus Policies..." -ForegroundColor Yellow
    $simProcessedAntivirusIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForAntivirus = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingAntivirus = $simConfigPoliciesForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
    if ($simMatchingAntivirus) {
        foreach ($policy in $simMatchingAntivirus) {
            if ($simProcessedAntivirusIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AntivirusProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Antivirus"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForAntivirus = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForAntivirus
    $simMatchingIntentsAntivirus = $simAllIntentsForAntivirus | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAntivirus' }
    if ($simMatchingIntentsAntivirus) {
        foreach ($policy in $simMatchingIntentsAntivirus) {
            if ($simProcessedAntivirusIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AntivirusProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Antivirus"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Endpoint Security: Disk Encryption ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Disk Encryption Policies..." -ForegroundColor Yellow
    $simProcessedDiskEncIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForDiskEnc = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingDiskEnc = $simConfigPoliciesForDiskEnc | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
    if ($simMatchingDiskEnc) {
        foreach ($policy in $simMatchingDiskEnc) {
            if ($simProcessedDiskEncIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.DiskEncryptionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Disk Encryption"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForDiskEnc = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForDiskEnc
    $simMatchingIntentsDiskEnc = $simAllIntentsForDiskEnc | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityDiskEncryption' }
    if ($simMatchingIntentsDiskEnc) {
        foreach ($policy in $simMatchingIntentsDiskEnc) {
            if ($simProcessedDiskEncIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.DiskEncryptionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Disk Encryption"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Endpoint Security: Firewall ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Firewall Policies..." -ForegroundColor Yellow
    $simProcessedFirewallIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForFirewall = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingFirewall = $simConfigPoliciesForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
    if ($simMatchingFirewall) {
        foreach ($policy in $simMatchingFirewall) {
            if ($simProcessedFirewallIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.FirewallProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Firewall"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForFirewall = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForFirewall
    $simMatchingIntentsFirewall = $simAllIntentsForFirewall | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityFirewall' }
    if ($simMatchingIntentsFirewall) {
        foreach ($policy in $simMatchingIntentsFirewall) {
            if ($simProcessedFirewallIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.FirewallProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Firewall"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Endpoint Security: EDR ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Endpoint Detection and Response Policies..." -ForegroundColor Yellow
    $simProcessedEDRIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForEDR = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingEDR = $simConfigPoliciesForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
    if ($simMatchingEDR) {
        foreach ($policy in $simMatchingEDR) {
            if ($simProcessedEDRIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.EndpointDetectionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - EDR"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForEDR = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForEDR
    $simMatchingIntentsEDR = $simAllIntentsForEDR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse' }
    if ($simMatchingIntentsEDR) {
        foreach ($policy in $simMatchingIntentsEDR) {
            if ($simProcessedEDRIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.EndpointDetectionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - EDR"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Endpoint Security: Attack Surface Reduction ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Attack Surface Reduction Policies..." -ForegroundColor Yellow
    $simProcessedASRIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForASR = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingASR = $simConfigPoliciesForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
    if ($simMatchingASR) {
        foreach ($policy in $simMatchingASR) {
            if ($simProcessedASRIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AttackSurfaceProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - ASR"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForASR = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForASR
    $simMatchingIntentsASR = $simAllIntentsForASR | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' }
    if ($simMatchingIntentsASR) {
        foreach ($policy in $simMatchingIntentsASR) {
            if ($simProcessedASRIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AttackSurfaceProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - ASR"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Endpoint Security: Account Protection ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Account Protection Policies..." -ForegroundColor Yellow
    $simProcessedAcctProtIds = [System.Collections.Generic.HashSet[string]]::new()

    $simConfigPoliciesForAcctProt = Get-IntuneEntities -EntityType "configurationPolicies"
    $simMatchingAcctProt = $simConfigPoliciesForAcctProt | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
    if ($simMatchingAcctProt) {
        foreach ($policy in $simMatchingAcctProt) {
            if ($simProcessedAcctProtIds.Add($policy.id)) {
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AccountProtectionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Account Protection"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    $simAllIntentsForAcctProt = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $simAllIntentsForAcctProt
    $simMatchingIntentsAcctProt = $simAllIntentsForAcctProt | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq 'endpointSecurityAccountProtection' }
    if ($simMatchingIntentsAcctProt) {
        foreach ($policy in $simMatchingIntentsAcctProt) {
            if ($simProcessedAcctProtIds.Add($policy.id)) {
                $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                $assignmentDetailsList = foreach ($assignment in $assignmentsResponse.value) {
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
                $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignmentDetailsList -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
                if ($delta.IsNewPolicy) {
                    $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                    [void]$deltaPolicies.AccountProtectionProfiles.Add($policy)
                }
                elseif ($delta.IsConflict) {
                    [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Endpoint Security - Account Protection"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
                }
            }
        }
    }

    # --- Autopilot Deployment Profiles ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
    $simAutoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    foreach ($profile in $simAutoProfiles) {
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $profile | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.DeploymentProfiles.Add($profile)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Autopilot Deployment Profile"; PolicyName = if ($profile.displayName) { $profile.displayName } else { $profile.name }; PolicyId = $profile.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Enrollment Status Page Profiles ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
    $simEnrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $simEspProfiles = $simEnrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    foreach ($esp in $simEspProfiles) {
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
        if ($delta.IsNewPolicy) {
            $esp | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            [void]$deltaPolicies.ESPProfiles.Add($esp)
        }
        elseif ($delta.IsConflict) {
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Enrollment Status Page"; PolicyName = if ($esp.displayName) { $esp.displayName } else { $esp.name }; PolicyId = $esp.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    # --- Windows 365 Cloud PC Provisioning Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
    try {
        $simCloudPCProvisioning = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
        foreach ($policy in $simCloudPCProvisioning) {
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
            $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
            if ($delta.IsNewPolicy) {
                $policy | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                [void]$deltaPolicies.CloudPCProvisioningPolicies.Add($policy)
            }
            elseif ($delta.IsConflict) {
                [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Cloud PC Provisioning"; PolicyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }; PolicyId = $policy.id; ConflictType = "Currently excluded; target group includes it" })
            }
        }
    }
    catch {
        Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant"
    }

    # --- Windows 365 Cloud PC User Settings ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
    try {
        $simCloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
        foreach ($setting in $simCloudPCUserSettings) {
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
            $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons @("All Users")
            if ($delta.IsNewPolicy) {
                $setting | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
                [void]$deltaPolicies.CloudPCUserSettings.Add($setting)
            }
            elseif ($delta.IsConflict) {
                [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Cloud PC User Setting"; PolicyName = if ($setting.displayName) { $setting.displayName } else { $setting.name }; PolicyId = $setting.id; ConflictType = "Currently excluded; target group includes it" })
            }
        }
    }
    catch {
        Write-Verbose "Skipping - Windows 365 may not be licensed for this tenant"
    }

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($deltaPolicies.Keys)) {
            $deltaPolicies[$key] = @(Filter-ByScopeTag -Items $deltaPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # ===== DISPLAY RESULTS =====
    Write-Host ""
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow
    Write-Host "  SIMULATION RESULTS - GROUP MEMBERSHIP IMPACT ANALYSIS" -ForegroundColor Yellow
    Write-Host "  (no changes were made)" -ForegroundColor DarkGray
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow
    Write-Host "  User: $simUpn" -ForegroundColor White
    Write-Host "  Target Group: $simTargetGroupName (ID: $simTargetGroupId)" -ForegroundColor White
    if ($alreadyMember) {
        Write-Host "  Status: User is ALREADY a member of this group" -ForegroundColor Yellow
    }
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow

    # Category display mapping
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
        CloudPCProvisioningPolicies = "Windows 365 Cloud PC Provisioning"
        CloudPCUserSettings         = "Windows 365 Cloud PC User Settings"
    }

    $totalNewPolicies = 0
    foreach ($catKey in $categoryDisplay.Keys) {
        $items = $deltaPolicies[$catKey]
        if ($items.Count -gt 0) {
            $catLabel = $categoryDisplay[$catKey]
            $totalNewPolicies += $items.Count
            Write-Host "`n------- NEW: $catLabel ($($items.Count)) -------" -ForegroundColor Green
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment Reason"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($item in $items) {
                $itemName = if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } else { $item.name }
                if (-not $itemName) { $itemName = "Unnamed" }
                if ($itemName.Length -gt 47) { $itemName = $itemName.Substring(0, 44) + "..." }

                $itemId = if ($item.id) { $item.id } else { "Unknown" }
                if ($itemId.Length -gt 37) { $itemId = $itemId.Substring(0, 34) + "..." }

                $reason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "Unknown" }
                if ($reason.Length -gt 27) { $reason = $reason.Substring(0, 24) + "..." }

                Write-Host ("{0,-50} {1,-40} {2,-30}" -f $itemName, $itemId, $reason) -ForegroundColor White
            }
            Write-Host $separator
        }
    }

    # Display conflicts
    if ($conflictPolicies.Count -gt 0) {
        Write-Host "`n------- CONFLICTS (Exclusion Overrides) -------" -ForegroundColor Red
        Write-Host "Note: In Intune, exclusions take priority over inclusions." -ForegroundColor Yellow
        $headerFormat = "{0,-50} {1,-35} {2,-35}" -f "Policy Name", "Category", "Conflict"
        $separator = Get-Separator
        Write-Host $separator
        Write-Host $headerFormat -ForegroundColor Yellow
        Write-Host $separator

        foreach ($conflict in $conflictPolicies) {
            $cName = $conflict.PolicyName
            if ($cName.Length -gt 47) { $cName = $cName.Substring(0, 44) + "..." }
            $cCat = $conflict.Category
            if ($cCat.Length -gt 32) { $cCat = $cCat.Substring(0, 29) + "..." }
            $cType = $conflict.ConflictType
            if ($cType.Length -gt 32) { $cType = $cType.Substring(0, 29) + "..." }
            Write-Host ("{0,-50} {1,-35} {2,-35}" -f $cName, $cCat, $cType) -ForegroundColor Red
        }
        Write-Host $separator
    }

    # Summary
    Write-Host "`n=== Impact Summary ===" -ForegroundColor Cyan
    if ($alreadyMember) {
        Write-Host "User '$simUpn' is already a member of '$simTargetGroupName'." -ForegroundColor Yellow
        Write-Host "The following shows policies currently received via this group:" -ForegroundColor Yellow
    }
    else {
        Write-Host "Adding '$simUpn' to '$simTargetGroupName' would result in:" -ForegroundColor White
    }

    $categoryCount = ($categoryDisplay.Keys | Where-Object { $deltaPolicies[$_].Count -gt 0 }).Count
    $conflictCount = $conflictPolicies.Count

    if ($totalNewPolicies -eq 0 -and $conflictCount -eq 0) {
        Write-Host "  No new policy assignments and no conflicts." -ForegroundColor Yellow
    }
    else {
        $parts = @()
        if ($totalNewPolicies -gt 0) {
            $parts += "$totalNewPolicies new $(if ($totalNewPolicies -eq 1) { 'policy' } else { 'policies' }) across $categoryCount $(if ($categoryCount -eq 1) { 'category' } else { 'categories' })"
        }
        if ($conflictCount -gt 0) {
            $parts += "$conflictCount $(if ($conflictCount -eq 1) { 'conflict' } else { 'conflicts' })"
        }
        Write-Host "  Impact: $($parts -join ', ')" -ForegroundColor $(if ($conflictCount -gt 0) { "Yellow" } else { "Green" })
    }

    # Export
    $exportData = [System.Collections.ArrayList]::new()
    $null = $exportData.Add([PSCustomObject]@{
        Category         = "Simulation Info"
        Item             = "User: $simUpn -> Group: $simTargetGroupName (ID: $simTargetGroupId)"
        ScopeTags        = ""
        AssignmentReason = if ($alreadyMember) { "Already a member" } else { "Impact Analysis" }
    })

    Add-ExportData -ExportData $exportData -Category "NEW: Device Configuration" -Items $deltaPolicies.DeviceConfigs -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Settings Catalog Policy" -Items $deltaPolicies.SettingsCatalog -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Compliance Policy" -Items $deltaPolicies.CompliancePolicies -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: App Protection Policy" -Items $deltaPolicies.AppProtectionPolicies -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: App Configuration Policy" -Items $deltaPolicies.AppConfigurationPolicies -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Required App" -Items $deltaPolicies.AppsRequired -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Available App" -Items $deltaPolicies.AppsAvailable -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Uninstall App" -Items $deltaPolicies.AppsUninstall -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Platform Script" -Items $deltaPolicies.PlatformScripts -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Proactive Remediation Script" -Items $deltaPolicies.HealthScripts -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - Antivirus" -Items $deltaPolicies.AntivirusProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - Disk Encryption" -Items $deltaPolicies.DiskEncryptionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - Firewall" -Items $deltaPolicies.FirewallProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - EDR" -Items $deltaPolicies.EndpointDetectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - ASR" -Items $deltaPolicies.AttackSurfaceProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Endpoint Security - Account Protection" -Items $deltaPolicies.AccountProtectionProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Autopilot Deployment Profile" -Items $deltaPolicies.DeploymentProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Enrollment Status Page Profile" -Items $deltaPolicies.ESPProfiles -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Cloud PC Provisioning Policy" -Items $deltaPolicies.CloudPCProvisioningPolicies -AssignmentReason { param($item) $item.AssignmentReason }
    Add-ExportData -ExportData $exportData -Category "NEW: Cloud PC User Setting" -Items $deltaPolicies.CloudPCUserSettings -AssignmentReason { param($item) $item.AssignmentReason }

    foreach ($conflict in $conflictPolicies) {
        $null = $exportData.Add([PSCustomObject]@{
            Category         = "CONFLICT: $($conflict.Category)"
            Item             = "$($conflict.PolicyName) (ID: $($conflict.PolicyId))"
            ScopeTags        = ""
            AssignmentReason = $conflict.ConflictType
        })
    }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneGroupMembershipImpact.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
