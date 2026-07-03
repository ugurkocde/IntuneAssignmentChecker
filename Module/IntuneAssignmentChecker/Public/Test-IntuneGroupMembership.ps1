function Test-IntuneGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter()][string]$UserPrincipalNames,
        [Parameter()][string]$DeviceNames,
        [Parameter()][string]$SimulateTargetGroup,
        [Parameter()][string]$GroupNames,
        [Parameter()][switch]$ExportToCSV,
        [Parameter()][string]$ExportPath,
        [Parameter()][string]$ScopeTagFilter
    )

    Write-Host "Group Membership Impact Analysis selected" -ForegroundColor Green

    # Get User Principal Name and/or Device Name. At least one must be supplied.
    $simUpnInput    = $UserPrincipalNames
    $simDeviceInput = $DeviceNames

    if (-not $simUpnInput -and -not $simDeviceInput) {
        Write-Host "Enter a User Principal Name, a Device name, or both (leave one blank to skip)." -ForegroundColor Cyan
        Write-Host "  User Principal Name: " -NoNewline -ForegroundColor Cyan
        $simUpnInput = Read-Host
        Write-Host "  Device Name: " -NoNewline -ForegroundColor Cyan
        $simDeviceInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($simUpnInput) -and [string]::IsNullOrWhiteSpace($simDeviceInput)) {
        Write-Host "No User or Device provided. Please supply at least one." -ForegroundColor Red
        return
    }

    $simUpn = $null
    if (-not [string]::IsNullOrWhiteSpace($simUpnInput)) {
        $simUpn = ($simUpnInput -split ',')[0].Trim()
        if ($simUpn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            Write-Host "Invalid UPN format: '$simUpn'. Expected: user@domain.com" -ForegroundColor Red
            return
        }
    }

    $simDeviceName = if (-not [string]::IsNullOrWhiteSpace($simDeviceInput)) { ($simDeviceInput -split ',')[0].Trim() } else { $null }

    # Get Target Group - SimulateTargetGroup takes precedence over GroupNames
    $simGroupInput = if ($SimulateTargetGroup) { $SimulateTargetGroup }
    elseif ($GroupNames) { $GroupNames }
    else {
        Write-Host "Please enter the Target Group name or Object ID: " -ForegroundColor Cyan
        Write-Host "Example: 'Marketing Team' or '12345678-1234-1234-1234-123456789012'" -ForegroundColor Gray
        Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($simGroupInput)) {
        Write-Host "No group provided. Please try again." -ForegroundColor Red
        return
    }

    $simGroupInput = ($simGroupInput -split ',')[0].Trim()

    # Resolve user (optional)
    $simUserInfo = $null
    if ($simUpn) {
        Write-Host "Looking up user: $simUpn" -ForegroundColor Yellow
        $simUserInfo = Get-UserInfo -UserPrincipalName $simUpn
        if (-not $simUserInfo.Success) {
            Write-Host "User not found: $simUpn" -ForegroundColor Red
            return
        }
    }

    # Resolve device (optional)
    $simDeviceInfo = $null
    if ($simDeviceName) {
        Write-Host "Looking up device: $simDeviceName" -ForegroundColor Yellow
        $simDeviceInfo = Get-DeviceInfo -DeviceName $simDeviceName
        if (-not $simDeviceInfo.Success) {
            Write-Host "Device not found: $simDeviceName" -ForegroundColor Red
            return
        }
        if ($simDeviceInfo.MultipleFound) {
            Write-Host "Multiple devices match name '$simDeviceName'. Use a more specific name." -ForegroundColor Red
            foreach ($d in $simDeviceInfo.AllDevices) {
                Write-Host "  - $($d.displayName) (ID: $($d.id), OS: $($d.operatingSystem))" -ForegroundColor Yellow
            }
            return
        }
    }

    # Determine simulation perspective
    $hasUserPersp   = [bool]$simUserInfo
    $hasDevicePersp = [bool]$simDeviceInfo
    $includeReasons = @()
    if ($hasUserPersp)   { $includeReasons += "All Users" }
    if ($hasDevicePersp) { $includeReasons += "All Devices" }

    # Resolve target group
    Write-Host "Looking up group: $simGroupInput" -ForegroundColor Yellow
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
        # Single quotes escaped for the OData filter (F9)
        $escapedSimGroupName = $simGroupInput -replace "'", "''"
        $simGroupUri = "$GraphEndpoint/v1.0/groups?`$filter=displayName eq '$escapedSimGroupName'"
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

    # Get current group memberships (union of user and device, depending on what was supplied)
    $simCurrentGroupIds = @()
    try {
        if ($hasUserPersp) {
            $simCurrentGroupIds += @(Get-GroupMemberships -ObjectId $simUserInfo.Id -ObjectType "User" | Where-Object { $_.id } | ForEach-Object { $_.id })
        }
        if ($hasDevicePersp) {
            $simCurrentGroupIds += @(Get-GroupMemberships -ObjectId $simDeviceInfo.Id -ObjectType "Device" | Where-Object { $_.id } | ForEach-Object { $_.id })
        }
        $simCurrentGroupIds = @($simCurrentGroupIds | Select-Object -Unique)
    }
    catch {
        Write-Host "Error fetching group memberships: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Check if subject is already in the target group
    $alreadyMember = $simCurrentGroupIds -contains $simTargetGroupId
    if ($alreadyMember) {
        Write-Host "`nNote: Subject is already a member of '$simTargetGroupName'. Showing policies received via this group." -ForegroundColor Yellow
    }

    # Get target group's parent groups (transitive)
    $simTargetParentGroups = Get-TransitiveGroupMembership -GroupId $simTargetGroupId
    $simTargetAllGroupIds = @($simTargetGroupId)
    if ($simTargetParentGroups) { $simTargetAllGroupIds += $simTargetParentGroups.id }

    # Build simulated group set (current + target + target's parents, deduplicated)
    $simSimulatedGroupIds = @($simCurrentGroupIds + $simTargetAllGroupIds | Select-Object -Unique)

    Write-Host "Analyzing impact..." -ForegroundColor Yellow

    # The legacy 18-step walk matches the UserContext registry entries (same display names, no
    # Settings Catalog ES filter): reorder to the legacy sequence and make Autopilot/ESP fetchable.
    $categoriesById = @{}
    foreach ($category in (Get-IntuneCategoryDefinition -Audience 'UserContext')) { $categoriesById[$category.Id] = $category }
    $categoriesById['DeploymentProfiles'].BucketOnly = $false
    $categoriesById['ESPProfiles'].BucketOnly = $false
    $categories = @(
        @('DeviceConfigurations', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies', 'AppConfigurationPolicies',
            'Applications', 'PlatformScripts', 'HealthScripts', 'ESAntivirus', 'ESDiskEncryption', 'ESFirewall',
            'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection', 'DeploymentProfiles', 'ESPProfiles',
            'CloudPCProvisioningPolicies', 'CloudPCUserSettings') | ForEach-Object { $categoriesById[$_] })

    # Legacy conflict-row category labels: registry export labels except these five
    $conflictLabelOverrides = @{
        SettingsCatalog             = 'Settings Catalog'
        PlatformScripts             = 'Platform Script'
        HealthScripts               = 'Proactive Remediation Script'
        CloudPCProvisioningPolicies = 'Cloud PC Provisioning'
        CloudPCUserSettings         = 'Cloud PC User Setting'
    }

    $conflictPolicies = [System.Collections.ArrayList]::new()
    # One shared cache: each entity set (configurationPolicies, intents, ...) hits Graph once per run
    $entityCache = @{}
    $appProgress = @{ Current = 0; Total = $null; FilteredTotal = $null }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity

        if ($ctx.Category.Kind -eq 'MobileApps') {
            if ($null -eq $appProgress.Total) {
                # Legacy progress counted against the unfiltered app list
                $allCachedApps = @($entityCache[$ctx.Category.EntityType])
                $appProgress.Total = $allCachedApps.Count
                $appProgress.FilteredTotal = @($allCachedApps | Where-Object { -not ($_.isFeatured -or $_.isBuiltIn) }).Count
            }
            $appProgress.Current++
            Write-Host "`rFetching Application $($appProgress.Current) of $($appProgress.Total)" -NoNewline

            # Legacy per-app walk: current vs simulated inclusion/exclusion tracked side by side
            $currentExcluded = $currentIncluded = $simExcluded = $simIncluded = $false
            $appIntent = $simWinningTarget = $null

            foreach ($assignment in $ctx.RawAssignments) {
                $targetType = $assignment.target.'@odata.type'
                $targetGroupId = $assignment.target.groupId

                if ($targetType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    if ($simCurrentGroupIds -contains $targetGroupId) { $currentExcluded = $true }
                    if ($simSimulatedGroupIds -contains $targetGroupId) { $simExcluded = $true }
                }
                elseif ($targetType -in @('#microsoft.graph.allLicensedUsersAssignmentTarget', '#microsoft.graph.allDevicesAssignmentTarget')) {
                    $allTargetReason = if ($targetType -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') { "All Users" } else { "All Devices" }
                    if ($includeReasons -contains $allTargetReason) {
                        $currentIncluded = $true
                        $simIncluded = $true
                        $appIntent = $assignment.intent
                        if (-not $simWinningTarget) { $simWinningTarget = $assignment.target }
                    }
                }
                elseif ($targetType -eq '#microsoft.graph.groupAssignmentTarget') {
                    if ($simCurrentGroupIds -contains $targetGroupId) { $currentIncluded = $true; $appIntent = $assignment.intent }
                    if ($simSimulatedGroupIds -contains $targetGroupId) {
                        $simIncluded = $true
                        $appIntent = $assignment.intent
                        if (-not $simWinningTarget) { $simWinningTarget = $assignment.target }
                    }
                }
            }

            $currentHasApp = $currentIncluded -and -not $currentExcluded
            $simHasApp = $simIncluded -and -not $simExcluded

            if ($simHasApp -and -not $currentHasApp) {
                $filterSuffix = ''
                if ($simWinningTarget) {
                    $filterSuffix = Format-AssignmentFilter -FilterId $simWinningTarget.deviceAndAppManagementAssignmentFilterId -FilterType $simWinningTarget.deviceAndAppManagementAssignmentFilterType
                }
                $appWithReason = $entity.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Group Assignment$filterSuffix" -Force
                $appWithReason | Add-Member -NotePropertyName 'AssignmentIntent' -NotePropertyValue $appIntent -Force
                switch ($appIntent) {
                    "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason) }
                    "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason) }
                    "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason) }
                }
            }
            elseif ($currentExcluded -and $simExcluded) {
                # Check if target group specifically includes this app while user is excluded
                foreach ($assignment in $ctx.RawAssignments) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                        $simTargetAllGroupIds -contains $assignment.target.groupId -and
                        $simCurrentGroupIds -notcontains $assignment.target.groupId) {
                        $appName = if ($entity.displayName) { $entity.displayName } else { $entity.name }
                        [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Application ($($assignment.intent))"; PolicyName = $appName; PolicyId = $entity.id; ConflictType = "Currently excluded; target group includes it" })
                        break
                    }
                }
            }

            if ($appProgress.Current -eq $appProgress.FilteredTotal) {
                # Legacy final overwrite before the next category header
                Write-Host "`rFetching Application $($appProgress.Total) of $($appProgress.Total)" -NoNewline
                Start-Sleep -Milliseconds 100
                Write-Host ""
            }
            return
        }

        $assignments = $ctx.Assignments
        if ($null -ne $ctx.RawAssignments) {
            # App Protection and intent-phase Endpoint Security detail rows historically carried
            # Reason/GroupId only, so the delta reason gets no filter suffix. App Protection
            # additionally never matched All Devices targets.
            $assignments = @($assignments | ForEach-Object { [PSCustomObject]@{ Reason = $_.Reason; GroupId = $_.GroupId } })
            if ($ctx.Category.Kind -eq 'AppProtection') {
                $assignments = @($assignments | Where-Object { $_.Reason -ne 'All Devices' })
            }
        }

        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons $includeReasons
        if ($delta.IsNewPolicy) {
            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.AssignmentReason -Force
            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
        }
        elseif ($delta.IsConflict) {
            $conflictLabel = if ($conflictLabelOverrides.ContainsKey($ctx.Category.Id)) { $conflictLabelOverrides[$ctx.Category.Id] } else { $ctx.Category.ExportCategory }
            $policyName = if ($entity.displayName) { $entity.displayName } else { $entity.name }
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = $conflictLabel; PolicyName = $policyName; PolicyId = $entity.id; ConflictType = "Currently excluded; target group includes it" })
        }
    }

    $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -ShowProgress -EntityCache $entityCache
    $deltaPolicies = $scanResult.Buckets

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
    if ($hasUserPersp)   { Write-Host "  User:   $simUpn" -ForegroundColor White }
    if ($hasDevicePersp) { Write-Host "  Device: $($simDeviceInfo.DisplayName) (ID: $($simDeviceInfo.Id))" -ForegroundColor White }
    Write-Host "  Target Group: $simTargetGroupName (ID: $simTargetGroupId)" -ForegroundColor White
    if ($alreadyMember) {
        Write-Host "  Status: Subject is ALREADY a member of this group" -ForegroundColor Yellow
    }
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow

    # Category display mapping (legacy section order and labels)
    $categoryDisplay = [ordered]@{
        DeviceConfigs = "Device Configurations"; SettingsCatalog = "Settings Catalog Policies"
        CompliancePolicies = "Compliance Policies"; AppProtectionPolicies = "App Protection Policies"
        AppConfigurationPolicies = "App Configuration Policies"; AppsRequired = "Required Apps"
        AppsAvailable = "Available Apps"; AppsUninstall = "Uninstall Apps"
        PlatformScripts = "Platform Scripts"; HealthScripts = "Proactive Remediation Scripts"
        AntivirusProfiles = "Endpoint Security - Antivirus"; DiskEncryptionProfiles = "Endpoint Security - Disk Encryption"
        FirewallProfiles = "Endpoint Security - Firewall"; EndpointDetectionProfiles = "Endpoint Security - EDR"
        AttackSurfaceProfiles = "Endpoint Security - ASR"; AccountProtectionProfiles = "Endpoint Security - Account Protection"
        DeploymentProfiles = "Autopilot Deployment Profiles"; ESPProfiles = "Enrollment Status Page Profiles"
        CloudPCProvisioningPolicies = "Windows 365 Cloud PC Provisioning"; CloudPCUserSettings = "Windows 365 Cloud PC User Settings"
    }

    # Legacy cell truncation: over Max chars becomes (Max - 3) chars plus "..."
    $truncate = { param($Text, $Max) if ($Text.Length -gt $Max) { $Text.Substring(0, $Max - 3) + "..." } else { $Text } }

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
                $itemId = if ($item.id) { $item.id } else { "Unknown" }
                $reason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "Unknown" }
                Write-Host ("{0,-50} {1,-40} {2,-30}" -f (& $truncate $itemName 47), (& $truncate $itemId 37), (& $truncate $reason 27)) -ForegroundColor White
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
            Write-Host ("{0,-50} {1,-35} {2,-35}" -f (& $truncate $conflict.PolicyName 47), (& $truncate $conflict.Category 32), (& $truncate $conflict.ConflictType 32)) -ForegroundColor Red
        }
        Write-Host $separator
    }

    # Build a display label for the simulation subject(s)
    $subjectLabel = if ($hasUserPersp -and $hasDevicePersp) {
        "User '$simUpn' + Device '$($simDeviceInfo.DisplayName)'"
    } elseif ($hasUserPersp) {
        "User '$simUpn'"
    } else {
        "Device '$($simDeviceInfo.DisplayName)'"
    }

    # Summary
    Write-Host "`n=== Impact Summary ===" -ForegroundColor Cyan
    if ($alreadyMember) {
        Write-Host "$subjectLabel is already a member of '$simTargetGroupName'." -ForegroundColor Yellow
        Write-Host "The following shows policies currently received via this group:" -ForegroundColor Yellow
    }
    else {
        Write-Host "Adding $subjectLabel to '$simTargetGroupName' would result in:" -ForegroundColor White
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
        Item             = "$subjectLabel -> Group: $simTargetGroupName (ID: $simTargetGroupId)"
        ScopeTags        = ""
        AssignmentReason = if ($alreadyMember) { "Already a member" } else { "Impact Analysis" }
    })

    # Legacy CSV order and labels for the NEW-policy rows
    $exportSections = [ordered]@{
        'NEW: Device Configuration' = 'DeviceConfigs'; 'NEW: Settings Catalog Policy' = 'SettingsCatalog'
        'NEW: Compliance Policy' = 'CompliancePolicies'; 'NEW: App Protection Policy' = 'AppProtectionPolicies'
        'NEW: App Configuration Policy' = 'AppConfigurationPolicies'; 'NEW: Required App' = 'AppsRequired'
        'NEW: Available App' = 'AppsAvailable'; 'NEW: Uninstall App' = 'AppsUninstall'
        'NEW: Platform Script' = 'PlatformScripts'; 'NEW: Proactive Remediation Script' = 'HealthScripts'
        'NEW: Endpoint Security - Antivirus' = 'AntivirusProfiles'; 'NEW: Endpoint Security - Disk Encryption' = 'DiskEncryptionProfiles'
        'NEW: Endpoint Security - Firewall' = 'FirewallProfiles'; 'NEW: Endpoint Security - EDR' = 'EndpointDetectionProfiles'
        'NEW: Endpoint Security - ASR' = 'AttackSurfaceProfiles'; 'NEW: Endpoint Security - Account Protection' = 'AccountProtectionProfiles'
        'NEW: Autopilot Deployment Profile' = 'DeploymentProfiles'; 'NEW: Enrollment Status Page Profile' = 'ESPProfiles'
        'NEW: Cloud PC Provisioning Policy' = 'CloudPCProvisioningPolicies'; 'NEW: Cloud PC User Setting' = 'CloudPCUserSettings'
    }
    foreach ($section in $exportSections.GetEnumerator()) {
        Add-ExportData -ExportData $exportData -Category $section.Key -Items $deltaPolicies[$section.Value] -AssignmentReason { param($item) $item.AssignmentReason }
    }

    foreach ($conflict in $conflictPolicies) {
        $null = $exportData.Add([PSCustomObject]@{
            Category         = "CONFLICT: $($conflict.Category)"
            Item             = "$($conflict.PolicyName) (ID: $($conflict.PolicyId))"
            ScopeTags        = ""
            AssignmentReason = $conflict.ConflictType
        })
    }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneGroupMembershipImpact.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$parameterMode
}
