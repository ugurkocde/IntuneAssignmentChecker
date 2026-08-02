function Test-IntuneGroupRemoval {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserPrincipalNames,

        [Parameter()]
        [string]$DeviceNames,

        [Parameter()]
        [string]$SimulateRemoveTargetGroup,

        [Parameter()]
        [string]$GroupNames,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter,

        [Parameter()]
        [switch]$PassThru
    )

    Write-Host "Group Membership Removal Impact Analysis selected" -ForegroundColor Green

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

    $simDeviceName = $null
    if (-not [string]::IsNullOrWhiteSpace($simDeviceInput)) {
        $simDeviceName = ($simDeviceInput -split ',')[0].Trim()
    }

    # Get Target Group - SimulateRemoveTargetGroup takes precedence over GroupNames
    if ($SimulateRemoveTargetGroup) {
        $simGroupInput = $SimulateRemoveTargetGroup
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
    $simTargetGroupId = $null
    $simTargetGroupName = $null
    $simResolvedGroupInfo = $null

    if ($simGroupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        $simGroupInfo = Get-GroupInfo -GroupId $simGroupInput
        if (-not $simGroupInfo.Success) {
            Write-Host "No group found with ID: $simGroupInput" -ForegroundColor Red
            return
        }
        $simTargetGroupId = $simGroupInfo.Id
        $simTargetGroupName = $simGroupInfo.DisplayName
        $simResolvedGroupInfo = $simGroupInfo
    }
    else {
        $escapedSimGroupName = $simGroupInput -replace "'", "''"
        $simGroupSelect = 'id,displayName,groupTypes,mailEnabled,securityEnabled,mail'
        $simGroupUri = "$script:GraphEndpoint/beta/groups?`$filter=displayName eq '$escapedSimGroupName'&`$select=$simGroupSelect"
        $simGroupResponse = Invoke-IACGraphRequest -Uri $simGroupUri -Method Get

        if ($simGroupResponse.value.Count -eq 0) {
            Write-Host "No group found with name: $simGroupInput" -ForegroundColor Red
            return
        }
        elseif ($simGroupResponse.value.Count -gt 1) {
            Write-Host "Multiple groups found with name: $simGroupInput. Please use the Object ID instead:" -ForegroundColor Red
            foreach ($g in $simGroupResponse.value) {
                $candidateInfo = ConvertTo-IntuneGroupInfo -Group $g
                Write-Host "  - $($candidateInfo.DisplayName) (ID: $($candidateInfo.Id); Type: $($candidateInfo.GroupType); Membership: $($candidateInfo.MembershipType))" -ForegroundColor Yellow
            }
            return
        }

        $simResolvedGroupInfo = ConvertTo-IntuneGroupInfo -Group $simGroupResponse.value[0]
        if (-not $simResolvedGroupInfo.Success) {
            Write-Host "The group lookup for '$simGroupInput' returned an invalid response without an Object ID." -ForegroundColor Red
            return
        }
        $simTargetGroupId = $simResolvedGroupInfo.Id
        $simTargetGroupName = $simResolvedGroupInfo.DisplayName
    }

    Write-Host "Target group: $simTargetGroupName (ID: $simTargetGroupId)" -ForegroundColor Green
    Write-Host "Group details: Type: $($simResolvedGroupInfo.GroupType); Membership: $($simResolvedGroupInfo.MembershipType)$(if ($simResolvedGroupInfo.Mail) { "; Mail: $($simResolvedGroupInfo.Mail)" })" -ForegroundColor Green

    # Get current group memberships (union of user and device, depending on what was supplied)
    $simCurrentGroupIds = @()
    try {
        if ($hasUserPersp) {
            $simUserGroups = Get-GroupMemberships -ObjectId $simUserInfo.Id -ObjectType "User"
            $simCurrentGroupIds += @($simUserGroups | Where-Object { $_.id } | ForEach-Object { $_.id })
        }
        if ($hasDevicePersp) {
            $simDeviceGroups = Get-GroupMemberships -ObjectId $simDeviceInfo.Id -ObjectType "Device"
            $simCurrentGroupIds += @($simDeviceGroups | Where-Object { $_.id } | ForEach-Object { $_.id })
        }
        $simCurrentGroupIds = @($simCurrentGroupIds | Select-Object -Unique)
    }
    catch {
        Write-Host "Error fetching group memberships: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Build subject label for messages
    $subjectLabel = if ($hasUserPersp -and $hasDevicePersp) {
        "User '$simUpn' + Device '$($simDeviceInfo.DisplayName)'"
    } elseif ($hasUserPersp) {
        "User '$simUpn'"
    } else {
        "Device '$($simDeviceInfo.DisplayName)'"
    }

    # Check if subject is a member of the target group (required for removal simulation)
    $isMember = $simCurrentGroupIds -contains $simTargetGroupId
    if (-not $isMember) {
        Write-Host "`n$subjectLabel is NOT a member of '$simTargetGroupName'. Nothing to simulate." -ForegroundColor Red
        return
    }

    # Get target group's parent groups (transitive)
    $simTargetParentGroups = Get-TransitiveGroupMembership -GroupId $simTargetGroupId
    $simTargetAllGroupIds = @($simTargetGroupId)
    if ($simTargetParentGroups) {
        $simTargetAllGroupIds += $simTargetParentGroups.id
    }

    # Build simulated group set (current MINUS target and target's parents)
    $simSimulatedGroupIds = @($simCurrentGroupIds | Where-Object { $simTargetAllGroupIds -notcontains $_ })

    Write-Host "Analyzing removal impact..." -ForegroundColor Yellow

    # UserContext supplies this cmdlet's legacy display names and the unfiltered Settings
    # Catalog fetch; extend the legacy walk with Imported Administrative Templates and
    # fetch the Autopilot/ESP categories that UserContext keeps bucket-only.
    $categoryIndex = @{}
    foreach ($category in (Get-IntuneCategoryDefinition -Audience 'UserContext')) { $categoryIndex[$category.Id] = $category }
    $categories = foreach ($id in @(
            'DeviceConfigurations', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies',
            'AppConfigurationPolicies', 'Applications', 'PlatformScripts', 'HealthScripts',
            'ESAntivirus', 'ESDiskEncryption', 'ESFirewall', 'ESEndpointDetection',
            'ESAttackSurface', 'ESAccountProtection', 'DeploymentProfiles', 'ESPProfiles',
            'WindowsFeatureUpdates', 'WindowsQualityUpdates', 'WindowsDriverUpdates', 'WindowsQualityUpdatePolicies',
            'CloudPCProvisioningPolicies', 'CloudPCUserSettings')) {
        $categoryIndex[$id].BucketOnly = $false
        $categoryIndex[$id]
    }

    # Conflict rows keep the legacy category labels; where those differ from the registry
    # export label the override below wins.
    $conflictLabels = @{
        SettingsCatalog             = 'Settings Catalog'
        PlatformScripts             = 'Platform Script'
        HealthScripts               = 'Proactive Remediation Script'
        CloudPCProvisioningPolicies = 'Cloud PC Provisioning'
        CloudPCUserSettings         = 'Cloud PC User Setting'
    }

    $conflictPolicies = [System.Collections.ArrayList]::new()
    # Caller-owned cache: each entity set is fetched from Graph once (the legacy walk
    # re-fetched configurationPolicies and intents for every Endpoint Security family)
    $entityCache = @{}
    $appProgress = @{ Current = 0; Total = $null; FilteredTotal = $null }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity

        if ($ctx.Category.Kind -eq 'MobileApps') {
            if ($null -eq $appProgress.Total) {
                $allCachedApps = @($entityCache[$ctx.Category.EntityType])
                $appProgress.Total = $allCachedApps.Count
                $appProgress.FilteredTotal = @($allCachedApps).Count
            }
            $appProgress.Current++
            Write-Host "`rFetching Application $($appProgress.Current) of $($appProgress.Total)" -NoNewline

            # Legacy app walk: track inclusion/exclusion against the current and the
            # simulated group sets. The first matching inclusion wins the filter suffix,
            # the last matching inclusion wins the intent.
            $currentExcluded = $false; $currentIncluded = $false
            $simExcluded = $false; $simIncluded = $false
            $currentAppIntent = $null
            $currentWinningTarget = $null

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
                        $currentAppIntent = $assignment.intent
                        if (-not $currentWinningTarget) { $currentWinningTarget = $assignment.target }
                    }
                }
                elseif ($targetType -eq '#microsoft.graph.groupAssignmentTarget') {
                    if ($simCurrentGroupIds -contains $targetGroupId) {
                        $currentIncluded = $true
                        $currentAppIntent = $assignment.intent
                        if (-not $currentWinningTarget) { $currentWinningTarget = $assignment.target }
                    }
                    if ($simSimulatedGroupIds -contains $targetGroupId) { $simIncluded = $true }
                }
            }

            $currentHasApp = $currentIncluded -and -not $currentExcluded
            $simHasApp = $simIncluded -and -not $simExcluded

            if ($currentHasApp -and -not $simHasApp) {
                $filterSuffix = ''
                if ($currentWinningTarget) {
                    $filterSuffix = Format-AssignmentFilter -FilterId $currentWinningTarget.deviceAndAppManagementAssignmentFilterId -FilterType $currentWinningTarget.deviceAndAppManagementAssignmentFilterType
                }
                $appWithReason = $entity.PSObject.Copy()
                $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Group Assignment$filterSuffix" -Force
                $appWithReason | Add-Member -NotePropertyName 'AssignmentIntent' -NotePropertyValue $currentAppIntent -Force
                switch ($currentAppIntent) {
                    "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason) }
                    "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason) }
                    "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason) }
                }
            }
            elseif ($currentExcluded -and $simExcluded) {
                # Check if target group specifically includes this app while the subject is excluded
                foreach ($assignment in $ctx.RawAssignments) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                        $simTargetAllGroupIds -contains $assignment.target.groupId -and
                        $simCurrentGroupIds -notcontains $assignment.target.groupId) {
                        $appName = if ($entity.displayName) { $entity.displayName } else { $entity.name }
                        [void]$conflictPolicies.Add([PSCustomObject]@{ Category = "Application ($($assignment.intent))"; PolicyName = $appName; PolicyId = $entity.id; ConflictType = "Currently included; removal would expose exclusion" })
                        break
                    }
                }
            }

            if ($appProgress.Current -eq $appProgress.FilteredTotal) {
                # Legacy final overwrite before the next category header
                Write-Host "`rFetching Application $($appProgress.Total) of $($appProgress.Total)"
            }
            return
        }

        $assignments = $ctx.Assignments
        if ($ctx.Category.Kind -eq 'AppProtection') {
            # The legacy App Protection walk never mapped All Devices targets and only
            # evaluated policies that had at least one relevant assignment
            $assignments = @($assignments | Where-Object { $_.Reason -ne 'All Devices' })
            if ($assignments.Count -eq 0) { return }
        }
        elseif ($ctx.Category.Kind -eq 'EndpointSecurity' -and $null -ne $ctx.RawAssignments) {
            # Intent-phase detail rows historically carried no filter info, so the resolved
            # status strings get no filter suffix (unlike the config-policy phase)
            $assignments = @($assignments | ForEach-Object { [PSCustomObject]@{ Reason = $_.Reason; GroupId = $_.GroupId } })
        }

        $delta = Resolve-SimulatedAssignmentDelta -Assignments $assignments -CurrentGroupIds $simCurrentGroupIds -SimulatedGroupIds $simSimulatedGroupIds -TargetGroupIds $simTargetAllGroupIds -IncludeReasons $includeReasons
        if ($delta.IsLostPolicy) {
            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $delta.CurrentStatus -Force
            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
        }
        elseif ($delta.IsConflict) {
            $conflictCategory = if ($conflictLabels.ContainsKey($ctx.Category.Id)) { $conflictLabels[$ctx.Category.Id] } else { $ctx.Category.ExportCategory }
            # Legacy App Protection conflict rows read displayName without a name fallback
            $conflictName = if ($ctx.Category.Kind -eq 'AppProtection') { $entity.displayName }
            elseif ($entity.displayName) { $entity.displayName }
            else { $entity.name }
            [void]$conflictPolicies.Add([PSCustomObject]@{ Category = $conflictCategory; PolicyName = $conflictName; PolicyId = $entity.id; ConflictType = "Currently included; removal would expose exclusion" })
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
    Write-Host "  SIMULATION RESULTS - GROUP MEMBERSHIP REMOVAL IMPACT" -ForegroundColor Yellow
    Write-Host "  (no changes were made)" -ForegroundColor DarkGray
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow
    if ($hasUserPersp)   { Write-Host "  User:   $simUpn" -ForegroundColor White }
    if ($hasDevicePersp) { Write-Host "  Device: $($simDeviceInfo.DisplayName) (ID: $($simDeviceInfo.Id))" -ForegroundColor White }
    Write-Host "  Target Group: $simTargetGroupName (ID: $simTargetGroupId)" -ForegroundColor White
    Write-Host (Get-Separator -Character "=") -ForegroundColor Yellow

    # Per-bucket display and export labels in the legacy order
    $categoryTable = @(
        @{ Key = 'DeviceConfigs'; Display = 'Device Configurations'; Export = 'Device Configuration' }
        @{ Key = 'ImportedAdministrativeTemplates'; Display = 'Imported Administrative Templates'; Export = 'Imported Administrative Template' }
        @{ Key = 'SettingsCatalog'; Display = 'Settings Catalog Policies'; Export = 'Settings Catalog Policy' }
        @{ Key = 'CompliancePolicies'; Display = 'Compliance Policies'; Export = 'Compliance Policy' }
        @{ Key = 'AppProtectionPolicies'; Display = 'App Protection Policies'; Export = 'App Protection Policy' }
        @{ Key = 'AppConfigurationPolicies'; Display = 'App Configuration Policies'; Export = 'App Configuration Policy' }
        @{ Key = 'AppsRequired'; Display = 'Required Apps'; Export = 'Required App' }
        @{ Key = 'AppsAvailable'; Display = 'Available Apps'; Export = 'Available App' }
        @{ Key = 'AppsUninstall'; Display = 'Uninstall Apps'; Export = 'Uninstall App' }
        @{ Key = 'PlatformScripts'; Display = 'Platform Scripts'; Export = 'Platform Script' }
        @{ Key = 'HealthScripts'; Display = 'Proactive Remediation Scripts'; Export = 'Proactive Remediation Script' }
        @{ Key = 'AntivirusProfiles'; Display = 'Endpoint Security - Antivirus'; Export = 'Endpoint Security - Antivirus' }
        @{ Key = 'DiskEncryptionProfiles'; Display = 'Endpoint Security - Disk Encryption'; Export = 'Endpoint Security - Disk Encryption' }
        @{ Key = 'FirewallProfiles'; Display = 'Endpoint Security - Firewall'; Export = 'Endpoint Security - Firewall' }
        @{ Key = 'EndpointDetectionProfiles'; Display = 'Endpoint Security - EDR'; Export = 'Endpoint Security - EDR' }
        @{ Key = 'AttackSurfaceProfiles'; Display = 'Endpoint Security - ASR'; Export = 'Endpoint Security - ASR' }
        @{ Key = 'AccountProtectionProfiles'; Display = 'Endpoint Security - Account Protection'; Export = 'Endpoint Security - Account Protection' }
        @{ Key = 'DeploymentProfiles'; Display = 'Autopilot Deployment Profiles'; Export = 'Autopilot Deployment Profile' }
        @{ Key = 'ESPProfiles'; Display = 'Enrollment Status Page Profiles'; Export = 'Enrollment Status Page Profile' }
        @{ Key = 'CloudPCProvisioningPolicies'; Display = 'Windows 365 Cloud PC Provisioning'; Export = 'Cloud PC Provisioning Policy' }
        @{ Key = 'CloudPCUserSettings'; Display = 'Windows 365 Cloud PC User Settings'; Export = 'Cloud PC User Setting' }
    )

    # Legacy column truncation (cut at max, keep max-3 characters plus "...")
    $truncate = { param($text, $max) if ($text.Length -gt $max) { $text.Substring(0, $max - 3) + "..." } else { $text } }

    $totalLostPolicies = 0
    foreach ($cat in $categoryTable) {
        $items = $deltaPolicies[$cat.Key]
        if ($items.Count -gt 0) {
            $totalLostPolicies += $items.Count
            Write-Host "`n------- LOST: $($cat.Display) ($($items.Count)) -------" -ForegroundColor Red
            $headerFormat = "{0,-50} {1,-40} {2,-30}" -f "Policy Name", "Policy ID", "Assignment Reason"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator

            foreach ($item in $items) {
                $itemName = if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } else { $item.name }
                if (-not $itemName) { $itemName = "Unnamed" }
                $itemName = & $truncate $itemName 47
                $itemId = if ($item.id) { $item.id } else { "Unknown" }
                $itemId = & $truncate $itemId 37
                $reason = if ($item.AssignmentReason) { $item.AssignmentReason } else { "Unknown" }
                $reason = & $truncate $reason 27
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
            $cName = & $truncate $conflict.PolicyName 47
            $cCat = & $truncate $conflict.Category 32
            $cType = & $truncate $conflict.ConflictType 32
            Write-Host ("{0,-50} {1,-35} {2,-35}" -f $cName, $cCat, $cType) -ForegroundColor Red
        }
        Write-Host $separator
    }

    # Summary
    Write-Host "`n=== Impact Summary ===" -ForegroundColor Cyan
    Write-Host "Removing $subjectLabel from '$simTargetGroupName' would result in:" -ForegroundColor White

    $categoryCount = ($categoryTable | Where-Object { $deltaPolicies[$_.Key].Count -gt 0 }).Count
    $conflictCount = $conflictPolicies.Count

    if ($totalLostPolicies -eq 0 -and $conflictCount -eq 0) {
        Write-Host "  No lost policy assignments and no conflicts." -ForegroundColor Yellow
    }
    else {
        $parts = @()
        if ($totalLostPolicies -gt 0) {
            $parts += "$totalLostPolicies lost $(if ($totalLostPolicies -eq 1) { 'policy' } else { 'policies' }) across $categoryCount $(if ($categoryCount -eq 1) { 'category' } else { 'categories' })"
        }
        if ($conflictCount -gt 0) {
            $parts += "$conflictCount $(if ($conflictCount -eq 1) { 'conflict' } else { 'conflicts' })"
        }
        Write-Host "  Impact: $($parts -join ', ')" -ForegroundColor $(if ($conflictCount -gt 0) { "Red" } else { "Yellow" })
    }

    # Export
    $exportData = [System.Collections.ArrayList]::new()
    $null = $exportData.Add([PSCustomObject]@{
        Category         = "Simulation Info"
        Item             = "$subjectLabel -> Remove from Group: $simTargetGroupName (ID: $simTargetGroupId)"
        ScopeTags        = ""
        AssignmentReason = "Removal Impact Analysis"
    })

    foreach ($cat in $categoryTable) {
        Add-ExportData -ExportData $exportData -Category "LOST: $($cat.Export)" -Items $deltaPolicies[$cat.Key] -AssignmentReason { param($item) $item.AssignmentReason }
    }

    foreach ($conflict in $conflictPolicies) {
        $null = $exportData.Add([PSCustomObject]@{
            Category         = "CONFLICT: $($conflict.Category)"
            Item             = "$($conflict.PolicyName) (ID: $($conflict.PolicyId))"
            ScopeTags        = ""
            AssignmentReason = $conflict.ConflictType
        })
    }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneGroupRemovalImpact.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$PassThru
    if ($PassThru) { $exportData }
}
