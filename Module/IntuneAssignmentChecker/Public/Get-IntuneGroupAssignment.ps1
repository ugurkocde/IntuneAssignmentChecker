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

    $categories = Get-IntuneCategoryDefinition -Audience 'GroupContext'
    # Shared across groups so each entity set is fetched from Graph once per run
    $entityCache = @{}

    foreach ($groupInput in $groupInputs) {
        Write-Host "`nProcessing input: $groupInput" -ForegroundColor Yellow

        # Initialize variables
        $groupId = $null
        $groupName = $null
        $resolvedGroupInfo = $null

        # Check if input is a GUID
        if ($groupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $groupInfo = Get-GroupInfo -GroupId $groupInput
            if (-not $groupInfo.Success) {
                Write-Host "No group found with ID: $groupInput" -ForegroundColor Red
                continue
            }
            $groupId = $groupInfo.Id
            $groupName = $groupInfo.DisplayName
            $resolvedGroupInfo = $groupInfo
        }
        else {
            # Try to find group by display name (single quotes escaped for the OData filter)
            $escapedGroupName = $groupInput -replace "'", "''"
            $groupSelect = 'id,displayName,groupTypes,mailEnabled,securityEnabled,mail'
            $groupUri = "$script:GraphEndpoint/beta/groups?`$filter=displayName eq '$escapedGroupName'&`$select=$groupSelect"
            $groupResponse = Invoke-IACGraphRequest -Uri $groupUri -Method Get

            if ($groupResponse.value.Count -eq 0) {
                Write-Host "No group found with name: $groupInput" -ForegroundColor Red
                continue
            }
            elseif ($groupResponse.value.Count -gt 1) {
                Write-Host "Multiple groups found with name: $groupInput. Please use the Object ID instead:" -ForegroundColor Red
                foreach ($group in $groupResponse.value) {
                    $candidateInfo = ConvertTo-IntuneGroupInfo -Group $group
                    $candidateDetails = "ID: $($candidateInfo.Id); Type: $($candidateInfo.GroupType); Membership: $($candidateInfo.MembershipType)"
                    if ($candidateInfo.Mail) { $candidateDetails += "; Mail: $($candidateInfo.Mail)" }
                    Write-Host "  - $($candidateInfo.DisplayName) ($candidateDetails)" -ForegroundColor Yellow
                }
                continue
            }

            $resolvedGroupInfo = ConvertTo-IntuneGroupInfo -Group $groupResponse.value[0]
            if (-not $resolvedGroupInfo.Success) {
                Write-Host "The group lookup for '$groupInput' returned an invalid response without an Object ID." -ForegroundColor Red
                continue
            }
            $groupId = $resolvedGroupInfo.Id
            $groupName = $resolvedGroupInfo.DisplayName
        }

        Write-Host "Found group: $groupName (ID: $groupId)" -ForegroundColor Green
        $groupDetails = "Type: $($resolvedGroupInfo.GroupType); Membership: $($resolvedGroupInfo.MembershipType)"
        if ($resolvedGroupInfo.Mail) { $groupDetails += "; Mail: $($resolvedGroupInfo.Mail)" }
        Write-Host "Group details: $groupDetails" -ForegroundColor Green

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

        $processEntity = {
            param($ctx)

            $entity = $ctx.Entity

            if ($ctx.Category.Kind -eq 'MobileApps') {
                # Apps resolve reason and intent together from the raw assignments.
                # Exclusion-only assignments are kept (issue #126): the reason strings say
                # "Group Exclusion"/"Inherited Exclusion (via X)" and, when no inclusion
                # supplied an intent, the excluding assignment's intent decides the bucket.
                $relevantAppAssignmentReasons = @()
                $intentForGroup = $null
                $exclusionIntentForGroup = $null

                foreach ($assignmentItem in $ctx.RawAssignments) {
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
                        if ($reasonText -and -not $exclusionIntentForGroup) { $exclusionIntentForGroup = $assignmentItem.intent }
                    }
                    if ($reasonText) {
                        $suffix = Format-AssignmentFilter -FilterId $assignmentItem.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignmentItem.target.deviceAndAppManagementAssignmentFilterType
                        $relevantAppAssignmentReasons += "$reasonText$suffix"
                    }
                }

                if ($relevantAppAssignmentReasons.Count -gt 0) {
                    $appWithReason = $entity.PSObject.Copy()
                    $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($relevantAppAssignmentReasons -join "; ") -Force
                    # Exclusion-only assignments carry the intent of the excluding assignment
                    if (-not $intentForGroup) { $intentForGroup = $exclusionIntentForGroup }
                    switch ($intentForGroup) {
                        "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason) }
                        "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason) }
                        "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason) }
                    }
                }
                return
            }

            # Every other category (entities, App Protection, both Endpoint Security phases)
            # maps the normalized assignments to Direct/Inherited reason strings via the parent map.
            $assignmentReasons = @(Get-GroupAssignmentReasons -Assignments $ctx.Assignments -DirectGroupId $groupId -ParentGroupMap $parentGroupMap)
            if ($assignmentReasons.Count -gt 0) {
                $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue ($assignmentReasons -join "; ") -Force
                $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
            }
        }

        $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -AssignmentGroupIds $allGroupIds -ShowProgress -EntityCache $entityCache
        $relevantPolicies = $scanResult.Buckets

        # Apply scope tag filter if specified
        if ($ScopeTagFilter) {
            foreach ($key in @($relevantPolicies.Keys)) {
                $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
            }
        }

        # Display sections in the legacy order with the legacy per-category name resolution.
        # Sections without GetName use the Show-CategoryResultTable default
        # (displayName, then name, then "Unnamed Profile").
        $nameFirst = { param($item) if ([string]::IsNullOrWhiteSpace($item.name)) { $item.displayName } else { $item.name } }
        $displayNameFirst = { param($item) if ([string]::IsNullOrWhiteSpace($item.displayName)) { $item.name } else { $item.displayName } }
        $displayNameOnly = { param($item) $item.displayName }

        $displaySections = @(
            @{ Title = 'Device Configurations'; Bucket = 'DeviceConfigs'; GetName = $nameFirst }
            @{ Title = 'Imported Administrative Templates'; Bucket = 'ImportedAdministrativeTemplates'; GetName = $displayNameFirst }
            @{ Title = 'Settings Catalog Policies'; Bucket = 'SettingsCatalog'; GetName = $nameFirst }
            @{ Title = 'Compliance Policies'; Bucket = 'CompliancePolicies'; GetName = $nameFirst }
            @{ Title = 'App Protection Policies'; Bucket = 'AppProtectionPolicies'; GetName = $displayNameOnly }
            @{ Title = 'App Configuration Policies'; Bucket = 'AppConfigurationPolicies'; GetName = $nameFirst }
            @{ Title = 'Platform Scripts'; Bucket = 'PlatformScripts'; GetName = $nameFirst }
            @{ Title = 'Proactive Remediation Scripts'; Bucket = 'HealthScripts'; GetName = $nameFirst }
            @{ Title = 'Autopilot Deployment Profiles'; Bucket = 'DeploymentProfiles'; GetName = $displayNameFirst }
            @{ Title = 'Enrollment Status Page Profiles'; Bucket = 'ESPProfiles'; GetName = $displayNameFirst }
            @{ Title = 'Windows 365 Cloud PC Provisioning Policies'; Bucket = 'CloudPCProvisioningPolicies'; GetName = $displayNameFirst }
            @{ Title = 'Windows 365 Cloud PC User Settings'; Bucket = 'CloudPCUserSettings'; GetName = $displayNameFirst }
            @{ Title = 'Required Apps'; Bucket = 'AppsRequired'; GetName = $displayNameOnly }
            @{ Title = 'Available Apps'; Bucket = 'AppsAvailable'; GetName = $displayNameOnly }
            @{ Title = 'Uninstall Apps'; Bucket = 'AppsUninstall'; GetName = $displayNameOnly }
            @{ Title = 'Endpoint Security - Antivirus Profiles'; Bucket = 'AntivirusProfiles' }
            @{ Title = 'Endpoint Security - Disk Encryption Profiles'; Bucket = 'DiskEncryptionProfiles' }
            @{ Title = 'Endpoint Security - Firewall Profiles'; Bucket = 'FirewallProfiles' }
            @{ Title = 'Endpoint Security - EDR Profiles'; Bucket = 'EndpointDetectionProfiles' }
            @{ Title = 'Endpoint Security - ASR Profiles'; Bucket = 'AttackSurfaceProfiles' }
            @{ Title = 'Endpoint Security - Account Protection Profiles'; Bucket = 'AccountProtectionProfiles' }
        )
        foreach ($section in $displaySections) {
            $sectionParams = @{
                Title        = $section.Title
                Items        = @($relevantPolicies[$section.Bucket])
                EmptyMessage = "No $($section.Title) found for this group."
            }
            if ($section.GetName) { $sectionParams.GetName = $section.GetName }
            Show-CategoryResultTable @sectionParams
        }

        # Add to export data: the Group row first, then categories in the legacy CSV order
        # (Endpoint Security after the Windows 365 categories, the app buckets last).
        $groupExportProperties = [ordered]@{
            GroupId        = $groupId
            GroupName      = $groupName
            GroupType      = $resolvedGroupInfo.GroupType
            MembershipType = $resolvedGroupInfo.MembershipType
            GroupMail      = $resolvedGroupInfo.Mail
        }
        Add-ExportData -ExportData $exportData -Category "Group" -Items @([PSCustomObject]@{
                displayName      = $groupName
                id               = $groupId
                AssignmentReason = "N/A"
            }) -AdditionalProperties $groupExportProperties

        $reasonProperty = { param($item) $item.AssignmentReason }
        $exportBatches = @(
            @{ Ids = @('DeviceConfigurations', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies'); Reason = $reasonProperty }
            # Historical quirk preserved: App Protection rows export AssignmentSummary,
            # a property this cmdlet never sets, so their AssignmentReason column stays empty.
            @{ Ids = @('AppProtectionPolicies'); Reason = { param($item) $item.AssignmentSummary } }
            @{ Ids = @('AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'DeploymentProfiles', 'ESPProfiles',
                    'CloudPCProvisioningPolicies', 'CloudPCUserSettings', 'ESAntivirus', 'ESDiskEncryption', 'ESFirewall',
                    'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection', 'Applications'); Reason = $reasonProperty }
        )
        foreach ($batch in $exportBatches) {
            $batchCategories = foreach ($id in $batch.Ids) { $categories | Where-Object { $_.Id -eq $id } }
            Add-CategoryExportData -ExportData $exportData -Categories $batchCategories -Buckets $relevantPolicies -AssignmentReason $batch.Reason -AdditionalProperties $groupExportProperties
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneGroupAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$parameterMode
}
