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

    # Shell Scripts stay outside the shared engine: their assignments live under
    # /groupAssignments (flat targetGroupId shape) instead of /assignments, which
    # the engine's assignment fetch does not model.
    $scanCategories = @(Get-IntuneCategoryDefinition -Audience 'Compare' | Where-Object { $_.Id -ne 'ShellScripts' })
    # Shared across groups so each entity set is fetched from Graph once per run
    $entityCache = @{}

    # Compare historically checks Endpoint Security via deviceManagement/intents only.
    # Skip the engine's configurationPolicies phase (those entities carry no top-level
    # templateId) so results and fetch counts match the legacy intents-only scope.
    $entityPreFilter = {
        param($entity, $category)
        if ($category.Kind -eq 'EndpointSecurity' -and -not $entity.templateId) { return $false }
        return $true
    }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity
        $category = $ctx.Category

        if ($category.Kind -eq 'MobileApps') {
            # Legacy per-assignment loop: every assignment targeting one of the checked
            # group ids yields its own entry, tagged [EXCLUDED]/[INHERITED]/filter and
            # bucketed by that assignment's intent (exclusion-only apps stay visible).
            foreach ($assignment in $ctx.RawAssignments) {
                if ($allGroupIds -notcontains $assignment.target.groupId) { continue }
                $exclusionSuffix = if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') { " [EXCLUDED]" } else { "" }
                $inheritedSuffix = if ($assignment.target.groupId -ne $groupId) { " [INHERITED]" } else { "" }
                $filterSuffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                $combinedSuffix = "$exclusionSuffix$inheritedSuffix$filterSuffix"
                switch ($assignment.intent) {
                    "required" { $ctx.Buckets['RequiredApps'].Add("$($entity.displayName)$combinedSuffix") }
                    "available" { $ctx.Buckets['AvailableApps'].Add("$($entity.displayName)$combinedSuffix") }
                    "uninstall" { $ctx.Buckets['UninstallApps'].Add("$($entity.displayName)$combinedSuffix") }
                }
            }
            return
        }

        if ($category.Kind -eq 'EndpointSecurity' -or $category.Id -eq 'HealthScripts') {
            # Backstop for the prefilter: never take ES results from the configurationPolicies phase
            if ($category.Kind -eq 'EndpointSecurity' -and $null -eq $ctx.RawAssignments) { return }
            # Legacy matching: inclusion targets only, [INHERITED] as the only tag
            $inclusions = @($ctx.Assignments | Where-Object { $_.Reason -eq 'Direct Assignment' })
            if ($inclusions.Count -eq 0) { return }
            $suffix = if (@($inclusions | Where-Object { $_.GroupId -ne $groupId }).Count -gt 0) { " [INHERITED]" } else { "" }
            $ctx.Buckets[$category.BucketKeys[0]].Add("$($entity.displayName)$suffix")
            return
        }

        if ($category.Id -eq 'PlatformScripts') {
            # Legacy matching: any group target (inclusion or exclusion) counts,
            # [INHERITED] as the only tag, "(PowerShell)" marker in the name
            if (@($ctx.Assignments).Count -eq 0) { return }
            $suffix = if (@($ctx.Assignments | Where-Object { $_.GroupId -ne $groupId }).Count -gt 0) { " [INHERITED]" } else { "" }
            $ctx.Buckets['PlatformScripts'].Add("$($entity.displayName) (PowerShell)$suffix")
            return
        }

        # Device Configurations / Settings Catalog / Compliance Policies: one entry per
        # policy with [EXCLUDED], [INHERITED] and filter suffixes, in that order
        if (@($ctx.Assignments).Count -eq 0) { return }
        $suffix = ""
        if (@($ctx.Assignments | Where-Object { $_.Reason -eq 'Direct Exclusion' }).Count -gt 0) { $suffix += " [EXCLUDED]" }
        if (@($ctx.Assignments | Where-Object { $_.GroupId -ne $groupId }).Count -gt 0) { $suffix += " [INHERITED]" }
        $filterMatch = $ctx.Assignments | Where-Object { $_.FilterId } | Select-Object -First 1
        if ($filterMatch) {
            $suffix += (Format-AssignmentFilter -FilterId $filterMatch.FilterId -FilterType $filterMatch.FilterType)
        }
        $entryName = if ($category.Id -eq 'SettingsCatalog') { $entity.name } else { $entity.displayName }
        $ctx.Buckets[$category.BucketKeys[0]].Add("$entryName$suffix")
    }

    # Process each group input
    $resolvedGroups = @{}
    foreach ($groupInput in $groupInputs) {
        Write-Host "`nProcessing input: $groupInput" -ForegroundColor Yellow

        # Initialize variables
        $groupId = $null
        $groupName = $null
        $resolvedGroupInfo = $null
        $groupSelect = 'id,displayName,groupTypes,mailEnabled,securityEnabled,mail'

        # Check if input is a GUID
        if ($groupInput -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            try {
                # Get group info from Graph API
                $groupUri = "$script:GraphEndpoint/beta/groups/$groupInput`?`$select=$groupSelect"
                $groupResponse = Invoke-IACGraphRequest -Uri $groupUri -Method Get
                $resolvedGroupInfo = ConvertTo-IntuneGroupInfo -Group $groupResponse
                if (-not $resolvedGroupInfo.Success) {
                    Write-Host "The group lookup for '$groupInput' returned an invalid response without an Object ID." -ForegroundColor Red
                    continue
                }
                $groupId = $resolvedGroupInfo.Id
                $groupName = $resolvedGroupInfo.DisplayName
                $resolvedGroups[$groupId] = $groupName
                Write-Host "Found group by ID: $groupName" -ForegroundColor Green
            }
            catch {
                Write-Host "No group found with ID: $groupInput" -ForegroundColor Red
                continue
            }
        }
        else {
            # Try to find group by display name (single quotes escaped for the OData filter)
            $escapedGroupName = $groupInput -replace "'", "''"
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
                    Write-Host "  - $($candidateInfo.DisplayName) (ID: $($candidateInfo.Id); Type: $($candidateInfo.GroupType); Membership: $($candidateInfo.MembershipType))" -ForegroundColor Yellow
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
            $resolvedGroups[$groupId] = $groupName
            Write-Host "Found group by name: $groupName (ID: $groupId)" -ForegroundColor Green
        }

        Write-Host "Group details: Type: $($resolvedGroupInfo.GroupType); Membership: $($resolvedGroupInfo.MembershipType)$(if ($resolvedGroupInfo.Mail) { "; Mail: $($resolvedGroupInfo.Mail)" })" -ForegroundColor Green

        # Build effective group IDs for nested group support (direct + transitive parents)
        $allGroupIds = @($groupId)
        if ($checkNestedGroupsCompare) {
            $parentGroups = Get-TransitiveGroupMembership -GroupId $groupId
            if ($parentGroups.Count -gt 0) {
                foreach ($pg in $parentGroups) {
                    $allGroupIds += $pg.id
                }
                Write-Host "  Found $($parentGroups.Count) parent group(s)" -ForegroundColor Green
            }
        }

        $scanResult = Invoke-IntuneCategoryScan -Categories $scanCategories -ProcessEntity $processEntity -AssignmentGroupIds $allGroupIds -EntityPreFilter $entityPreFilter -ShowProgress -EntityCache $entityCache
        $groupAssignments[$groupName] = $scanResult.Buckets

        # Process Shell Scripts (macOS) via the legacy /groupAssignments endpoint
        Write-Host "Fetching Shell Scripts..." -ForegroundColor Yellow
        if (-not $entityCache.ContainsKey('deviceShellScripts')) {
            $entityCache['deviceShellScripts'] = @(Get-IntuneEntities -EntityType 'deviceShellScripts')
        }
        foreach ($shellScript in $entityCache['deviceShellScripts']) {
            $assignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/deviceShellScripts('$($shellScript.id)')/groupAssignments"
            $shellAssignments = @((Invoke-IACGraphRequest -Uri $assignmentsUri -Method Get).value)

            $hasAssignment = @($shellAssignments | Where-Object { $allGroupIds -contains $_.targetGroupId })
            if ($hasAssignment.Count -gt 0) {
                $isInherited = @($hasAssignment | Where-Object { $_.targetGroupId -ne $groupId })
                $suffix = if ($isInherited.Count -gt 0) { " [INHERITED]" } else { "" }
                $groupAssignments[$groupName]['PlatformScripts'].Add("$($shellScript.displayName) (Shell)$suffix")
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
        "Imported Administrative Templates"   = "ImportedAdministrativeTemplates"
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
