function Search-IntunePolicy {
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentRecord')]
    param(
        [Parameter()]
        [string]$PolicySearchTerm,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [switch]$PassThru
    )

    Write-Host "Policy Search / Reverse Lookup selected" -ForegroundColor Green

    if ($PolicySearchTerm) {
        $searchTerm = $PolicySearchTerm
    }
    else {
        Write-Host "Enter policy name or partial name to search for: " -ForegroundColor Cyan
        $searchTerm = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "No search term provided. Please try again." -ForegroundColor Red
        return
    }

    Write-Host "Searching for policies matching '$searchTerm'..." -ForegroundColor Yellow

    $groupNameCache = @{}

    # Cached group display name lookup shared by all row emitters
    function Get-SearchTargetGroupName {
        param([string]$GroupId)
        if (-not $groupNameCache.ContainsKey($GroupId)) {
            $groupInfo = Get-GroupInfo -GroupId $GroupId
            $groupNameCache[$GroupId] = if ($groupInfo.Success) { $groupInfo.DisplayName } else { "Unknown Group" }
        }
        return $groupNameCache[$GroupId]
    }

    # Helper function to resolve assignment targets for a matched policy
    function Resolve-SearchAssignments {
        param (
            [object[]]$Assignments,
            [string]$CategoryLabel,
            [string]$PolicyName,
            [string]$PolicyId,
            [System.Collections.Generic.List[object]]$Results
        )

        if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
            $Results.Add([PSCustomObject]@{
                    Category       = $CategoryLabel
                    PolicyName     = $PolicyName
                    PolicyId       = $PolicyId
                    AssignmentType = "None"
                    TargetName     = "No assignments"
                    TargetGroupId  = ""
                    FilterName     = ""
                    FilterType     = ""
                })
            return
        }

        foreach ($assignment in $Assignments) {
            $assignmentType = "Include"
            $targetName = ""
            $targetGroupId = ""

            if ($assignment.Reason -eq "Group Assignment") {
                $targetGroupId = $assignment.GroupId
                $targetName = Get-SearchTargetGroupName -GroupId $targetGroupId
            }
            elseif ($assignment.Reason -eq "Group Exclusion") {
                $assignmentType = "Exclude"
                $targetGroupId = $assignment.GroupId
                $targetName = Get-SearchTargetGroupName -GroupId $targetGroupId
            }
            elseif ($assignment.Reason -eq "All Users") {
                $targetName = "All Users"
            }
            elseif ($assignment.Reason -eq "All Devices") {
                $targetName = "All Devices"
            }
            else {
                continue
            }

            $filterName = ''
            $filterType = ''
            if ($assignment.FilterId -and $assignment.FilterType -and $assignment.FilterType -ne 'none') {
                if ($script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey($assignment.FilterId)) {
                    $filterName = $script:AssignmentFilterLookup[$assignment.FilterId].Name
                }
                else {
                    $filterName = "Unknown Filter ($($assignment.FilterId))"
                }
                $filterType = switch ($assignment.FilterType) {
                    'include' { 'Include' }
                    'exclude' { 'Exclude' }
                    default { $assignment.FilterType }
                }
            }

            $Results.Add([PSCustomObject]@{
                    Category       = $CategoryLabel
                    PolicyName     = $PolicyName
                    PolicyId       = $PolicyId
                    AssignmentType = $assignmentType
                    TargetName     = $targetName
                    TargetGroupId  = $targetGroupId
                    FilterName     = $filterName
                    FilterType     = $filterType
                })
        }
    }

    # Applications keep their historical row emission: raw target walk with the
    # install intent appended to include targets (never to exclusions).
    function Add-SearchAppRows {
        param(
            [object]$App,
            [object[]]$RawAssignments,
            [System.Collections.Generic.List[object]]$Results
        )

        $appName = if (-not [string]::IsNullOrWhiteSpace($App.displayName)) { $App.displayName } else { $App.name }

        if ($null -eq $RawAssignments -or $RawAssignments.Count -eq 0) {
            $Results.Add([PSCustomObject]@{
                    Category       = "Application"
                    PolicyName     = $appName
                    PolicyId       = $App.id
                    AssignmentType = "None"
                    TargetName     = "No assignments"
                    TargetGroupId  = ""
                })
            return
        }

        foreach ($assignment in $RawAssignments) {
            $assignmentType = "Include"
            $targetName = ""
            $targetGroupId = ""
            $intentLabel = if ($assignment.intent) { " ($($assignment.intent))" } else { "" }

            switch ($assignment.target.'@odata.type') {
                '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                    $targetName = "All Users$intentLabel"
                }
                '#microsoft.graph.allDevicesAssignmentTarget' {
                    $targetName = "All Devices$intentLabel"
                }
                '#microsoft.graph.groupAssignmentTarget' {
                    $targetGroupId = $assignment.target.groupId
                    $targetName = "$(Get-SearchTargetGroupName -GroupId $targetGroupId)$intentLabel"
                }
                '#microsoft.graph.exclusionGroupAssignmentTarget' {
                    $assignmentType = "Exclude"
                    $targetGroupId = $assignment.target.groupId
                    $targetName = Get-SearchTargetGroupName -GroupId $targetGroupId
                }
                default { continue }
            }

            $Results.Add([PSCustomObject]@{
                    Category       = "Application"
                    PolicyName     = $appName
                    PolicyId       = $App.id
                    AssignmentType = $assignmentType
                    TargetName     = $targetName
                    TargetGroupId  = $targetGroupId
                })
        }
    }

    $categories = Get-IntuneCategoryDefinition -Audience 'Search'

    # Name matching happens BEFORE any per-entity assignment fetch: only entities
    # passing this pre-filter ever trigger an assignments request.
    $entityPreFilter = {
        param($entity, $category)
        $entity.displayName -like "*$searchTerm*" -or $entity.name -like "*$searchTerm*"
    }

    $processEntity = {
        param($ctx)

        $results = $ctx.Buckets['SearchResults']

        if ($ctx.Category.Id -eq 'Applications') {
            Add-SearchAppRows -App $ctx.Entity -RawAssignments $ctx.RawAssignments -Results $results
            return
        }

        $policyName = if (-not [string]::IsNullOrWhiteSpace($ctx.Entity.displayName)) { $ctx.Entity.displayName } else { $ctx.Entity.name }
        Resolve-SearchAssignments -Assignments $ctx.Assignments -CategoryLabel $ctx.Category.ExportCategory -PolicyName $policyName -PolicyId $ctx.Entity.id -Results $results
    }

    $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -EntityPreFilter $entityPreFilter -ShowProgress -ProgressVerb 'Searching' -BuildRecords:$PassThru
    $allSearchResults = $scanResult.Buckets['SearchResults']

    # --- Display Results ---
    $uniquePolicies = $allSearchResults | Select-Object -Property PolicyId -Unique
    $totalMatches = $uniquePolicies.Count

    if ($totalMatches -eq 0) {
        Write-Host "`nNo policies found matching '$searchTerm'." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan
        Write-Host "  POLICY SEARCH RESULTS" -ForegroundColor Cyan
        Write-Host "  Search term: '$searchTerm'" -ForegroundColor White
        Write-Host "  Found $totalMatches matching $(if ($totalMatches -eq 1) { 'policy' } else { 'policies' })" -ForegroundColor White
        Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan

        $groupedResults = $allSearchResults | Group-Object -Property PolicyId

        foreach ($policyGroup in $groupedResults) {
            $first = $policyGroup.Group[0]
            $policyName = $first.PolicyName
            if (-not $policyName) { $policyName = "Unnamed Policy" }

            Write-Host "`n===== $policyName =====" -ForegroundColor White
            Write-Host "Category: $($first.Category) | Policy ID: $($first.PolicyId)" -ForegroundColor Gray

            $separator = Get-Separator
            Write-Host $separator -ForegroundColor Gray
            Write-Host "Assignment Targets:" -ForegroundColor Yellow

            foreach ($result in $policyGroup.Group) {
                $filterDisplay = ''
                if ($result.FilterName) {
                    $filterDisplay = " (Filter: $($result.FilterName) [$($result.FilterType)])"
                }
                if ($result.AssignmentType -eq "None") {
                    Write-Host "  No assignments" -ForegroundColor DarkGray
                }
                elseif ($result.AssignmentType -eq "Exclude") {
                    $target = if ($result.TargetGroupId) { "Group: $($result.TargetName) (ID: $($result.TargetGroupId))" } else { $result.TargetName }
                    Write-Host "  [EXCLUDE] $target$filterDisplay" -ForegroundColor Red
                }
                else {
                    $target = if ($result.TargetGroupId) { "Group: $($result.TargetName) (ID: $($result.TargetGroupId))" } else { $result.TargetName }
                    Write-Host "  [INCLUDE] $target$filterDisplay" -ForegroundColor Green
                }
            }
            Write-Host $separator -ForegroundColor Gray
        }

        # Summary
        $totalTargets = ($allSearchResults | Where-Object { $_.AssignmentType -ne "None" }).Count
        Write-Host "`n=== Search Summary ===" -ForegroundColor Cyan
        Write-Host "  Found $totalMatches $(if ($totalMatches -eq 1) { 'policy' } else { 'policies' }) matching '$searchTerm'" -ForegroundColor White
        Write-Host "  Total assignment targets: $totalTargets" -ForegroundColor White
    }

    # --- Export ---
    $exportData = [System.Collections.ArrayList]::new()
    $null = $exportData.Add([PSCustomObject]@{
            Category         = "Search Info"
            Item             = "Search term: $searchTerm"
            ScopeTags        = ""
            AssignmentReason = "Found $totalMatches policies"
            FilterName       = ""
            FilterType       = ""
        })

    foreach ($result in $allSearchResults) {
        $filterLabel = if ($result.FilterName) { " (Filter: $($result.FilterName) [$($result.FilterType)])" } else { "" }
        $null = $exportData.Add([PSCustomObject]@{
                Category         = $result.Category
                Item             = "$($result.PolicyName) (ID: $($result.PolicyId))"
                ScopeTags        = ""
                AssignmentReason = "[$($result.AssignmentType)] $($result.TargetName)$(if ($result.TargetGroupId) { " (ID: $($result.TargetGroupId))" })$filterLabel"
                FilterName       = $result.FilterName
                FilterType       = $result.FilterType
            })
    }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntunePolicySearch.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:($parameterMode -or $PassThru)
    if ($PassThru) {
        Select-IACAssignmentRecord -Records $scanResult.Records -Buckets $scanResult.Buckets `
            -SubjectType 'Search' -SubjectName $searchTerm -Source 'Search-IntunePolicy'
    }
}
