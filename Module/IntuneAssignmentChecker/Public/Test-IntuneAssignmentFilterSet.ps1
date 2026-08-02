function Test-IntuneAssignmentFilterSet {
    <#
    .SYNOPSIS
    Audits all tenant assignment filters and their policy references.

    .DESCRIPTION
    Finds unused, orphaned, duplicate, unsupported, platform-mismatched, match-all,
    and match-none filters. Optional device samples are evaluated through the same
    safe local parser used by Test-IntuneAssignmentFilter; filter text is never run.

    .PARAMETER SnapshotPath
    Assignment snapshot used to resolve filter references offline.

    .PARAMETER FilterDefinitionPath
    Optional JSON export of assignment-filter definitions for offline analysis.

    .PARAMETER DeviceName
    Managed-device names or IDs used to identify match-all or match-none filters.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentFilterSetFinding')]
    param(
        [Parameter()]
        [string]$SnapshotPath,

        [Parameter()]
        [string]$FilterDefinitionPath,

        [Parameter()]
        [string[]]$DeviceName = @(),

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'Json'
    )

    $coverageComplete = $true
    $coverageErrors = @()
    $records = if ($SnapshotPath) {
        $snapshot = Read-IACAssignmentSnapshot -Path $SnapshotPath
        $coverageComplete = -not (Test-IACCoverageHasBlockingFailure -Coverage $snapshot.Coverage)
        $coverageErrors = @($snapshot.Coverage.Errors)
        @($snapshot.Records)
    }
    else {
        if (-not $script:GraphEndpoint) { throw 'Connect first with Connect-IntuneAssignmentChecker or supply -SnapshotPath.' }
        $categories = @(Get-IntuneCategoryDefinition -Audience Effective)
        $scan = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{} -BuildRecords
        $coverageErrors = @($scan.Errors)
        $coverageComplete = $coverageErrors.Count -eq 0
        @($scan.Records)
    }
    $filters = if ($FilterDefinitionPath) {
        $document = Get-Content -LiteralPath $FilterDefinitionPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 -ErrorAction Stop
        if ($document.Filters) { @($document.Filters) } else { @($document) }
    }
    else {
        if (-not $script:GraphEndpoint) {
            @($records | Where-Object FilterId | Group-Object FilterId | ForEach-Object {
                    $sample = $_.Group[0]
                    [PSCustomObject]@{ Id = $sample.FilterId; Name = $sample.FilterName; Platform = $sample.FilterPlatform; Rule = $sample.FilterRule; AssignmentFilterManagementType = $null }
                })
        }
        else {
            $script:AssignmentFilterLookup = Get-AssignmentFilterLookup
            @($script:AssignmentFilterLookup.Values)
        }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $addFinding = {
        param($RuleId, $Severity, $Title, $Filter, $Message, $Evidence, $Remediation)
        $item = [PSCustomObject][ordered]@{
            SchemaName    = 'IntuneAssignmentChecker.AssignmentFilterSetFinding'
            SchemaVersion = 1
            RuleId        = $RuleId
            Severity      = $Severity
            Title         = $Title
            FilterId      = $Filter.Id
            FilterName    = $Filter.Name
            Platform      = $Filter.Platform
            Rule          = $Filter.Rule
            Message       = $Message
            References    = @($records | Where-Object FilterId -EQ $Filter.Id | Select-Object CategoryId, PolicyId, PolicyName, AssignmentId -Unique)
            Evidence      = $Evidence
            Remediation   = $Remediation
            DetectedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
        }
        $item.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentFilterSetFinding')
        [void]$findings.Add($item)
    }

    $filterIds = @($filters.Id | ForEach-Object { "$_" })
    if (-not $coverageComplete) {
        $coverageFilter = [PSCustomObject]@{ Id = $null; Name = 'Scan coverage'; Platform = $null; Rule = $null }
        & $addFinding 'IAF007' 'High' 'Incomplete assignment coverage' $coverageFilter 'Unused-filter findings were suppressed because one or more assignment workloads were unavailable.' @{ Errors = @($coverageErrors) } 'Restore workload access and rerun the filter-set audit before removing filters.'
    }
    foreach ($reference in @($records | Where-Object FilterId | Group-Object FilterId)) {
        if ($reference.Name -notin $filterIds) {
            $sample = $reference.Group[0]
            $missing = [PSCustomObject]@{ Id = $sample.FilterId; Name = $sample.FilterName; Platform = $sample.FilterPlatform; Rule = $sample.FilterRule }
            & $addFinding 'IAF006' 'High' 'Orphaned filter reference' $missing "Assignments reference missing filter '$($sample.FilterId)'." @{ ReferenceCount = $reference.Count } 'Replace or remove the stale filter reference.'
        }
    }

    foreach ($filter in $filters) {
        $references = @($records | Where-Object FilterId -EQ $filter.Id)
        if ($coverageComplete -and $references.Count -eq 0) {
            & $addFinding 'IAF001' 'Low' 'Unused assignment filter' $filter "Filter '$($filter.Name)' is not referenced by the scanned assignments." @{ ReferenceCount = 0 } 'Confirm the scan is complete, then remove or document the unused filter.'
        }
        try {
            $tokens = ConvertTo-IACTokenList -Rule "$($filter.Rule)"
            $null = ConvertTo-IACFilterAst -Tokens $tokens
        }
        catch {
            & $addFinding 'IAF003' 'High' 'Unsupported assignment filter expression' $filter "Filter '$($filter.Name)' cannot be evaluated safely: $($_.Exception.Message)" @{ ParserError = $_.Exception.Message } 'Rewrite the rule with documented properties and supported operators.'
        }
        $managementType = "$($filter.AssignmentFilterManagementType)"
        if (($managementType -eq 'devices' -and "$($filter.Rule)" -match '(?i)\bapp\.') -or
            ($managementType -eq 'apps' -and "$($filter.Rule)" -match '(?i)\bdevice\.')) {
            & $addFinding 'IAF004' 'High' 'Filter management type mismatch' $filter "Filter '$($filter.Name)' uses properties that conflict with management type '$managementType'." @{ AssignmentFilterManagementType = $managementType } 'Align the rule property prefix and assignmentFilterManagementType.'
        }
    }

    foreach ($duplicates in @($filters | Group-Object {
                ("$($_.Rule)" -replace '\s+', '').ToLowerInvariant() + '|' + "$($_.Platform)".ToLowerInvariant() + '|' + "$($_.AssignmentFilterManagementType)".ToLowerInvariant()
            } | Where-Object Count -gt 1)) {
        foreach ($filter in $duplicates.Group) {
            & $addFinding 'IAF002' 'Medium' 'Duplicate assignment filter' $filter "Filter '$($filter.Name)' duplicates $($duplicates.Count - 1) other filter(s)." @{ DuplicateFilterIds = @($duplicates.Group.Id | Where-Object { $_ -ne $filter.Id }) } 'Consolidate references onto one filter and retire the duplicates.'
        }
    }

    if ($DeviceName.Count -gt 0) {
        if (-not $script:GraphEndpoint) { throw '-DeviceName evaluation requires an active Microsoft Graph connection.' }
        foreach ($filter in $filters) {
            $evaluations = foreach ($device in $DeviceName) {
                Test-IntuneAssignmentFilter -DeviceName $device -FilterId "$($filter.Id)" -FilterMode Include
            }
            $known = @($evaluations | Where-Object Result -In @('Match', 'NotMatch'))
            if ($known.Count -eq $DeviceName.Count -and @($known | Where-Object Result -EQ 'Match').Count -eq $known.Count) {
                & $addFinding 'IAF005' 'Medium' 'Filter matches every sampled device' $filter "Filter '$($filter.Name)' matched all $($known.Count) sampled devices." @{ Evaluations = @($evaluations) } 'Review whether the filter meaningfully narrows the assignment.'
            }
            elseif ($known.Count -eq $DeviceName.Count -and @($known | Where-Object Result -EQ 'NotMatch').Count -eq $known.Count) {
                & $addFinding 'IAF005' 'Medium' 'Filter matches no sampled devices' $filter "Filter '$($filter.Name)' matched none of the $($known.Count) sampled devices." @{ Evaluations = @($evaluations) } 'Validate the filter rule and sample population before relying on the assignment.'
            }
        }
    }

    $ordered = @($findings | Sort-Object @{ Expression = { -(Get-IACSeverityRank $_.Severity) } }, RuleId, FilterName)
    if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject $ordered -Path $OutputPath -Format $OutputFormat }
    $ordered | Write-Output
}
