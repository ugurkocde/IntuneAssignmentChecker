function Format-AssignmentFilter {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$FilterId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$FilterType
    )

    if (-not $FilterType -or $FilterType -eq 'none') { return '' }
    if (-not $FilterId) { return '' }

    $filterName = $null
    if ($script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey($FilterId)) {
        $filterName = $script:AssignmentFilterLookup[$FilterId].Name
    }
    if (-not $filterName) { $filterName = "Unknown Filter ($FilterId)" }

    $typeLabel = switch ($FilterType) {
        'include' { 'Include' }
        'exclude' { 'Exclude' }
        default   { $FilterType }
    }

    return " (Filter: $filterName [$typeLabel])"
}
