function Compare-IntuneAssignmentSnapshot {
    <#
    .SYNOPSIS
    Compares two Intune assignment snapshot files.

    .DESCRIPTION
    Reports Added, Removed, and Changed canonical assignment records using a
    schema-versioned stable identity key. By default, comparison rejects
    failed or unknown coverage, cross-tenant, or category-coverage-mismatched
    snapshots. Categories marked Skipped are excluded from both sides with a warning.

    .PARAMETER ReferencePath
    Older or baseline snapshot.

    .PARAMETER DifferencePath
    Newer snapshot.

    .PARAMETER AllowIncompleteCoverage
    Allows comparison when either snapshot contains failed or unknown coverage.

    .PARAMETER AllowCoverageMismatch
    Allows comparison when the snapshots cover different category ID sets.

    .EXAMPLE
    Compare-IntuneAssignmentSnapshot -ReferencePath './before.json' -DifferencePath './after.json'
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentSnapshotDifference')]
    param(
        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter()]
        [switch]$AllowIncompleteCoverage,

        [Parameter()]
        [switch]$AllowCoverageMismatch
    )

    $reference = Read-IACAssignmentSnapshot -Path $ReferencePath
    $difference = Read-IACAssignmentSnapshot -Path $DifferencePath

    if ("$($reference.Tenant.Id)" -cne "$($difference.Tenant.Id)") {
        throw "Snapshots belong to different tenants ('$($reference.Tenant.Id)' and '$($difference.Tenant.Id)')."
    }
    $hasBlockingIncompleteCoverage = (Test-IACCoverageHasBlockingFailure -Coverage $reference.Coverage) -or
        (Test-IACCoverageHasBlockingFailure -Coverage $difference.Coverage)
    if (-not $AllowIncompleteCoverage -and $hasBlockingIncompleteCoverage) {
        throw 'One or both snapshots have incomplete category coverage; use -AllowIncompleteCoverage to compare them explicitly.'
    }
    $referenceCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($categoryId in @($reference.Coverage.Categories.CategoryId)) { [void]$referenceCategories.Add("$categoryId") }
    $differenceCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($categoryId in @($difference.Coverage.Categories.CategoryId)) { [void]$differenceCategories.Add("$categoryId") }
    if (-not $AllowCoverageMismatch -and -not $referenceCategories.SetEquals($differenceCategories)) {
        throw 'Snapshots cover different category sets; use -AllowCoverageMismatch to compare them explicitly.'
    }

    $skippedCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($category in @($reference.Coverage.Categories) + @($difference.Coverage.Categories)) {
        if ($category.Status -ceq 'Skipped') {
            [void]$skippedCategories.Add("$($category.CategoryId)")
        }
    }
    if ($skippedCategories.Count -gt 0) {
        $orderedSkippedCategories = [System.Collections.Generic.List[string]]::new($skippedCategories)
        $orderedSkippedCategories.Sort([System.StringComparer]::Ordinal)
        Write-Warning "Skipped categories were not compared: $($orderedSkippedCategories -join ', ')."
    }

    $referenceByKey = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($record in @($reference.Records)) {
        if ($skippedCategories.Contains("$($record.CategoryId)")) { continue }
        $referenceByKey.Add((Get-IACAssignmentIdentityKey -Record $record), $record)
    }
    $differenceByKey = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($record in @($difference.Records)) {
        if ($skippedCategories.Contains("$($record.CategoryId)")) { continue }
        $differenceByKey.Add((Get-IACAssignmentIdentityKey -Record $record), $record)
    }

    $changes = [System.Collections.Generic.List[object]]::new()
    $propertyNames = Get-IACAssignmentRecordPropertyNames
    foreach ($key in $differenceByKey.Keys) {
        if (-not $referenceByKey.ContainsKey($key)) {
            $after = $differenceByKey[$key]
            [void]$changes.Add([PSCustomObject][ordered]@{
                    ChangeType   = 'Added'
                    IdentityKey  = $key
                    CategoryId   = $after.CategoryId
                    PolicyId     = $after.PolicyId
                    AssignmentId = $after.AssignmentId
                    ChangedFields = @()
                    Before       = $null
                    After        = $after
                })
            continue
        }

        $before = $referenceByKey[$key]
        $after = $differenceByKey[$key]
        $changedFields = foreach ($propertyName in $propertyNames) {
            $beforeJson = ConvertTo-Json -InputObject $before.$propertyName -Depth 12 -Compress
            $afterJson = ConvertTo-Json -InputObject $after.$propertyName -Depth 12 -Compress
            if (-not [string]::Equals($beforeJson, $afterJson, [System.StringComparison]::Ordinal)) { $propertyName }
        }
        if (@($changedFields).Count -gt 0) {
            [void]$changes.Add([PSCustomObject][ordered]@{
                    ChangeType   = 'Changed'
                    IdentityKey  = $key
                    CategoryId   = $after.CategoryId
                    PolicyId     = $after.PolicyId
                    AssignmentId = $after.AssignmentId
                    ChangedFields = @($changedFields)
                    Before       = $before
                    After        = $after
                })
        }
    }
    foreach ($key in $referenceByKey.Keys) {
        if ($differenceByKey.ContainsKey($key)) { continue }
        $before = $referenceByKey[$key]
        [void]$changes.Add([PSCustomObject][ordered]@{
                ChangeType   = 'Removed'
                IdentityKey  = $key
                CategoryId   = $before.CategoryId
                PolicyId     = $before.PolicyId
                AssignmentId = $before.AssignmentId
                ChangedFields = @()
                Before       = $before
                After        = $null
            })
    }

    foreach ($changeType in @('Added', 'Removed', 'Changed')) {
        foreach ($change in @($changes | Where-Object ChangeType -CEQ $changeType)) {
            $change.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentSnapshotDifference')
            Write-Output $change
        }
    }
}
