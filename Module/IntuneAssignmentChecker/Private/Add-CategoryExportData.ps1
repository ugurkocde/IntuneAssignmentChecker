function Add-CategoryExportData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$ExportData,

        # Category registry entries from Get-IntuneCategoryDefinition; export rows are
        # emitted in registry order so CSV output matches the pre-refactor sequence.
        [Parameter(Mandatory = $true)]
        [object[]]$Categories,

        # Bucket hashtable as returned by Invoke-IntuneCategoryScan (possibly filtered).
        [Parameter(Mandatory = $true)]
        [hashtable]$Buckets,

        # Passed through to Add-ExportData when provided (string or scriptblock).
        [Parameter(Mandatory = $false)]
        [object]$AssignmentReason,

        # Optional attribution columns added uniformly to every exported row.
        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$AdditionalProperties
    )

    # Categories may share a bucket (e.g. Compare's ShellScripts feed PlatformScripts);
    # export each bucket only once, under the first category that declares it.
    $exportedBucketKeys = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($category in $Categories) {
        foreach ($bucketKey in $category.BucketKeys) {
            if (-not $exportedBucketKeys.Add($bucketKey)) { continue }

            $label = if ($category.BucketExportCategories) {
                $category.BucketExportCategories[$bucketKey]
            }
            else {
                $category.ExportCategory
            }
            if (-not $label) { continue }

            $items = if ($Buckets.ContainsKey($bucketKey)) { @($Buckets[$bucketKey]) } else { @() }

            # Empty buckets still go through Add-ExportData as a no-op, matching the
            # unconditional per-category calls the cmdlets made before the migration.
            $addParams = @{
                ExportData = $ExportData
                Category   = $label
                Items      = $items
            }
            if ($PSBoundParameters.ContainsKey('AssignmentReason')) {
                $addParams.AssignmentReason = $AssignmentReason
            }
            if ($PSBoundParameters.ContainsKey('AdditionalProperties')) {
                $addParams.AdditionalProperties = $AdditionalProperties
            }
            Add-ExportData @addParams
        }
    }
}
