function Add-AppExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Apps,
        [string]$AssignmentReason = "N/A"
    )

    foreach ($app in $Apps) {
        $appName = if ($app.displayName) { $app.displayName } else { $app.name }
        $reason = "$AssignmentReason - $($app.AssignmentIntent)"

        $filterName = ''
        $filterType = ''
        if ($AssignmentReason -match ' \(Filter: (?<name>.+?) \[(?<type>Include|Exclude)\]\)') {
            $filterName = $Matches['name']
            $filterType = $Matches['type']
        }

        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$appName (ID: $($app.id))"
                ScopeTags        = Get-ScopeTagNames -ScopeTagIds $app.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
                AssignmentReason = $reason
                FilterName       = $filterName
                FilterType       = $filterType
            })
    }
}
