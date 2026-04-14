function Add-ExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Items,
        [Parameter(Mandatory = $false)]
        [object]$AssignmentReason = "N/A"
    )

    foreach ($item in $Items) {
        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }

        # Handle different types of assignment reason input
        $reason = if ($AssignmentReason -is [scriptblock]) {
            & $AssignmentReason $item
        }
        elseif ($item.AssignmentReason) {
            $item.AssignmentReason
        }
        elseif ($item.AssignmentSummary) {
            $item.AssignmentSummary
        }
        else {
            $AssignmentReason
        }

        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$itemName (ID: $($item.id))"
                ScopeTags        = Get-ScopeTagNames -ScopeTagIds $item.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
                AssignmentReason = $reason
            })
    }
}
