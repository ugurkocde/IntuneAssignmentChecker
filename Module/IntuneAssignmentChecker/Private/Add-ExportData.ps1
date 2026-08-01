function Add-ExportData {
    [CmdletBinding()]
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Items,
        [Parameter(Mandatory = $false)]
        [object]$AssignmentReason = "N/A",
        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$AdditionalProperties
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

        $filterName = ''
        $filterType = ''
        if ($reason -is [string] -and $reason -match ' \(Filter: (?<name>.+?) \[(?<type>Include|Exclude)\]\)') {
            $filterName = $Matches['name']
            $filterType = $Matches['type']
        }

        $row = [ordered]@{
            Category         = $Category
            Item             = "$itemName (ID: $($item.id))"
            ScopeTags        = Get-ScopeTagNames -ScopeTagIds $item.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
            AssignmentReason = $reason
            FilterName       = $filterName
            FilterType       = $filterType
        }
        if ($AdditionalProperties) {
            foreach ($propertyName in $AdditionalProperties.Keys) {
                if ($row.Contains($propertyName)) {
                    throw "Additional export property '$propertyName' conflicts with a reserved export column."
                }
                $row[$propertyName] = $AdditionalProperties[$propertyName]
            }
        }

        $null = $ExportData.Add([PSCustomObject]$row)
    }
}
