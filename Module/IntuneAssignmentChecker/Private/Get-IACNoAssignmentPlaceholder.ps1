function Get-IACNoAssignmentPlaceholder {
    [CmdletBinding()]
    param(
        [string]$Reason = 'No Assignment'
    )

    [PSCustomObject][ordered]@{
        AssignmentId   = $null
        Reason         = $Reason
        AssignmentMode = 'None'
        TargetType     = 'None'
        TargetId       = $null
        GroupId        = $null
        Intent         = $null
        Apps           = $null
        FilterId       = $null
        FilterType     = $null
    }
}
