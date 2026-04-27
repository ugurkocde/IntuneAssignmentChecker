function Resolve-AssignmentReason {
    param (
        [object[]]$Assignments,
        [object[]]$GroupMembershipIds,
        [string[]]$IncludeReasons = @("All Users")
    )

    $isExcluded = $false
    $excludingAssignment = $null
    $inclusionReason = $null
    $inclusionAssignment = $null

    foreach ($a in $Assignments) {
        if ($a.Reason -eq "Group Exclusion" -and $GroupMembershipIds -contains $a.GroupId) {
            $isExcluded = $true
            $excludingAssignment = $a
        }
        elseif (-not $inclusionReason) {
            if ($IncludeReasons -contains $a.Reason) {
                $inclusionReason = $a.Reason
                $inclusionAssignment = $a
            }
            elseif ($a.Reason -eq "Group Assignment" -and $GroupMembershipIds -contains $a.GroupId) {
                $inclusionReason = $a.Reason
                $inclusionAssignment = $a
            }
        }
    }

    if ($isExcluded) {
        $suffix = Format-AssignmentFilter -FilterId $excludingAssignment.FilterId -FilterType $excludingAssignment.FilterType
        return "Excluded$suffix"
    }

    if ($inclusionReason) {
        $suffix = Format-AssignmentFilter -FilterId $inclusionAssignment.FilterId -FilterType $inclusionAssignment.FilterType
        return "$inclusionReason$suffix"
    }

    return $null
}
