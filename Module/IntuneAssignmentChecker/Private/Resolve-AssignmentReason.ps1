function Resolve-AssignmentReason {
    param (
        [object[]]$Assignments,
        [object[]]$GroupMembershipIds,
        [string[]]$IncludeReasons = @("All Users")
    )

    $isExcluded = $false
    $inclusionReason = $null

    foreach ($a in $Assignments) {
        if ($a.Reason -eq "Group Exclusion" -and $GroupMembershipIds -contains $a.GroupId) {
            $isExcluded = $true
        }
        elseif (-not $inclusionReason) {
            if ($IncludeReasons -contains $a.Reason) {
                $inclusionReason = $a.Reason
            }
            elseif ($a.Reason -eq "Group Assignment" -and $GroupMembershipIds -contains $a.GroupId) {
                $inclusionReason = $a.Reason
            }
        }
    }

    if ($isExcluded) { return "Excluded" }
    return $inclusionReason
}
