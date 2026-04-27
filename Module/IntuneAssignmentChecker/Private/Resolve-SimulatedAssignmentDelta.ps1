function Resolve-SimulatedAssignmentDelta {
    param (
        [object[]]$Assignments,
        [object[]]$CurrentGroupIds,
        [object[]]$SimulatedGroupIds,
        [object[]]$TargetGroupIds = @(),
        [string[]]$IncludeReasons = @("All Users")
    )

    $currentStatus = Resolve-AssignmentReason -Assignments $Assignments -GroupMembershipIds $CurrentGroupIds -IncludeReasons $IncludeReasons
    $simulatedStatus = Resolve-AssignmentReason -Assignments $Assignments -GroupMembershipIds $SimulatedGroupIds -IncludeReasons $IncludeReasons

    $isCurrentExcluded   = $currentStatus   -like "Excluded*"
    $isSimulatedExcluded = $simulatedStatus -like "Excluded*"

    $isNewPolicy = $false
    $isConflict = $false

    # New policy: user doesn't currently receive it (null or excluded), but would after simulation (non-null, non-excluded)
    if ((-not $currentStatus -or $isCurrentExcluded) -and $simulatedStatus -and -not $isSimulatedExcluded) {
        $isNewPolicy = $true
    }

    # Conflict: user is currently excluded, and the target group specifically includes it (but exclusion still wins in Intune)
    if ($isCurrentExcluded -and $isSimulatedExcluded -and $TargetGroupIds.Count -gt 0) {
        foreach ($a in $Assignments) {
            if ($a.Reason -eq "Group Assignment" -and $TargetGroupIds -contains $a.GroupId) {
                $isConflict = $true
                break
            }
        }
    }

    # Lost policy: user currently receives it, but would not after simulation
    $isLostPolicy = $false
    if ($currentStatus -and -not $isCurrentExcluded -and (-not $simulatedStatus -or $isSimulatedExcluded)) {
        $isLostPolicy = $true
    }

    return [PSCustomObject]@{
        CurrentStatus    = $currentStatus
        SimulatedStatus  = $simulatedStatus
        IsNewPolicy      = $isNewPolicy
        IsLostPolicy     = $isLostPolicy
        IsConflict       = $isConflict
        AssignmentReason = $simulatedStatus
    }
}
