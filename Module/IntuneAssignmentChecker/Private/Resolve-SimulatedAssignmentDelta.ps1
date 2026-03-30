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

    $isNewPolicy = $false
    $isConflict = $false

    # New policy: user doesn't currently receive it (null or excluded), but would after simulation (non-null, non-excluded)
    if ((-not $currentStatus -or $currentStatus -eq "Excluded") -and $simulatedStatus -and $simulatedStatus -ne "Excluded") {
        $isNewPolicy = $true
    }

    # Conflict: user is currently excluded, and the target group specifically includes it (but exclusion still wins in Intune)
    if ($currentStatus -eq "Excluded" -and $simulatedStatus -eq "Excluded" -and $TargetGroupIds.Count -gt 0) {
        foreach ($a in $Assignments) {
            if ($a.Reason -eq "Group Assignment" -and $TargetGroupIds -contains $a.GroupId) {
                $isConflict = $true
                break
            }
        }
    }

    # Lost policy: user currently receives it, but would not after simulation
    $isLostPolicy = $false
    if ($currentStatus -and $currentStatus -ne "Excluded" -and (-not $simulatedStatus -or $simulatedStatus -eq "Excluded")) {
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
