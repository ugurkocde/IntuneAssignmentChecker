function Invoke-MultipleAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$Assignments,

        [Parameter(Mandatory = $false)]
        [string]$TargetGroupId = $null
    )

    $processedAssignments = [System.Collections.ArrayList]::new()

    foreach ($assignment in $Assignments) {
        $assignmentInfo = @{
            Reason    = $assignment.Reason
            GroupId   = $assignment.GroupId
            GroupName = $null
        }

        # Get group name for both assignments and exclusions
        if ($assignment.GroupId) {
            $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
            if ($groupInfo.Success) {
                $assignmentInfo.GroupName = $groupInfo.DisplayName
            }
        }

        # If we're checking for a specific group
        if ($TargetGroupId) {
            if ($assignment.GroupId -eq $TargetGroupId) {
                $null = $processedAssignments.Add($assignmentInfo)
            }
        }
        else {
            $null = $processedAssignments.Add($assignmentInfo)
        }
    }

    return $processedAssignments
}
