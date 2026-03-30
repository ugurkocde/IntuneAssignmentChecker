function Get-AssignmentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]$Assignments
    )

    if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
        return @{
            Type   = "None"
            Target = "Not Assigned"
        }
    }

    $assignment = $Assignments[0]  # Take the first assignment
    $type = switch ($assignment.Reason) {
        "All Users" { "All Users"; break }
        "All Devices" { "All Devices"; break }
        "Group Assignment" { "Group"; break }
        default { "None" }
    }

    $target = switch ($type) {
        "All Users" { "All Users" }
        "All Devices" { "All Devices" }
        "Group" {
            if ($assignment.GroupId) {
                $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                $groupInfo.DisplayName
            }
            else {
                "Unknown Group"
            }
        }
        default { "Not Assigned" }
    }

    return @{
        Type   = $type
        Target = $target
    }
}
