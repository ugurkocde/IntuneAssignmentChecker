function Get-AssignmentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]$Assignments
    )

    if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
        return @{
            Type       = "None"
            Target     = "Not Assigned"
            FilterId   = $null
            FilterType = $null
            FilterName = $null
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

    $filterSuffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
    if ($filterSuffix) { $target = "$target$filterSuffix" }

    $filterName = $null
    if ($assignment.FilterId -and $script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey($assignment.FilterId)) {
        $filterName = $script:AssignmentFilterLookup[$assignment.FilterId].Name
    }

    return @{
        Type       = $type
        Target     = $target
        FilterId   = $assignment.FilterId
        FilterType = $assignment.FilterType
        FilterName = $filterName
    }
}
