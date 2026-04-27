function Format-AssignmentSummaryLine {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Assignment
    )

    $line = switch ($Assignment.Reason) {
        { $_ -in @('Group Assignment', 'Group Exclusion', 'Direct Assignment', 'Direct Exclusion') } {
            $groupInfo = Get-GroupInfo -GroupId $Assignment.GroupId
            "$($Assignment.Reason) - $($groupInfo.DisplayName)"
            break
        }
        default { $Assignment.Reason }
    }

    $suffix = Format-AssignmentFilter -FilterId $Assignment.FilterId -FilterType $Assignment.FilterType
    return "$line$suffix"
}
