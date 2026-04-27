function Get-GroupAssignmentReasons {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Assignments,

        [Parameter(Mandatory = $true)]
        [string]$DirectGroupId,

        [Parameter(Mandatory = $false)]
        [hashtable]$ParentGroupMap = @{}
    )

    $reasons = @()
    foreach ($assignment in $Assignments) {
        if ($assignment.Reason -eq "Direct Assignment" -or $assignment.Reason -eq "Direct Exclusion") {
            $reasonText = $null
            if ($assignment.GroupId -eq $DirectGroupId) {
                $reasonText = $assignment.Reason
            }
            elseif ($ParentGroupMap.ContainsKey($assignment.GroupId)) {
                $parentName = $ParentGroupMap[$assignment.GroupId]
                if ($assignment.Reason -eq "Direct Assignment") {
                    $reasonText = "Inherited (via $parentName)"
                }
                else {
                    $reasonText = "Inherited Exclusion (via $parentName)"
                }
            }
            if ($reasonText) {
                $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                $reasons += "$reasonText$suffix"
            }
        }
    }
    return $reasons
}
