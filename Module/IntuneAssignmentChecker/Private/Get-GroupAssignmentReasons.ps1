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
            if ($assignment.GroupId -eq $DirectGroupId) {
                $reasons += $assignment.Reason
            }
            elseif ($ParentGroupMap.ContainsKey($assignment.GroupId)) {
                $parentName = $ParentGroupMap[$assignment.GroupId]
                if ($assignment.Reason -eq "Direct Assignment") {
                    $reasons += "Inherited (via $parentName)"
                }
                else {
                    $reasons += "Inherited Exclusion (via $parentName)"
                }
            }
        }
    }
    return $reasons
}
