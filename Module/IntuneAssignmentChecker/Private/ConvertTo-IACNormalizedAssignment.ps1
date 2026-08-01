function ConvertTo-IACNormalizedAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Assignment,
        [string[]]$GroupIds = @()
    )

    if (-not $Assignment.target -or -not $Assignment.target.'@odata.type') { return }

    $odataType = "$($Assignment.target.'@odata.type')"
    $targetGroupId = if ($odataType -in @(
            '#microsoft.graph.groupAssignmentTarget',
            '#microsoft.graph.exclusionGroupAssignmentTarget'
        )) { "$($Assignment.target.groupId)" } else { $null }

    $reason = switch ($odataType) {
        '#microsoft.graph.groupAssignmentTarget' {
            if ($GroupIds.Count -eq 0) { 'Group Assignment' }
            elseif ($GroupIds -contains $targetGroupId) { 'Direct Assignment' }
        }
        '#microsoft.graph.exclusionGroupAssignmentTarget' {
            if ($GroupIds.Count -eq 0) { 'Group Exclusion' }
            elseif ($GroupIds -contains $targetGroupId) { 'Direct Exclusion' }
        }
        '#microsoft.graph.allLicensedUsersAssignmentTarget' {
            if ($GroupIds.Count -eq 0) { 'All Users' }
        }
        '#microsoft.graph.allDevicesAssignmentTarget' {
            if ($GroupIds.Count -eq 0) { 'All Devices' }
        }
    }
    if (-not $reason) { return }

    $filterId = $null
    $filterType = $null
    $rawFilterId = $Assignment.target.deviceAndAppManagementAssignmentFilterId
    $rawFilterType = $Assignment.target.deviceAndAppManagementAssignmentFilterType
    if ($rawFilterType -and $rawFilterType -ne 'none' -and $rawFilterId -and $rawFilterId -ne '00000000-0000-0000-0000-000000000000') {
        $filterId = "$rawFilterId"
        $filterType = "$rawFilterType"
    }

    [PSCustomObject][ordered]@{
        AssignmentId   = if ($null -ne $Assignment.id) { "$($Assignment.id)" } else { $null }
        Reason         = $reason
        AssignmentMode = if ($odataType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') { 'Exclude' } else { 'Include' }
        TargetType     = switch ($odataType) {
            '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'AllUsers' }
            '#microsoft.graph.allDevicesAssignmentTarget' { 'AllDevices' }
            '#microsoft.graph.groupAssignmentTarget' { 'Group' }
            '#microsoft.graph.exclusionGroupAssignmentTarget' { 'Group' }
        }
        TargetId       = $targetGroupId
        GroupId        = $targetGroupId
        Intent         = if ($null -ne $Assignment.intent) { "$($Assignment.intent)" } else { $null }
        Apps           = $null
        FilterId       = $filterId
        FilterType     = $filterType
    }
}
