function ConvertTo-IACAssignmentRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Category,
        [Parameter(Mandatory)] [object]$Entity,
        [Parameter(Mandatory)] [object]$Assignment,
        [string]$SubjectType,
        [string]$SubjectId,
        [string]$SubjectName,
        [string]$Source = 'MicrosoftGraph',
        [switch]$ResolveTargetName
    )

    $policyName = if (-not [string]::IsNullOrWhiteSpace($Entity.displayName)) { $Entity.displayName }
        elseif (-not [string]::IsNullOrWhiteSpace($Entity.name)) { $Entity.name }
        else { 'Unnamed Policy' }

    $targetType = if ($Assignment.TargetType) { "$($Assignment.TargetType)" }
        else {
            switch ("$($Assignment.Reason)") {
                'All Users' { 'AllUsers' }
                'All Devices' { 'AllDevices' }
                'Group Assignment' { 'Group' }
                'Direct Assignment' { 'Group' }
                'Group Exclusion' { 'Group' }
                'Direct Exclusion' { 'Group' }
                'No Assignment' { 'None' }
                default { 'Unknown' }
            }
        }
    $assignmentMode = if ($Assignment.AssignmentMode) { "$($Assignment.AssignmentMode)" }
        elseif ($Assignment.Reason -in @('Group Exclusion', 'Direct Exclusion')) { 'Exclude' }
        elseif ($Assignment.Reason -eq 'No Assignment') { 'None' }
        else { 'Include' }
    $targetId = if ($Assignment.TargetId) { $Assignment.TargetId } else { $Assignment.GroupId }
    $targetName = switch ($targetType) {
        'AllUsers' { 'All Users' }
        'AllDevices' { 'All Devices' }
        'Group' {
            if ($ResolveTargetName -and $targetId) { (Get-GroupInfo -GroupId $targetId).DisplayName }
            else { $null }
        }
        default { $null }
    }
    $filter = if ($Assignment.FilterId -and $script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey("$($Assignment.FilterId)")) {
        $script:AssignmentFilterLookup["$($Assignment.FilterId)"]
    }
    else { $null }
    $scopeTagIds = @($Entity.roleScopeTagIds | ForEach-Object { "$_" })
    $scopeTagNames = if ($scopeTagIds.Count -eq 0) { @('Default') }
        elseif ($null -eq $script:ScopeTagLookup) { @($scopeTagIds | ForEach-Object { "Tag:$_" }) }
        else { @((Get-ScopeTagNames -ScopeTagIds $scopeTagIds -ScopeTagLookup $script:ScopeTagLookup) -split ', ') }
    $categoryName = if ($Category.ExportCategory) { $Category.ExportCategory } else { $Category.DisplayName }

    New-IACAssignmentRecord `
        -CategoryId "$($Category.Id)" -Category "$categoryName" `
        -PolicyId "$($Entity.id)" -PolicyName $policyName `
        -Platform (Get-PolicyPlatform -Policy $Entity) `
        -ScopeTagIds $scopeTagIds -ScopeTags $scopeTagNames `
        -AssignmentId $Assignment.AssignmentId `
        -AssignmentMode $assignmentMode `
        -TargetType $targetType -TargetId $targetId -TargetName $targetName `
        -Intent $Assignment.Intent -FilterId $Assignment.FilterId `
        -FilterName $(if ($filter) { $filter.Name } else { $null }) `
        -FilterMode $Assignment.FilterType `
        -FilterRule $(if ($filter) { $filter.Rule } else { $null }) `
        -FilterPlatform $(if ($filter) { $filter.Platform } else { $null }) `
        -SubjectType $SubjectType -SubjectId $SubjectId -SubjectName $SubjectName `
        -AssignmentReason $Assignment.Reason -Source $Source
}
