function New-IACAssignmentRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$CategoryId,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Category,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PolicyId,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PolicyName,
        [string]$Platform = 'Unknown',
        [string[]]$ScopeTagIds = @(),
        [string[]]$ScopeTags = @(),
        [string]$AssignmentId,
        [ValidateSet('Include', 'Exclude', 'None', 'Unknown')]
        [string]$AssignmentMode = 'Unknown',
        [ValidateSet('AllUsers', 'AllDevices', 'Group', 'None', 'Unknown')]
        [string]$TargetType = 'Unknown',
        [string]$TargetId,
        [string]$TargetName,
        [string]$Intent,
        [string]$FilterId,
        [string]$FilterName,
        [string]$FilterMode,
        [string]$FilterRule,
        [string]$FilterPlatform,
        [string]$SubjectType,
        [string]$SubjectId,
        [string]$SubjectName,
        [string]$AssignmentReason,
        [string]$Source = 'MicrosoftGraph'
    )

    $record = [PSCustomObject][ordered]@{
        SchemaVersion    = 1
        TenantId         = $script:CurrentTenantId
        TenantName       = $script:CurrentTenantName
        SubjectType      = $SubjectType
        SubjectId        = $SubjectId
        SubjectName      = $SubjectName
        CategoryId       = $CategoryId
        Category         = $Category
        PolicyId         = $PolicyId
        PolicyName       = $PolicyName
        Platform         = $Platform
        ScopeTagIds      = @($ScopeTagIds | ForEach-Object { "$_" })
        ScopeTags        = @($ScopeTags | ForEach-Object { "$_" })
        AssignmentId     = $AssignmentId
        AssignmentMode   = $AssignmentMode
        TargetType       = $TargetType
        TargetId         = $TargetId
        TargetName       = $TargetName
        Intent           = $Intent
        FilterId         = $FilterId
        FilterName       = $FilterName
        FilterMode       = $FilterMode
        FilterRule       = $FilterRule
        FilterPlatform   = $FilterPlatform
        AssignmentReason = $AssignmentReason
        Source           = $Source
    }
    $record.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentRecord')
    return $record
}
