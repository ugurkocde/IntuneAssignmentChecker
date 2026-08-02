function Get-IACSha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$InputText)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $algorithm.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-IACAssignmentRecordId {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    $identity = @(
        $Record.SubjectType, $Record.SubjectId, $Record.CategoryId, $Record.PolicyId,
        $(if ($Record.AssignmentId) { "id:$($Record.AssignmentId)" } else { "fallback:$($Record.AssignmentMode)|$($Record.TargetType)|$($Record.TargetId)|$($Record.Intent)" })
    ) -join "`u{001f}"
    Get-IACSha256Hex -InputText $identity
}

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
        [ValidateSet('Included', 'Excluded', 'NotTargeted', 'Unknown')]
        [AllowNull()]
        [string]$EffectiveState,
        [object[]]$ReasonChain = @(),
        [string]$SubjectType,
        [string]$SubjectId,
        [string]$SubjectName,
        [string]$AssignmentReason,
        [string]$Source = 'MicrosoftGraph'
    )

    $record = [PSCustomObject][ordered]@{
        SchemaName       = 'IntuneAssignmentChecker.AssignmentRecord'
        SchemaVersion    = 2
        RecordId         = $null
        GraphApiVersion  = 'beta'
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
        EffectiveState   = if ([string]::IsNullOrWhiteSpace($EffectiveState)) { $null } else { $EffectiveState }
        ReasonChain      = @($ReasonChain)
        AssignmentReason = $AssignmentReason
        Source           = $Source
    }
    $record.RecordId = Get-IACAssignmentRecordId -Record $record
    $record.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentRecord')
    return $record
}
