function Get-IACAssignmentRecordPropertyNames {
    [CmdletBinding()]
    param()

    @(
        'SchemaVersion', 'TenantId', 'TenantName', 'SubjectType', 'SubjectId', 'SubjectName',
        'CategoryId', 'Category', 'PolicyId', 'PolicyName', 'Platform', 'ScopeTagIds', 'ScopeTags',
        'AssignmentId', 'AssignmentMode', 'TargetType', 'TargetId', 'TargetName', 'Intent',
        'FilterId', 'FilterName', 'FilterMode', 'FilterRule', 'FilterPlatform', 'EffectiveState',
        'ReasonChain', 'AssignmentReason', 'Source'
    )
}

function Get-IACOrdinalSortedUniqueString {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$InputObject = @()
    )

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) { continue }
        [void]$set.Add("$item")
    }
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $set) { [void]$list.Add($item) }
    $list.Sort([System.StringComparer]::Ordinal)
    return $list.ToArray()
}

function Get-IACOrdinalSortedObject {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$InputObject = @(),
        [Parameter(Mandatory)][scriptblock]$KeySelector
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) { continue }
        $key = $item | ForEach-Object $KeySelector
        [void]$entries.Add([PSCustomObject]@{ Key = "$key"; Index = $index; Value = $item })
        $index++
    }
    $entries.Sort([System.Comparison[object]]{
            param($left, $right)
            $comparison = [System.StringComparer]::Ordinal.Compare($left.Key, $right.Key)
            if ($comparison -ne 0) { return $comparison }
            return $left.Index.CompareTo($right.Index)
        })
    return @($entries | ForEach-Object Value)
}

function ConvertTo-IACSnapshotRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject
    )

    process {
        $requiredProperties = Get-IACAssignmentRecordPropertyNames
        $missing = @($requiredProperties | Where-Object { $null -eq $InputObject.PSObject.Properties[$_] })
        if ($missing.Count -gt 0) {
            throw "Snapshot input is not a canonical assignment record; missing properties: $($missing -join ', ')."
        }
        $recordSchemaVersion = 0
        if (-not [int]::TryParse("$($InputObject.SchemaVersion)", [ref]$recordSchemaVersion) -or $recordSchemaVersion -ne 1) {
            throw "Assignment record schema version '$($InputObject.SchemaVersion)' is not supported; expected version 1."
        }
        if ([string]::IsNullOrWhiteSpace("$($InputObject.CategoryId)")) {
            throw 'Snapshot input contains an assignment record without CategoryId.'
        }
        $assignmentMode = switch ("$($InputObject.AssignmentMode)".ToLowerInvariant()) {
            'include' { 'Include' }
            'exclude' { 'Exclude' }
            'none' { 'None' }
            'unknown' { 'Unknown' }
            default { $null }
        }
        if ($null -eq $assignmentMode) {
            throw "Snapshot input contains unsupported AssignmentMode '$($InputObject.AssignmentMode)'."
        }
        $targetType = switch ("$($InputObject.TargetType)".ToLowerInvariant()) {
            'allusers' { 'AllUsers' }
            'alldevices' { 'AllDevices' }
            'group' { 'Group' }
            'none' { 'None' }
            'unknown' { 'Unknown' }
            default { $null }
        }
        if ($null -eq $targetType) {
            throw "Snapshot input contains unsupported TargetType '$($InputObject.TargetType)'."
        }
        $effectiveState = if ([string]::IsNullOrWhiteSpace("$($InputObject.EffectiveState)")) { $null }
            else {
                switch ("$($InputObject.EffectiveState)".ToLowerInvariant()) {
                    'included' { 'Included' }
                    'excluded' { 'Excluded' }
                    'nottargeted' { 'NotTargeted' }
                    'unknown' { 'Unknown' }
                    default { $null }
                }
            }
        if (-not [string]::IsNullOrWhiteSpace("$($InputObject.EffectiveState)") -and $null -eq $effectiveState) {
            throw "Snapshot input contains unsupported EffectiveState '$($InputObject.EffectiveState)'."
        }

        $reasonChain = foreach ($reason in @($InputObject.ReasonChain | Where-Object { $null -ne $_ })) {
            $sequence = 0
            if (-not [int]::TryParse("$($reason.Sequence)", [ref]$sequence) -or $sequence -lt 0) {
                throw "Snapshot input contains a reason-chain entry with invalid Sequence '$($reason.Sequence)'."
            }
            [PSCustomObject][ordered]@{
                Sequence          = $sequence
                Code              = $reason.Code
                FilterCode        = $reason.FilterCode
                Outcome           = $reason.Outcome
                AssignmentId      = $reason.AssignmentId
                AssignmentMode    = $reason.AssignmentMode
                TargetType        = $reason.TargetType
                TargetId          = $reason.TargetId
                MembershipSources = @(Get-IACOrdinalSortedUniqueString -InputObject @($reason.MembershipSources))
                TargetResult      = $reason.TargetResult
                FilterId          = $reason.FilterId
                FilterMode        = $reason.FilterMode
                FilterResult      = $reason.FilterResult
                Message           = $reason.Message
            }
        }

        [PSCustomObject][ordered]@{
            SchemaVersion    = 1
            TenantId         = $InputObject.TenantId
            TenantName       = $InputObject.TenantName
            SubjectType      = $InputObject.SubjectType
            SubjectId        = $InputObject.SubjectId
            SubjectName      = $InputObject.SubjectName
            CategoryId       = $InputObject.CategoryId
            Category         = $InputObject.Category
            PolicyId         = $InputObject.PolicyId
            PolicyName       = $InputObject.PolicyName
            Platform         = $InputObject.Platform
            ScopeTagIds      = @(Get-IACOrdinalSortedUniqueString -InputObject @($InputObject.ScopeTagIds))
            ScopeTags        = @(Get-IACOrdinalSortedUniqueString -InputObject @($InputObject.ScopeTags))
            AssignmentId     = $InputObject.AssignmentId
            AssignmentMode   = $assignmentMode
            TargetType       = $targetType
            TargetId         = $InputObject.TargetId
            TargetName       = $InputObject.TargetName
            Intent           = $InputObject.Intent
            FilterId         = $InputObject.FilterId
            FilterName       = $InputObject.FilterName
            FilterMode       = $InputObject.FilterMode
            FilterRule       = $InputObject.FilterRule
            FilterPlatform   = $InputObject.FilterPlatform
            EffectiveState   = $effectiveState
            ReasonChain      = @(Get-IACOrdinalSortedObject -InputObject @($reasonChain) -KeySelector {
                    '{0:D10}|{1}' -f $_.Sequence, (ConvertTo-IACIdentityComponent $_.Code)
                })
            AssignmentReason = $InputObject.AssignmentReason
            Source           = $InputObject.Source
        }
    }
}

function ConvertTo-IACIdentityComponent {
    param([AllowNull()]$Value)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$Value")
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-IACAssignmentIdentityKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Record
    )

    $assignmentComponent = if (-not [string]::IsNullOrWhiteSpace("$($Record.AssignmentId)")) {
        "id:$($Record.AssignmentId)"
    }
    elseif ($Record.AssignmentMode -eq 'None') {
        'none'
    }
    else {
        "fallback:$($Record.AssignmentMode)|$($Record.TargetType)|$($Record.TargetId)|$($Record.Intent)"
    }
    return 'v1:{0}:{1}:{2}:{3}:{4}' -f @(
        ConvertTo-IACIdentityComponent $Record.SubjectType
        ConvertTo-IACIdentityComponent $Record.SubjectId
        ConvertTo-IACIdentityComponent $Record.CategoryId
        ConvertTo-IACIdentityComponent $Record.PolicyId
        ConvertTo-IACIdentityComponent $assignmentComponent
    )
}

function Get-IACInstalledModuleVersion {
    [CmdletBinding()]
    param()

    $loadedModule = Get-Module -Name IntuneAssignmentChecker | Select-Object -First 1
    if ($loadedModule -and $loadedModule.Version) { return $loadedModule.Version.ToString() }

    $manifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'IntuneAssignmentChecker.psd1'
    return (Test-ModuleManifest -Path $manifestPath -ErrorAction Stop).Version.ToString()
}

function New-IACAssignmentSnapshot {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Records = @(),
        [Parameter(Mandatory)][datetimeoffset]$CapturedAtUtc,
        [AllowEmptyCollection()][object[]]$CoverageCategories = @(),
        [AllowEmptyCollection()][object[]]$CoverageErrors = @(),
        [Parameter(Mandatory)][bool]$CoverageComplete,
        [Parameter(Mandatory)][string]$CoverageMode
    )

    $canonicalRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($Records)) {
        [void]$canonicalRecords.Add((ConvertTo-IACSnapshotRecord -InputObject $record))
    }

    $recordsByKey = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($record in $canonicalRecords) {
        $identityKey = Get-IACAssignmentIdentityKey -Record $record
        if ($recordsByKey.ContainsKey($identityKey)) {
            throw "Snapshot contains duplicate assignment identity key '$identityKey'."
        }
        $recordsByKey.Add($identityKey, $record)
    }
    $orderedRecords = @($recordsByKey.Values)

    $tenantIds = @(Get-IACOrdinalSortedUniqueString -InputObject @(
            $orderedRecords.TenantId | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
        ))
    if ($tenantIds.Count -gt 1) { throw 'Snapshot records contain more than one tenant ID.' }
    if ($script:CurrentTenantId -and $tenantIds.Count -eq 1 -and "$script:CurrentTenantId" -ne "$($tenantIds[0])") {
        throw "Snapshot record tenant '$($tenantIds[0])' does not match the connected tenant '$script:CurrentTenantId'."
    }
    $tenantNames = @(Get-IACOrdinalSortedUniqueString -InputObject @(
            $orderedRecords.TenantName | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
        ))
    $resolvedTenantId = if ($script:CurrentTenantId) { "$script:CurrentTenantId" } elseif ($tenantIds.Count -eq 1) { "$($tenantIds[0])" } else { $null }
    if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
        throw 'A tenant ID is required to export an assignment snapshot; connect first or supply records with TenantId.'
    }

    [PSCustomObject][ordered]@{
        SchemaName    = 'IntuneAssignmentChecker.AssignmentSnapshot'
        SchemaVersion = 1
        CapturedAtUtc = $CapturedAtUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        ModuleVersion = Get-IACInstalledModuleVersion
        Tenant        = [PSCustomObject][ordered]@{
            Id   = $resolvedTenantId
            Name = if ($script:CurrentTenantName) { "$script:CurrentTenantName" } elseif ($tenantNames.Count -eq 1) { "$($tenantNames[0])" } else { $null }
        }
        Coverage      = [PSCustomObject][ordered]@{
            Mode       = $CoverageMode
            Complete   = $CoverageComplete
            RecordCount = $orderedRecords.Count
            Categories = @(Get-IACOrdinalSortedObject -InputObject @($CoverageCategories) -KeySelector {
                    '{0}|{1}' -f (ConvertTo-IACIdentityComponent $_.CategoryId), (ConvertTo-IACIdentityComponent $_.DisplayName)
                })
            Errors     = @(Get-IACOrdinalSortedObject -InputObject @($CoverageErrors) -KeySelector {
                    '{0}|{1}' -f (ConvertTo-IACIdentityComponent $_.CategoryId), (ConvertTo-IACIdentityComponent $_.Message)
                })
        }
        Records       = $orderedRecords
    }
}

function Write-IACAssignmentSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$Path
    )

    $json = $Snapshot | ConvertTo-Json -Depth 20
    $json = ($json -replace "`r`n", "`n").TrimEnd("`r", "`n") + "`n"
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Read-IACAssignmentSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Assignment snapshot '$Path' does not exist."
    }
    try {
        $snapshot = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    }
    catch {
        throw "Assignment snapshot '$Path' is not valid JSON: $($_.Exception.Message)"
    }
    if ($snapshot -is [array] -or $null -eq $snapshot) { throw "Assignment snapshot '$Path' must contain one JSON object." }
    if ($snapshot.SchemaName -ne 'IntuneAssignmentChecker.AssignmentSnapshot') {
        throw "Assignment snapshot '$Path' has schema '$($snapshot.SchemaName)'; expected 'IntuneAssignmentChecker.AssignmentSnapshot'."
    }
    $snapshotSchemaVersion = 0
    if (-not [int]::TryParse("$($snapshot.SchemaVersion)", [ref]$snapshotSchemaVersion) -or $snapshotSchemaVersion -ne 1) {
        throw "Assignment snapshot '$Path' uses unsupported schema version '$($snapshot.SchemaVersion)'; expected version 1."
    }
    foreach ($property in @('CapturedAtUtc', 'ModuleVersion', 'Tenant', 'Coverage', 'Records')) {
        if ($null -eq $snapshot.PSObject.Properties[$property]) {
            throw "Assignment snapshot '$Path' is malformed: missing '$property'."
        }
    }
    $captured = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse("$($snapshot.CapturedAtUtc)", [ref]$captured)) {
        throw "Assignment snapshot '$Path' has an invalid CapturedAtUtc value."
    }
    if ("$($snapshot.ModuleVersion)" -notmatch '^\d+(?:\.\d+){1,3}(?:[-+].+)?$') {
        throw "Assignment snapshot '$Path' has an invalid ModuleVersion value."
    }
    if ($null -eq $snapshot.Tenant -or $null -eq $snapshot.Coverage -or $null -eq $snapshot.Records) {
        throw "Assignment snapshot '$Path' is malformed: Tenant, Coverage, and Records cannot be null."
    }
    foreach ($property in @('Id', 'Name')) {
        if ($null -eq $snapshot.Tenant.PSObject.Properties[$property]) {
            throw "Assignment snapshot '$Path' is malformed: Tenant is missing '$property'."
        }
    }
    if ([string]::IsNullOrWhiteSpace("$($snapshot.Tenant.Id)")) {
        throw "Assignment snapshot '$Path' is malformed: Tenant.Id cannot be empty."
    }
    foreach ($property in @('Mode', 'Complete', 'RecordCount', 'Categories', 'Errors')) {
        if ($null -eq $snapshot.Coverage.PSObject.Properties[$property]) {
            throw "Assignment snapshot '$Path' is malformed: Coverage is missing '$property'."
        }
    }
    if ($snapshot.Coverage.Complete -isnot [bool]) {
        throw "Assignment snapshot '$Path' is malformed: Coverage.Complete must be a Boolean."
    }
    if ($snapshot.Coverage.Mode -cnotin @('TenantScan', 'ProvidedRecords')) {
        throw "Assignment snapshot '$Path' is malformed: unsupported Coverage.Mode '$($snapshot.Coverage.Mode)'."
    }
    $recordCount = 0
    if (-not [int]::TryParse("$($snapshot.Coverage.RecordCount)", [ref]$recordCount) -or $recordCount -lt 0) {
        throw "Assignment snapshot '$Path' is malformed: Coverage.RecordCount must be a non-negative integer."
    }
    if ($null -eq $snapshot.Coverage.Categories -or $null -eq $snapshot.Coverage.Errors) {
        throw "Assignment snapshot '$Path' is malformed: Coverage.Categories and Coverage.Errors cannot be null."
    }
    foreach ($category in @($snapshot.Coverage.Categories)) {
        foreach ($property in @('CategoryId', 'DisplayName', 'Status', 'RecordCount')) {
            if ($null -eq $category.PSObject.Properties[$property]) {
                throw "Assignment snapshot '$Path' is malformed: a coverage category is missing '$property'."
            }
        }
        if ([string]::IsNullOrWhiteSpace("$($category.CategoryId)")) {
            throw "Assignment snapshot '$Path' is malformed: a coverage category has no CategoryId."
        }
        if ($category.Status -cnotin @('Captured', 'Provided', 'Failed', 'Skipped', 'Unknown')) {
            throw "Assignment snapshot '$Path' is malformed: unsupported coverage status '$($category.Status)'."
        }
        $categoryRecordCount = 0
        if (-not [int]::TryParse("$($category.RecordCount)", [ref]$categoryRecordCount) -or $categoryRecordCount -lt 0) {
            throw "Assignment snapshot '$Path' is malformed: a coverage category has an invalid RecordCount."
        }
    }
    foreach ($coverageError in @($snapshot.Coverage.Errors)) {
        foreach ($property in @('CategoryId', 'Message')) {
            if ($null -eq $coverageError.PSObject.Properties[$property]) {
                throw "Assignment snapshot '$Path' is malformed: a coverage error is missing '$property'."
            }
        }
        if ([string]::IsNullOrWhiteSpace("$($coverageError.CategoryId)") -or [string]::IsNullOrWhiteSpace("$($coverageError.Message)")) {
            throw "Assignment snapshot '$Path' is malformed: coverage errors require CategoryId and Message."
        }
    }

    $validatedRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($snapshot.Records)) {
        try { [void]$validatedRecords.Add((ConvertTo-IACSnapshotRecord -InputObject $record)) }
        catch { throw "Assignment snapshot '$Path' contains an invalid record: $($_.Exception.Message)" }
    }
    if ($recordCount -ne $validatedRecords.Count) {
        throw "Assignment snapshot '$Path' record count does not match Coverage.RecordCount."
    }
    $coverageByCategory = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($category in @($snapshot.Coverage.Categories)) {
        if ($coverageByCategory.ContainsKey("$($category.CategoryId)")) {
            throw "Assignment snapshot '$Path' contains duplicate coverage category '$($category.CategoryId)'."
        }
        $coverageByCategory.Add("$($category.CategoryId)", $category)
    }
    foreach ($record in $validatedRecords) {
        if (-not $coverageByCategory.ContainsKey("$($record.CategoryId)")) {
            throw "Assignment snapshot '$Path' contains record category '$($record.CategoryId)' outside declared coverage."
        }
    }
    foreach ($categoryId in $coverageByCategory.Keys) {
        $actualCount = @($validatedRecords | Where-Object CategoryId -CEQ $categoryId).Count
        if ([int]$coverageByCategory[$categoryId].RecordCount -ne $actualCount) {
            throw "Assignment snapshot '$Path' has an incorrect RecordCount for coverage category '$categoryId'."
        }
    }
    foreach ($coverageError in @($snapshot.Coverage.Errors)) {
        if (-not $coverageByCategory.ContainsKey("$($coverageError.CategoryId)")) {
            throw "Assignment snapshot '$Path' contains a coverage error outside declared categories."
        }
    }
    if ([bool]$snapshot.Coverage.Complete -and
        (@($snapshot.Coverage.Errors).Count -gt 0 -or @($snapshot.Coverage.Categories | Where-Object Status -in @('Failed', 'Skipped', 'Unknown')).Count -gt 0)) {
        throw "Assignment snapshot '$Path' is malformed: complete coverage cannot contain failed, skipped, or unknown categories."
    }
    $recordsByKey = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($record in $validatedRecords) {
        $identityKey = Get-IACAssignmentIdentityKey -Record $record
        if ($recordsByKey.ContainsKey($identityKey)) {
            throw "Assignment snapshot '$Path' contains duplicate identity key '$identityKey'."
        }
        $recordsByKey.Add($identityKey, $record)
    }

    $snapshot.Records = @($recordsByKey.Values)
    return $snapshot
}
