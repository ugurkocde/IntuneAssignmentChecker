function ConvertFrom-IACReportResponse {
    [CmdletBinding()]
    param([AllowNull()]$Response)

    if ($Response -is [string]) {
        try { $Response = $Response | ConvertFrom-Json -Depth 30 -ErrorAction Stop }
        catch { throw "The Intune report endpoint returned invalid JSON: $($_.Exception.Message)" }
    }
    if ($Response -is [System.Collections.IDictionary] -and $Response.Contains('body') -and $Response.body -is [string]) {
        $Response = $Response.body | ConvertFrom-Json -Depth 30 -ErrorAction Stop
    }
    return $Response
}

function ConvertFrom-IACReportRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report)

    $columns = @($Report.Schema | ForEach-Object Column)
    foreach ($values in @($Report.Values)) {
        $row = [ordered]@{}
        for ($index = 0; $index -lt $columns.Count; $index++) {
            $row["$($columns[$index])"] = if ($index -lt @($values).Count) { $values[$index] } else { $null }
        }
        [PSCustomObject]$row
    }
}

function ConvertTo-IACDeliveryState {
    [CmdletBinding()]
    param([AllowNull()]$Status)

    if ($Status -is [byte] -or $Status -is [int16] -or $Status -is [int32] -or $Status -is [int64]) {
        $mappedState = switch ([int]$Status) {
            '1' { 'NotApplicable' }
            '2' { 'Succeeded' }
            '3' { 'Failed' }
            '4' { 'Conflict' }
            '5' { 'Pending' }
            default { 'Unknown' }
        }
        return $mappedState
    }
    switch -Regex ("$Status") {
        '^(?i:installed|success|succeeded|compliant|remediated)$' { 'Succeeded' }
        '^(?i:failed|error|uninstallFailed|nonCompliant)$' { 'Failed' }
        '^(?i:conflict)$' { 'Conflict' }
        '^(?i:notApplicable)$' { 'NotApplicable' }
        '^(?i:pending|pendingInstall|notInstalled|notEvaluated)$' { 'Pending' }
        default { 'Unknown' }
    }
}

function New-IACAssignmentHealthRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Workload,
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][string]$PolicyName,
        [AllowNull()][string]$DeviceId,
        [AllowNull()][string]$DeviceName,
        [AllowNull()][string]$UserPrincipalName,
        [AllowNull()]$RawStatus,
        [AllowNull()][string]$Detail,
        [AllowNull()]$LastReportedDateTime,
        [Parameter(Mandatory)][timespan]$StaleAfter
    )

    $state = ConvertTo-IACDeliveryState -Status $RawStatus
    $reported = [datetimeoffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $hasReported = [datetimeoffset]::TryParse("$LastReportedDateTime", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$reported)
    $record = [PSCustomObject][ordered]@{
        SchemaName        = 'IntuneAssignmentChecker.AssignmentHealth'
        SchemaVersion     = 1
        RecordType        = 'Status'
        TenantId          = $script:CurrentTenantId
        Workload          = $Workload
        PolicyId          = $PolicyId
        PolicyName        = $PolicyName
        DeviceId          = $DeviceId
        DeviceName        = $DeviceName
        UserPrincipalName = $UserPrincipalName
        TargetingState    = 'Targeted'
        Applicability     = if ($state -eq 'NotApplicable') { 'NotApplicable' } elseif ($state -eq 'Unknown') { 'Unknown' } else { 'Applicable' }
        DeliveryState     = $state
        RawStatus         = $RawStatus
        Detail            = $Detail
        LastReportedUtc   = if ($hasReported) { $reported.ToUniversalTime().ToString('o') } else { $null }
        ReportingState    = if (-not $hasReported) { 'NeverReported' } elseif ([datetimeoffset]::UtcNow - $reported -gt $StaleAfter) { 'Stale' } else { 'Current' }
    }
    $record.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentHealth')
    return $record
}

function New-IACAssignmentHealthCoverage {
    [CmdletBinding()]
    param([string]$Workload, [string]$Status, [string]$Message)

    $record = [PSCustomObject][ordered]@{
        SchemaName        = 'IntuneAssignmentChecker.AssignmentHealth'
        SchemaVersion     = 1
        RecordType        = 'Coverage'
        TenantId          = $script:CurrentTenantId
        Workload          = $Workload
        CoverageStatus    = $Status
        CoverageMessage   = $Message
        PolicyId          = $null
        PolicyName        = $null
        DeviceId          = $null
        DeviceName        = $null
        UserPrincipalName = $null
        TargetingState    = $null
        Applicability     = $null
        DeliveryState     = $null
        RawStatus         = $null
        Detail            = $null
        LastReportedUtc   = $null
        ReportingState    = $null
    }
    $record.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentHealth')
    return $record
}
