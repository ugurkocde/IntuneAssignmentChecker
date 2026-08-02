function Get-IACGovernanceRule {
    [CmdletBinding()]
    param([string]$RulePath)

    $defaultPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Data/GovernanceRules.json'
    $path = if ($RulePath) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RulePath) } else { $defaultPath }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Governance rule file '$path' does not exist." }
    $document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    if ([int]$document.schemaVersion -ne 1) { throw "Governance rule schema version '$($document.schemaVersion)' is not supported." }
    $known = @('IAC001', 'IAC002', 'IAC003', 'IAC004', 'IAC005', 'IAC006', 'IAC007', 'IAC008')
    foreach ($rule in @($document.rules)) {
        if ($rule.id -notin $known) { throw "Unknown governance rule '$($rule.id)'." }
        if ($rule.severity -notin @('Low', 'Medium', 'High', 'Critical')) { throw "Rule '$($rule.id)' has invalid severity '$($rule.severity)'." }
    }
    return @($document.rules)
}

function New-IACGovernanceFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation,
        [AllowNull()]$Record,
        [AllowNull()]$Evidence,
        [AllowNull()]$Waiver
    )

    $identity = "$($Rule.id)|$($Record.TenantId)|$($Record.PolicyId)|$($Record.AssignmentId)|$($Record.TargetId)|$Message"
    $findingId = (Get-IACSha256Hex -InputText $identity).Substring(0, 24)
    $finding = [PSCustomObject][ordered]@{
        SchemaName    = 'IntuneAssignmentChecker.GovernanceFinding'
        SchemaVersion = 1
        FindingId     = $findingId
        RuleId        = "$($Rule.id)"
        Severity      = "$($Rule.severity)"
        Title         = "$($Rule.title)"
        Message       = $Message
        TenantId      = $Record.TenantId
        TenantName    = $Record.TenantName
        CategoryId    = $Record.CategoryId
        PolicyId      = $Record.PolicyId
        PolicyName    = $Record.PolicyName
        AssignmentId  = $Record.AssignmentId
        TargetId      = $Record.TargetId
        TargetName    = $Record.TargetName
        Evidence      = $Evidence
        Remediation   = $Remediation
        Suppressed    = $null -ne $Waiver
        Waiver        = $Waiver
        DetectedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    }
    $finding.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.GovernanceFinding')
    return $finding
}

function Find-IACGovernanceWaiver {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Waiver = @(),
        [Parameter(Mandatory)][string]$RuleId,
        [AllowNull()][string]$PolicyId,
        [AllowNull()][string]$TargetId
    )

    foreach ($entry in @($Waiver)) {
        if ($entry.RuleId -ne $RuleId) { continue }
        if ($entry.PolicyId -and $entry.PolicyId -ne $PolicyId) { continue }
        if ($entry.TargetId -and $entry.TargetId -ne $TargetId) { continue }
        $expiration = [datetimeoffset]::MinValue
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [datetimeoffset]::TryParse("$($entry.ExpiresAtUtc)", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$expiration)) {
            throw "Waiver expiration '$($entry.ExpiresAtUtc)' is not a valid UTC date-time."
        }
        if ($expiration -le [datetimeoffset]::UtcNow) { continue }
        return $entry
    }
    return $null
}
