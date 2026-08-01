function Test-IntuneAssignmentFilter {
    <#
    .SYNOPSIS
    Safely evaluates an Intune managed-device assignment filter locally.

    .DESCRIPTION
    Resolves a managed device through Microsoft Graph beta and evaluates either a
    cached tenant assignment filter or an explicit rule. Tenant rule text is parsed
    as data and is never executed. Result is Match, NotMatch, or Unknown.

    .PARAMETER DeviceName
    Intune managed-device name or managed-device ID.

    .PARAMETER FilterId
    ID of an assignment filter cached by Connect-IntuneAssignmentChecker.

    .PARAMETER Rule
    Explicit managed-device assignment-filter rule to evaluate.

    .PARAMETER FilterMode
    Include applies the rule result directly; Exclude inverts Match/NotMatch.

    .PARAMETER Platform
    Optional Intune assignment-filter platform for an ad hoc rule. Use the Graph
    enum value, such as windows10AndLater, macOS, iOS, android, or androidAOSP.

    .EXAMPLE
    Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -FilterId $filterId -FilterMode Include

    .EXAMPLE
    Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -Rule '(device.deviceOwnership -eq "Corporate")'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByFilterId')]
    [OutputType('IntuneAssignmentChecker.AssignmentFilterEvaluation')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$DeviceName,

        [Parameter(Mandatory, ParameterSetName = 'ByFilterId')]
        [string]$FilterId,

        [Parameter(Mandatory, ParameterSetName = 'ByRule')]
        [AllowEmptyString()]
        [string]$Rule,

        [Parameter()]
        [ValidateSet('Include', 'Exclude', 'None')]
        [string]$FilterMode = 'Include',

        [Parameter(ParameterSetName = 'ByRule')]
        [ValidateSet('android', 'androidForWork', 'androidWorkProfile', 'androidAOSP', 'iOS', 'macOS',
            'windows10AndLater', 'windows81AndLater', 'windowsPhone81')]
        [string]$Platform
    )

    $filterFound = $false
    if ($PSCmdlet.ParameterSetName -eq 'ByFilterId') {
        if ($null -eq $script:AssignmentFilterLookup) {
            $script:AssignmentFilterLookup = Get-AssignmentFilterLookup
        }
        if ($script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey($FilterId)) {
            $filter = $script:AssignmentFilterLookup[$FilterId]
            $filterFound = $true
        }
        else {
            $filter = [PSCustomObject]@{
                Id = $FilterId; Name = $null; Platform = $null; Rule = $null
                AssignmentFilterManagementType = $null
            }
        }
    }
    else {
        $filter = [PSCustomObject]@{
            Id = $null; Name = 'Ad hoc rule'; Platform = $Platform; Rule = $Rule
            AssignmentFilterManagementType = 'devices'
        }
    }

    $deviceResult = Get-IACManagedDevice -Identity $DeviceName
    $evaluation = Test-IACAssignmentFilter -Filter $filter -Device $deviceResult.Device -FilterMode $FilterMode
    if (-not $deviceResult.Success) {
        $evaluation.Result = 'Unknown'
        $evaluation.RuleResult = 'Unknown'
        $evaluation.Reason = $deviceResult.Reason
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'ByFilterId' -and -not $filterFound) {
        $evaluation.Result = 'Unknown'
        $evaluation.RuleResult = 'Unknown'
        $evaluation.Reason = "Assignment filter '$FilterId' was not found in the tenant filter cache."
    }
    return $evaluation
}
