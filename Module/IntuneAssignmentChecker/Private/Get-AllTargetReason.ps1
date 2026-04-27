function Get-AllTargetReason {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Assignments,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All Users', 'All Devices')]
        [string]$TargetReason
    )

    if (-not $Assignments) { return $null }
    $match = $Assignments | Where-Object { $_.Reason -eq $TargetReason } | Select-Object -First 1
    if ($null -eq $match) { return $null }

    $suffix = Format-AssignmentFilter -FilterId $match.FilterId -FilterType $match.FilterType
    return "$TargetReason$suffix"
}
