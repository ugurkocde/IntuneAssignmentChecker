function Get-IntuneAssignmentOperation {
    <#
    .SYNOPSIS
    Returns structured metadata for exported module operations.

    .DESCRIPTION
    Discovers every exported operational command and returns structured metadata
    for its help, capabilities, parameter sets, parameters, and validation choices.
    This is an automation and documentation surface. The task-oriented terminal
    interface uses its own workflow registry backed by the same module functions.

    .PARAMETER Name
    Optional wildcard pattern used to filter command names.

    .PARAMETER Category
    Optional operation category filter.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.OperationDescriptor')]
    param(
        [Parameter(Position = 0)]
        [SupportsWildcards()]
        [string]$Name = '*',

        [Parameter()]
        [string]$Category
    )

    Get-IACOperationCatalog | Where-Object {
        $_.Name -like $Name -and (-not $Category -or $_.Category -eq $Category)
    }
}
