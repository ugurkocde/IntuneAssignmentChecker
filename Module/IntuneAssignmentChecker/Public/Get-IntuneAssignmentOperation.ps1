function Get-IntuneAssignmentOperation {
    <#
    .SYNOPSIS
    Returns the operation catalog used by the terminal UI.

    .DESCRIPTION
    Discovers every exported operational command and returns structured metadata
    for its help, capabilities, parameter sets, parameters, and validation choices.
    The terminal UI consumes this catalog directly, which keeps it in parity with
    the PowerShell module without a second command implementation.

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
