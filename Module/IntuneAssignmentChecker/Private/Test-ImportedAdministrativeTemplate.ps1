function Test-ImportedAdministrativeTemplate {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Policy
    )

    return $Policy.policyConfigurationIngestionType -in @('custom', 'mixed')
}
