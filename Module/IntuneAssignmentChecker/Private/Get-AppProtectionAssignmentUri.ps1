function Get-AppProtectionAssignmentUri {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    $specificPolicyTypePath = switch ($Policy.'@odata.type') {
        "#microsoft.graph.androidManagedAppProtection" { "androidManagedAppProtections" }
        "#microsoft.graph.iosManagedAppProtection" { "iosManagedAppProtections" }
        "#microsoft.graph.windowsManagedAppProtection" { "windowsManagedAppProtections" }
        default { $null }
    }

    if (-not $specificPolicyTypePath) {
        return $null
    }

    return "$script:GraphEndpoint/beta/deviceAppManagement/$specificPolicyTypePath('$($Policy.id)')/assignments"
}
