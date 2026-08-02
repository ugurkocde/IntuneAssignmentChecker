function Resolve-IACCapabilityPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Core', 'Applications', 'Devices', 'Scripts', 'CloudPC', 'ScopeTags', 'Audit', 'Full')]
        [string[]]$Capability
    )

    $selected = if ($Capability -contains 'Full') { @($script:CapabilityProfiles.Keys | Where-Object { $_ -ne 'Full' }) }
    else { @($Capability) }
    $permissionNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($capabilityName in $selected) {
        foreach ($permission in @($script:CapabilityProfiles[$capabilityName])) { [void]$permissionNames.Add($permission) }
    }
    @($script:RequiredPermissions | Where-Object { $permissionNames.Contains($_.Permission) })
}

function Get-IACCapabilityStatus {
    [CmdletBinding()]
    param(
        [AllowNull()][string[]]$GrantedPermission,
        [switch]$AppOnly
    )

    foreach ($capabilityName in @($script:CapabilityProfiles.Keys | Where-Object { $_ -ne 'Full' } | Sort-Object)) {
        $required = @($script:CapabilityProfiles[$capabilityName])
        $missing = if ($AppOnly) { @() }
        else {
            @($required | Where-Object {
                    $permission = $_
                    $GrantedPermission -notcontains $permission -and
                    $GrantedPermission -notcontains $permission.Replace('.Read', '.ReadWrite')
                })
        }
        [PSCustomObject][ordered]@{
            Name                = $capabilityName
            Requested           = $script:RequestedCapabilities -contains 'Full' -or $script:RequestedCapabilities -contains $capabilityName
            Status              = if (-not ($script:RequestedCapabilities -contains 'Full' -or $script:RequestedCapabilities -contains $capabilityName)) {
                'Skipped'
            }
            elseif ($AppOnly) { 'Unknown' }
            elseif ($missing.Count -eq 0) { 'Available' }
            else { 'Unavailable' }
            RequiredPermissions = $required
            MissingPermissions  = @($missing)
        }
    }
}
