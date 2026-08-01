function Get-TransitiveGroupMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $parentGroups = [System.Collections.ArrayList]::new()
    $uri = "$script:GraphEndpoint/beta/groups/$GroupId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"

    try {
        foreach ($group in @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)) {
            $null = $parentGroups.Add([PSCustomObject]@{
                    id          = $group.id
                    displayName = $group.displayName
                })
        }
    }
    catch {
        Write-Warning "Error fetching parent group memberships for group '$GroupId': $($_.Exception.Message)"
    }

    return $parentGroups
}
