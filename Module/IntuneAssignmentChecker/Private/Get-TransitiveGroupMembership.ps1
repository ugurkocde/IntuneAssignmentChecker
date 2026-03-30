function Get-TransitiveGroupMembership {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $parentGroups = [System.Collections.ArrayList]::new()
    $uri = "$GraphEndpoint/v1.0/groups/$GroupId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"

    try {
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            if ($response -and $null -ne $response.value) {
                foreach ($group in $response.value) {
                    $null = $parentGroups.Add([PSCustomObject]@{
                        id          = $group.id
                        displayName = $group.displayName
                    })
                }
            }
            $uri = $response.'@odata.nextLink'
        } while (![string]::IsNullOrEmpty($uri))
    }
    catch {
        Write-Warning "Error fetching parent group memberships for group '$GroupId': $($_.Exception.Message)"
    }

    return $parentGroups
}
