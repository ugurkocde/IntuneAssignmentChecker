function Get-GroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Device")]
        [string]$ObjectType
    )

    $uri = "$GraphEndpoint/v1.0/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf?`$select=id,displayName"

    try {
        $response = Invoke-MgGraphRequest -Uri $uri -Method Get
        return $response.value
    }
    catch {
        Write-Warning "Error fetching group memberships for $ObjectType '$ObjectId': $($_.Exception.Message)"
        throw
    }
}
