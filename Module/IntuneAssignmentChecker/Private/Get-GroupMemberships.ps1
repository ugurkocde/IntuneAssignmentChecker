function Get-GroupMemberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Device")]
        [string]$ObjectType
    )

    $memberships = [System.Collections.ArrayList]::new()
    $uri = "$script:GraphEndpoint/v1.0/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf?`$select=id,displayName"

    try {
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            if ($response -and $null -ne $response.value) {
                $memberships.AddRange([object[]]$response.value)
            }
            $uri = $response.'@odata.nextLink'
        } while (![string]::IsNullOrEmpty($uri))
        return $memberships
    }
    catch {
        Write-Warning "Error fetching group memberships for $ObjectType '$ObjectId': $($_.Exception.Message)"
        throw
    }
}
