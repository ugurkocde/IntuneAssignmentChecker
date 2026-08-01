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
    $uri = "$script:GraphEndpoint/beta/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"

    try {
        $pagedMemberships = @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)
        if ($pagedMemberships.Count -gt 0) { $memberships.AddRange([object[]]$pagedMemberships) }
        return $memberships
    }
    catch {
        Write-Warning "Error fetching group memberships for $ObjectType '$ObjectId': $($_.Exception.Message)"
        throw
    }
}
