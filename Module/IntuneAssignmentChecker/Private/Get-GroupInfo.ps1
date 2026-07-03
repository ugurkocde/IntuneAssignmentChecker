function Get-GroupInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    if ($null -eq $script:GroupInfoCache) {
        $script:GroupInfoCache = @{}
    }
    if ($script:GroupInfoCache.ContainsKey($GroupId)) {
        return $script:GroupInfoCache[$GroupId]
    }

    try {
        $groupUri = "$script:GraphEndpoint/v1.0/groups/$GroupId"
        $group = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        $result = @{
            Id          = $group.id
            DisplayName = $group.displayName
            Success     = $true
        }
    }
    catch {
        $result = @{
            Id          = $GroupId
            DisplayName = "Unknown Group"
            Success     = $false
        }
    }

    $script:GroupInfoCache[$GroupId] = $result
    return $result
}
