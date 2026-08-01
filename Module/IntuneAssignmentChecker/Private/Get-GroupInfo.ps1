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
        $selectProperties = 'id,displayName,groupTypes,mailEnabled,securityEnabled,mail'
        $groupUri = "$script:GraphEndpoint/v1.0/groups/$GroupId`?`$select=$selectProperties"
        $group = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        $result = ConvertTo-IntuneGroupInfo -Group $group
        if (-not $result.Success) {
            throw "Microsoft Graph returned a group response without an Object ID."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $statusCode = if ($_.Exception.Response -and $null -ne $_.Exception.Response.StatusCode) {
            [int]$_.Exception.Response.StatusCode
        }
        else {
            $null
        }
        # Invoke-MgGraphRequest does not consistently expose Response.StatusCode,
        # so also recognize the standard message-only not-found shapes.
        $isNotFound = $statusCode -eq 404 -or
            $errorMessage -match '(?i)\b404\b|Not\s*Found|Request_ResourceNotFound'
        if (-not $isNotFound) {
            Write-Warning "Group '$GroupId' lookup failed: $errorMessage"
        }
        $result = [PSCustomObject]@{
            Id                = $GroupId
            DisplayName       = "Unknown Group"
            GroupType         = "Unknown"
            MembershipType    = "Unknown"
            IsMicrosoft365    = $false
            Mail              = $null
            GroupTypes        = @()
            MailEnabled       = $false
            SecurityEnabled   = $false
            Success           = $false
        }
    }

    $script:GroupInfoCache[$GroupId] = $result
    return $result
}
