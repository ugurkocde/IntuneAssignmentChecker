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
        $groupUri = "$script:GraphEndpoint/beta/groups/$GroupId`?`$select=$selectProperties"
        $group = Invoke-IACGraphRequest -Uri $groupUri -Method Get
        $result = ConvertTo-IntuneGroupInfo -Group $group
        if (-not $result.Success) {
            throw "Microsoft Graph returned a group response without an Object ID."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $statusCode = if ($_.Exception.Data.Contains('StatusCode')) {
            $_.Exception.Data['StatusCode']
        }
        elseif ($_.Exception.Response -and $null -ne $_.Exception.Response.StatusCode) {
            [int]$_.Exception.Response.StatusCode
        }
        else {
            $null
        }
        # Fall back to message recognition for non-transport collaborators and older SDK errors.
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
