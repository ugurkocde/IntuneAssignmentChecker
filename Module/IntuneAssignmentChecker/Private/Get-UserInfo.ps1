function Get-UserInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        $userUri = "$script:GraphEndpoint/v1.0/users/$([uri]::EscapeDataString($UserPrincipalName))"
        $user = Invoke-MgGraphRequest -Uri $userUri -Method Get
        return @{
            Id                = $user.id
            UserPrincipalName = $user.userPrincipalName
            Success           = $true
        }
    }
    catch {
        return @{
            Id                = $null
            UserPrincipalName = $UserPrincipalName
            Success           = $false
        }
    }
}
