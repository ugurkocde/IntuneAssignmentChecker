# Private/Core.ps1
# Core helper functions for Intune Assignment Checker
# These functions are not exported and are used internally by the module

function Get-PolicyPlatform {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Policy
    )

    # Get the platform based on the @odata.type
    $odataType = $Policy.'@odata.type'

    if ($null -eq $odataType) {
        return "Unknown"
    }

    switch -Regex ($odataType) {
        "android" {
            if ($odataType -like "*WorkProfile*") {
                return "Android Work Profile"
            }
            elseif ($odataType -like "*DeviceOwner*") {
                return "Android Enterprise"
            }
            else {
                return "Android"
            }
        }
        "ios|iPad|iPhone" {
            if ($odataType -like "*macOS*") {
                return "macOS"
            }
            else {
                return "iOS/iPadOS"
            }
        }
        "windows" {
            if ($odataType -like "*windows10*" -or $odataType -like "*windows81*") {
                return "Windows"
            }
            elseif ($odataType -like "*windowsPhone*") {
                return "Windows Phone"
            }
            else {
                return "Windows"
            }
        }
        "macOS|mac" {
            return "macOS"
        }
        "aosp" {
            return "Android (AOSP)"
        }
        default {
            # For Settings Catalog and other generic types, try to determine from other properties
            if ($Policy.platforms) {
                return $Policy.platforms -join ", "
            }
            elseif ($Policy.technologies) {
                # Settings catalog might have technologies property
                return "Settings Catalog"
            }
            else {
                return "Multi-Platform"
            }
        }
    }
}

function Get-GroupInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    try {
        $groupUri = "$GraphEndpoint/v1.0/groups/$GroupId"
        $group = Invoke-MgGraphRequest -Uri $groupUri -Method Get
        return @{
            Id          = $group.id
            DisplayName = $group.displayName
            Success     = $true
        }
    }
    catch {
        return @{
            Id          = $GroupId
            DisplayName = "Unknown Group"
            Success     = $false
        }
    }
}

function Get-DeviceInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    $deviceUri = "$GraphEndpoint/v1.0/devices?`$filter=displayName eq '$DeviceName'"
    $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get

    if ($deviceResponse.value) {
        return @{
            Id          = $deviceResponse.value[0].id
            DisplayName = $deviceResponse.value[0].displayName
            Success     = $true
        }
    }

    return @{
        Id          = $null
        DisplayName = $DeviceName
        Success     = $false
    }
}

function Get-UserInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        $userUri = "$GraphEndpoint/v1.0/users/$UserPrincipalName"
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

function Get-GroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Device")]
        [string]$ObjectType
    )

    $uri = "$GraphEndpoint/v1.0/$($ObjectType.ToLower())s/$ObjectId/transitiveMemberOf?`$select=id,displayName"
    $response = Invoke-MgGraphRequest -Uri $uri -Method Get

    return $response.value
}
