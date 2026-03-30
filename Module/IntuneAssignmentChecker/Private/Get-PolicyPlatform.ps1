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
