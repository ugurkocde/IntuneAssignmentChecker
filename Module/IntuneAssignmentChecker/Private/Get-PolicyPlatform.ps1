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

    # macOS must be checked before ios/windows because strings like "macOSOfficeSuiteApp"
    # could otherwise be matched by other branches.
    if ($odataType -match "macOS|osxApp|\.mac[A-Z]") {
        return "macOS"
    }

    # Windows app types that don't contain the literal "windows" substring.
    if ($odataType -match "win32LobApp|winGetApp|microsoftStoreForBusinessApp|officeSuiteApp") {
        return "Windows"
    }

    # Cross-platform app types (web links, managed Play Store web apps).
    if ($odataType -match "^#microsoft\.graph\.webApp$") {
        return "Web App"
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
            return "iOS/iPadOS"
        }
        "windows" {
            if ($odataType -like "*windowsPhone*") {
                return "Windows Phone"
            }
            else {
                return "Windows"
            }
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
