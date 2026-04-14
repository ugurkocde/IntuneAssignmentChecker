function Test-PlatformCompatibility {
    param (
        [string]$DeviceOS,
        [PSObject]$Policy
    )

    # If device OS unknown, include everything (conservative)
    if ([string]::IsNullOrWhiteSpace($DeviceOS)) { return $true }

    $policyPlatform = Get-PolicyPlatform -Policy $Policy

    # If platform can't be determined, include (conservative)
    if ($policyPlatform -in @("Unknown", "Multi-Platform", "Settings Catalog")) {
        return $true
    }

    # Handle Settings Catalog comma-separated platforms (e.g. "windows10, macOS")
    if ($policyPlatform -match ',') {
        $platforms = ($policyPlatform -split ',').Trim().ToLower()
        switch ($DeviceOS) {
            "Windows" { return [bool]($platforms | Where-Object { $_ -match "windows" }) }
            "iOS"     { return [bool]($platforms | Where-Object { $_ -match "ios" }) }
            "macOS"   { return [bool]($platforms | Where-Object { $_ -match "macos" }) }
            "Android" { return [bool]($platforms | Where-Object { $_ -match "android" }) }
            "Linux"   { return [bool]($platforms | Where-Object { $_ -match "linux" }) }
            default   { return $true }
        }
    }

    # Single platform string matching
    switch ($DeviceOS) {
        "Windows" { return $policyPlatform -match "^Windows" }
        "iOS"     { return $policyPlatform -match "iOS|iPadOS" }
        "macOS"   { return $policyPlatform -eq "macOS" }
        "Android" { return $policyPlatform -match "^Android" }
        "Linux"   { return $policyPlatform -match "Linux" }
        default   { return $true }
    }
}
