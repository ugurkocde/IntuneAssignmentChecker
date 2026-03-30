function Test-AppPlatformCompatibility {
    param (
        [string]$DeviceOS,
        [PSObject]$App
    )

    if ([string]::IsNullOrWhiteSpace($DeviceOS)) { return $true }

    $odataType = $App.'@odata.type'
    if ([string]::IsNullOrWhiteSpace($odataType)) { return $true }

    $typeLower = $odataType.ToLower()

    # Web apps and managed app bundles target any platform
    if ($typeLower -match "webapp") { return $true }

    switch ($DeviceOS) {
        "Windows" { return $typeLower -match "win32|windows|officesuite|microsoftstore|winget" }
        "iOS"     { return $typeLower -match "ios|ipad|iphone" }
        "macOS"   { return $typeLower -match "macos" }
        "Android" { return $typeLower -match "android" }
        "Linux"   { return $typeLower -match "linux" }
        default   { return $true }
    }
}
