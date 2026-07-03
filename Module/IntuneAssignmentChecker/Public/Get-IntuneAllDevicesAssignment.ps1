function Get-IntuneAllDevicesAssignment {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching all 'All Devices' assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Local display-name helpers preserving the historical per-category fallback quirks.
    function Get-NamePreferringName { param($Item) if ([string]::IsNullOrWhiteSpace($Item.name)) { $Item.displayName } else { $Item.name } }
    function Get-NamePreferringDisplayName { param($Item) if ([string]::IsNullOrWhiteSpace($Item.displayName)) { $Item.name } else { $Item.displayName } }
    function Get-NameWithUnnamedFallback {
        param($Item, [string]$Fallback)
        if (-not [string]::IsNullOrWhiteSpace($Item.displayName)) { $Item.displayName }
        elseif (-not [string]::IsNullOrWhiteSpace($Item.name)) { $Item.name }
        else { $Fallback }
    }

    # UserContext is the registry audience whose category set covers this cmdlet
    # (Applications included, no ES exclusion on Settings Catalog). Local adjustments
    # reproduce the pre-migration behavior of this cmdlet: Autopilot/ESP profiles ARE
    # fetched here (UserContext registers them bucket-only for export parity) and the
    # Windows 365 Cloud PC categories are not part of this cmdlet.
    $categoryById = @{}
    foreach ($category in (Get-IntuneCategoryDefinition -Audience 'UserContext')) { $categoryById[$category.Id] = $category }
    foreach ($id in @('DeploymentProfiles', 'ESPProfiles')) { $categoryById[$id].BucketOnly = $false }

    # Fetch order matches the pre-migration cmdlet (16 categories).
    $scanCategories = foreach ($id in @(
            'DeviceConfigurations', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies',
            'AppConfigurationPolicies', 'Applications', 'PlatformScripts', 'HealthScripts',
            'DeploymentProfiles', 'ESPProfiles',
            'ESAntivirus', 'ESDiskEncryption', 'ESFirewall', 'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection')) {
        $categoryById[$id]
    }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity

        if ($ctx.Category.Kind -eq 'MobileApps') {
            # Historical app handling: only the first 'All Devices' assignment counts,
            # and the app lands in the bucket matching that assignment's intent.
            foreach ($assignment in $ctx.RawAssignments) {
                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                    $suffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                    $appWithReason = $entity.PSObject.Copy()
                    $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Devices$suffix" -Force
                    switch ($assignment.intent) {
                        'required' { $ctx.Buckets['AppsRequired'].Add($appWithReason); break }
                        'available' { $ctx.Buckets['AppsAvailable'].Add($appWithReason); break }
                        'uninstall' { $ctx.Buckets['AppsUninstall'].Add($appWithReason); break }
                    }
                    break
                }
            }
            return
        }

        $reason = if ($null -ne $ctx.RawAssignments) {
            # App Protection policies and legacy intent-based ES policies: historical
            # wording built the filter suffix from the first raw 'All Devices' target.
            $allDevicesAssignment = $ctx.RawAssignments |
                Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' } |
                Select-Object -First 1
            if ($allDevicesAssignment) {
                $suffix = Format-AssignmentFilter -FilterId $allDevicesAssignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $allDevicesAssignment.target.deviceAndAppManagementAssignmentFilterType
                "All Devices$suffix"
            }
        }
        else {
            Get-AllTargetReason -Assignments $ctx.Assignments -TargetReason 'All Devices'
        }

        if ($reason) {
            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
        }
    }

    $scanResult = Invoke-IntuneCategoryScan -Categories $scanCategories -ProcessEntity $processEntity -ShowProgress
    $allDevicesAssignments = $scanResult.Buckets

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allDevicesAssignments.Keys)) {
            $allDevicesAssignments[$key] = @(Filter-ByScopeTag -Items $allDevicesAssignments[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # Display results
    Write-Host "`nPolicies Assigned to All Devices:" -ForegroundColor Green

    $displaySpecs = @(
        @{ Bucket = 'DeviceConfigs'; Header = 'Device Configurations'; Empty = 'Device Configurations'; Line = { param($item) "Device Configuration Name: $(Get-NamePreferringName $item), Platform: $(Get-PolicyPlatform -Policy $item), Configuration ID: $($item.id)" } }
        @{ Bucket = 'SettingsCatalog'; Header = 'Settings Catalog Policies'; Empty = 'Settings Catalog Policies'; Line = { param($item) "Settings Catalog Policy Name: $(Get-NamePreferringName $item), Policy ID: $($item.id)" } }
        @{ Bucket = 'CompliancePolicies'; Header = 'Compliance Policies'; Empty = 'Compliance Policies'; Line = { param($item) "Compliance Policy Name: $(Get-NamePreferringName $item), Platform: $(Get-PolicyPlatform -Policy $item), Policy ID: $($item.id)" } }
        @{ Bucket = 'AppProtectionPolicies'; Header = 'App Protection Policies'; Empty = 'App Protection Policies'; Line = {
                param($item)
                $policyType = switch ($item.'@odata.type') {
                    "#microsoft.graph.androidManagedAppProtection" { "Android" }
                    "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                    "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                    default { "Unknown" }
                }
                "App Protection Policy Name: $($item.displayName), Policy ID: $($item.id), Type: $policyType"
            }
        }
        @{ Bucket = 'AppConfigurationPolicies'; Header = 'App Configuration Policies'; Empty = 'App Configuration Policies'; Line = { param($item) "App Configuration Policy Name: $(Get-NamePreferringName $item), Policy ID: $($item.id)" } }
        @{ Bucket = 'PlatformScripts'; Header = 'Platform Scripts'; Empty = 'Platform Scripts'; Line = { param($item) "Script Name: $(Get-NamePreferringName $item), Script ID: $($item.id)" } }
        @{ Bucket = 'HealthScripts'; Header = 'Proactive Remediation Scripts'; Empty = 'Proactive Remediation Scripts'; Line = { param($item) "Script Name: $(Get-NamePreferringName $item), Script ID: $($item.id)" } }
        @{ Bucket = 'AppsRequired'; Header = 'Required Apps'; Empty = 'Required Apps'; Line = { param($item) "App Name: $($item.displayName), App ID: $($item.id)" } }
        @{ Bucket = 'AppsAvailable'; Header = 'Available Apps'; Empty = 'Available Apps'; Line = { param($item) "App Name: $($item.displayName), App ID: $($item.id)" } }
        @{ Bucket = 'AppsUninstall'; Header = 'Uninstall Apps'; Empty = 'Uninstall Apps'; Line = { param($item) "App Name: $($item.displayName), App ID: $($item.id)" } }
        @{ Bucket = 'AntivirusProfiles'; Header = 'Endpoint Security - Antivirus Profiles'; Empty = 'Antivirus Profiles'; Line = { param($item) "Antivirus Profile Name: $($item.displayName), Profile ID: $($item.id)" } }
        @{ Bucket = 'DiskEncryptionProfiles'; Header = 'Endpoint Security - Disk Encryption Profiles'; Empty = 'Disk Encryption Profiles'; Line = { param($item) "Disk Encryption Profile Name: $($item.displayName), Profile ID: $($item.id)" } }
        @{ Bucket = 'FirewallProfiles'; Header = 'Endpoint Security - Firewall Profiles'; Empty = 'Firewall Profiles'; Line = { param($item) "Firewall Profile Name: $($item.displayName), Profile ID: $($item.id)" } }
        @{ Bucket = 'EndpointDetectionProfiles'; Header = 'Endpoint Security - EDR Profiles'; Empty = 'EDR Profiles'; Line = { param($item) "EDR Profile Name: $(Get-NameWithUnnamedFallback $item 'Unnamed EDR Profile'), Profile ID: $($item.id)" } }
        @{ Bucket = 'AttackSurfaceProfiles'; Header = 'Endpoint Security - ASR Profiles'; Empty = 'ASR Profiles'; Line = { param($item) "ASR Profile Name: $($item.displayName), Profile ID: $($item.id)" } }
        @{ Bucket = 'AccountProtectionProfiles'; Header = 'Endpoint Security - Account Protection Profiles'; Empty = 'Account Protection Profiles'; Line = { param($item) "Account Protection Profile Name: $(Get-NameWithUnnamedFallback $item 'Unnamed Account Protection Profile'), Profile ID: $($item.id)" } }
        @{ Bucket = 'DeploymentProfiles'; Header = 'Autopilot Deployment Profiles'; Empty = 'Autopilot Deployment Profiles'; Line = { param($item) "Deployment Profile Name: $(Get-NamePreferringDisplayName $item), Profile ID: $($item.id)" } }
        @{ Bucket = 'ESPProfiles'; Header = 'Enrollment Status Page Profiles'; Empty = 'Enrollment Status Page Profiles'; Line = { param($item) "Enrollment Status Page Name: $(Get-NamePreferringDisplayName $item), Profile ID: $($item.id)" } }
    )

    foreach ($spec in $displaySpecs) {
        Write-Host "`n------- $($spec.Header) -------" -ForegroundColor Cyan
        $items = @($allDevicesAssignments[$spec.Bucket])
        if ($items.Count -eq 0) {
            Write-Host "No $($spec.Empty) assigned to All Devices" -ForegroundColor Gray
            continue
        }
        foreach ($item in $items) {
            Write-Host (& $spec.Line $item) -ForegroundColor White
        }
    }

    # Export rows in the pre-migration CSV order (apps after scripts, Autopilot/ESP last).
    $exportCategories = foreach ($id in @(
            'DeviceConfigurations', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies',
            'AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'Applications',
            'ESAntivirus', 'ESDiskEncryption', 'ESFirewall', 'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection',
            'DeploymentProfiles', 'ESPProfiles')) {
        $categoryById[$id]
    }
    Add-CategoryExportData -ExportData $exportData -Categories $exportCategories -Buckets $allDevicesAssignments -AssignmentReason "All Devices"

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllDevicesAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$parameterMode
}
