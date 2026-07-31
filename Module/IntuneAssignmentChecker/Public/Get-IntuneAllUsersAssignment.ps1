function Get-IntuneAllUsersAssignment {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter
    )

    Write-Host "Fetching all 'All Users' assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Renders one result section: Cyan header, Gray empty message, one White line per item.
    function Show-AllUsersSection {
        param (
            [string]$Header,
            [string]$EmptyLabel,
            [object[]]$Items,
            [scriptblock]$Line
        )

        Write-Host "`n------- $Header -------" -ForegroundColor Cyan
        if ($null -eq $Items -or $Items.Count -eq 0) {
            Write-Host "No $EmptyLabel assigned to All Users" -ForegroundColor Gray
            return
        }
        foreach ($item in $Items) {
            Write-Host (& $Line $item) -ForegroundColor White
        }
    }

    # UserContext carries this cmdlet's exact category order and buckets, with three
    # caller-side adjustments to match the legacy walk:
    # - Cloud PC categories were never fetched here, so drop them entirely
    # - Autopilot/ESP are BucketOnly for a single user but ARE fetched by this cmdlet
    # - the legacy ESP export label here was "Enrollment Status Page Profile"
    $categories = @(Get-IntuneCategoryDefinition -Audience 'UserContext' | Where-Object { $_.Id -notin @('CloudPCProvisioningPolicies', 'CloudPCUserSettings') })
    foreach ($category in $categories) {
        if ($category.Id -in @('DeploymentProfiles', 'ESPProfiles')) { $category.BucketOnly = $false }
        if ($category.Id -eq 'ESPProfiles') { $category.ExportCategory = 'Enrollment Status Page Profile' }
    }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity

        if ($ctx.Category.Kind -eq 'MobileApps') {
            # Legacy quirk: only the first "All Users" assignment counts, so each app
            # lands in exactly one intent bucket, on a copy of the app object.
            foreach ($assignment in $ctx.RawAssignments) {
                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                    $suffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                    $appWithReason = $entity.PSObject.Copy()
                    $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "All Users$suffix" -Force
                    switch ($assignment.intent) {
                        "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason); break }
                        "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason); break }
                        "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason); break }
                    }
                    break
                }
            }
            return
        }

        # All other categories: keep the entity only when an "All Users" target exists;
        # exclusions and group targets never qualify. Reason keeps the filter suffix.
        if (($reason = Get-AllTargetReason -Assignments $ctx.Assignments -TargetReason "All Users")) {
            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
        }
    }

    $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -ShowProgress
    $allUsersAssignments = $scanResult.Buckets

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allUsersAssignments.Keys)) {
            $allUsersAssignments[$key] = @(Filter-ByScopeTag -Items $allUsersAssignments[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # Display results
    Write-Host "`nPolicies Assigned to All Users:" -ForegroundColor Green

    Show-AllUsersSection -Header "Device Configurations" -EmptyLabel "Device Configurations" -Items $allUsersAssignments.DeviceConfigs -Line {
        param($config)
        $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
        $platform = Get-PolicyPlatform -Policy $config
        "Device Configuration Name: $configName, Platform: $platform, Configuration ID: $($config.id)"
    }

    Show-AllUsersSection -Header "Imported Administrative Templates" -EmptyLabel "Imported Administrative Templates" -Items $allUsersAssignments.ImportedAdministrativeTemplates -Line {
        param($policy)
        "Imported Administrative Template Name: $($policy.displayName), Policy ID: $($policy.id)"
    }

    Show-AllUsersSection -Header "Settings Catalog Policies" -EmptyLabel "Settings Catalog Policies" -Items $allUsersAssignments.SettingsCatalog -Line {
        param($policy)
        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
        "Settings Catalog Policy Name: $policyName, Policy ID: $($policy.id)"
    }

    Show-AllUsersSection -Header "Compliance Policies" -EmptyLabel "Compliance Policies" -Items $allUsersAssignments.CompliancePolicies -Line {
        param($policy)
        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
        $platform = Get-PolicyPlatform -Policy $policy
        "Compliance Policy Name: $policyName, Platform: $platform, Policy ID: $($policy.id)"
    }

    Show-AllUsersSection -Header "App Protection Policies" -EmptyLabel "App Protection Policies" -Items $allUsersAssignments.AppProtectionPolicies -Line {
        param($policy)
        $policyType = switch ($policy.'@odata.type') {
            "#microsoft.graph.androidManagedAppProtection" { "Android" }
            "#microsoft.graph.iosManagedAppProtection" { "iOS" }
            "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
            default { "Unknown" }
        }
        "App Protection Policy Name: $($policy.displayName), Policy ID: $($policy.id), Type: $policyType"
    }

    Show-AllUsersSection -Header "App Configuration Policies" -EmptyLabel "App Configuration Policies" -Items $allUsersAssignments.AppConfigurationPolicies -Line {
        param($policy)
        $policyName = if ([string]::IsNullOrWhiteSpace($policy.name)) { $policy.displayName } else { $policy.name }
        "App Configuration Policy Name: $policyName, Policy ID: $($policy.id)"
    }

    $scriptLine = {
        param($script)
        $scriptName = if ([string]::IsNullOrWhiteSpace($script.name)) { $script.displayName } else { $script.name }
        "Script Name: $scriptName, Script ID: $($script.id)"
    }
    Show-AllUsersSection -Header "Platform Scripts" -EmptyLabel "Platform Scripts" -Items $allUsersAssignments.PlatformScripts -Line $scriptLine
    Show-AllUsersSection -Header "Proactive Remediation Scripts" -EmptyLabel "Proactive Remediation Scripts" -Items $allUsersAssignments.HealthScripts -Line $scriptLine

    $appLine = {
        param($app)
        "App Name: $($app.displayName), App ID: $($app.id)"
    }
    Show-AllUsersSection -Header "Required Apps" -EmptyLabel "Required Apps" -Items $allUsersAssignments.AppsRequired -Line $appLine
    Show-AllUsersSection -Header "Available Apps" -EmptyLabel "Available Apps" -Items $allUsersAssignments.AppsAvailable -Line $appLine
    Show-AllUsersSection -Header "Uninstall Apps" -EmptyLabel "Uninstall Apps" -Items $allUsersAssignments.AppsUninstall -Line $appLine

    $esSections = @(
        @{ Bucket = 'AntivirusProfiles'; Label = 'Antivirus' }
        @{ Bucket = 'DiskEncryptionProfiles'; Label = 'Disk Encryption' }
        @{ Bucket = 'FirewallProfiles'; Label = 'Firewall' }
        @{ Bucket = 'EndpointDetectionProfiles'; Label = 'EDR' }
        @{ Bucket = 'AttackSurfaceProfiles'; Label = 'ASR' }
        @{ Bucket = 'AccountProtectionProfiles'; Label = 'Account Protection' }
    )
    foreach ($section in $esSections) {
        $esLabel = $section.Label
        Show-AllUsersSection -Header "Endpoint Security - $esLabel Profiles" -EmptyLabel "$esLabel Profiles" -Items $allUsersAssignments[$section.Bucket] -Line {
            param($policyProfile)
            $profileNameForDisplay = if ($policyProfile.displayName) { $policyProfile.displayName } else { $policyProfile.name }
            "$esLabel Profile Name: $profileNameForDisplay, Profile ID: $($policyProfile.id)"
        }.GetNewClosure()
    }

    Show-AllUsersSection -Header "Autopilot Deployment Profiles" -EmptyLabel "Autopilot Deployment Profiles" -Items $allUsersAssignments.DeploymentProfiles -Line {
        param($policyProfile)
        $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.displayName } else { $policyProfile.name }
        "Autopilot Deployment Profile Name: $profileName, Profile ID: $($policyProfile.id)"
    }

    Show-AllUsersSection -Header "Enrollment Status Page Profiles" -EmptyLabel "Enrollment Status Page Profiles" -Items $allUsersAssignments.ESPProfiles -Line {
        param($policyProfile)
        $profileName = if ([string]::IsNullOrWhiteSpace($policyProfile.name)) { $policyProfile.displayName } else { $policyProfile.name }
        "Enrollment Status Page Profile Name: $profileName, Profile ID: $($policyProfile.id)"
    }

    # Add to export data. The legacy CSV row order follows the display order above,
    # where the app buckets came after the script categories, so export in that order
    # rather than fetch order.
    $exportOrderIds = @(
        'DeviceConfigurations', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies',
        'AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'Applications',
        'ESAntivirus', 'ESDiskEncryption', 'ESFirewall', 'ESEndpointDetection', 'ESAttackSurface',
        'ESAccountProtection', 'DeploymentProfiles', 'ESPProfiles'
    )
    $exportCategories = foreach ($id in $exportOrderIds) { $categories | Where-Object { $_.Id -eq $id } }
    Add-CategoryExportData -ExportData $exportData -Categories $exportCategories -Buckets $allUsersAssignments -AssignmentReason "All Users"

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllUsersAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$parameterMode
}
