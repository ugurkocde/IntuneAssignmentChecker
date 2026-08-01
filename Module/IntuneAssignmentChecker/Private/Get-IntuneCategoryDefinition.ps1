function Get-IntuneCategoryDefinition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('UserContext', 'DeviceContext', 'GroupContext', 'AllPolicies', 'Search', 'Compare')]
        [string]$Audience
    )

    # Local constructor keeps each category entry terse while guaranteeing a uniform schema.
    $newCategory = {
        param([hashtable]$Props)
        $entry = [ordered]@{
            Id                     = $null
            Kind                   = 'Entity'
            EntityType             = $null
            AssignmentEntityType   = $null
            TemplateFamily         = $null
            EntityFilter           = $null
            BucketKeys             = @()
            DisplayName            = $null
            ExportCategory         = $null
            Platform               = $null
            OptionalFeature        = $false
            # BucketOnly categories register their BucketKeys for export parity but are never fetched.
            BucketOnly             = $false
            BucketExportCategories = $null
        }
        foreach ($key in $Props.Keys) { $entry[$key] = $Props[$key] }
        if (-not $entry.AssignmentEntityType) { $entry.AssignmentEntityType = $entry.EntityType }
        [PSCustomObject]$entry
    }

    # GroupContext Settings Catalog filter, copied verbatim from Get-IntuneGroupAssignment.ps1:157-167.
    # Exclude Windows-only Endpoint Security policies from this generic Settings Catalog fetch
    # Allow macOS and cross-platform endpoint security policies through
    $groupSettingsCatalogFilter = {
        if ($_.templateReference -and $_.templateReference.templateFamily -like "endpointSecurity*") {
            $platforms = $_.platforms
            # Only skip if this is a Windows-only policy (not macOS or other platforms)
            if ($platforms -and
                (($platforms -contains "windows10" -or $platforms -contains "windows10AndLater") -and
                 $platforms -notcontains "macOS")) {
                return $false
            }
        }
        return $true
    }

    # Search Settings Catalog filter, copied verbatim from Search-IntunePolicy.ps1:144-146.
    # Exclude endpoint security policies (they will be handled separately)
    $searchSettingsCatalogFilter = {
        -not ($_.templateReference -and $_.templateReference.templateFamily -and $_.templateReference.templateFamily -like 'endpointSecurity*')
    }

    $espEntityFilter = { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    # Imported Administrative Templates are group policy configurations whose settings
    # were ingested by an administrator. A mixed configuration contains both imported
    # and built-in definitions and must remain visible as an imported template policy.
    $importedAdministrativeTemplateFilter = { Test-ImportedAdministrativeTemplate -Policy $_ }

    $baseCategories = @{
        DeviceConfigurations        = @{ Id = 'DeviceConfigurations'; EntityType = 'deviceConfigurations'; BucketKeys = @('DeviceConfigs'); DisplayName = 'Device Configurations'; ExportCategory = 'Device Configuration' }
        ImportedAdministrativeTemplates = @{ Id = 'ImportedAdministrativeTemplates'; EntityType = 'groupPolicyConfigurations'; EntityFilter = $importedAdministrativeTemplateFilter; BucketKeys = @('ImportedAdministrativeTemplates'); DisplayName = 'Imported Administrative Templates'; ExportCategory = 'Imported Administrative Template' }
        SettingsCatalog             = @{ Id = 'SettingsCatalog'; EntityType = 'configurationPolicies'; BucketKeys = @('SettingsCatalog'); DisplayName = 'Settings Catalog Policies'; ExportCategory = 'Settings Catalog Policy' }
        CompliancePolicies          = @{ Id = 'CompliancePolicies'; EntityType = 'deviceCompliancePolicies'; BucketKeys = @('CompliancePolicies'); DisplayName = 'Compliance Policies'; ExportCategory = 'Compliance Policy' }
        AppProtectionPolicies       = @{ Id = 'AppProtectionPolicies'; Kind = 'AppProtection'; EntityType = 'deviceAppManagement/managedAppPolicies'; BucketKeys = @('AppProtectionPolicies'); DisplayName = 'App Protection Policies'; ExportCategory = 'App Protection Policy' }
        AppConfigurationPolicies    = @{ Id = 'AppConfigurationPolicies'; EntityType = 'deviceAppManagement/mobileAppConfigurations'; AssignmentEntityType = 'mobileAppConfigurations'; BucketKeys = @('AppConfigurationPolicies'); DisplayName = 'App Configuration Policies'; ExportCategory = 'App Configuration Policy' }
        Applications                = @{ Id = 'Applications'; Kind = 'MobileApps'; EntityType = 'deviceAppManagement/mobileApps'; BucketKeys = @('AppsRequired', 'AppsAvailable', 'AppsUninstall'); BucketExportCategories = @{ AppsRequired = 'Required Apps'; AppsAvailable = 'Available Apps'; AppsUninstall = 'Uninstall Apps' }; DisplayName = 'Applications' }
        PlatformScripts             = @{ Id = 'PlatformScripts'; EntityType = 'deviceManagementScripts'; BucketKeys = @('PlatformScripts'); DisplayName = 'Platform Scripts'; ExportCategory = 'Platform Scripts' }
        HealthScripts               = @{ Id = 'HealthScripts'; EntityType = 'deviceHealthScripts'; BucketKeys = @('HealthScripts'); DisplayName = 'Proactive Remediation Scripts'; ExportCategory = 'Proactive Remediation Scripts' }
        DeploymentProfiles          = @{ Id = 'DeploymentProfiles'; EntityType = 'windowsAutopilotDeploymentProfiles'; BucketKeys = @('DeploymentProfiles'); DisplayName = 'Autopilot Deployment Profiles'; ExportCategory = 'Autopilot Deployment Profile' }
        ESPProfiles                 = @{ Id = 'ESPProfiles'; EntityType = 'deviceEnrollmentConfigurations'; EntityFilter = $espEntityFilter; BucketKeys = @('ESPProfiles'); DisplayName = 'Enrollment Status Page Profiles'; ExportCategory = 'Enrollment Status Page' }
        CloudPCProvisioningPolicies = @{ Id = 'CloudPCProvisioningPolicies'; EntityType = 'virtualEndpoint/provisioningPolicies'; BucketKeys = @('CloudPCProvisioningPolicies'); DisplayName = 'Windows 365 Cloud PC Provisioning Policies'; ExportCategory = 'Windows 365 Cloud PC Provisioning Policy'; OptionalFeature = $true }
        CloudPCUserSettings         = @{ Id = 'CloudPCUserSettings'; EntityType = 'virtualEndpoint/userSettings'; BucketKeys = @('CloudPCUserSettings'); DisplayName = 'Windows 365 Cloud PC User Settings'; ExportCategory = 'Windows 365 Cloud PC User Setting'; OptionalFeature = $true }
        WindowsFeatureUpdates       = @{ Id = 'WindowsFeatureUpdates'; EntityType = 'windowsFeatureUpdateProfiles'; BucketKeys = @('WindowsFeatureUpdates'); DisplayName = 'Windows Feature Update Profiles'; ExportCategory = 'Windows Feature Update Profile'; Platform = 'Windows'; OptionalFeature = $true }
        WindowsQualityUpdates       = @{ Id = 'WindowsQualityUpdates'; EntityType = 'windowsQualityUpdateProfiles'; BucketKeys = @('WindowsQualityUpdates'); DisplayName = 'Windows Quality Update Profiles'; ExportCategory = 'Windows Quality Update Profile'; Platform = 'Windows'; OptionalFeature = $true }
        WindowsDriverUpdates        = @{ Id = 'WindowsDriverUpdates'; EntityType = 'windowsDriverUpdateProfiles'; BucketKeys = @('WindowsDriverUpdates'); DisplayName = 'Windows Driver Update Profiles'; ExportCategory = 'Windows Driver Update Profile'; Platform = 'Windows'; OptionalFeature = $true }
        WindowsQualityUpdatePolicies = @{ Id = 'WindowsQualityUpdatePolicies'; EntityType = 'windowsQualityUpdatePolicies'; BucketKeys = @('WindowsQualityUpdatePolicies'); DisplayName = 'Windows Quality Update Policies'; ExportCategory = 'Windows Quality Update Policy'; Platform = 'Windows'; OptionalFeature = $true }
    }

    $use = {
        param([string]$Name, [hashtable]$Overrides)
        $props = @{} + $baseCategories[$Name]
        if ($Overrides) { foreach ($key in $Overrides.Keys) { $props[$key] = $Overrides[$key] } }
        & $newCategory $props
    }

    $esFamilies = @(
        [PSCustomObject]@{ Id = 'ESAntivirus'; Family = 'endpointSecurityAntivirus'; Bucket = 'AntivirusProfiles'; Export = 'Endpoint Security - Antivirus'; Name = 'Antivirus'; ShortName = 'Antivirus' }
        [PSCustomObject]@{ Id = 'ESDiskEncryption'; Family = 'endpointSecurityDiskEncryption'; Bucket = 'DiskEncryptionProfiles'; Export = 'Endpoint Security - Disk Encryption'; Name = 'Disk Encryption'; ShortName = 'Disk Encryption' }
        [PSCustomObject]@{ Id = 'ESFirewall'; Family = 'endpointSecurityFirewall'; Bucket = 'FirewallProfiles'; Export = 'Endpoint Security - Firewall'; Name = 'Firewall'; ShortName = 'Firewall' }
        [PSCustomObject]@{ Id = 'ESEndpointDetection'; Family = 'endpointSecurityEndpointDetectionAndResponse'; Bucket = 'EndpointDetectionProfiles'; Export = 'Endpoint Security - EDR'; Name = 'Endpoint Detection and Response'; ShortName = 'EDR' }
        [PSCustomObject]@{ Id = 'ESAttackSurface'; Family = 'endpointSecurityAttackSurfaceReduction'; Bucket = 'AttackSurfaceProfiles'; Export = 'Endpoint Security - ASR'; Name = 'Attack Surface Reduction'; ShortName = 'ASR' }
        [PSCustomObject]@{ Id = 'ESAccountProtection'; Family = 'endpointSecurityAccountProtection'; Bucket = 'AccountProtectionProfiles'; Export = 'Endpoint Security - Account Protection'; Name = 'Account Protection'; ShortName = 'Account Protection' }
    )

    $newEsCategories = {
        param([scriptblock]$DisplayNameBuilder, [hashtable]$Overrides)
        foreach ($family in $esFamilies) {
            $props = @{
                Id             = $family.Id
                Kind           = 'EndpointSecurity'
                EntityType     = 'configurationPolicies'
                TemplateFamily = $family.Family
                BucketKeys     = @($family.Bucket)
                DisplayName    = (& $DisplayNameBuilder $family)
                ExportCategory = $family.Export
            }
            if ($Overrides) { foreach ($key in $Overrides.Keys) { $props[$key] = $Overrides[$key] } }
            & $newCategory $props
        }
    }

    switch ($Audience) {
        'UserContext' {
            # Order and display names from Get-IntuneUserAssignment.ps1 (17 progress steps).
            $categories = @(
                & $use 'DeviceConfigurations'
                & $use 'ImportedAdministrativeTemplates'
                # UserContext applies no ES exclusion to Settings Catalog (Get-IntuneUserAssignment.ps1:125-133)
                & $use 'SettingsCatalog'
                & $use 'CompliancePolicies'
                & $use 'AppProtectionPolicies'
                & $use 'AppConfigurationPolicies'
                & $use 'Applications'
                & $use 'PlatformScripts'
                & $use 'HealthScripts'
            )
            $categories += @(& $newEsCategories { param($family) "$($family.Name) Policies" })
            $categories += @(
                & $use 'WindowsFeatureUpdates'
                & $use 'WindowsQualityUpdates'
                & $use 'WindowsDriverUpdates'
                & $use 'WindowsQualityUpdatePolicies'
                & $use 'CloudPCProvisioningPolicies'
                & $use 'CloudPCUserSettings'
                # Autopilot/ESP buckets exist for export parity but are not fetched for a user
                # (see $relevantPolicies init in Get-IntuneUserAssignment.ps1:86-107)
                & $use 'DeploymentProfiles' @{ BucketOnly = $true }
                & $use 'ESPProfiles' @{ BucketOnly = $true }
            )
            return $categories
        }
        'DeviceContext' {
            # Order and display names from Get-IntuneDeviceAssignment.ps1 (17 fetch steps).
            # Autopilot/ESP are Windows-only conditional fetches there; the migrated cmdlet
            # decides whether to flip BucketOnly off for Windows devices.
            $categories = @(
                & $use 'DeviceConfigurations'
                & $use 'ImportedAdministrativeTemplates'
                # DeviceContext applies no ES exclusion to Settings Catalog (Get-IntuneDeviceAssignment.ps1:171-180)
                & $use 'SettingsCatalog'
                & $use 'CompliancePolicies'
                & $use 'AppProtectionPolicies'
                & $use 'AppConfigurationPolicies'
                & $use 'PlatformScripts'
                & $use 'HealthScripts'
                & $use 'CloudPCProvisioningPolicies'
                & $use 'CloudPCUserSettings'
                & $use 'WindowsFeatureUpdates'
                & $use 'WindowsQualityUpdates'
                & $use 'WindowsDriverUpdates'
                & $use 'WindowsQualityUpdatePolicies'
            )
            $categories += @(& $newEsCategories { param($family) "$($family.ShortName) Policies" })
            $categories += @(
                & $use 'Applications'
                & $use 'DeploymentProfiles' @{ BucketOnly = $true }
                & $use 'ESPProfiles' @{ BucketOnly = $true }
            )
            return $categories
        }
        'GroupContext' {
            # Order and display names from Get-IntuneGroupAssignment.ps1 (19 fetch steps).
            $categories = @(
                & $use 'DeviceConfigurations'
                & $use 'ImportedAdministrativeTemplates'
                & $use 'SettingsCatalog' @{ EntityFilter = $groupSettingsCatalogFilter }
                & $use 'CompliancePolicies'
                & $use 'AppProtectionPolicies'
                & $use 'AppConfigurationPolicies'
            )
            $categories += @(& $newEsCategories { param($family) "$($family.Name) Policies for group" })
            $categories += @(
                & $use 'Applications'
                & $use 'PlatformScripts'
                & $use 'HealthScripts'
                & $use 'DeploymentProfiles'
                & $use 'ESPProfiles'
                & $use 'CloudPCProvisioningPolicies'
                & $use 'CloudPCUserSettings'
                & $use 'WindowsFeatureUpdates'
                & $use 'WindowsQualityUpdates'
                & $use 'WindowsDriverUpdates'
                & $use 'WindowsQualityUpdatePolicies'
            )
            return $categories
        }
        'AllPolicies' {
            # Order and display names from Get-IntuneAllPolicies.ps1 (18 categories, no Applications).
            $categories = @(
                & $use 'DeviceConfigurations'
                & $use 'ImportedAdministrativeTemplates'
                # AllPolicies applies no ES exclusion to Settings Catalog (Get-IntuneAllPolicies.ps1:83-92)
                & $use 'SettingsCatalog'
                & $use 'CompliancePolicies'
                & $use 'AppProtectionPolicies'
                & $use 'AppConfigurationPolicies'
                & $use 'PlatformScripts'
                & $use 'HealthScripts'
                & $use 'DeploymentProfiles'
                & $use 'ESPProfiles'
                & $use 'CloudPCProvisioningPolicies'
                & $use 'CloudPCUserSettings'
                & $use 'WindowsFeatureUpdates'
                & $use 'WindowsQualityUpdates'
                & $use 'WindowsDriverUpdates'
                & $use 'WindowsQualityUpdatePolicies'
            )
            $categories += @(& $newEsCategories { param($family) "$($family.ShortName) Policies" })
            return $categories
        }
        'Search' {
            # Order, display names and export labels from Search-IntunePolicy.ps1 (19 categories).
            # All Search categories feed one flat SearchResults bucket (grouped rows at display time).
            $searchBucket = @{ BucketKeys = @('SearchResults'); BucketExportCategories = $null }
            $categories = @(
                & $use 'DeviceConfigurations' $searchBucket
                & $use 'ImportedAdministrativeTemplates' $searchBucket
                & $use 'SettingsCatalog' ($searchBucket + @{ EntityFilter = $searchSettingsCatalogFilter; ExportCategory = 'Settings Catalog' })
                & $use 'CompliancePolicies' $searchBucket
                & $use 'AppProtectionPolicies' $searchBucket
                & $use 'AppConfigurationPolicies' $searchBucket
                & $use 'Applications' ($searchBucket + @{ ExportCategory = 'Application' })
                & $use 'PlatformScripts' ($searchBucket + @{ ExportCategory = 'Platform Script' })
                & $use 'HealthScripts' ($searchBucket + @{ ExportCategory = 'Proactive Remediation Script' })
            )
            $categories += @(& $newEsCategories { param($family) $family.Export } $searchBucket)
            $categories += @(
                & $use 'DeploymentProfiles' $searchBucket
                & $use 'ESPProfiles' $searchBucket
                & $use 'CloudPCProvisioningPolicies' ($searchBucket + @{ DisplayName = 'Cloud PC Provisioning Policies'; ExportCategory = 'Cloud PC Provisioning Policy' })
                & $use 'CloudPCUserSettings' ($searchBucket + @{ DisplayName = 'Cloud PC User Settings'; ExportCategory = 'Cloud PC User Setting' })
                & $use 'WindowsFeatureUpdates' $searchBucket
                & $use 'WindowsQualityUpdates' $searchBucket
                & $use 'WindowsDriverUpdates' $searchBucket
                & $use 'WindowsQualityUpdatePolicies' $searchBucket
            )
            return $categories
        }
        'Compare' {
            # Categories Compare-IntuneGroupAssignment.ps1 currently walks (14 fetch categories).
            # Compare currently checks intents only for ES; the shared EndpointSecurity kind adds
            # the configurationPolicies phase when Compare is migrated onto the engine.
            $categories = @(
                & $use 'DeviceConfigurations' @{ ExportCategory = 'Device Configurations' }
                & $use 'ImportedAdministrativeTemplates' @{ ExportCategory = 'Imported Administrative Templates' }
                # Compare applies no ES exclusion to Settings Catalog (Compare-IntuneGroupAssignment.ps1:214-252)
                & $use 'SettingsCatalog' @{ ExportCategory = 'Settings Catalog' }
                & $use 'CompliancePolicies' @{ ExportCategory = 'Compliance Policies' }
                & $use 'Applications' @{ BucketKeys = @('RequiredApps', 'AvailableApps', 'UninstallApps'); BucketExportCategories = @{ RequiredApps = 'Required Apps'; AvailableApps = 'Available Apps'; UninstallApps = 'Uninstall Apps' } }
                & $use 'PlatformScripts'
                # deviceShellScripts assignments live under /groupAssignments in the current Compare code
                # (Compare-IntuneGroupAssignment.ps1:348-363); the migration must account for that shape.
                & $newCategory @{ Id = 'ShellScripts'; EntityType = 'deviceShellScripts'; BucketKeys = @('PlatformScripts'); DisplayName = 'Shell Scripts'; ExportCategory = 'Platform Scripts' }
                & $use 'HealthScripts'
                & $use 'WindowsFeatureUpdates' @{ ExportCategory = 'Windows Feature Update Profiles' }
                & $use 'WindowsQualityUpdates' @{ ExportCategory = 'Windows Quality Update Profiles' }
                & $use 'WindowsDriverUpdates' @{ ExportCategory = 'Windows Driver Update Profiles' }
                & $use 'WindowsQualityUpdatePolicies' @{ ExportCategory = 'Windows Quality Update Policies' }
            )
            $categories += @(& $newEsCategories { param($family) $family.Export })
            return $categories
        }
    }
}
