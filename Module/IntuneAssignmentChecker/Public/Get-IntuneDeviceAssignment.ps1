function Get-IntuneDeviceAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DeviceNames,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter
    )

    Write-Host "Device selection chosen" -ForegroundColor Green

    # Get Device names from parameter or prompt
    if ($DeviceNames) {
        $deviceInput = $DeviceNames
    }
    else {
        # Prompt for one or more Device Names
        Write-Host "Please enter Device Name(s), separated by commas (,): " -ForegroundColor Cyan
        $deviceInput = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($deviceInput)) {
        Write-Host "No device name provided. Please try again." -ForegroundColor Red
        return
    }

    # Distinct name from the [string]$DeviceNames parameter: assigning this array to the
    # case-insensitively identical, type-constrained parameter variable would coerce it
    # back into one space-joined string and break multi-device input.
    $deviceNameList = $deviceInput -split ',' | ForEach-Object { $_.Trim() }
    $exportData = [System.Collections.ArrayList]::new()

    $categories = Get-IntuneCategoryDefinition -Audience 'DeviceContext'
    # Categories the legacy code fetched only for Windows (or unknown-OS) devices
    $windowsOnlyCategoryIds = @('ImportedAdministrativeTemplates', 'DeploymentProfiles', 'ESPProfiles', 'CloudPCProvisioningPolicies', 'CloudPCUserSettings')
    # These legacy categories retain their historical first-match assignment walk.
    # Imported templates use standard exclusion precedence instead.
    $firstMatchCategoryIds = @('DeploymentProfiles', 'ESPProfiles', 'CloudPCProvisioningPolicies', 'CloudPCUserSettings')
    # Shared across devices so each entity set is fetched from Graph once per run
    $entityCache = @{}

    # Legacy device table: four columns (no Platform), "No Assignment" fallback,
    # red rows for exclusions. Kept local because it differs from Show-CategoryResultTable.
    function Format-PolicyTable {
        param (
            [string]$Title,
            [object[]]$Policies,
            [scriptblock]$GetName
        )
        $tableSeparator = Get-Separator

        # Create prominent section header
        $headerSeparator = "-" * ($Title.Length + 16)
        Write-Host "`n$headerSeparator" -ForegroundColor Cyan
        Write-Host "------- $Title -------" -ForegroundColor Cyan
        Write-Host "$headerSeparator" -ForegroundColor Cyan

        if ($Policies.Count -eq 0) {
            Write-Host "No $Title found for this device." -ForegroundColor Gray
            Write-Host $tableSeparator -ForegroundColor Gray
            Write-Host ""
            return
        }

        # Create table header
        $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-30}" -f "Policy Name", "Scope Tags", "ID", "Assignment"

        Write-Host $headerFormat -ForegroundColor Yellow
        Write-Host $tableSeparator -ForegroundColor Gray

        # Display each policy in table format
        foreach ($policy in $Policies) {
            $name = & $GetName $policy

            if ($name.Length -gt 42) {
                $name = $name.Substring(0, 39) + "..."
            }

            $scopeTags = Get-ScopeTagNames -ScopeTagIds $policy.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
            if ($scopeTags.Length -gt 17) { $scopeTags = $scopeTags.Substring(0, 14) + "..." }

            $id = $policy.id
            if ($id.Length -gt 32) {
                $id = $id.Substring(0, 29) + "..."
            }

            $assignment = if ($policy.AssignmentReason) { $policy.AssignmentReason } else { "No Assignment" }
            if ($assignment.Length -gt 27) {
                $assignment = $assignment.Substring(0, 24) + "..."
            }

            $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-30}" -f $name, $scopeTags, $id, $assignment
            if ($assignment -like "Excluded*" -or $assignment -like "*Exclusion*") {
                Write-Host $rowFormat -ForegroundColor Red
            }
            else {
                Write-Host $rowFormat -ForegroundColor White
            }
        }

        Write-Host $tableSeparator -ForegroundColor Gray
    }

    foreach ($deviceName in $deviceNameList) {
        Write-Host "`nProcessing device: $deviceName" -ForegroundColor Yellow

        # Check if input is a GUID (Object ID)
        $deviceInfo = $null
        if ($deviceName -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            try {
                $selectProps = "id,displayName,operatingSystem,operatingSystemVersion,managementType,deviceOwnership,trustType,isCompliant,isManaged,approximateLastSignInDateTime,manufacturer,model,enrollmentProfileName"
                $directDevice = Invoke-MgGraphRequest -Uri "$script:GraphEndpoint/beta/devices/$($deviceName)?`$select=$selectProps" -Method Get
                $deviceInfo = @{
                    Id              = $directDevice.id
                    DisplayName     = $directDevice.displayName
                    OperatingSystem = $directDevice.operatingSystem
                    Success         = $true
                    MultipleFound   = $false
                    AllDevices      = $null
                }
            }
            catch {
                Write-Host "No device found with Object ID: $deviceName" -ForegroundColor Red
                continue
            }
        }
        else {
            # Get Device Info by display name
            $deviceInfo = Get-DeviceInfo -DeviceName $deviceName
        }

        # Handle multiple devices found
        if ($deviceInfo.MultipleFound) {
            if ($DeviceNames) {
                Write-Host "Multiple devices found with name '$deviceName'. Please use the Object ID instead:" -ForegroundColor Red
                foreach ($d in $deviceInfo.AllDevices) {
                    $lastSignIn = if ($d.approximateLastSignInDateTime) { ([datetime]$d.approximateLastSignInDateTime).ToString("yyyy-MM-dd") } else { "N/A" }
                    Write-Host "  - $($d.displayName) | OS: $($d.operatingSystem) $($d.operatingSystemVersion) | Trust: $($d.trustType) | Ownership: $($d.deviceOwnership) | Last sign-in: $lastSignIn | ID: $($d.id)" -ForegroundColor Yellow
                }
                continue
            }

            Write-Host "`nMultiple devices found with name '$deviceName':" -ForegroundColor Yellow
            Write-Host ""
            for ($i = 0; $i -lt $deviceInfo.AllDevices.Count; $i++) {
                $d = $deviceInfo.AllDevices[$i]
                $lastSignIn = if ($d.approximateLastSignInDateTime) { ([datetime]$d.approximateLastSignInDateTime).ToString("yyyy-MM-dd") } else { "N/A" }
                $managedStatus = if ($d.isManaged) { "Managed" } else { "Not managed" }
                $compliantStatus = if ($d.isCompliant) { "Compliant" } else { "Not compliant" }
                Write-Host "  [$($i + 1)] $($d.displayName)" -ForegroundColor Cyan
                Write-Host "      OS: $($d.operatingSystem) $($d.operatingSystemVersion) | Trust: $($d.trustType) | Ownership: $($d.deviceOwnership)" -ForegroundColor Gray
                Write-Host "      $managedStatus | $compliantStatus | Last sign-in: $lastSignIn" -ForegroundColor Gray
                Write-Host "      Object ID: $($d.id)" -ForegroundColor Gray
            }
            Write-Host "  [0] Skip this device" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Select a device (1-$($deviceInfo.AllDevices.Count)) or 0 to skip: " -ForegroundColor Cyan -NoNewline
            $selection = Read-Host

            if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $deviceInfo.AllDevices.Count) {
                $selectedDevice = $deviceInfo.AllDevices[[int]$selection - 1]
                $deviceInfo = @{
                    Id              = $selectedDevice.id
                    DisplayName     = $selectedDevice.displayName
                    OperatingSystem = $selectedDevice.operatingSystem
                    Success         = $true
                    MultipleFound   = $false
                    AllDevices      = $null
                }
            }
            else {
                Write-Host "Skipping device: $deviceName" -ForegroundColor Yellow
                continue
            }
        }

        if (-not $deviceInfo.Success) {
            Write-Host "Device not found: $deviceName" -ForegroundColor Red
            Write-Host "Please verify the device name is correct." -ForegroundColor Yellow
            continue
        }

        $deviceOS = $deviceInfo.OperatingSystem
        if ($deviceOS) {
            Write-Host "Device OS: $deviceOS" -ForegroundColor Green
        }

        # Get Device Group Memberships
        try {
            $groupMemberships = Get-GroupMemberships -ObjectId $deviceInfo.Id -ObjectType "Device"
            Write-Host "Device Group Memberships: $($groupMemberships.displayName -join ', ')" -ForegroundColor Green
        }
        catch {
            Write-Host "Error fetching group memberships for device: $deviceName" -ForegroundColor Red
            Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        Write-Host "Fetching Intune Profiles and Applications for the device..." -ForegroundColor Yellow

        # Autopilot/ESP/Windows 365 stay bucket-only (export parity, never fetched) unless
        # the device is Windows or its OS is unknown, matching the legacy conditional fetch.
        $isWindowsDevice = (-not $deviceOS) -or ($deviceOS -eq "Windows")
        foreach ($category in $categories) {
            if ($category.Id -in $windowsOnlyCategoryIds) { $category.BucketOnly = -not $isWindowsDevice }
        }

        # The legacy code platform-filtered apps and App Protection policies before fetching
        # their assignments; every other category is platform-checked after reason resolution.
        $entityPreFilter = {
            param($entity, $category)
            switch ($category.Kind) {
                'MobileApps' { Test-AppPlatformCompatibility -DeviceOS $deviceOS -App $entity }
                'AppProtection' { Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $entity }
                default { $true }
            }
        }

        $processEntity = {
            param($ctx)

            $entity = $ctx.Entity
            $bucketKey = $ctx.Category.BucketKeys[0]

            if ($ctx.Category.Kind -eq 'MobileApps') {
                # Winning-assignment walk: an exclusion for a member group wins immediately;
                # otherwise the intent comes from the FIRST matching inclusion assignment
                # while the reason text reflects the last one (historical behavior, F14).
                $isExcluded = $false
                $isIncluded = $false
                $inclusionReason = ""
                $exclusionReason = ""
                $inclusionAssignment = $null
                $exclusionAssignment = $null

                foreach ($assignment in $ctx.RawAssignments) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                        $groupMemberships.id -contains $assignment.target.groupId) {
                        $isExcluded = $true
                        $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                        $exclusionReason = "Excluded via group: $($groupInfo.DisplayName)"
                        $exclusionAssignment = $assignment
                        break
                    }
                    elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                        if (-not $isIncluded) { $inclusionAssignment = $assignment }
                        $isIncluded = $true
                        $inclusionReason = "All Devices"
                    }
                    elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                        $groupMemberships.id -contains $assignment.target.groupId) {
                        if (-not $isIncluded) { $inclusionAssignment = $assignment }
                        $isIncluded = $true
                        $groupInfo = Get-GroupInfo -GroupId $assignment.target.groupId
                        $inclusionReason = "Group Assignment - $($groupInfo.DisplayName)"
                    }
                }

                $winningAssignment = if ($isExcluded) { $exclusionAssignment } elseif ($isIncluded) { $inclusionAssignment } else { $null }
                if ($winningAssignment) {
                    $reasonText = if ($isExcluded) { $exclusionReason } else { $inclusionReason }
                    $suffix = Format-AssignmentFilter `
                        -FilterId   $winningAssignment.target.deviceAndAppManagementAssignmentFilterId `
                        -FilterType $winningAssignment.target.deviceAndAppManagementAssignmentFilterType
                    $appWithReason = $entity.PSObject.Copy()
                    $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$reasonText$suffix" -Force
                    # F14: the bucket comes from the winning assignment's intent
                    switch ($winningAssignment.intent) {
                        "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason) }
                        "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason) }
                        "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason) }
                    }
                }
                return
            }

            if ($ctx.Category.Kind -eq 'AppProtection') {
                # Membership check: All Devices always counts, group targets only when the
                # device is a member, All Users targets are dropped (device context).
                $relevantAssignments = @($ctx.Assignments | Where-Object {
                        $_.Reason -eq 'All Devices' -or
                        ($_.Reason -in @('Group Assignment', 'Group Exclusion') -and $groupMemberships.id -contains $_.GroupId)
                    })
                if ($relevantAssignments.Count -gt 0) {
                    $assignmentSummary = $relevantAssignments | ForEach-Object { Format-AssignmentSummaryLine -Assignment $_ }
                    $entity | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                    $ctx.Buckets[$bucketKey].Add($entity)
                }
                return
            }

            if ($ctx.Category.Id -in $firstMatchCategoryIds) {
                # First-match walk with no platform filtering: All Devices or a member group
                # assignment includes; a member group exclusion shows as "Excluded".
                foreach ($assignment in $ctx.Assignments) {
                    if (($assignment.Reason -eq "All Devices") -or
                        ($assignment.Reason -eq "Group Assignment" -and $groupMemberships.id -contains $assignment.GroupId)) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                        $ctx.Buckets[$bucketKey].Add($entity)
                        return
                    }
                    elseif ($assignment.Reason -eq "Group Exclusion" -and $groupMemberships.id -contains $assignment.GroupId) {
                        $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                        $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                        $ctx.Buckets[$bucketKey].Add($entity)
                        return
                    }
                }
                return
            }

            # Standard categories and both Endpoint Security phases: resolve the reason
            # (All Devices counts as inclusion) first, then drop other-platform policies.
            $reason = Resolve-AssignmentReason -Assignments $ctx.Assignments -GroupMembershipIds $groupMemberships.id -IncludeReasons @("All Devices")
            if ($reason -and (Test-PlatformCompatibility -DeviceOS $deviceOS -Policy $entity)) {
                $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                $ctx.Buckets[$bucketKey].Add($entity)
            }
        }

        $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -EntityPreFilter $entityPreFilter -ShowProgress -EntityCache $entityCache
        $relevantPolicies = $scanResult.Buckets

        # Apply scope tag filter if specified
        if ($ScopeTagFilter) {
            foreach ($key in @($relevantPolicies.Keys)) {
                $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
            }
        }

        # Display results
        Write-Host "`nAssignments for Device: $deviceName" -ForegroundColor Green

        # Legacy per-category name resolution. Windows 365 buckets are exported but were
        # never displayed by the old code, so they get no section here either.
        $nameFirst = { param($item) if ([string]::IsNullOrWhiteSpace($item.name)) { $item.displayName } else { $item.name } }
        $displayNameFirst = { param($item) if ([string]::IsNullOrWhiteSpace($item.displayName)) { $item.name } else { $item.displayName } }
        $displayNameOnly = { param($item) $item.displayName }
        $esProfileName = { param($item) if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } elseif (-not [string]::IsNullOrWhiteSpace($item.name)) { $item.name } else { "Unnamed Profile" } }

        $displaySections = @(
            @{ Title = 'Device Configurations'; Bucket = 'DeviceConfigs'; GetName = $nameFirst }
            @{ Title = 'Imported Administrative Templates'; Bucket = 'ImportedAdministrativeTemplates'; GetName = $displayNameFirst }
            @{ Title = 'Settings Catalog Policies'; Bucket = 'SettingsCatalog'; GetName = $nameFirst }
            @{ Title = 'Compliance Policies'; Bucket = 'CompliancePolicies'; GetName = $nameFirst }
            @{ Title = 'App Protection Policies'; Bucket = 'AppProtectionPolicies'; GetName = $displayNameOnly }
            @{ Title = 'App Configuration Policies'; Bucket = 'AppConfigurationPolicies'; GetName = $nameFirst }
            @{ Title = 'Platform Scripts'; Bucket = 'PlatformScripts'; GetName = $nameFirst }
            @{ Title = 'Proactive Remediation Scripts'; Bucket = 'HealthScripts'; GetName = $nameFirst }
            @{ Title = 'Autopilot Deployment Profiles'; Bucket = 'DeploymentProfiles'; GetName = $displayNameFirst }
            @{ Title = 'Enrollment Status Page Profiles'; Bucket = 'ESPProfiles'; GetName = $displayNameFirst }
            @{ Title = 'Required Apps'; Bucket = 'AppsRequired'; GetName = $displayNameOnly }
            @{ Title = 'Available Apps'; Bucket = 'AppsAvailable'; GetName = $displayNameOnly }
            @{ Title = 'Uninstall Apps'; Bucket = 'AppsUninstall'; GetName = $displayNameOnly }
            @{ Title = 'Endpoint Security - Antivirus Profiles'; Bucket = 'AntivirusProfiles'; GetName = $esProfileName }
            @{ Title = 'Endpoint Security - Disk Encryption Profiles'; Bucket = 'DiskEncryptionProfiles'; GetName = $esProfileName }
            @{ Title = 'Endpoint Security - Firewall Profiles'; Bucket = 'FirewallProfiles'; GetName = $esProfileName }
            @{ Title = 'Endpoint Security - EDR Profiles'; Bucket = 'EndpointDetectionProfiles'; GetName = $esProfileName }
            @{ Title = 'Endpoint Security - ASR Profiles'; Bucket = 'AttackSurfaceProfiles'; GetName = $esProfileName }
            @{ Title = 'Endpoint Security - Account Protection Profiles'; Bucket = 'AccountProtectionProfiles'; GetName = $esProfileName }
        )
        foreach ($section in $displaySections) {
            Format-PolicyTable -Title $section.Title -Policies @($relevantPolicies[$section.Bucket]) -GetName $section.GetName
        }

        # Add to export data: the Device row first, then categories in the legacy CSV order
        # (Autopilot/ESP before Endpoint Security, Windows 365 after it, app buckets last).
        Add-ExportData -ExportData $exportData -Category "Device" -Items @([PSCustomObject]@{
                displayName      = $deviceName
                id               = $deviceInfo.Id
                AssignmentReason = "N/A"
            })

        $reasonProperty = { param($item) $item.AssignmentReason }
        $exportBatches = @(
            @{ Ids = @('DeviceConfigurations', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies'); Reason = $reasonProperty }
            # App Protection rows export the AssignmentSummary built above
            @{ Ids = @('AppProtectionPolicies'); Reason = { param($item) $item.AssignmentSummary } }
            @{ Ids = @('AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'DeploymentProfiles', 'ESPProfiles',
                    'ESAntivirus', 'ESDiskEncryption', 'ESFirewall', 'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection',
                    'CloudPCProvisioningPolicies', 'CloudPCUserSettings', 'Applications'); Reason = $reasonProperty }
        )
        foreach ($batch in $exportBatches) {
            $batchCategories = foreach ($id in $batch.Ids) { $categories | Where-Object { $_.Id -eq $id } }
            Add-CategoryExportData -ExportData $exportData -Categories $batchCategories -Buckets $relevantPolicies -AssignmentReason $batch.Reason
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneDeviceAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:$parameterMode
}
