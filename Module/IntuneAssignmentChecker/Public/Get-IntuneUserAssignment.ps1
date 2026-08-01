function Get-IntuneUserAssignment {
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentRecord')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalNames,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagFilter,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    Write-Host "User selection chosen" -ForegroundColor Green

    # Get User Principal Names from parameter or prompt
    if ($UserPrincipalNames) {
        $upnInput = $UserPrincipalNames
    }
    else {
        # Prompt for one or more User Principal Names
        Write-Host "Please enter User Principal Name(s), separated by commas (,): " -ForegroundColor Cyan
        $upnInput = Read-Host
    }

    # Validate input
    if ([string]::IsNullOrWhiteSpace($upnInput)) {
        Write-Host "No UPN provided. Please try again with a valid UPN." -ForegroundColor Red
        return
    }

    $upns = $upnInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($upns.Count -eq 0) {
        Write-Host "No valid UPNs provided. Please try again with at least one valid UPN." -ForegroundColor Red
        return
    }

    # Validate UPN format
    $upnRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    $invalidUpns = @($upns | Where-Object { $_ -notmatch $upnRegex })
    if ($invalidUpns.Count -gt 0) {
        foreach ($badUpn in $invalidUpns) {
            Write-Host "Invalid UPN format: '$badUpn'. Expected: user@domain.com" -ForegroundColor Red
        }
        $upns = @($upns | Where-Object { $_ -match $upnRegex })
        if ($upns.Count -eq 0) {
            Write-Host "No valid UPNs remaining. Please try again." -ForegroundColor Red
            return
        }
    }

    $exportData = [System.Collections.ArrayList]::new()
    $passThruRecords = [System.Collections.Generic.List[object]]::new()

    # Renders one legacy three-column section (name/ID/assignment). The Device
    # Configurations and App Protection sections keep their bespoke extra column below.
    function Show-UserSectionTable {
        param(
            [string]$Title,
            [object[]]$Items,
            [string]$NameLabel,
            [string]$IdLabel,
            [scriptblock]$GetName,
            [string]$RedPattern = 'Excluded*'
        )
        if ($null -eq $Items -or $Items.Count -eq 0) { return }
        Write-Host "`n------- $Title -------" -ForegroundColor Cyan
        $headerFormat = "{0,-50} {1,-40} {2,-30}" -f $NameLabel, $IdLabel, "Assignment"
        $separator = Get-Separator
        Write-Host $separator
        Write-Host $headerFormat -ForegroundColor Yellow
        Write-Host $separator
        foreach ($item in $Items) {
            $name = & $GetName $item
            if ($name.Length -gt 47) { $name = $name.Substring(0, 44) + "..." }
            $id = $item.id
            if ($id.Length -gt 37) { $id = $id.Substring(0, 34) + "..." }
            $assignment = $item.AssignmentReason
            if ($assignment.Length -gt 27) { $assignment = $assignment.Substring(0, 24) + "..." }
            $rowFormat = "{0,-50} {1,-40} {2,-30}" -f $name, $id, $assignment
            if ($assignment -like $RedPattern) {
                Write-Host $rowFormat -ForegroundColor Red
            }
            else {
                Write-Host $rowFormat -ForegroundColor White
            }
        }
        Write-Host $separator
    }

    # Legacy per-section name resolution
    $nameFirst = { param($item) if ([string]::IsNullOrWhiteSpace($item.name)) { $item.displayName } else { $item.name } }
    $displayNameOnly = { param($item) $item.displayName }
    $profileNameFirst = { param($item) if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } elseif (-not [string]::IsNullOrWhiteSpace($item.name)) { $item.name } else { "Unnamed Profile" } }
    $policyNameFirst = { param($item) if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } elseif (-not [string]::IsNullOrWhiteSpace($item.name)) { $item.name } else { "Unnamed Policy" } }
    $settingNameFirst = { param($item) if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName } elseif (-not [string]::IsNullOrWhiteSpace($item.name)) { $item.name } else { "Unnamed Setting" } }

    $categories = Get-IntuneCategoryDefinition -Audience 'UserContext'
    # Shared across UPNs so each entity set is fetched from Graph once per run
    $entityCache = @{}
    $memberGroupIds = @()
    $appProgress = @{ Current = 0; Total = $null; FilteredTotal = $null }

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity

        switch ($ctx.Category.Kind) {
            'MobileApps' {
                if ($null -eq $appProgress.Total) {
                    $allCachedApps = @($entityCache[$ctx.Category.EntityType])
                    $appProgress.Total = $allCachedApps.Count
                    $appProgress.FilteredTotal = @($allCachedApps).Count
                }
                $appProgress.Current++
                Write-Host "`rFetching Application $($appProgress.Current) of $($appProgress.Total)" -NoNewline

                # Winning-assignment walk: an exclusion for one of the user's groups wins
                # immediately; otherwise the first inclusion (All Users or member group) wins.
                $isExcluded = $false
                $isIncluded = $false
                $winningAssignment = $null
                foreach ($assignment in $ctx.RawAssignments) {
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and
                        $memberGroupIds -contains $assignment.target.groupId) {
                        $isExcluded = $true
                        $winningAssignment = $assignment
                        break
                    }
                    elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' -or
                        ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                        $memberGroupIds -contains $assignment.target.groupId)) {
                        if (-not $isIncluded) { $winningAssignment = $assignment }
                        $isIncluded = $true
                    }
                }

                if ($isIncluded -or $isExcluded) {
                    $filterSuffix = Format-AssignmentFilter `
                        -FilterId $winningAssignment.target.deviceAndAppManagementAssignmentFilterId `
                        -FilterType $winningAssignment.target.deviceAndAppManagementAssignmentFilterType
                    # Excluded apps stay visible in the intent bucket of the excluding assignment
                    $reasonText = if ($isExcluded) { "Excluded$filterSuffix" } else { "Included$filterSuffix" }
                    $appWithReason = $entity.PSObject.Copy()
                    $appWithReason | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reasonText -Force
                    switch ($winningAssignment.intent) {
                        "required" { $ctx.Buckets['AppsRequired'].Add($appWithReason) }
                        "available" { $ctx.Buckets['AppsAvailable'].Add($appWithReason) }
                        "uninstall" { $ctx.Buckets['AppsUninstall'].Add($appWithReason) }
                    }
                }

                if ($appProgress.Current -eq $appProgress.FilteredTotal) {
                    # Legacy final overwrite before the next category header
                    Write-Host "`rFetching Application $($appProgress.Total) of $($appProgress.Total)"
                }
            }
            'AppProtection' {
                # Only All Users targets and groups the user is actually a member of count
                $matchingAssignments = @($ctx.Assignments | Where-Object {
                        $_.Reason -eq 'All Users' -or
                        ($_.Reason -in @('Group Assignment', 'Group Exclusion') -and $memberGroupIds -contains $_.GroupId)
                    })
                if ($matchingAssignments.Count -gt 0) {
                    $assignmentSummary = $matchingAssignments | ForEach-Object { Format-AssignmentSummaryLine -Assignment $_ }
                    $entity | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($assignmentSummary -join "; ") -Force
                    $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
                }
            }
            'EndpointSecurity' {
                $assignments = $ctx.Assignments
                if ($null -ne $ctx.RawAssignments) {
                    # Intent-phase detail rows historically carried no filter info, so the
                    # resolved reason gets no filter suffix (unlike the config-policy phase)
                    $assignments = @($assignments | ForEach-Object { [PSCustomObject]@{ Reason = $_.Reason; GroupId = $_.GroupId } })
                }
                $reason = Resolve-AssignmentReason -Assignments $assignments -GroupMembershipIds $memberGroupIds -IncludeReasons @("All Users")
                if ($reason) {
                    $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
                }
            }
            default {
                if ($ctx.Category.Id -in @('CloudPCProvisioningPolicies', 'CloudPCUserSettings')) {
                    # Legacy Cloud PC walk: the first matching assignment wins in raw order
                    foreach ($assignment in $ctx.Assignments) {
                        if ($assignment.Reason -eq "All Users" -or
                            ($assignment.Reason -eq "Group Assignment" -and $memberGroupIds -contains $assignment.GroupId)) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "$($assignment.Reason)$suffix" -Force
                            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
                            break
                        }
                        elseif ($assignment.Reason -eq "Group Exclusion" -and $memberGroupIds -contains $assignment.GroupId) {
                            $suffix = Format-AssignmentFilter -FilterId $assignment.FilterId -FilterType $assignment.FilterType
                            $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue "Excluded$suffix" -Force
                            $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
                            break
                        }
                    }
                    return
                }
                $reason = Resolve-AssignmentReason -Assignments $ctx.Assignments -GroupMembershipIds $memberGroupIds -IncludeReasons @("All Users")
                if ($reason) {
                    $entity | Add-Member -NotePropertyName 'AssignmentReason' -NotePropertyValue $reason -Force
                    $ctx.Buckets[$ctx.Category.BucketKeys[0]].Add($entity)
                }
            }
        }
    }

    foreach ($upn in $upns) {
        Write-Host "Checking following UPN: $upn" -ForegroundColor Yellow

        # Get User Info
        $userInfo = Get-UserInfo -UserPrincipalName $upn
        if (-not $userInfo.Success) {
            Write-Host "User not found: $upn" -ForegroundColor Red
            Write-Host "Please verify the User Principal Name is correct." -ForegroundColor Yellow
            continue
        }

        # Get User Group Memberships
        try {
            $groupMemberships = Get-GroupMemberships -ObjectId $userInfo.Id -ObjectType "User"
            Write-Host "User Group Memberships: $($groupMemberships.displayName -join ', ')" -ForegroundColor Green
        }
        catch {
            Write-Host "Error fetching group memberships for user: $upn" -ForegroundColor Red
            Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        Write-Host "Fetching Intune Profiles and Applications for the user..." -ForegroundColor Yellow

        $memberGroupIds = @($groupMemberships.id)
        $appProgress = @{ Current = 0; Total = $null; FilteredTotal = $null }

        $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -ShowProgress -EntityCache $entityCache -BuildRecords:$PassThru
        $relevantPolicies = $scanResult.Buckets

        # Apply scope tag filter if specified
        if ($ScopeTagFilter) {
            foreach ($key in @($relevantPolicies.Keys)) {
                $relevantPolicies[$key] = @(Filter-ByScopeTag -Items $relevantPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
            }
        }

        if ($PassThru) {
            $selectedRecords = @(Select-IACAssignmentRecord -Records $scanResult.Records -Buckets $relevantPolicies `
                    -TargetTypes @('AllUsers', 'Group') -GroupIds $memberGroupIds `
                    -SubjectType 'User' -SubjectId $userInfo.Id -SubjectName $upn -Source 'Get-IntuneUserAssignment')
            foreach ($record in $selectedRecords) { $passThruRecords.Add($record) }
        }

        # Display results
        Write-Host "`nAssignments for User: $upn" -ForegroundColor Green

        # Calculate category summary
        $categoryNames = @('DeviceConfigs', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies', 'AppProtectionPolicies', 'AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'AppsRequired', 'AppsAvailable', 'AppsUninstall', 'AntivirusProfiles', 'DiskEncryptionProfiles', 'FirewallProfiles', 'EndpointDetectionProfiles', 'AttackSurfaceProfiles', 'AccountProtectionProfiles', 'CloudPCProvisioningPolicies', 'CloudPCUserSettings')
        $nonEmptyCount = ($categoryNames | Where-Object { $relevantPolicies[$_].Count -gt 0 }).Count
        $totalDisplayCategories = $categoryNames.Count
        Write-Host "`nFound assignments in $nonEmptyCount of $totalDisplayCategories categories." -ForegroundColor Cyan

        # Display Device Configurations (bespoke four-column table with Platform)
        if ($relevantPolicies.DeviceConfigs.Count -gt 0) {
            Write-Host "`n------- Device Configurations -------" -ForegroundColor Cyan
            $headerFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f "Configuration Name", "Platform", "Configuration ID", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator
            foreach ($config in $relevantPolicies.DeviceConfigs) {
                $configName = if ([string]::IsNullOrWhiteSpace($config.name)) { $config.displayName } else { $config.name }
                if ($configName.Length -gt 42) { $configName = $configName.Substring(0, 39) + "..." }
                $platform = Get-PolicyPlatform -Policy $config
                if ($platform.Length -gt 17) { $platform = $platform.Substring(0, 14) + "..." }
                $configId = $config.id
                if ($configId.Length -gt 32) { $configId = $configId.Substring(0, 29) + "..." }
                $assignment = $config.AssignmentReason
                if ($assignment.Length -gt 17) { $assignment = $assignment.Substring(0, 14) + "..." }
                $rowFormat = "{0,-45} {1,-20} {2,-35} {3,-20}" -f $configName, $platform, $configId, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        Show-UserSectionTable -Title 'Imported Administrative Templates' -Items @($relevantPolicies.ImportedAdministrativeTemplates) -NameLabel 'Policy Name' -IdLabel 'Policy ID' -GetName $displayNameOnly
        Show-UserSectionTable -Title 'Settings Catalog Policies' -Items @($relevantPolicies.SettingsCatalog) -NameLabel 'Policy Name' -IdLabel 'Policy ID' -GetName $nameFirst
        Show-UserSectionTable -Title 'Compliance Policies' -Items @($relevantPolicies.CompliancePolicies) -NameLabel 'Policy Name' -IdLabel 'Policy ID' -GetName $nameFirst

        # Display App Protection Policies (bespoke four-column table with Type; the legacy
        # table reads AssignmentReason, which this category never sets, so the column stays blank)
        if ($relevantPolicies.AppProtectionPolicies.Count -gt 0) {
            Write-Host "`n------- App Protection Policies -------" -ForegroundColor Cyan
            $headerFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f "Policy Name", "Policy ID", "Type", "Assignment"
            $separator = Get-Separator
            Write-Host $separator
            Write-Host $headerFormat -ForegroundColor Yellow
            Write-Host $separator
            foreach ($policy in $relevantPolicies.AppProtectionPolicies) {
                $policyName = $policy.displayName
                if ($policyName.Length -gt 37) { $policyName = $policyName.Substring(0, 34) + "..." }
                $policyId = $policy.id
                if ($policyId.Length -gt 27) { $policyId = $policyId.Substring(0, 24) + "..." }
                $policyType = switch ($policy.'@odata.type') {
                    "#microsoft.graph.androidManagedAppProtection" { "Android" }
                    "#microsoft.graph.iosManagedAppProtection" { "iOS" }
                    "#microsoft.graph.windowsManagedAppProtection" { "Windows" }
                    default { "Unknown" }
                }
                $assignment = $policy.AssignmentReason
                if ($assignment.Length -gt 27) { $assignment = $assignment.Substring(0, 24) + "..." }
                $rowFormat = "{0,-40} {1,-30} {2,-20} {3,-30}" -f $policyName, $policyId, $policyType, $assignment
                if ($assignment -like "Excluded*") {
                    Write-Host $rowFormat -ForegroundColor Red
                }
                else {
                    Write-Host $rowFormat -ForegroundColor White
                }
            }
            Write-Host $separator
        }

        # Remaining sections in the legacy display order. App rows keep the legacy
        # "*Exclusion*" red-row pattern, which never matches "Excluded..." reasons.
        $displaySections = @(
            @{ Title = 'App Configuration Policies'; Bucket = 'AppConfigurationPolicies'; NameLabel = 'Policy Name'; IdLabel = 'Policy ID'; GetName = $nameFirst }
            @{ Title = 'Platform Scripts'; Bucket = 'PlatformScripts'; NameLabel = 'Script Name'; IdLabel = 'Script ID'; GetName = $nameFirst }
            @{ Title = 'Proactive Remediation Scripts'; Bucket = 'HealthScripts'; NameLabel = 'Script Name'; IdLabel = 'Script ID'; GetName = $nameFirst }
            @{ Title = 'Required Apps'; Bucket = 'AppsRequired'; NameLabel = 'App Name'; IdLabel = 'App ID'; GetName = $displayNameOnly; RedPattern = '*Exclusion*' }
            @{ Title = 'Available Apps'; Bucket = 'AppsAvailable'; NameLabel = 'App Name'; IdLabel = 'App ID'; GetName = $displayNameOnly; RedPattern = '*Exclusion*' }
            @{ Title = 'Uninstall Apps'; Bucket = 'AppsUninstall'; NameLabel = 'App Name'; IdLabel = 'App ID'; GetName = $displayNameOnly; RedPattern = '*Exclusion*' }
            @{ Title = 'Endpoint Security - Antivirus Profiles'; Bucket = 'AntivirusProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Endpoint Security - Disk Encryption Profiles'; Bucket = 'DiskEncryptionProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Endpoint Security - Firewall Profiles'; Bucket = 'FirewallProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Endpoint Security - Endpoint Detection and Response Profiles'; Bucket = 'EndpointDetectionProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Endpoint Security - Attack Surface Reduction Profiles'; Bucket = 'AttackSurfaceProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Endpoint Security - Account Protection Profiles'; Bucket = 'AccountProtectionProfiles'; NameLabel = 'Profile Name'; IdLabel = 'Profile ID'; GetName = $profileNameFirst }
            @{ Title = 'Windows 365 Cloud PC Provisioning Policies'; Bucket = 'CloudPCProvisioningPolicies'; NameLabel = 'Policy Name'; IdLabel = 'Policy ID'; GetName = $policyNameFirst }
            @{ Title = 'Windows 365 Cloud PC User Settings'; Bucket = 'CloudPCUserSettings'; NameLabel = 'Setting Name'; IdLabel = 'Setting ID'; GetName = $settingNameFirst }
        )
        foreach ($section in $displaySections) {
            $sectionParams = @{
                Title     = $section.Title
                Items     = @($relevantPolicies[$section.Bucket])
                NameLabel = $section.NameLabel
                IdLabel   = $section.IdLabel
                GetName   = $section.GetName
            }
            if ($section.RedPattern) { $sectionParams.RedPattern = $section.RedPattern }
            Show-UserSectionTable @sectionParams
        }

        # Add all data to export: the User row first, then categories in the legacy CSV order
        # (Endpoint Security after the Windows 365 categories, the app buckets last).
        Add-ExportData -ExportData $exportData -Category "User" -Items @([PSCustomObject]@{
                displayName      = $upn
                id               = $userInfo.Id
                AssignmentReason = "N/A"
            })

        $reasonProperty = { param($item) $item.AssignmentReason }
        $exportBatches = @(
            @{ Ids = @('DeviceConfigurations', 'ImportedAdministrativeTemplates', 'SettingsCatalog', 'CompliancePolicies'); Reason = $reasonProperty }
            # App Protection rows export the AssignmentSummary built during the scan
            @{ Ids = @('AppProtectionPolicies'); Reason = { param($item) $item.AssignmentSummary } }
            @{ Ids = @('AppConfigurationPolicies', 'PlatformScripts', 'HealthScripts', 'DeploymentProfiles', 'ESPProfiles',
                    'CloudPCProvisioningPolicies', 'CloudPCUserSettings', 'ESAntivirus', 'ESDiskEncryption', 'ESFirewall',
                    'ESEndpointDetection', 'ESAttackSurface', 'ESAccountProtection', 'Applications'); Reason = $reasonProperty }
        )
        foreach ($batch in $exportBatches) {
            $batchCategories = foreach ($id in $batch.Ids) { $categories | Where-Object { $_.Id -eq $id } }
            Add-CategoryExportData -ExportData $exportData -Categories $batchCategories -Buckets $relevantPolicies -AssignmentReason $batch.Reason
        }
    }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneUserAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:($parameterMode -or $PassThru)
    if ($PassThru) { $passThruRecords }
}
