#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'Get-Separator.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentFilter.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentSummaryLine.ps1')
    . (Join-Path $modulePrivate 'Resolve-AssignmentReason.ps1')
    . (Join-Path $modulePrivate 'Test-PlatformCompatibility.ps1')
    . (Join-Path $modulePrivate 'Test-AppPlatformCompatibility.ps1')
    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Select-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Add-CategoryExportData.ps1')
    . (Join-Path $moduleRoot 'Public/Get-IntuneDeviceAssignment.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{ 'filter-1' = @{ Name = 'Test Filter' } }

    # Stub collaborators so Pester can mock them per test
    function Get-IntuneEntities {
        param([string]$EntityType, [string]$Filter, [string]$Select, [string]$Expand, [switch]$Quiet)
        @()
    }
    function Get-IntuneAssignments {
        param([string]$EntityType, [string]$EntityId, [string]$GroupId, [string[]]$GroupIds = @())
        @()
    }
    function Add-IntentTemplateFamilyInfo {
        param($IntentPolicies)
    }
    function Invoke-IACGraphRequest {
        param($Uri, $Method)
        @{ value = @() }
    }
    function Get-GroupInfo {
        param([string]$GroupId)
        @{ Id = $GroupId; DisplayName = 'Group One'; Success = $true }
    }
    function Get-DeviceInfo {
        param([string]$DeviceName)
        @{ Id = $null; DisplayName = $DeviceName; OperatingSystem = $null; Success = $false; MultipleFound = $false; AllDevices = $null }
    }
    function Get-GroupMemberships {
        param([string]$ObjectId, [string]$ObjectType)
        @()
    }
    function Filter-ByScopeTag {
        param($Items, $FilterTag, $ScopeTagLookup)
        $Items
    }
    function Export-ResultsIfRequested {
        param([System.Collections.ArrayList]$ExportData, [string]$DefaultFileName, [switch]$ForceExport, [string]$CustomExportPath, [switch]$ExportToCSV, [switch]$ParameterMode)
    }
}

Describe 'Get-IntuneDeviceAssignment' {
    BeforeEach {
        $script:memberGroupId = '11111111-1111-1111-1111-111111111111'
        $script:capturedExport = $null
        $script:consoleLines = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $script:consoleLines.Add("$Object") }
        Mock Get-IntuneEntities { @() }
        Mock Get-IntuneAssignments { @() }
        Mock Add-IntentTemplateFamilyInfo {}
        Mock Get-GroupInfo { @{ Id = $GroupId; DisplayName = 'Group One'; Success = $true } }
        Mock Get-DeviceInfo {
            $os = if ($DeviceName -like 'MAC*') { 'macOS' } else { 'Windows' }
            @{ Id = "dev-$DeviceName"; DisplayName = $DeviceName; OperatingSystem = $os; Success = $true; MultipleFound = $false; AllDevices = $null }
        }
        Mock Get-GroupMemberships { @([PSCustomObject]@{ id = $script:memberGroupId; displayName = 'Group One' }) }
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Invoke-IACGraphRequest { @{ value = @() } }
    }

    It 'exports the Device row first' {
        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $script:capturedExport[0].Category | Should -BeExactly 'Device'
        $script:capturedExport[0].Item | Should -BeExactly 'PC-1 (ID: dev-PC-1)'
        $script:capturedExport[0].AssignmentReason | Should -BeExactly 'N/A'
    }

    It 'renders all display sections in order with device-specific empty messages' {
        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $sectionTitles = @($script:consoleLines | Where-Object { $_ -match '^------- (.+) -------$' } | ForEach-Object { $Matches[1] })
        $sectionTitles | Should -Be @(
            'Device Configurations', 'Imported Administrative Templates', 'Settings Catalog Policies', 'Compliance Policies', 'App Protection Policies',
            'App Configuration Policies', 'Platform Scripts', 'Proactive Remediation Scripts',
            'Autopilot Deployment Profiles', 'Enrollment Status Page Profiles',
            'Required Apps', 'Available Apps', 'Uninstall Apps',
            'Endpoint Security - Antivirus Profiles', 'Endpoint Security - Disk Encryption Profiles',
            'Endpoint Security - Firewall Profiles', 'Endpoint Security - EDR Profiles',
            'Endpoint Security - ASR Profiles', 'Endpoint Security - Account Protection Profiles',
            'Windows Feature Update Profiles', 'Windows Quality Update Profiles',
            'Windows Driver Update Profiles', 'Windows Quality Update Policies')
        $script:consoleLines | Should -Contain 'No Device Configurations found for this device.'
    }

    It 'resolves reasons for member groups and All Devices and drops other-platform policies' {
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                return @(
                    [PSCustomObject]@{ id = 'cfg-win'; displayName = 'Win Config'; '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration' }
                    [PSCustomObject]@{ id = 'cfg-ios'; displayName = 'iOS Config'; '@odata.type' = '#microsoft.graph.iosGeneralDeviceConfiguration' }
                    [PSCustomObject]@{ id = 'cfg-excl'; displayName = 'Excluded Config'; '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration' }
                )
            }
            @()
        }
        Mock Get-IntuneAssignments {
            switch ($EntityId) {
                'cfg-win' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = $script:memberGroupId; FilterId = 'filter-1'; FilterType = 'include' }) }
                'cfg-ios' { @([PSCustomObject]@{ Reason = 'All Devices'; GroupId = $null; FilterId = $null; FilterType = $null }) }
                'cfg-excl' { @([PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = $script:memberGroupId; FilterId = $null; FilterType = $null }) }
                default { @() }
            }
        }

        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $rows = @($script:capturedExport | Where-Object { $_.Category -eq 'Device Configuration' })
        $rows.Count | Should -Be 2
        $rows[0].Item | Should -BeExactly 'Win Config (ID: cfg-win)'
        $rows[0].AssignmentReason | Should -BeExactly 'Group Assignment (Filter: Test Filter [Include])'
        $rows[1].AssignmentReason | Should -BeExactly 'Excluded'
        # The iOS-only policy must be dropped for a Windows device
        @($rows | Where-Object { $_.Item -like '*cfg-ios*' }).Count | Should -Be 0
    }

    It 'gives an imported template group exclusion precedence over an earlier inclusion' {
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'groupPolicyConfigurations') {
                return @([PSCustomObject]@{
                        id = 'iat-conflict'
                        displayName = 'Imported Conflict Policy'
                        policyConfigurationIngestionType = 'custom'
                    })
            }
            @()
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'iat-conflict') {
                return @(
                    [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = $script:memberGroupId; FilterId = $null; FilterType = $null }
                    [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = $script:memberGroupId; FilterId = $null; FilterType = $null }
                )
            }
            @()
        }

        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $row = @($script:capturedExport | Where-Object { $_.Category -eq 'Imported Administrative Template' })
        $row | Should -HaveCount 1
        $row[0].AssignmentReason | Should -BeExactly 'Excluded'
    }

    Context 'applications' {
        BeforeEach {
            Mock Invoke-IACGraphRequest {
                if ($Uri -like '*mobileApps?*isAssigned*') {
                    return @{ value = @(
                            @{ id = 'app-f14'; displayName = 'F14 App'; isFeatured = $false; isBuiltIn = $false; '@odata.type' = '#microsoft.graph.win32LobApp' }
                            @{ id = 'app-excl'; displayName = 'Excluded App'; isFeatured = $false; isBuiltIn = $false; '@odata.type' = '#microsoft.graph.win32LobApp' }
                            @{ id = 'app-ios'; displayName = 'iOS App'; isFeatured = $false; isBuiltIn = $false; '@odata.type' = '#microsoft.graph.iosStoreApp' }
                        )
                    }
                }
                if ($Uri -like "*mobileApps('app-f14')/assignments*") {
                    # F14 fixture: intent comes from the first inclusion assignment (available),
                    # the reason text from the last matching one (member group assignment)
                    return @{ value = @(
                            @{ intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = 'filter-1'; deviceAndAppManagementAssignmentFilterType = 'include' } }
                            @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:memberGroupId } }
                        )
                    }
                }
                if ($Uri -like "*mobileApps('app-excl')/assignments*") {
                    return @{ value = @(
                            @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:memberGroupId } }
                            @{ intent = 'uninstall'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $script:memberGroupId } }
                        )
                    }
                }
                return @{ value = @() }
            }
        }

        It 'buckets a multi-assignment app by the first inclusion intent with the last inclusion reason (F14)' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

            $availableRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Available Apps' })
            $availableRows.Count | Should -Be 1
            $availableRows[0].Item | Should -BeExactly 'F14 App (ID: app-f14)'
            $availableRows[0].AssignmentReason | Should -BeExactly 'Group Assignment - Group One (Filter: Test Filter [Include])'
            @($script:capturedExport | Where-Object { $_.Category -eq 'Required Apps' -and $_.Item -like '*app-f14*' }).Count | Should -Be 0
        }

        It 'shows excluded apps under the excluding assignment intent' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

            $uninstallRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Uninstall Apps' })
            $uninstallRows.Count | Should -Be 1
            $uninstallRows[0].Item | Should -BeExactly 'Excluded App (ID: app-excl)'
            $uninstallRows[0].AssignmentReason | Should -BeExactly 'Excluded via group: Group One'
        }

        It 'never fetches assignments for apps of another platform' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

            Should -Invoke Invoke-IACGraphRequest -Times 0 -ParameterFilter { $Uri -like "*mobileApps('app-ios')*" }
            @($script:capturedExport | Where-Object { $_.Item -like '*app-ios*' }).Count | Should -Be 0
        }
    }

    It 'keeps App Protection policies only when the device is targeted and drops All Users targets' {
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceAppManagement/managedAppPolicies') {
                return @(
                    [PSCustomObject]@{ id = 'mam-member'; displayName = 'Member MAM'; '@odata.type' = '#microsoft.graph.windowsManagedAppProtection' }
                    [PSCustomObject]@{ id = 'mam-other'; displayName = 'Nonmember MAM'; '@odata.type' = '#microsoft.graph.windowsManagedAppProtection' }
                    [PSCustomObject]@{ id = 'mam-android'; displayName = 'Android MAM'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection' }
                )
            }
            @()
        }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like "*windowsManagedAppProtections('mam-member')/assignments*") {
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:memberGroupId } }
                    )
                }
            }
            if ($Uri -like "*windowsManagedAppProtections('mam-other')/assignments*") {
                return @{ value = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'not-a-member' } }) }
            }
            return @{ value = @() }
        }

        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $rows = @($script:capturedExport | Where-Object { $_.Category -eq 'App Protection Policy' })
        $rows.Count | Should -Be 1
        $rows[0].Item | Should -BeExactly 'Member MAM (ID: mam-member)'
        $rows[0].AssignmentReason | Should -BeExactly 'Group Assignment - Group One'
        # Platform-incompatible policies never trigger an assignment fetch
        Should -Invoke Invoke-IACGraphRequest -Times 0 -ParameterFilter { $Uri -like '*androidManagedAppProtections*' }
    }

    It 'surfaces Endpoint Security policies from both configurationPolicies and intents' {
        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'configurationPolicies' {
                    return @([PSCustomObject]@{ id = 'av-1'; name = 'AV Policy'; platforms = @('windows10'); technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityAntivirus' } })
                }
                'deviceManagement/intents' {
                    return @([PSCustomObject]@{ id = 'av-int-1'; displayName = 'AV Intent'; templateId = 'tmpl-av'; templateReference = @{ templateFamily = 'endpointSecurityAntivirus' } })
                }
                default { return @() }
            }
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'av-1') { return @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = $script:memberGroupId; FilterId = $null; FilterType = $null }) }
            @()
        }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*intents/av-int-1/assignments*') {
                return @{ value = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }
            }
            return @{ value = @() }
        }

        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        $rows = @($script:capturedExport | Where-Object { $_.Category -eq 'Endpoint Security - Antivirus' })
        $rows.Count | Should -Be 2
        $rows[0].Item | Should -BeExactly 'AV Policy (ID: av-1)'
        $rows[0].AssignmentReason | Should -BeExactly 'Group Assignment'
        $rows[1].Item | Should -BeExactly 'AV Intent (ID: av-int-1)'
        $rows[1].AssignmentReason | Should -BeExactly 'All Devices'
    }

    Context 'Windows-conditional categories' {
        It 'fetches Imported Administrative Templates, Autopilot, ESP and Windows 365 categories for a Windows device' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

            foreach ($windowsEntityType in @('groupPolicyConfigurations', 'windowsAutopilotDeploymentProfiles', 'deviceEnrollmentConfigurations', 'virtualEndpoint/provisioningPolicies', 'virtualEndpoint/userSettings')) {
                Should -Invoke Get-IntuneEntities -Exactly -Times 1 -ParameterFilter { $EntityType -eq $windowsEntityType }
            }
        }

        It 'never fetches Imported Administrative Templates, Autopilot, ESP or Windows 365 categories for a macOS device' {
            Get-IntuneDeviceAssignment -DeviceNames 'MAC-1'

            foreach ($windowsEntityType in @('groupPolicyConfigurations', 'windowsAutopilotDeploymentProfiles', 'deviceEnrollmentConfigurations', 'virtualEndpoint/provisioningPolicies', 'virtualEndpoint/userSettings')) {
                Should -Invoke Get-IntuneEntities -Times 0 -ParameterFilter { $EntityType -eq $windowsEntityType }
            }
        }
    }

    Context 'multiple devices' {
        It 'processes every device from a comma-separated parameter' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1,PC-2'

            $deviceRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Device' })
            $deviceRows.Count | Should -Be 2
            $deviceRows[0].Item | Should -BeExactly 'PC-1 (ID: dev-PC-1)'
            $deviceRows[1].Item | Should -BeExactly 'PC-2 (ID: dev-PC-2)'
        }

        It 'fetches each entity set once for the whole run (shared entity cache)' {
            Get-IntuneDeviceAssignment -DeviceNames 'PC-1,PC-2'

            Should -Invoke Get-IntuneEntities -Exactly -Times 1 -ParameterFilter { $EntityType -eq 'configurationPolicies' }
            Should -Invoke Get-IntuneEntities -Exactly -Times 1 -ParameterFilter { $EntityType -eq 'deviceManagement/intents' }
            Should -Invoke Invoke-IACGraphRequest -Exactly -Times 1 -ParameterFilter { $Uri -like '*mobileApps?*isAssigned*' }
        }
    }

    It 'exports categories in the legacy CSV order' {
        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'deviceConfigurations' { return @([PSCustomObject]@{ id = 'cfg-1'; displayName = 'Cfg'; '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration' }) }
                'windowsAutopilotDeploymentProfiles' { return @([PSCustomObject]@{ id = 'ap-1'; displayName = 'AP' }) }
                'virtualEndpoint/provisioningPolicies' { return @([PSCustomObject]@{ id = 'cpc-1'; displayName = 'CPC' }) }
                'configurationPolicies' { return @([PSCustomObject]@{ id = 'av-1'; name = 'AV'; platforms = @('windows10'); technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityAntivirus' } }) }
                default { return @() }
            }
        }
        Mock Get-IntuneAssignments { @([PSCustomObject]@{ Reason = 'All Devices'; GroupId = $null; FilterId = $null; FilterType = $null }) }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*mobileApps?*isAssigned*') {
                return @{ value = @(@{ id = 'app-1'; displayName = 'App'; isFeatured = $false; isBuiltIn = $false; '@odata.type' = '#microsoft.graph.win32LobApp' }) }
            }
            if ($Uri -like "*mobileApps('app-1')/assignments*") {
                return @{ value = @(@{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }
            }
            return @{ value = @() }
        }

        Get-IntuneDeviceAssignment -DeviceNames 'PC-1'

        # Autopilot before Endpoint Security, Windows 365 after it, app buckets last
        $categorySequence = @($script:capturedExport | ForEach-Object { $_.Category })
        $categorySequence | Should -Be @('Device', 'Device Configuration', 'Settings Catalog Policy', 'Autopilot Deployment Profile',
            'Endpoint Security - Antivirus', 'Windows 365 Cloud PC Provisioning Policy', 'Required Apps')
    }
}
