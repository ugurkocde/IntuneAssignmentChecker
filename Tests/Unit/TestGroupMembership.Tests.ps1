#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'ConvertTo-IntuneGroupInfo.ps1')
    . (Join-Path $modulePrivate 'Get-Separator.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentFilter.ps1')
    . (Join-Path $modulePrivate 'Resolve-AssignmentReason.ps1')
    . (Join-Path $modulePrivate 'Resolve-SimulatedAssignmentDelta.ps1')
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Get-IACNoAssignmentPlaceholder.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $moduleRoot 'Public/Test-IntuneGroupMembership.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{}

    # Stub collaborators so Pester can mock them per test
    function Get-UserInfo {
        param([string]$UserPrincipalName)
        @{ Id = $null; UserPrincipalName = $UserPrincipalName; Success = $false }
    }
    function Get-DeviceInfo {
        param([string]$DeviceName)
        @{ Id = $null; DisplayName = $DeviceName; Success = $false; MultipleFound = $false; AllDevices = @() }
    }
    function Get-GroupMemberships {
        param([string]$ObjectId, [string]$ObjectType)
        @()
    }
    function Get-GroupInfo {
        param([string]$GroupId)
        @{ Id = $GroupId; DisplayName = 'Target Group'; Success = $true }
    }
    function Get-TransitiveGroupMembership {
        param([string]$GroupId)
        @()
    }
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
    function Filter-ByScopeTag {
        param($Items, $FilterTag, $ScopeTagLookup)
        $Items
    }
    function Export-ResultsIfRequested {
        param([System.Collections.ArrayList]$ExportData, [string]$DefaultFileName, [switch]$ForceExport, [string]$CustomExportPath, [switch]$ExportToCSV, [switch]$ParameterMode)
    }
}

Describe 'Test-IntuneGroupMembership' {
    BeforeEach {
        $script:capturedExport = $null
        $script:hostLines = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { if ($null -ne $Object) { $script:hostLines.Add([string]$Object) } }
        Mock Start-Sleep {}
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Get-UserInfo {
            if ($UserPrincipalName -eq 'user1@contoso.com') { @{ Id = 'u1'; UserPrincipalName = $UserPrincipalName; Success = $true } }
            else { @{ Id = $null; UserPrincipalName = $UserPrincipalName; Success = $false } }
        }
        Mock Get-DeviceInfo {
            if ($DeviceName -eq 'DEV1') { @{ Id = 'd1'; DisplayName = 'DEV1'; Success = $true; MultipleFound = $false; AllDevices = @() } }
            else { @{ Id = $null; DisplayName = $DeviceName; Success = $false; MultipleFound = $false; AllDevices = @() } }
        }
        Mock Get-GroupMemberships {
            switch ($ObjectType) {
                'User' { @([PSCustomObject]@{ id = 'g-cur'; displayName = 'Current Group' }) }
                'Device' { @([PSCustomObject]@{ id = 'g-dev'; displayName = 'Device Group' }) }
                default { @() }
            }
        }
        Mock Get-TransitiveGroupMembership { @() }
        Mock Add-IntentTemplateFamilyInfo {
            foreach ($intent in $IntentPolicies) {
                if ($intent.id -eq 'av-intent') {
                    $intent | Add-Member -NotePropertyName 'templateReference' -NotePropertyValue ([PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' }) -Force
                }
            }
        }
        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'deviceConfigurations' {
                    @(
                        [PSCustomObject]@{ id = 'dc-new'; displayName = 'New Config' }
                        [PSCustomObject]@{ id = 'dc-cur'; displayName = 'Current Config' }
                        [PSCustomObject]@{ id = 'dc-allusers'; displayName = 'All Users Config' }
                        [PSCustomObject]@{ id = 'dc-alldev'; displayName = 'All Devices Config' }
                        [PSCustomObject]@{ id = 'dc-conflict'; displayName = 'Conflict Config' }
                        [PSCustomObject]@{ id = 'dc-devconflict'; displayName = 'Device Conflict Config' }
                    )
                }
                'configurationPolicies' {
                    @([PSCustomObject]@{ id = 'av-cfg'; name = 'AV Config Policy'; templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' } })
                }
                'deviceAppManagement/managedAppPolicies' {
                    @(
                        [PSCustomObject]@{ id = 'apppol-new'; displayName = 'AP New'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection' }
                        [PSCustomObject]@{ id = 'apppol-alldev'; displayName = 'AP AllDev'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection' }
                    )
                }
                'deviceManagement/intents' {
                    @([PSCustomObject]@{ id = 'av-intent'; displayName = 'AV Intent Legacy' })
                }
                default { @() }
            }
        }
        Mock Get-IntuneAssignments {
            switch ($EntityId) {
                'dc-new' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }) }
                'dc-cur' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-cur'; FilterId = $null; FilterType = $null }) }
                'dc-allusers' { @([PSCustomObject]@{ Reason = 'All Users'; GroupId = $null; FilterId = $null; FilterType = $null }) }
                'dc-alldev' { @([PSCustomObject]@{ Reason = 'All Devices'; GroupId = $null; FilterId = $null; FilterType = $null }) }
                'dc-conflict' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = 'g-cur'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }
                    )
                }
                'dc-devconflict' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = 'g-dev'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }
                    )
                }
                'av-cfg' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }) }
                default { @() }
            }
        }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*beta/groups?*') {
                return @{ value = @([PSCustomObject]@{ id = 'g-target'; displayName = 'Target Group' }) }
            }
            if ($Uri -like '*mobileApps?*isAssigned*') {
                return @{ value = @(
                        [PSCustomObject]@{ id = 'app-new'; displayName = 'New App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-conflict'; displayName = 'Conflict App'; isFeatured = $false; isBuiltIn = $false }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-new')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-target' } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-conflict')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g-cur' } }
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-target' } }
                    )
                }
            }
            if ($Uri -like "*androidManagedAppProtections('apppol-new')/assignments*") {
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-target' } }
                    )
                }
            }
            if ($Uri -like "*androidManagedAppProtections('apppol-alldev')/assignments*") {
                # Legacy App Protection walk never mapped All Devices targets
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
                    )
                }
            }
            if ($Uri -like '*deviceManagement/intents/av-intent/assignments*') {
                # Filter fields present on the target, but the legacy intent rows carried
                # Reason/GroupId only, so the delta reason must have no filter suffix
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-target'; deviceAndAppManagementAssignmentFilterId = 'f1'; deviceAndAppManagementAssignmentFilterType = 'include' } }
                    )
                }
            }
            return @{ value = @() }
        }
    }

    It 'exports the Simulation Info row first with the legacy subject label' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $script:capturedExport[0].Category | Should -BeExactly 'Simulation Info'
        $script:capturedExport[0].Item | Should -BeExactly "User 'user1@contoso.com' -> Group: Target Group (ID: g-target)"
        $script:capturedExport[0].AssignmentReason | Should -BeExactly 'Impact Analysis'
    }

    It 'reports policies gained via the target group as NEW and drops already-received policies' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $configRows = @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: Device Configuration' })
        @($configRows | Where-Object { $_.Item -eq 'New Config (ID: dc-new)' -and $_.AssignmentReason -eq 'Group Assignment' }).Count | Should -Be 1
        # Already received via another group or All Users: not part of the delta
        @($script:capturedExport | Where-Object { $_.Item -like '*dc-cur*' }).Count | Should -Be 0
        @($script:capturedExport | Where-Object { $_.Item -like '*dc-allusers*' }).Count | Should -Be 0
    }

    It 'reports exclusion conflicts with the legacy category label and wording' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $conflictRows = @($script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Device Configuration' })
        $conflictRows.Count | Should -Be 1
        $conflictRows[0].Item | Should -BeExactly 'Conflict Config (ID: dc-conflict)'
        $conflictRows[0].AssignmentReason | Should -BeExactly 'Currently excluded; target group includes it'
    }

    It 'runs device-only against device memberships and never treats All Devices targets as new' {
        Test-IntuneGroupMembership -DeviceNames 'DEV1' -SimulateTargetGroup 'Target Group'

        $script:capturedExport[0].Item | Should -BeExactly "Device 'DEV1' -> Group: Target Group (ID: g-target)"
        # Assigned to the target group: new for the device too
        @($script:capturedExport | Where-Object { $_.Item -eq 'New Config (ID: dc-new)' }).Count | Should -Be 1
        # All Devices already applies; the device exclusion conflict surfaces instead of the user one
        @($script:capturedExport | Where-Object { $_.Item -like '*dc-alldev*' }).Count | Should -Be 0
        @($script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Device Configuration' -and $_.Item -like '*dc-devconflict*' }).Count | Should -Be 1
        # App Protection assignments never match All Devices targets (legacy walk parity)
        @($script:capturedExport | Where-Object { $_.Item -like '*apppol-alldev*' }).Count | Should -Be 0
    }

    It 'unions user and device memberships in a combined run' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -DeviceNames 'DEV1' -SimulateTargetGroup 'Target Group'

        $script:capturedExport[0].Item | Should -BeExactly "User 'user1@contoso.com' + Device 'DEV1' -> Group: Target Group (ID: g-target)"
        # Both exclusion conflicts surface because current membership is the union of user and device groups
        $conflictItems = @($script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Device Configuration' } | ForEach-Object { $_.Item })
        $conflictItems | Should -Contain 'Conflict Config (ID: dc-conflict)'
        $conflictItems | Should -Contain 'Device Conflict Config (ID: dc-devconflict)'
        # dc-devconflict is NOT new (it is a conflict), and already-had policies stay absent
        @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: Device Configuration' -and $_.Item -like '*dc-devconflict*' }).Count | Should -Be 0
        @($script:capturedExport | Where-Object { $_.Item -like '*dc-allusers*' -or $_.Item -like '*dc-alldev*' }).Count | Should -Be 0
    }

    It 'resolves Endpoint Security across both phases, keeping the legacy Settings Catalog double-count and no intent filter suffix' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        # av-cfg surfaces both as a Settings Catalog policy and as an ES Antivirus profile (legacy walk had no ES filter)
        @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: Settings Catalog Policy' -and $_.Item -eq 'AV Config Policy (ID: av-cfg)' }).Count | Should -Be 1
        $avRows = @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: Endpoint Security - Antivirus' })
        $avRows.Count | Should -Be 2
        @($avRows | Where-Object { $_.Item -eq 'AV Config Policy (ID: av-cfg)' -and $_.AssignmentReason -eq 'Group Assignment' }).Count | Should -Be 1
        # The intent target carries filter fields, but the legacy reason has no suffix
        @($avRows | Where-Object { $_.Item -eq 'AV Intent Legacy (ID: av-intent)' -and $_.AssignmentReason -eq 'Group Assignment' }).Count | Should -Be 1
    }

    It 'routes new apps by intent and reports app exclusion conflicts with the intent label' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $requiredRows = @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: Required App' })
        $requiredRows.Count | Should -Be 1
        $requiredRows[0].Item | Should -BeExactly 'New App (ID: app-new)'
        $requiredRows[0].AssignmentReason | Should -BeExactly 'Group Assignment'
        $appConflicts = @($script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Application (required)' })
        $appConflicts.Count | Should -Be 1
        $appConflicts[0].Item | Should -BeExactly 'Conflict App (ID: app-conflict)'
    }

    It 'reports new App Protection policies gained via the target group' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $apRows = @($script:capturedExport | Where-Object { $_.Category -eq 'NEW: App Protection Policy' })
        $apRows.Count | Should -Be 1
        $apRows[0].Item | Should -BeExactly 'AP New (ID: apppol-new)'
        $apRows[0].AssignmentReason | Should -BeExactly 'Group Assignment'
    }

    It 'fetches each entity set from Graph only once even with user and device supplied' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -DeviceNames 'DEV1' -SimulateTargetGroup 'Target Group'

        # The legacy walk fetched configurationPolicies 7 times and intents 6 times per run
        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'configurationPolicies' }
        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'deviceManagement/intents' }
        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'deviceConfigurations' }
        Should -Invoke Invoke-IACGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -like '*mobileApps?*isAssigned*' }
    }

    It 'emits the 23-step progress lines including Windows Update workloads' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup 'Target Group'

        $script:hostLines | Should -Contain '[1/23] Fetching Device Configurations...'
        $script:hostLines | Should -Contain '[2/23] Fetching Imported Administrative Templates...'
        $script:hostLines | Should -Contain '[7/23] Fetching Applications...'
        $script:hostLines | Should -Contain '[10/23] Fetching Antivirus Policies...'
        $script:hostLines | Should -Contain '[13/23] Fetching Endpoint Detection and Response Policies...'
        $script:hostLines | Should -Contain '[16/23] Fetching Autopilot Deployment Profiles...'
        $script:hostLines | Should -Contain '[17/23] Fetching Enrollment Status Page Profiles...'
        $script:hostLines | Should -Contain '[18/23] Fetching Windows Feature Update Profiles...'
        $script:hostLines | Should -Contain '[21/23] Fetching Windows Quality Update Policies...'
        $script:hostLines | Should -Contain '[23/23] Fetching Windows 365 Cloud PC User Settings...'
    }

    It 'escapes single quotes in the group name OData filter (F9)' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -SimulateTargetGroup "O'Brien Team"

        Should -Invoke Invoke-IACGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -like "*displayName eq 'O''Brien Team'*" }
    }

    It 'emits export categories in the legacy CSV order' {
        Test-IntuneGroupMembership -UserPrincipalNames 'user1@contoso.com' -DeviceNames 'DEV1' -SimulateTargetGroup 'Target Group'

        $expectedOrder = @(
            'Simulation Info',
            'NEW: Device Configuration', 'NEW: Imported Administrative Template', 'NEW: Settings Catalog Policy', 'NEW: Compliance Policy',
            'NEW: App Protection Policy', 'NEW: App Configuration Policy',
            'NEW: Required App', 'NEW: Available App', 'NEW: Uninstall App',
            'NEW: Platform Script', 'NEW: Proactive Remediation Script',
            'NEW: Endpoint Security - Antivirus', 'NEW: Endpoint Security - Disk Encryption',
            'NEW: Endpoint Security - Firewall', 'NEW: Endpoint Security - EDR',
            'NEW: Endpoint Security - ASR', 'NEW: Endpoint Security - Account Protection',
            'NEW: Autopilot Deployment Profile', 'NEW: Enrollment Status Page Profile',
            'NEW: Windows Feature Update Profile', 'NEW: Windows Quality Update Profile',
            'NEW: Windows Driver Update Profile', 'NEW: Windows Quality Update Policy',
            'NEW: Cloud PC Provisioning Policy', 'NEW: Cloud PC User Setting',
            'CONFLICT: Device Configuration', 'CONFLICT: Application (required)'
        )
        $actualOrder = @($script:capturedExport.Category | Select-Object -Unique)
        # Empty buckets emit no rows; the observed sequence must be a subsequence of the legacy order
        $cursor = 0
        foreach ($category in $actualOrder) {
            $position = $expectedOrder.IndexOf($category)
            $position | Should -BeGreaterOrEqual $cursor -Because "category '$category' must not appear out of legacy order"
            $cursor = $position
        }
    }
}
