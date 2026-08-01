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
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Add-CategoryExportData.ps1')
    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $moduleRoot 'Public/Get-IntuneUserAssignment.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{}

    # Stub collaborators so Pester can mock them per test
    function Get-UserInfo {
        param([string]$UserPrincipalName)
        @{ Id = $null; UserPrincipalName = $UserPrincipalName; Success = $false }
    }
    function Get-GroupMemberships {
        param([string]$ObjectId, [string]$ObjectType)
        @()
    }
    function Get-IntuneEntities {
        param([string]$EntityType, [string]$Filter, [string]$Select, [string]$Expand)
        @()
    }
    function Get-IntuneAssignments {
        param([string]$EntityType, [string]$EntityId, [string]$GroupId, [string[]]$GroupIds = @())
        @()
    }
    function Add-IntentTemplateFamilyInfo {
        param($IntentPolicies)
    }
    function Invoke-MgGraphRequest {
        param($Uri, $Method)
        @{ value = @() }
    }
    function Get-GroupInfo {
        param([string]$GroupId)
        @{ Id = $GroupId; DisplayName = 'Test Group'; Success = $true }
    }
    function Filter-ByScopeTag {
        param($Items, $FilterTag, $ScopeTagLookup)
        $Items
    }
    function Export-ResultsIfRequested {
        param([System.Collections.ArrayList]$ExportData, [string]$DefaultFileName, [switch]$ForceExport, [string]$CustomExportPath, [switch]$ExportToCSV, [switch]$ParameterMode)
    }
}

Describe 'Get-IntuneUserAssignment' {
    BeforeEach {
        $script:capturedExport = $null
        Mock Write-Host {}
        Mock Add-IntentTemplateFamilyInfo {
            foreach ($intent in $IntentPolicies) {
                if ($intent.id -eq 'av-intent') {
                    $intent | Add-Member -NotePropertyName 'templateReference' -NotePropertyValue ([PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' }) -Force
                }
            }
        }
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Get-UserInfo {
            switch ($UserPrincipalName) {
                'user1@contoso.com' { @{ Id = 'u1'; UserPrincipalName = $UserPrincipalName; Success = $true } }
                'user2@contoso.com' { @{ Id = 'u2'; UserPrincipalName = $UserPrincipalName; Success = $true } }
                default { @{ Id = $null; UserPrincipalName = $UserPrincipalName; Success = $false } }
            }
        }
        Mock Get-GroupMemberships {
            switch ($ObjectId) {
                'u1' { @([PSCustomObject]@{ id = 'g-a'; displayName = 'Group A' }) }
                'u2' { @([PSCustomObject]@{ id = 'g-b'; displayName = 'Group B' }) }
                default { @() }
            }
        }
        Mock Get-GroupInfo {
            $names = @{ 'g-a' = 'Group A'; 'g-b' = 'Group B'; 'g-x' = 'Group X' }
            @{ Id = $GroupId; DisplayName = $names[$GroupId]; Success = $true }
        }
        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'deviceConfigurations' {
                    @(
                        [PSCustomObject]@{ id = 'dc-mine'; displayName = 'Config Mine' }
                        [PSCustomObject]@{ id = 'dc-other'; displayName = 'Config Other' }
                        [PSCustomObject]@{ id = 'dc-all'; displayName = 'Config All Users' }
                        [PSCustomObject]@{ id = 'dc-excl'; displayName = 'Config Excluded' }
                    )
                }
                'configurationPolicies' {
                    @([PSCustomObject]@{ id = 'av-cfg'; name = 'AV Config Policy'; templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' } })
                }
                'deviceAppManagement/managedAppPolicies' {
                    @(
                        [PSCustomObject]@{ id = 'apppol-in'; displayName = 'AP In'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection' }
                        [PSCustomObject]@{ id = 'apppol-out'; displayName = 'AP Out'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection' }
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
                'dc-mine' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-a'; FilterId = 'f1'; FilterType = 'include' }) }
                'dc-other' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-x'; FilterId = $null; FilterType = $null }) }
                'dc-all' { @([PSCustomObject]@{ Reason = 'All Users'; GroupId = $null; FilterId = $null; FilterType = $null }) }
                'dc-excl' {
                    @(
                        [PSCustomObject]@{ Reason = 'All Users'; GroupId = $null; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = 'g-a'; FilterId = $null; FilterType = $null }
                    )
                }
                'av-cfg' { @([PSCustomObject]@{ Reason = 'All Users'; GroupId = $null; FilterId = $null; FilterType = $null }) }
                default { @() }
            }
        }
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*mobileApps?*isAssigned*') {
                return @{ value = @(
                        [PSCustomObject]@{ id = 'app-req-inc'; displayName = 'Required Included App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-avail-inc'; displayName = 'Available Included App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-excl'; displayName = 'Excluded App'; isFeatured = $false; isBuiltIn = $false }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-req-inc')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-a' } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-avail-inc')/assignments*") {
                # F14 fixture: the winning assignment intent decides the bucket
                return @{ value = @(
                        @{ intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-excl')/assignments*") {
                # Excluded-app fixture: exclusion for g-a wins over the All Users include
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g-a'; deviceAndAppManagementAssignmentFilterId = 'f1'; deviceAndAppManagementAssignmentFilterType = 'include' } }
                    )
                }
            }
            if ($Uri -like "*androidManagedAppProtections('apppol-in')/assignments*") {
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-a' } }
                    )
                }
            }
            if ($Uri -like "*androidManagedAppProtections('apppol-out')/assignments*") {
                # F13 regression fixture: the user is not a member of g-x
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-x' } }
                    )
                }
            }
            if ($Uri -like '*deviceManagement/intents/av-intent/assignments*') {
                # Intent-phase fixture: filter fields present on the target, but the legacy
                # detail rows never carried them, so the reason must have no filter suffix
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-a'; deviceAndAppManagementAssignmentFilterId = 'f1'; deviceAndAppManagementAssignmentFilterType = 'include' } }
                    )
                }
            }
            return @{ value = @() }
        }
    }

    It 'exports the User row first with the UPN and user id' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $script:capturedExport[0].Category | Should -BeExactly 'User'
        $script:capturedExport[0].Item | Should -BeExactly 'user1@contoso.com (ID: u1)'
        $script:capturedExport[0].AssignmentReason | Should -BeExactly 'N/A'
    }

    It 'includes All Users and member-group policies, drops other groups, and honors exclusion override' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $configRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Device Configuration' })
        $configRows.Count | Should -Be 3
        @($configRows | Where-Object { $_.Item -eq 'Config Mine (ID: dc-mine)' -and $_.AssignmentReason -eq 'Group Assignment (Filter: Unknown Filter (f1) [Include])' }).Count | Should -Be 1
        @($configRows | Where-Object { $_.Item -eq 'Config All Users (ID: dc-all)' -and $_.AssignmentReason -eq 'All Users' }).Count | Should -Be 1
        @($configRows | Where-Object { $_.Item -eq 'Config Excluded (ID: dc-excl)' -and $_.AssignmentReason -eq 'Excluded' }).Count | Should -Be 1
        @($configRows | Where-Object { $_.Item -like '*dc-other*' }).Count | Should -Be 0
    }

    It 'keeps excluded apps visible in the excluding assignment intent bucket with filter suffix' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $requiredRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Required Apps' })
        @($requiredRows | Where-Object { $_.Item -eq 'Excluded App (ID: app-excl)' -and $_.AssignmentReason -eq 'Excluded (Filter: Unknown Filter (f1) [Include])' }).Count | Should -Be 1
        @($requiredRows | Where-Object { $_.Item -eq 'Required Included App (ID: app-req-inc)' -and $_.AssignmentReason -eq 'Included' }).Count | Should -Be 1
    }

    It 'routes included apps by the winning assignment intent (F14)' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $availableRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Available Apps' })
        $availableRows.Count | Should -Be 1
        $availableRows[0].Item | Should -BeExactly 'Available Included App (ID: app-avail-inc)'
        $availableRows[0].AssignmentReason | Should -BeExactly 'Included'
    }

    It 'filters App Protection policies by actual group membership (F13)' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $apRows = @($script:capturedExport | Where-Object { $_.Category -eq 'App Protection Policy' })
        $apRows.Count | Should -Be 1
        $apRows[0].Item | Should -BeExactly 'AP In (ID: apppol-in)'
        $apRows[0].AssignmentReason | Should -BeExactly 'All Users; Group Assignment - Group A'
        @($script:capturedExport | Where-Object { $_.Item -like '*apppol-out*' }).Count | Should -Be 0
    }

    It 'resolves Endpoint Security policies across both phases, intent phase without filter suffix' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $avRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Endpoint Security - Antivirus' })
        $avRows.Count | Should -Be 2
        @($avRows | Where-Object { $_.Item -eq 'AV Config Policy (ID: av-cfg)' -and $_.AssignmentReason -eq 'All Users' }).Count | Should -Be 1
        # The intent target carries filter fields, but the legacy reason has no suffix
        @($avRows | Where-Object { $_.Item -eq 'AV Intent Legacy (ID: av-intent)' -and $_.AssignmentReason -eq 'Group Assignment' }).Count | Should -Be 1
    }

    It 'fetches each entity set from Graph only once for multiple UPNs (finding 10)' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com,user2@contoso.com'

        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'configurationPolicies' }
        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'deviceConfigurations' }
        Should -Invoke Get-IntuneEntities -Times 1 -Exactly -ParameterFilter { $EntityType -eq 'deviceManagement/intents' }
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -like '*mobileApps?*isAssigned*' }
    }

    It 'still resolves assignments per user when the entity cache is shared (second UPN)' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com,user2@contoso.com'

        # user2 is only in g-b: no device configuration except All Users may appear in its block
        $userRowIndexes = @(0..($script:capturedExport.Count - 1) | Where-Object { $script:capturedExport[$_].Category -eq 'User' })
        $userRowIndexes.Count | Should -Be 2
        $user2Rows = @($script:capturedExport | Select-Object -Skip $userRowIndexes[1])
        $user2ConfigRows = @($user2Rows | Where-Object { $_.Category -eq 'Device Configuration' })
        $user2ConfigRows.Count | Should -Be 2
        @($user2ConfigRows | Where-Object { $_.Item -eq 'Config All Users (ID: dc-all)' -and $_.AssignmentReason -eq 'All Users' }).Count | Should -Be 1
        # dc-excl excludes only g-a, so user2 keeps the All Users inclusion
        @($user2ConfigRows | Where-Object { $_.Item -eq 'Config Excluded (ID: dc-excl)' -and $_.AssignmentReason -eq 'All Users' }).Count | Should -Be 1
    }

    It 'emits export categories in the legacy CSV order' {
        Get-IntuneUserAssignment -UserPrincipalNames 'user1@contoso.com'

        $expectedOrder = @(
            'User', 'Device Configuration', 'Settings Catalog Policy', 'Compliance Policy', 'App Protection Policy',
            'App Configuration Policy', 'Platform Scripts', 'Proactive Remediation Scripts',
            'Autopilot Deployment Profile', 'Enrollment Status Page',
            'Windows 365 Cloud PC Provisioning Policy', 'Windows 365 Cloud PC User Setting',
            'Endpoint Security - Antivirus', 'Endpoint Security - Disk Encryption', 'Endpoint Security - Firewall',
            'Endpoint Security - EDR', 'Endpoint Security - ASR', 'Endpoint Security - Account Protection',
            'Required Apps', 'Available Apps', 'Uninstall Apps'
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
