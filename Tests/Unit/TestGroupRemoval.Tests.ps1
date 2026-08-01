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
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $moduleRoot 'Public/Test-IntuneGroupRemoval.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{ 'f1' = @{ Name = 'Filter One' } }

    # Builds one raw Graph assignment object (apps, app protection, intents)
    function Build-RawAssignment {
        param([string]$Type, [string]$TargetGroupId, [string]$FilterId, [string]$FilterType, [string]$Intent)
        [PSCustomObject]@{
            intent = $Intent
            target = [PSCustomObject]@{
                '@odata.type'                              = $Type
                groupId                                    = $TargetGroupId
                deviceAndAppManagementAssignmentFilterId   = $FilterId
                deviceAndAppManagementAssignmentFilterType = $FilterType
            }
        }
    }

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

Describe 'Test-IntuneGroupRemoval' {
    BeforeEach {
        $script:capturedExport = $null
        $script:hostLines = [System.Collections.Generic.List[string]]::new()
        $script:requestedUris = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { if ($null -ne $Object) { $script:hostLines.Add([string]$Object) } }
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Get-UserInfo {
            if ($UserPrincipalName -eq 'user1@contoso.com') { @{ Id = 'u1'; UserPrincipalName = $UserPrincipalName; Success = $true } }
            else { @{ Id = $null; UserPrincipalName = $UserPrincipalName; Success = $false } }
        }
        Mock Get-DeviceInfo {
            if ($DeviceName -eq 'DEV1') { @{ Id = 'd1'; DisplayName = 'DEV1'; Success = $true; MultipleFound = $false; AllDevices = @() } }
            else { @{ Id = $null; DisplayName = $DeviceName; Success = $false; MultipleFound = $false; AllDevices = @() } }
        }
        # User is member of the target group plus one other; device of the target plus a device group
        Mock Get-GroupMemberships {
            switch ($ObjectType) {
                'User' { @([PSCustomObject]@{ id = 'g-target' }, [PSCustomObject]@{ id = 'g-other' }) }
                'Device' { @([PSCustomObject]@{ id = 'g-target' }, [PSCustomObject]@{ id = 'g-dev' }) }
                default { @() }
            }
        }
        Mock Get-TransitiveGroupMembership { @([PSCustomObject]@{ id = 'g-parent'; displayName = 'Parent Group' }) }
        Mock Add-IntentTemplateFamilyInfo {
            foreach ($intent in $IntentPolicies) {
                if ($intent.id -in @('av-intent', 'av-cfg')) {
                    $intent | Add-Member -NotePropertyName 'templateReference' -NotePropertyValue ([PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' }) -Force
                }
            }
        }
        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'deviceConfigurations' {
                    @(
                        [PSCustomObject]@{ id = 'dc-lost'; displayName = 'DC Lost' }
                        [PSCustomObject]@{ id = 'dc-kept'; displayName = 'DC Kept' }
                        [PSCustomObject]@{ id = 'dc-allusers'; displayName = 'DC AllUsers' }
                        [PSCustomObject]@{ id = 'dc-conflict'; displayName = 'DC Conflict' }
                        [PSCustomObject]@{ id = 'dc-lifted'; displayName = 'DC Lifted' }
                    )
                }
                'configurationPolicies' {
                    @([PSCustomObject]@{ id = 'av-cfg'; name = 'AV Cfg'; templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' } })
                }
                'deviceAppManagement/managedAppPolicies' {
                    @([PSCustomObject]@{ id = 'ap-alldev'; displayName = 'AP AllDev'; '@odata.type' = '#microsoft.graph.iosManagedAppProtection' })
                }
                'deviceManagement/intents' {
                    @(
                        [PSCustomObject]@{ id = 'av-intent'; displayName = 'AV Intent' }
                        [PSCustomObject]@{ id = 'av-cfg'; displayName = 'AV Cfg Duplicate' }
                    )
                }
                'virtualEndpoint/provisioningPolicies' { throw 'Windows 365 not licensed' }
                default { @() }
            }
        }
        Mock Get-IntuneAssignments {
            switch ($EntityId) {
                'dc-lost' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = 'f1'; FilterType = 'include' }) }
                'dc-kept' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-other'; FilterId = $null; FilterType = $null }
                    )
                }
                'dc-allusers' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'All Users'; GroupId = $null; FilterId = $null; FilterType = $null }
                    )
                }
                'dc-conflict' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = 'g-other'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-parent'; FilterId = $null; FilterType = $null }
                    )
                }
                'dc-lifted' {
                    @(
                        [PSCustomObject]@{ Reason = 'Group Exclusion'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-other'; FilterId = $null; FilterType = $null }
                    )
                }
                'av-cfg' { @([PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'g-target'; FilterId = $null; FilterType = $null }) }
                default { @() }
            }
        }
        Mock Invoke-IACGraphRequest {
            $script:requestedUris.Add([string]$Uri)
            switch -Wildcard ($Uri) {
                '*/beta/groups[?]*' { return @{ value = @([PSCustomObject]@{ id = 'g-target'; displayName = 'Target Group' }) } }
                '*mobileApps[?]*' {
                    return @{
                        value = @(
                            [PSCustomObject]@{ id = 'app-builtin'; displayName = 'App BuiltIn'; isBuiltIn = $true; isFeatured = $false }
                            [PSCustomObject]@{ id = 'app-lost'; displayName = 'App Lost'; isBuiltIn = $false; isFeatured = $false }
                            [PSCustomObject]@{ id = 'app-conflict'; displayName = 'App Conflict'; isBuiltIn = $false; isFeatured = $false }
                        )
                    }
                }
                "*mobileApps('app-lost')/assignments" {
                    return @{ value = @((Build-RawAssignment -Type '#microsoft.graph.groupAssignmentTarget' -TargetGroupId 'g-target' -FilterId 'f1' -FilterType 'include' -Intent 'required')) }
                }
                "*mobileApps('app-conflict')/assignments" {
                    return @{ value = @(
                            (Build-RawAssignment -Type '#microsoft.graph.exclusionGroupAssignmentTarget' -TargetGroupId 'g-other' -FilterType 'none' -Intent 'available')
                            (Build-RawAssignment -Type '#microsoft.graph.groupAssignmentTarget' -TargetGroupId 'g-parent' -FilterType 'none' -Intent 'available')
                        ) }
                }
                "*iosManagedAppProtections('ap-alldev')/assignments" {
                    return @{ value = @(
                            (Build-RawAssignment -Type '#microsoft.graph.allDevicesAssignmentTarget' -FilterType 'none')
                            (Build-RawAssignment -Type '#microsoft.graph.groupAssignmentTarget' -TargetGroupId 'g-target' -FilterType 'none')
                        ) }
                }
                '*deviceManagement/intents/av-intent/assignments*' {
                    return @{ value = @((Build-RawAssignment -Type '#microsoft.graph.groupAssignmentTarget' -TargetGroupId 'g-target' -FilterId 'f1' -FilterType 'include')) }
                }
                default { return @{ value = @() } }
            }
        }
    }

    Context 'user perspective' {
        BeforeEach {
            Test-IntuneGroupRemoval -UserPrincipalNames 'user1@contoso.com' -GroupNames 'Target Group'
        }

        It 'reports a policy assigned only via the target group as lost with its filter suffix' {
            $row = $script:capturedExport | Where-Object { $_.Category -eq 'LOST: Device Configuration' -and $_.Item -like 'DC Lost*' }
            $row | Should -HaveCount 1
            $row.AssignmentReason | Should -Be 'Group Assignment (Filter: Filter One [Include])'
        }

        It 'keeps a policy still reachable via another group out of the results' {
            @($script:capturedExport | Where-Object { $_.Item -like 'DC Kept*' }) | Should -HaveCount 0
        }

        It 'keeps an All Users policy for a user perspective' {
            @($script:capturedExport | Where-Object { $_.Item -like 'DC AllUsers*' }) | Should -HaveCount 0
        }

        It 'flags an exclusion that removal would expose as a conflict' {
            $row = $script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Device Configuration' }
            $row | Should -HaveCount 1
            $row.Item | Should -Be 'DC Conflict (ID: dc-conflict)'
            $row.AssignmentReason | Should -Be 'Currently included; removal would expose exclusion'
        }

        It 'stays silent about a policy gained through a lifted exclusion (legacy behavior)' {
            @($script:capturedExport | Where-Object { $_.Item -like 'DC Lifted*' }) | Should -HaveCount 0
        }

        It 'reports the Endpoint Security policy lost through both scan phases' {
            # av-cfg also surfaces in the unfiltered Settings Catalog walk, as before the migration
            ($script:capturedExport | Where-Object { $_.Category -eq 'LOST: Settings Catalog Policy' }).Item | Should -Be 'AV Cfg (ID: av-cfg)'
            $esRows = @($script:capturedExport | Where-Object { $_.Category -eq 'LOST: Endpoint Security - Antivirus' })
            @($esRows | ForEach-Object { $_.Item }) | Should -Be @('AV Cfg (ID: av-cfg)', 'AV Intent (ID: av-intent)')
        }

        It 'resolves intent-phase reasons without a filter suffix and dedupes intent ids' {
            $intentRow = $script:capturedExport | Where-Object { $_.Item -eq 'AV Intent (ID: av-intent)' }
            $intentRow.AssignmentReason | Should -Be 'Group Assignment'
            # The intent sharing the config policy id is skipped by the two-phase dedupe
            @($script:requestedUris | Where-Object { $_ -like '*intents/av-cfg/assignments*' }) | Should -HaveCount 0
        }

        It 'buckets a lost app under its intent with the winning filter suffix' {
            $row = $script:capturedExport | Where-Object { $_.Category -eq 'LOST: Required App' }
            $row | Should -HaveCount 1
            $row.Item | Should -Be 'App Lost (ID: app-lost)'
            $row.AssignmentReason | Should -Be 'Group Assignment (Filter: Filter One [Include])'
        }

        It 'labels an app exclusion conflict with the excluding intent' {
            $row = $script:capturedExport | Where-Object { $_.Category -eq 'CONFLICT: Application (available)' }
            $row.Item | Should -Be 'App Conflict (ID: app-conflict)'
        }

        It 'ignores All Devices targets on App Protection policies (legacy quirk)' {
            $row = $script:capturedExport | Where-Object { $_.Category -eq 'LOST: App Protection Policy' }
            $row.Item | Should -Be 'AP AllDev (ID: ap-alldev)'
        }

        It 'walks the 19 categories including Imported Administrative Templates' {
            $headers = @($script:hostLines | Where-Object { $_ -match '^\[\d+/19\] Fetching ' })
            $headers | Should -HaveCount 19
            $headers[0] | Should -Be '[1/19] Fetching Device Configurations...'
            $headers[1] | Should -Be '[2/19] Fetching Imported Administrative Templates...'
            $headers[6] | Should -Be '[7/19] Fetching Applications...'
            $headers[9] | Should -Be '[10/19] Fetching Antivirus Policies...'
            $headers[15] | Should -Be '[16/19] Fetching Autopilot Deployment Profiles...'
            $headers[18] | Should -Be '[19/19] Fetching Windows 365 Cloud PC User Settings...'
        }

        It 'skips unlicensed Windows 365 categories without failing the run' {
            $script:capturedExport[0].Category | Should -Be 'Simulation Info'
            ($script:hostLines -join "`n") | Should -Match 'Impact:'
        }
    }

    Context 'device perspective' {
        BeforeEach {
            Test-IntuneGroupRemoval -DeviceNames 'DEV1' -GroupNames 'Target Group'
        }

        It 'loses an All Users policy because only All Devices counts for a device' {
            $row = $script:capturedExport | Where-Object { $_.Item -like 'DC AllUsers*' }
            $row.Category | Should -Be 'LOST: Device Configuration'
        }

        It 'raises no conflict for exclusions the device does not hold' {
            @($script:capturedExport | Where-Object { $_.Category -like 'CONFLICT:*' }) | Should -HaveCount 0
        }
    }

    Context 'combined user and device perspective' {
        BeforeEach {
            Test-IntuneGroupRemoval -UserPrincipalNames 'user1@contoso.com' -DeviceNames 'DEV1' -GroupNames 'Target Group'
        }

        It 'labels the simulation info row with both subjects' {
            $script:capturedExport[0].Item | Should -Be "User 'user1@contoso.com' + Device 'DEV1' -> Remove from Group: Target Group (ID: g-target)"
        }

        It 'keeps the All Users policy when the user perspective is present' {
            @($script:capturedExport | Where-Object { $_.Item -like 'DC AllUsers*' }) | Should -HaveCount 0
        }
    }

    Context 'input handling' {
        It 'escapes single quotes in the group name OData filter' {
            Test-IntuneGroupRemoval -UserPrincipalNames 'user1@contoso.com' -GroupNames "O'Brien Team" | Out-Null
            $groupLookup = @($script:requestedUris | Where-Object { $_ -like '*/beta/groups*' })
            $groupLookup[0] | Should -Match ([regex]::Escape("displayName eq 'O''Brien Team'"))
        }

        It 'stops when the subject is not a member of the target group' {
            Mock Get-GroupMemberships { @([PSCustomObject]@{ id = 'g-other' }) }
            Test-IntuneGroupRemoval -UserPrincipalNames 'user1@contoso.com' -GroupNames 'Target Group'
            ($script:hostLines -join "`n") | Should -Match 'is NOT a member of'
            $script:capturedExport | Should -BeNullOrEmpty
        }
    }
}
