#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'

    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Get-IACNoAssignmentPlaceholder.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Add-CategoryExportData.ps1')

    $script:GraphEndpoint = 'https://graph.microsoft.com'

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

    function New-TestCategory {
        param([hashtable]$Props)
        $entry = [ordered]@{
            Id                     = 'TestCategory'
            Kind                   = 'Entity'
            EntityType             = 'deviceConfigurations'
            AssignmentEntityType   = $null
            TemplateFamily         = $null
            EntityFilter           = $null
            BucketKeys             = @('DeviceConfigs')
            DisplayName            = 'Test Category'
            ExportCategory         = 'Test Category'
            OptionalFeature        = $false
            BucketOnly             = $false
            BucketExportCategories = $null
        }
        foreach ($key in $Props.Keys) { $entry[$key] = $Props[$key] }
        if (-not $entry.AssignmentEntityType) { $entry.AssignmentEntityType = $entry.EntityType }
        [PSCustomObject]$entry
    }

    function New-EsPolicy {
        param([string]$Id, [string]$Family, [string]$Name = 'ES Policy')
        [PSCustomObject]@{
            id                = $Id
            name              = $Name
            displayName       = $Name
            templateReference = [PSCustomObject]@{ templateFamily = $Family }
        }
    }
}

Describe 'Get-AppProtectionAssignmentUri' {
    It 'maps androidManagedAppProtection to the android assignments URI' {
        $policy = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.androidManagedAppProtection'; id = 'pol-android' }
        Get-AppProtectionAssignmentUri -Policy $policy |
            Should -BeExactly "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('pol-android')/assignments"
    }

    It 'maps iosManagedAppProtection to the ios assignments URI' {
        $policy = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.iosManagedAppProtection'; id = 'pol-ios' }
        Get-AppProtectionAssignmentUri -Policy $policy |
            Should -BeExactly "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('pol-ios')/assignments"
    }

    It 'maps windowsManagedAppProtection to the windows assignments URI' {
        $policy = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.windowsManagedAppProtection'; id = 'pol-win' }
        Get-AppProtectionAssignmentUri -Policy $policy |
            Should -BeExactly "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('pol-win')/assignments"
    }

    It 'returns null for an unknown policy type' {
        $policy = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.mdmWindowsInformationProtectionPolicy'; id = 'pol-wip' }
        Get-AppProtectionAssignmentUri -Policy $policy | Should -BeNullOrEmpty
    }

    It 'returns null when the policy has no @odata.type' {
        $policy = [PSCustomObject]@{ id = 'pol-untyped' }
        Get-AppProtectionAssignmentUri -Policy $policy | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-IntuneCategoryScan' {
    BeforeEach {
        Mock Write-Host {}
        Mock Write-Error {}
        Mock Get-IntuneEntities { @() }
        Mock Get-IntuneAssignments { @() }
        Mock Add-IntentTemplateFamilyInfo {}
        Mock Invoke-IACGraphRequest { @{ value = @() } }
    }

    Context 'entity caching' {
        It 'fetches configurationPolicies exactly once across SettingsCatalog and six ES categories' {
            Mock Get-IntuneEntities {
                if ($EntityType -eq 'configurationPolicies') {
                    return @(New-EsPolicy -Id 'cp-1' -Family 'endpointSecurityAntivirus')
                }
                return @()
            }

            $categories = Get-IntuneCategoryDefinition -Audience UserContext
            $null = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{}

            Should -Invoke Get-IntuneEntities -Exactly 1 -ParameterFilter { $EntityType -eq 'configurationPolicies' }
        }

        It 'fetches deviceManagement/intents exactly once across the six ES categories' {
            $categories = Get-IntuneCategoryDefinition -Audience UserContext
            $null = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{}

            Should -Invoke Get-IntuneEntities -Exactly 1 -ParameterFilter { $EntityType -eq 'deviceManagement/intents' }
        }
    }

    Context 'endpoint security two-phase dedup' {
        It 'delivers an id present in both configurationPolicies and intents to the callback only once' {
            Mock Get-IntuneEntities {
                switch ($EntityType) {
                    'configurationPolicies' { return @(New-EsPolicy -Id 'dup-1' -Family 'endpointSecurityAntivirus' -Name 'AV config policy') }
                    'deviceManagement/intents' { return @(New-EsPolicy -Id 'dup-1' -Family 'endpointSecurityAntivirus' -Name 'AV intent') }
                    default { return @() }
                }
            }

            $script:seenIds = [System.Collections.Generic.List[string]]::new()
            $antivirusCategory = @(Get-IntuneCategoryDefinition -Audience UserContext | Where-Object { $_.Id -eq 'ESAntivirus' })
            $null = Invoke-IntuneCategoryScan -Categories $antivirusCategory -ProcessEntity {
                param($ctx)
                $script:seenIds.Add($ctx.Entity.id)
            }

            $script:seenIds.Count | Should -Be 1
            $script:seenIds[0] | Should -Be 'dup-1'
        }

        It 'still delivers intents that have no configurationPolicies counterpart' {
            Mock Get-IntuneEntities {
                switch ($EntityType) {
                    'deviceManagement/intents' { return @(New-EsPolicy -Id 'intent-macos-fv' -Family 'endpointSecurityDiskEncryption' -Name 'macOS FileVault') }
                    default { return @() }
                }
            }
            Mock Invoke-IACGraphRequest {
                @{ value = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }
            }

            $script:intentContexts = [System.Collections.Generic.List[object]]::new()
            $diskEncCategory = @(Get-IntuneCategoryDefinition -Audience UserContext | Where-Object { $_.Id -eq 'ESDiskEncryption' })
            $null = Invoke-IntuneCategoryScan -Categories $diskEncCategory -ProcessEntity {
                param($ctx)
                $script:intentContexts.Add($ctx)
            }

            $script:intentContexts.Count | Should -Be 1
            $script:intentContexts[0].Entity.id | Should -Be 'intent-macos-fv'
            $script:intentContexts[0].Assignments[0].Reason | Should -BeExactly 'All Devices'
            @($script:intentContexts[0].RawAssignments).Count | Should -Be 1
            Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter { $Uri -like '*deviceManagement/intents/intent-macos-fv/assignments*' }
        }
    }

    Context 'error handling' {
        It 'continues with other categories and records the failure when a category fetch throws' {
            Mock Get-IntuneEntities {
                if ($EntityType -eq 'deviceConfigurations') { throw 'boom' }
                return @([PSCustomObject]@{ id = 'comp-1'; displayName = 'Compliance 1' })
            }

            $script:processedIds = [System.Collections.Generic.List[string]]::new()
            $categories = @(
                New-TestCategory @{ Id = 'DeviceConfigurations'; EntityType = 'deviceConfigurations'; DisplayName = 'Device Configurations' }
                New-TestCategory @{ Id = 'CompliancePolicies'; EntityType = 'deviceCompliancePolicies'; BucketKeys = @('CompliancePolicies'); DisplayName = 'Compliance Policies' }
            )

            $result = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {
                param($ctx)
                $script:processedIds.Add($ctx.Entity.id)
            }

            $script:processedIds | Should -Be @('comp-1')
            $result.Errors.Count | Should -Be 1
            $result.Errors[0].CategoryId | Should -Be 'DeviceConfigurations'
            $result.Errors[0].DisplayName | Should -BeExactly 'Device Configurations'
            $result.Errors[0].Message | Should -Match 'boom'
            Should -Invoke Write-Error -Exactly 1
        }

        It 'skips OptionalFeature category failures quietly without an error record' {
            Mock Get-IntuneEntities {
                if ($EntityType -eq 'virtualEndpoint/provisioningPolicies') { throw 'not licensed' }
                return @([PSCustomObject]@{ id = 'comp-1'; displayName = 'Compliance 1' })
            }

            $script:processedIds = [System.Collections.Generic.List[string]]::new()
            $categories = @(
                New-TestCategory @{ Id = 'CloudPCProvisioningPolicies'; EntityType = 'virtualEndpoint/provisioningPolicies'; BucketKeys = @('CloudPCProvisioningPolicies'); DisplayName = 'Windows 365 Cloud PC Provisioning Policies'; OptionalFeature = $true }
                New-TestCategory @{ Id = 'CompliancePolicies'; EntityType = 'deviceCompliancePolicies'; BucketKeys = @('CompliancePolicies'); DisplayName = 'Compliance Policies' }
            )

            $result = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {
                param($ctx)
                $script:processedIds.Add($ctx.Entity.id)
            }

            $script:processedIds | Should -Be @('comp-1')
            $result.Errors.Count | Should -Be 0
            Should -Invoke Write-Error -Exactly 0
        }
    }

    Context 'buckets' {
        It 'returns List[object] buckets and surfaces callback mutations' {
            Mock Get-IntuneEntities { @([PSCustomObject]@{ id = 'cfg-1'; displayName = 'Config 1' }) }

            $categories = @(New-TestCategory @{})
            $result = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {
                param($ctx)
                $ctx.Buckets['DeviceConfigs'].Add($ctx.Entity)
            }

            $result.Buckets['DeviceConfigs'].GetType().Name | Should -Be 'List`1'
            $result.Buckets['DeviceConfigs'].Count | Should -Be 1
            $result.Buckets['DeviceConfigs'][0].id | Should -Be 'cfg-1'
        }

        It 'creates empty buckets for BucketOnly categories without fetching them' {
            $categories = @(
                New-TestCategory @{ Id = 'DeploymentProfiles'; EntityType = 'windowsAutopilotDeploymentProfiles'; BucketKeys = @('DeploymentProfiles'); BucketOnly = $true }
            )
            $result = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {}

            $result.Buckets.ContainsKey('DeploymentProfiles') | Should -BeTrue
            $result.Buckets['DeploymentProfiles'].Count | Should -Be 0
            $result.CategoryCount | Should -Be 0
            Should -Invoke Get-IntuneEntities -Exactly 0
        }
    }

    Context 'assignment group ids' {
        It 'passes AssignmentGroupIds through to Get-IntuneAssignments' {
            Mock Get-IntuneEntities { @([PSCustomObject]@{ id = 'cfg-1' }) }

            $categories = @(New-TestCategory @{})
            $null = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -AssignmentGroupIds @('grp-1', 'grp-2')

            Should -Invoke Get-IntuneAssignments -Exactly 1 -ParameterFilter {
                $EntityId -eq 'cfg-1' -and $GroupIds.Count -eq 2 -and $GroupIds -contains 'grp-1' -and $GroupIds -contains 'grp-2'
            }
        }
    }

    Context 'entity prefilter' {
        It 'never fetches assignments for entities that fail the prefilter' {
            Mock Get-IntuneEntities {
                @(
                    [PSCustomObject]@{ id = 'cfg-match'; displayName = 'Corp Baseline' }
                    [PSCustomObject]@{ id = 'cfg-nomatch'; displayName = 'Pilot Policy' }
                )
            }

            $script:processedIds = [System.Collections.Generic.List[string]]::new()
            $categories = @(New-TestCategory @{})
            $null = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {
                param($ctx)
                $script:processedIds.Add($ctx.Entity.id)
            } -EntityPreFilter { param($entity) $entity.displayName -like '*Corp*' }

            $script:processedIds | Should -Be @('cfg-match')
            Should -Invoke Get-IntuneAssignments -Exactly 1
            Should -Invoke Get-IntuneAssignments -Exactly 1 -ParameterFilter { $EntityId -eq 'cfg-match' }
            Should -Invoke Get-IntuneAssignments -Exactly 0 -ParameterFilter { $EntityId -eq 'cfg-nomatch' }
        }
    }

    Context 'mobile apps' {
        It 'keeps every assigned app regardless of featured metadata and passes RawAssignments to the callback' {
            Mock Invoke-IACGraphRequest {
                if ($Uri.Contains('mobileApps?$filter=isAssigned')) {
                    return @{ value = @(
                            @{ id = 'app-1'; displayName = 'Real App'; isFeatured = $false; isBuiltIn = $false }
                            @{ id = 'app-2'; displayName = 'Featured App'; isFeatured = $true; isBuiltIn = $false }
                            @{ id = 'app-3'; displayName = 'BuiltIn App'; isFeatured = $false; isBuiltIn = $true }
                        )
                    }
                }
                if ($Uri -like "*mobileApps('app-1')/assignments*") {
                    return @{ value = @(
                            @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                        )
                    }
                }
                return @{ value = @() }
            }

            $script:appContexts = [System.Collections.Generic.List[object]]::new()
            $appsCategory = @(Get-IntuneCategoryDefinition -Audience UserContext | Where-Object { $_.Id -eq 'Applications' })
            $null = Invoke-IntuneCategoryScan -Categories $appsCategory -ProcessEntity {
                param($ctx)
                $script:appContexts.Add($ctx)
            }

            $script:appContexts.Count | Should -Be 3
            $script:appContexts[0].Entity.id | Should -Be 'app-1'
            @($script:appContexts[0].RawAssignments).Count | Should -Be 1
            $script:appContexts[0].RawAssignments[0].intent | Should -Be 'required'
            $script:appContexts[0].Assignments[0].Reason | Should -BeExactly 'All Users'
            @($script:appContexts.Entity.id) | Should -Contain 'app-2'
            @($script:appContexts.Entity.id) | Should -Contain 'app-3'
        }
    }

    Context 'app protection normalization' {
        It 'reproduces the GroupIds label duality for raw App Protection assignments' {
            Mock Get-IntuneEntities {
                if ($EntityType -eq 'deviceAppManagement/managedAppPolicies') {
                    return @([PSCustomObject]@{ id = 'app-prot-1'; displayName = 'iOS MAM'; '@odata.type' = '#microsoft.graph.iosManagedAppProtection' })
                }
                return @()
            }
            Mock Invoke-IACGraphRequest {
                @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1' } }
                        @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-other' } }
                        @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
                    )
                }
            }

            $appProtectionCategory = @(Get-IntuneCategoryDefinition -Audience GroupContext | Where-Object { $_.Id -eq 'AppProtectionPolicies' })

            # Group-scoped run: only Direct Assignment for the matching group survives
            $script:groupScoped = [System.Collections.Generic.List[object]]::new()
            $null = Invoke-IntuneCategoryScan -Categories $appProtectionCategory -AssignmentGroupIds @('grp-1') -ProcessEntity {
                param($ctx)
                $script:groupScoped.Add($ctx)
            }
            @($script:groupScoped[0].Assignments).Count | Should -Be 1
            $script:groupScoped[0].Assignments[0].Reason | Should -BeExactly 'Direct Assignment'
            @($script:groupScoped[0].RawAssignments).Count | Should -Be 3

            # Unscoped run: group labels plus All Users pass through
            $script:unscoped = [System.Collections.Generic.List[object]]::new()
            $null = Invoke-IntuneCategoryScan -Categories $appProtectionCategory -ProcessEntity {
                param($ctx)
                $script:unscoped.Add($ctx)
            }
            @($script:unscoped[0].Assignments).Reason | Should -Be @('Group Assignment', 'Group Exclusion', 'All Users')
        }
    }

    Context 'zero-assignment entities' {
        It 'invokes the callback for entities without any assignment' {
            Mock Get-IntuneEntities { @([PSCustomObject]@{ id = 'cfg-empty'; displayName = 'Unassigned Config' }) }
            Mock Get-IntuneAssignments { @() }

            $script:emptyContexts = [System.Collections.Generic.List[object]]::new()
            $categories = @(New-TestCategory @{})
            $null = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {
                param($ctx)
                $script:emptyContexts.Add($ctx)
            }

            $script:emptyContexts.Count | Should -Be 1
            @($script:emptyContexts[0].Assignments).Count | Should -Be 0
        }
    }
}

Describe 'Add-CategoryExportData' {
    BeforeEach {
        $script:ScopeTagLookup = @{}
        $script:exportData = [System.Collections.ArrayList]::new()
    }

    It 'exports buckets in registry order using each category ExportCategory label' {
        $categories = @(
            New-TestCategory @{ Id = 'DeviceConfigurations'; BucketKeys = @('DeviceConfigs'); ExportCategory = 'Device Configuration' }
            New-TestCategory @{ Id = 'CompliancePolicies'; BucketKeys = @('CompliancePolicies'); ExportCategory = 'Compliance Policy' }
        )
        $buckets = @{
            DeviceConfigs      = @([PSCustomObject]@{ id = 'cfg-1'; displayName = 'Config 1'; AssignmentSummary = 'All Users' })
            CompliancePolicies = @([PSCustomObject]@{ id = 'comp-1'; displayName = 'Compliance 1'; AssignmentSummary = 'All Devices' })
        }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets

        $script:exportData.Count | Should -Be 2
        $script:exportData[0].Category | Should -BeExactly 'Device Configuration'
        $script:exportData[0].Item | Should -BeExactly 'Config 1 (ID: cfg-1)'
        $script:exportData[1].Category | Should -BeExactly 'Compliance Policy'
    }

    It 'uses BucketExportCategories labels for multi-bucket categories' {
        $categories = @(
            New-TestCategory @{
                Id                     = 'Applications'
                BucketKeys             = @('AppsRequired', 'AppsAvailable', 'AppsUninstall')
                ExportCategory         = $null
                BucketExportCategories = @{ AppsRequired = 'Required Apps'; AppsAvailable = 'Available Apps'; AppsUninstall = 'Uninstall Apps' }
            }
        )
        $buckets = @{
            AppsRequired  = @([PSCustomObject]@{ id = 'app-1'; displayName = 'App 1' })
            AppsAvailable = @([PSCustomObject]@{ id = 'app-2'; displayName = 'App 2' })
            AppsUninstall = @()
        }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets

        $script:exportData.Count | Should -Be 2
        $script:exportData[0].Category | Should -BeExactly 'Required Apps'
        $script:exportData[1].Category | Should -BeExactly 'Available Apps'
    }

    It 'exports a bucket shared by multiple categories only once' {
        $categories = @(
            New-TestCategory @{ Id = 'PlatformScripts'; BucketKeys = @('PlatformScripts'); ExportCategory = 'Platform Scripts' }
            New-TestCategory @{ Id = 'ShellScripts'; BucketKeys = @('PlatformScripts'); ExportCategory = 'Platform Scripts' }
        )
        $buckets = @{
            PlatformScripts = @([PSCustomObject]@{ id = 'scr-1'; displayName = 'Script 1' })
        }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets

        $script:exportData.Count | Should -Be 1
    }

    It 'emits no rows for empty or missing buckets without erroring' {
        $categories = @(
            New-TestCategory @{ Id = 'DeviceConfigurations'; BucketKeys = @('DeviceConfigs'); ExportCategory = 'Device Configuration' }
            New-TestCategory @{ Id = 'CompliancePolicies'; BucketKeys = @('CompliancePolicies'); ExportCategory = 'Compliance Policy' }
        )
        $buckets = @{ DeviceConfigs = [System.Collections.Generic.List[object]]::new() }

        { Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets } | Should -Not -Throw
        $script:exportData.Count | Should -Be 0
    }

    It 'passes an AssignmentReason scriptblock through to Add-ExportData' {
        $categories = @(
            New-TestCategory @{ Id = 'DeviceConfigurations'; BucketKeys = @('DeviceConfigs'); ExportCategory = 'Device Configuration' }
        )
        $buckets = @{
            DeviceConfigs = @(
                [PSCustomObject]@{ id = 'cfg-1'; displayName = 'Config 1'; AssignmentSummary = 'Group Assignment - Sales (Filter: Corp Devices [Include])' }
                [PSCustomObject]@{ id = 'cfg-2'; displayName = 'Config 2'; AssignmentSummary = '' }
            )
        }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets -AssignmentReason { param($item) $item.AssignmentSummary }

        $script:exportData.Count | Should -Be 2
        $script:exportData[0].AssignmentReason | Should -BeExactly 'Group Assignment - Sales (Filter: Corp Devices [Include])'
        $script:exportData[0].FilterName | Should -BeExactly 'Corp Devices'
        $script:exportData[0].FilterType | Should -BeExactly 'Include'
        # The scriptblock returns the raw empty summary rather than the N/A default
        $script:exportData[1].AssignmentReason | Should -BeExactly ''
    }

    It 'adds caller-provided attribution columns uniformly to category rows' {
        $categories = @(
            New-TestCategory @{ Id = 'DeviceConfigurations'; BucketKeys = @('DeviceConfigs'); ExportCategory = 'Device Configuration' }
        )
        $buckets = @{
            DeviceConfigs = @(
                [PSCustomObject]@{ id = 'cfg-1'; displayName = 'Config 1' }
                [PSCustomObject]@{ id = 'cfg-2'; displayName = 'Config 2' }
            )
        }
        $attribution = [ordered]@{ GroupId = 'group-1'; GroupType = 'Microsoft 365' }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets -AdditionalProperties $attribution

        $script:exportData | Should -HaveCount 2
        @($script:exportData.GroupId | Select-Object -Unique) | Should -Be @('group-1')
        @($script:exportData.GroupType | Select-Object -Unique) | Should -Be @('Microsoft 365')
    }

    It 'rejects additional properties that collide with reserved export columns' {
        $item = [PSCustomObject]@{ id = 'cfg-1'; displayName = 'Config 1' }

        {
            Add-ExportData -ExportData $script:exportData -Category 'Device Configuration' -Items @($item) `
                -AdditionalProperties ([ordered]@{ Category = 'Overwritten' })
        } | Should -Throw '*conflicts with a reserved export column*'

        $script:exportData | Should -HaveCount 0
    }

    It 'covers every AllPolicies export label in registry order matching the pre-migration sequence' {
        $expectedLabels = @(
            'Device Configuration'
            'Imported Administrative Template'
            'Settings Catalog Policy'
            'Compliance Policy'
            'App Protection Policy'
            'App Configuration Policy'
            'Platform Scripts'
            'Proactive Remediation Scripts'
            'Autopilot Deployment Profile'
            'Enrollment Status Page'
            'Windows 365 Cloud PC Provisioning Policy'
            'Windows 365 Cloud PC User Setting'
            'Windows Feature Update Profile'
            'Windows Quality Update Profile'
            'Windows Driver Update Profile'
            'Windows Quality Update Policy'
            'Endpoint Security - Antivirus'
            'Endpoint Security - Disk Encryption'
            'Endpoint Security - Firewall'
            'Endpoint Security - EDR'
            'Endpoint Security - ASR'
            'Endpoint Security - Account Protection'
        )

        $categories = Get-IntuneCategoryDefinition -Audience AllPolicies
        $buckets = @{}
        foreach ($category in $categories) {
            foreach ($bucketKey in $category.BucketKeys) {
                $buckets[$bucketKey] = @([PSCustomObject]@{ id = "$bucketKey-1"; displayName = "$bucketKey item" })
            }
        }

        Add-CategoryExportData -ExportData $script:exportData -Categories $categories -Buckets $buckets

        @($script:exportData | ForEach-Object { $_.Category }) | Should -Be $expectedLabels
    }
}

Describe 'Get-IntuneCategoryDefinition' {
    It 'returns 21 fetchable categories plus Autopilot/ESP bucket placeholders for UserContext' {
        $categories = Get-IntuneCategoryDefinition -Audience UserContext
        @($categories | Where-Object { -not $_.BucketOnly }).Count | Should -Be 21
        @($categories | Where-Object { $_.BucketOnly }).Id | Should -Be @('DeploymentProfiles', 'ESPProfiles')
    }

    It 'returns 21 fetchable categories plus Autopilot/ESP bucket placeholders for DeviceContext' {
        $categories = Get-IntuneCategoryDefinition -Audience DeviceContext
        @($categories | Where-Object { -not $_.BucketOnly }).Count | Should -Be 21
        @($categories | Where-Object { $_.BucketOnly }).Id | Should -Be @('DeploymentProfiles', 'ESPProfiles')
    }

    It 'returns 23 categories including Windows Update, Imported Administrative Templates, Autopilot and ESP for GroupContext' {
        $categories = Get-IntuneCategoryDefinition -Audience GroupContext
        @($categories).Count | Should -Be 23
        @($categories | Where-Object { $_.BucketOnly }).Count | Should -Be 0
        $categories.Id | Should -Contain 'DeploymentProfiles'
        $categories.Id | Should -Contain 'ESPProfiles'
    }

    It 'returns 22 categories without Applications for AllPolicies' {
        $categories = Get-IntuneCategoryDefinition -Audience AllPolicies
        @($categories).Count | Should -Be 22
        $categories.Id | Should -Not -Contain 'Applications'
    }

    It 'returns 23 categories with a shared SearchResults bucket for Search' {
        $categories = Get-IntuneCategoryDefinition -Audience Search
        @($categories).Count | Should -Be 23
        foreach ($category in $categories) {
            $category.BucketKeys | Should -Be @('SearchResults')
        }
    }

    It 'returns 18 categories for Compare' {
        $categories = Get-IntuneCategoryDefinition -Audience Compare
        @($categories).Count | Should -Be 18
        $categories.Id | Should -Contain 'ShellScripts'
    }

    It 'returns a complete 23-category inventory for Effective targeting' {
        $categories = Get-IntuneCategoryDefinition -Audience Effective
        @($categories).Count | Should -Be 23
        @($categories | Where-Object { $_.BucketOnly }).Count | Should -Be 0
        ($categories | Where-Object Id -eq SettingsCatalog).EntityFilter | Should -Not -BeNullOrEmpty
    }

    It 'registers every Windows Update workload as an optional shared entity category' {
        $expected = [ordered]@{
            WindowsFeatureUpdates = 'windowsFeatureUpdateProfiles'
            WindowsQualityUpdates = 'windowsQualityUpdateProfiles'
            WindowsDriverUpdates = 'windowsDriverUpdateProfiles'
            WindowsQualityUpdatePolicies = 'windowsQualityUpdatePolicies'
        }
        foreach ($audience in @('UserContext', 'DeviceContext', 'GroupContext', 'AllPolicies', 'Search', 'Compare', 'Effective')) {
            $categories = Get-IntuneCategoryDefinition -Audience $audience
            foreach ($id in $expected.Keys) {
                $category = $categories | Where-Object Id -eq $id
                $category.EntityType | Should -BeExactly $expected[$id]
                $category.OptionalFeature | Should -BeTrue
            }
        }
    }

    It 'includes custom and mixed imported templates but excludes built-in-only configurations' {
        $category = @(Get-IntuneCategoryDefinition -Audience GroupContext | Where-Object { $_.Id -eq 'ImportedAdministrativeTemplates' })[0]
        $policies = @(
            [PSCustomObject]@{ id = 'custom'; policyConfigurationIngestionType = 'custom' }
            [PSCustomObject]@{ id = 'mixed'; policyConfigurationIngestionType = 'mixed' }
            [PSCustomObject]@{ id = 'built-in'; policyConfigurationIngestionType = 'builtIn' }
            [PSCustomObject]@{ id = 'unknown'; policyConfigurationIngestionType = 'unknown' }
        )

        @($policies | Where-Object $category.EntityFilter).id | Should -Be @('custom', 'mixed')
        $category.EntityType | Should -BeExactly 'groupPolicyConfigurations'
        $category.ExportCategory | Should -BeExactly 'Imported Administrative Template'
    }

    Context 'audience-specific SettingsCatalog filters' {
        BeforeAll {
            $script:windowsOnlyEsPolicy = [PSCustomObject]@{
                id                = 'sc-win-es'
                templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityFirewall' }
                platforms         = @('windows10')
            }
            $script:macOsEsPolicy = [PSCustomObject]@{
                id                = 'sc-mac-es'
                templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityDiskEncryption' }
                platforms         = @('macOS')
            }
            $script:plainPolicy = [PSCustomObject]@{
                id                = 'sc-plain'
                templateReference = $null
                platforms         = @('windows10AndLater')
            }
        }

        It 'GroupContext skips Windows-only ES settings-catalog policies but keeps the macOS ones' {
            $settingsCatalog = @(Get-IntuneCategoryDefinition -Audience GroupContext | Where-Object { $_.Id -eq 'SettingsCatalog' })[0]
            $kept = @(@($script:windowsOnlyEsPolicy, $script:macOsEsPolicy, $script:plainPolicy) | Where-Object $settingsCatalog.EntityFilter)
            $kept.id | Should -Be @('sc-mac-es', 'sc-plain')
        }

        It 'Search skips all ES settings-catalog policies' {
            $settingsCatalog = @(Get-IntuneCategoryDefinition -Audience Search | Where-Object { $_.Id -eq 'SettingsCatalog' })[0]
            $kept = @(@($script:windowsOnlyEsPolicy, $script:macOsEsPolicy, $script:plainPolicy) | Where-Object $settingsCatalog.EntityFilter)
            $kept.id | Should -Be @('sc-plain')
        }

        It 'UserContext and AllPolicies apply no SettingsCatalog filter' {
            foreach ($audience in @('UserContext', 'AllPolicies')) {
                $settingsCatalog = @(Get-IntuneCategoryDefinition -Audience $audience | Where-Object { $_.Id -eq 'SettingsCatalog' })[0]
                $settingsCatalog.EntityFilter | Should -BeNullOrEmpty
            }
        }
    }
}
