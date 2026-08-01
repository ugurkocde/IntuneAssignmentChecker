#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'ConvertTo-IntuneGroupInfo.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Get-IACNoAssignmentPlaceholder.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentFilter.ps1')
    . (Join-Path $moduleRoot 'Public/Compare-IntuneGroupAssignment.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:AssignmentFilterLookup = @{}

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
    function Get-TransitiveGroupMembership {
        param([string]$GroupId)
        @()
    }
}

Describe 'Compare-IntuneGroupAssignment' {
    BeforeEach {
        $script:groupA = '11111111-1111-1111-1111-111111111111'
        $script:groupB = '22222222-2222-2222-2222-222222222222'
        $script:csvPath = Join-Path $TestDrive 'comparison.csv'

        Mock Write-Host {}
        Mock Get-TransitiveGroupMembership { @() }
        Mock Add-IntentTemplateFamilyInfo {}

        Mock Get-IntuneEntities {
            switch ($EntityType) {
                'deviceConfigurations' {
                    @(
                        [PSCustomObject]@{ id = 'dc-1'; displayName = 'Shared Config' }
                        [PSCustomObject]@{ id = 'dc-2'; displayName = 'A Only Config' }
                        [PSCustomObject]@{ id = 'dc-3'; displayName = 'Excluded Config' }
                        [PSCustomObject]@{ id = 'dc-4'; displayName = 'Inherited Config' }
                        [PSCustomObject]@{ id = 'dc-5'; displayName = 'Filtered Config' }
                    )
                }
                'configurationPolicies' {
                    # ES-family Settings Catalog policy: legacy Compare surfaced it under
                    # Settings Catalog only, never under Endpoint Security (intents-only scope)
                    @(
                        [PSCustomObject]@{ id = 'escp-1'; name = 'ES CP Policy'; templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' } }
                    )
                }
                'deviceManagementScripts' {
                    @(
                        [PSCustomObject]@{ id = 'ps-1'; displayName = 'PS One' }
                        [PSCustomObject]@{ id = 'ps-2'; displayName = 'Excluded PS' }
                    )
                }
                'deviceHealthScripts' {
                    @(
                        [PSCustomObject]@{ id = 'hs-1'; displayName = 'Health One' }
                        [PSCustomObject]@{ id = 'hs-2'; displayName = 'Excluded Health' }
                    )
                }
                'deviceShellScripts' {
                    @(
                        [PSCustomObject]@{ id = 'ss-1'; displayName = 'Shell One' }
                    )
                }
                'deviceManagement/intents' {
                    @(
                        [PSCustomObject]@{ id = 'intent-av'; displayName = 'AV Intent Policy'; templateId = 'tmpl-av'; templateReference = [PSCustomObject]@{ templateFamily = 'endpointSecurityAntivirus' } }
                    )
                }
                'windowsFeatureUpdateProfiles' {
                    @([PSCustomObject]@{ id = 'feature-1'; displayName = 'Windows 11 24H2'; roleScopeTagIds = @('0') })
                }
                default { @() }
            }
        }

        Mock Get-IntuneAssignments {
            $records = switch ($EntityId) {
                'dc-1' {
                    @(
                        [PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }
                        [PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupB; FilterId = $null; FilterType = $null }
                    )
                }
                'dc-2' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'dc-3' { @([PSCustomObject]@{ Reason = 'Direct Exclusion'; GroupId = $script:groupB; FilterId = $null; FilterType = $null }) }
                'dc-4' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = 'parent-a'; FilterId = $null; FilterType = $null }) }
                'dc-5' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = 'f-1'; FilterType = 'include' }) }
                'escp-1' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'ps-1' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'ps-2' { @([PSCustomObject]@{ Reason = 'Direct Exclusion'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'hs-1' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'hs-2' { @([PSCustomObject]@{ Reason = 'Direct Exclusion'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                'feature-1' { @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupA; FilterId = $null; FilterType = $null }) }
                default { @() }
            }
            # Mirror the real helper: only assignments targeting the requested group ids
            @($records | Where-Object { $GroupIds -contains $_.GroupId })
        }

        Mock Invoke-IACGraphRequest {
            if ($Uri -like "*/beta/groups*displayName eq*") {
                if ($Uri -like "*O''Brien Team*") {
                    return @{ value = @(@{ id = $script:groupB; displayName = "O'Brien Team" }) }
                }
                return @{ value = @() }
            }
            if ($Uri -like "*/beta/groups/$($script:groupA)*") {
                return @{ id = $script:groupA; displayName = 'Group A'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true }
            }
            if ($Uri -like "*/beta/groups/$($script:groupB)*") {
                return @{ id = $script:groupB; displayName = 'Group B'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false; mail = 'groupb@contoso.com' }
            }
            if ($Uri -like '*mobileApps*isAssigned eq true*') {
                return @{ value = @(
                        [PSCustomObject]@{ id = 'app-shared'; displayName = 'Shared App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-excluded'; displayName = 'Excluded App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-featured'; displayName = 'Featured App'; isFeatured = $true }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-shared')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupA } }
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupB } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-excluded')/assignments*") {
                # Exclusion-only app assignment (issue #126 shape): stays visible, tagged [EXCLUDED]
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $script:groupA } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-featured')/assignments*") {
                return @{ value = @(
                        @{ intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupA } }
                    )
                }
            }
            if ($Uri -like "*deviceManagement/intents/intent-av/assignments*") {
                return @{ value = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupB } }
                    )
                }
            }
            if ($Uri -like "*deviceShellScripts('ss-1')/groupAssignments*") {
                return @{ value = @(
                        @{ targetGroupId = $script:groupB }
                    )
                }
            }
            return @{ value = @() }
        }
    }

    Context 'input validation' {
        It 'requires at least two groups' {
            Compare-IntuneGroupAssignment -CompareGroupNames 'Only One Group'

            Should -Invoke Write-Host -ParameterFilter { $Object -eq 'Please provide at least two groups to compare.' }
            Should -Invoke Get-IntuneEntities -Exactly 0
        }

        It 'escapes single quotes in group name lookups' {
            Compare-IntuneGroupAssignment -CompareGroupNames "O'Brien Team, $($script:groupA)" -ExportToCSV -ExportPath $script:csvPath

            Should -Invoke Invoke-IACGraphRequest -ParameterFilter { $Uri -like "*displayName eq 'O''Brien Team'*" }
        }

        It 'skips a GUID lookup response that omits the group Object ID' {
            Mock Invoke-IACGraphRequest {
                @{ displayName = 'Incomplete Group'; groupTypes = @('Unified'); mailEnabled = $true }
            } -ParameterFilter { $Uri -like "*/beta/groups/$($script:groupA)*" }

            Compare-IntuneGroupAssignment -CompareGroupNames "$($script:groupA), $($script:groupB)" -ExportToCSV -ExportPath $script:csvPath

            Should -Invoke Write-Host -Exactly 1 -ParameterFilter {
                $Object -eq "The group lookup for '$($script:groupA)' returned an invalid response without an Object ID."
            }
            Should -Invoke Get-IntuneAssignments -Exactly 0 -ParameterFilter {
                $null -eq $GroupIds -or $GroupIds -contains $null
            }
        }
    }

    Context 'two-group comparison matrix' {
        BeforeEach {
            Compare-IntuneGroupAssignment -CompareGroupNames "$($script:groupA), $($script:groupB)" -ExportToCSV -ExportPath $script:csvPath
            $script:rows = @(Import-Csv $script:csvPath)
        }

        It 'marks a policy assigned to both groups as Included for both' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Shared Config' }
            $row.Category | Should -BeExactly 'Device Configurations'
            $row.'Group A' | Should -BeExactly 'Included'
            $row.'Group B' | Should -BeExactly 'Included'
        }

        It 'marks a policy assigned to one group only in that column' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'A Only Config' }
            $row.'Group A' | Should -BeExactly 'Included'
            $row.'Group B' | Should -BeExactly ''
        }

        It 'marks group exclusions on policies as Excluded' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Excluded Config' }
            $row.'Group A' | Should -BeExactly ''
            $row.'Group B' | Should -BeExactly 'Excluded'
        }

        It 'keeps the assignment filter suffix on the policy name' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Filtered Config (Filter: Unknown Filter (f-1) [Include])' }
            $row.'Group A' | Should -BeExactly 'Included'
        }

        It 'keeps exclusion-only app assignments visible and tagged Excluded' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Excluded App' }
            $row.Category | Should -BeExactly 'Required Apps'
            $row.'Group A' | Should -BeExactly 'Excluded'
            $row.'Group B' | Should -BeExactly ''
        }

        It 'buckets every assigned app by intent, including featured apps' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Shared App' }
            $row.Category | Should -BeExactly 'Required Apps'
            $row.'Group A' | Should -BeExactly 'Included'
            $row.'Group B' | Should -BeExactly 'Included'
            $featuredRow = $script:rows | Where-Object { $_.PolicyName -eq 'Featured App' }
            $featuredRow.Category | Should -BeExactly 'Available Apps'
            $featuredRow.'Group A' | Should -BeExactly 'Included'
        }

        It 'labels platform and shell scripts with their type marker' {
            $psRow = $script:rows | Where-Object { $_.PolicyName -eq 'PS One (PowerShell)' }
            $psRow.Category | Should -BeExactly 'Platform Scripts'
            $psRow.'Group A' | Should -BeExactly 'Included'

            $shellRow = $script:rows | Where-Object { $_.PolicyName -eq 'Shell One (Shell)' }
            $shellRow.Category | Should -BeExactly 'Platform Scripts'
            $shellRow.'Group B' | Should -BeExactly 'Included'
            $shellRow.'Group A' | Should -BeExactly ''
        }

        It 'keeps the legacy quirk that platform script exclusions count as Included' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Excluded PS (PowerShell)' }
            $row.'Group A' | Should -BeExactly 'Included'
        }

        It 'keeps the legacy inclusion-only matching for health scripts' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Health One' }
            $row.Category | Should -BeExactly 'Proactive Remediation Scripts'
            $row.'Group A' | Should -BeExactly 'Included'
            @($script:rows | Where-Object { $_.PolicyName -like 'Excluded Health*' }).Count | Should -Be 0
        }

        It 'keeps the legacy intents-only Endpoint Security scope' {
            $intentRow = $script:rows | Where-Object { $_.PolicyName -eq 'AV Intent Policy' }
            $intentRow.Category | Should -BeExactly 'Endpoint Security - Antivirus'
            $intentRow.'Group B' | Should -BeExactly 'Included'

            # The ES-family configurationPolicies policy stays under Settings Catalog only
            $cpRows = @($script:rows | Where-Object { $_.PolicyName -eq 'ES CP Policy' })
            $cpRows.Count | Should -Be 1
            $cpRows[0].Category | Should -BeExactly 'Settings Catalog'
            $cpRows[0].'Group A' | Should -BeExactly 'Included'
        }

        It 'includes Windows Update policies in the comparison matrix' {
            $row = $script:rows | Where-Object { $_.PolicyName -eq 'Windows 11 24H2' }
            $row.Category | Should -BeExactly 'Windows Feature Update Profiles'
            $row.'Group A' | Should -BeExactly 'Included'
            $row.'Group B' | Should -BeExactly ''
        }

        It 'never fetches assignments for ES configurationPolicies policies (prefilter)' {
            # escp-1 assignments are fetched once per group by the Settings Catalog
            # category; the Endpoint Security phase 1 must not add extra fetches
            Should -Invoke Get-IntuneAssignments -Exactly 2 -ParameterFilter { $EntityId -eq 'escp-1' }
        }

        It 'fetches each entity set from Graph once across both groups' {
            Should -Invoke Get-IntuneEntities -Exactly 1 -ParameterFilter { $EntityType -eq 'deviceConfigurations' }
            Should -Invoke Get-IntuneEntities -Exactly 1 -ParameterFilter { $EntityType -eq 'deviceManagement/intents' }
            Should -Invoke Get-IntuneEntities -Exactly 1 -ParameterFilter { $EntityType -eq 'deviceShellScripts' }
            Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter { $Uri -like '*mobileApps*isAssigned eq true*' }
        }
    }

    Context 'nested group support' {
        It 'tags assignments inherited from parent groups' {
            Mock Get-TransitiveGroupMembership {
                if ($GroupId -eq $script:groupA) {
                    return @([PSCustomObject]@{ id = 'parent-a'; displayName = 'Parent A' })
                }
                @()
            }

            Compare-IntuneGroupAssignment -CompareGroupNames "$($script:groupA), $($script:groupB)" -IncludeNestedGroups -ExportToCSV -ExportPath $script:csvPath
            $rows = @(Import-Csv $script:csvPath)

            $row = $rows | Where-Object { $_.PolicyName -eq 'Inherited Config' }
            $row.'Group A' | Should -BeExactly 'Inherited'
            $row.'Group B' | Should -BeExactly ''

            Should -Invoke Get-IntuneAssignments -ParameterFilter {
                $EntityId -eq 'dc-1' -and $GroupIds.Count -eq 2 -and $GroupIds -contains $script:groupA -and $GroupIds -contains 'parent-a'
            }
        }
    }
}
