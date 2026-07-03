#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'Get-Separator.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'Show-CategoryResultTable.ps1')
    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'Invoke-IntuneCategoryScan.ps1')
    . (Join-Path $modulePrivate 'Get-GroupAssignmentReasons.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentFilter.ps1')
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Add-CategoryExportData.ps1')
    . (Join-Path $moduleRoot 'Public/Get-IntuneGroupAssignment.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{}

    # Stub collaborators so Pester can mock them per test
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
    function Get-TransitiveGroupMembership {
        param([string]$GroupId)
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

Describe 'Show-CategoryResultTable' {
    BeforeEach {
        $script:consoleLines = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $script:consoleLines.Add("$ForegroundColor|$Object") }
    }

    It 'renders the section header block in Cyan' {
        Show-CategoryResultTable -Title 'Device Configurations' -Items @()

        $script:consoleLines[0] | Should -BeExactly "Cyan|`n$('-' * ('Device Configurations'.Length + 16))"
        $script:consoleLines[1] | Should -BeExactly 'Cyan|------- Device Configurations -------'
    }

    It 'renders the default empty message in Gray when there are no items' {
        Show-CategoryResultTable -Title 'Compliance Policies' -Items @()

        $script:consoleLines | Should -Contain 'Gray|No Compliance Policies found.'
    }

    It 'renders a custom empty message when provided' {
        Show-CategoryResultTable -Title 'Compliance Policies' -Items $null -EmptyMessage 'No Compliance Policies found for this group.'

        $script:consoleLines | Should -Contain 'Gray|No Compliance Policies found for this group.'
    }

    It 'renders the column header in Yellow for non-empty sections' {
        $items = @([PSCustomObject]@{ id = 'pol-1'; displayName = 'Policy One'; AssignmentReason = 'Direct Assignment' })
        Show-CategoryResultTable -Title 'Policies' -Items $items

        $expectedHeader = 'Yellow|' + ('{0,-40} {1,-15} {2,-20} {3,-30} {4,-35}' -f 'Policy Name', 'Platform', 'Scope Tags', 'ID', 'Assignment')
        $script:consoleLines | Should -Contain $expectedHeader
    }

    It 'applies the legacy row coloring per assignment reason' {
        $items = @(
            [PSCustomObject]@{ id = 'p1'; displayName = 'Direct Policy'; AssignmentReason = 'Direct Assignment' }
            [PSCustomObject]@{ id = 'p2'; displayName = 'Inherited Policy'; AssignmentReason = 'Inherited (via Parent)' }
            [PSCustomObject]@{ id = 'p3'; displayName = 'Excluded Policy'; AssignmentReason = 'Direct Exclusion' }
            [PSCustomObject]@{ id = 'p4'; displayName = 'Parent Excluded Policy'; AssignmentReason = 'Inherited Exclusion (via Parent)' }
            [PSCustomObject]@{ id = 'p5'; displayName = 'Group Excluded App'; AssignmentReason = 'Group Exclusion' }
        )
        Show-CategoryResultTable -Title 'Policies' -Items $items

        @($script:consoleLines | Where-Object { $_ -like 'White|Direct Policy*' }).Count | Should -Be 1
        @($script:consoleLines | Where-Object { $_ -like 'DarkYellow|Inherited Policy*' }).Count | Should -Be 1
        @($script:consoleLines | Where-Object { $_ -like 'Red|Excluded Policy*' }).Count | Should -Be 1
        @($script:consoleLines | Where-Object { $_ -like 'Magenta|Parent Excluded Policy*' }).Count | Should -Be 1
        # Legacy quirk: "Group Exclusion" (issue #126 app reason) stays White
        @($script:consoleLines | Where-Object { $_ -like 'White|Group Excluded App*' }).Count | Should -Be 1
    }

    It 'falls back to displayName, then name, then Unnamed Profile by default' {
        $items = @(
            [PSCustomObject]@{ id = 'p1'; displayName = 'Display Name'; name = 'Name'; AssignmentReason = 'Direct Assignment' }
            [PSCustomObject]@{ id = 'p2'; displayName = $null; name = 'Name Only'; AssignmentReason = 'Direct Assignment' }
            [PSCustomObject]@{ id = 'p3'; displayName = $null; name = $null; AssignmentReason = 'Direct Assignment' }
        )
        Show-CategoryResultTable -Title 'Policies' -Items $items

        @($script:consoleLines | Where-Object { $_ -like 'White|Display Name *' }).Count | Should -Be 1
        @($script:consoleLines | Where-Object { $_ -like 'White|Name Only *' }).Count | Should -Be 1
        @($script:consoleLines | Where-Object { $_ -like 'White|Unnamed Profile *' }).Count | Should -Be 1
    }

    It 'uses a caller-provided GetName scriptblock' {
        $items = @([PSCustomObject]@{ id = 'p1'; displayName = 'Display'; name = 'Preferred'; AssignmentReason = 'Direct Assignment' })
        Show-CategoryResultTable -Title 'Policies' -Items $items -GetName { param($item) $item.name }

        @($script:consoleLines | Where-Object { $_ -like 'White|Preferred *' }).Count | Should -Be 1
    }

    It 'truncates long values exactly like the legacy table' {
        $longName = 'A' * 50
        $items = @([PSCustomObject]@{ id = 'p1'; displayName = $longName; AssignmentReason = 'Direct Assignment' })
        Show-CategoryResultTable -Title 'Policies' -Items $items

        $expectedName = ('A' * 34) + '...'
        @($script:consoleLines | Where-Object { $_ -like "White|$expectedName *" }).Count | Should -Be 1
    }
}

Describe 'Get-IntuneGroupAssignment' {
    BeforeEach {
        $script:groupGuid = '11111111-1111-1111-1111-111111111111'
        $script:capturedExport = $null
        Mock Write-Host {}
        Mock Get-IntuneEntities { @() }
        Mock Get-IntuneAssignments { @() }
        Mock Add-IntentTemplateFamilyInfo {}
        Mock Get-TransitiveGroupMembership { @() }
        Mock Get-GroupInfo { @{ Id = $GroupId; DisplayName = 'Sales Team'; Success = $true } }
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*mobileApps*isAssigned eq true*') {
                return @{ value = @(
                        [PSCustomObject]@{ id = 'app-inc'; displayName = 'Included App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-exc'; displayName = 'Excluded Only App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-both'; displayName = 'Included And Excluded App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-exc-uninstall'; displayName = 'Excluded Uninstall App'; isFeatured = $false; isBuiltIn = $false }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-inc')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupGuid } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-exc')/assignments*") {
                # Issue #126 fixture: exclusion-only assignment for the checked group
                return @{ value = @(
                        @{ intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $script:groupGuid } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-both')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupGuid } }
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $script:groupGuid } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-exc-uninstall')/assignments*") {
                return @{ value = @(
                        @{ intent = 'uninstall'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $script:groupGuid } }
                    )
                }
            }
            return @{ value = @() }
        }
    }

    It 'exports the corrected Group row first' {
        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $script:capturedExport[0].Category | Should -BeExactly 'Group'
        $script:capturedExport[0].Item | Should -BeExactly "Sales Team (ID: $($script:groupGuid))"
        $script:capturedExport[0].AssignmentReason | Should -BeExactly 'N/A'
    }

    It 'keeps exclusion-only apps under the excluding assignment intent (issue #126)' {
        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $availableRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Available Apps' })
        $availableRows.Count | Should -Be 1
        $availableRows[0].Item | Should -BeExactly 'Excluded Only App (ID: app-exc)'
        $availableRows[0].AssignmentReason | Should -BeExactly 'Group Exclusion'

        $uninstallRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Uninstall Apps' })
        $uninstallRows.Count | Should -Be 1
        $uninstallRows[0].Item | Should -BeExactly 'Excluded Uninstall App (ID: app-exc-uninstall)'
        $uninstallRows[0].AssignmentReason | Should -BeExactly 'Group Exclusion'
    }

    It 'prefers the inclusion intent when the group is both included and excluded' {
        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $requiredRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Required Apps' })
        @($requiredRows | Where-Object { $_.Item -eq 'Included App (ID: app-inc)' -and $_.AssignmentReason -eq 'Direct Assignment' }).Count | Should -Be 1
        @($requiredRows | Where-Object { $_.Item -eq 'Included And Excluded App (ID: app-both)' -and $_.AssignmentReason -eq 'Direct Assignment; Group Exclusion' }).Count | Should -Be 1
    }

    It 'resolves inherited assignment reasons through the parent group map' {
        Mock Get-TransitiveGroupMembership { @([PSCustomObject]@{ id = 'parent-1'; displayName = 'All Staff' }) }
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                return @([PSCustomObject]@{ id = 'dc-1'; displayName = 'Config One' })
            }
            @()
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'dc-1') {
                return @([PSCustomObject]@{ Reason = 'Direct Exclusion'; GroupId = 'parent-1'; FilterId = $null; FilterType = $null })
            }
            @()
        }

        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $configRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Device Configuration' })
        $configRows.Count | Should -Be 1
        $configRows[0].AssignmentReason | Should -BeExactly 'Inherited Exclusion (via All Staff)'
    }

    It 'passes the direct and parent group ids to the category scan' {
        Mock Get-TransitiveGroupMembership { @([PSCustomObject]@{ id = 'parent-1'; displayName = 'All Staff' }) }
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                return @([PSCustomObject]@{ id = 'dc-1'; displayName = 'Config One' })
            }
            @()
        }

        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        Should -Invoke Get-IntuneAssignments -ParameterFilter {
            $EntityId -eq 'dc-1' -and $GroupIds.Count -eq 2 -and $GroupIds -contains $script:groupGuid -and $GroupIds -contains 'parent-1'
        }
    }
}
