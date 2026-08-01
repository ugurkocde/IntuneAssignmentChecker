#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'Get-Separator.ps1')
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IntuneGroupInfo.ps1')
    . (Join-Path $modulePrivate 'Show-CategoryResultTable.ps1')
    . (Join-Path $modulePrivate 'Get-AppProtectionAssignmentUri.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneCategoryDefinition.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Select-IACAssignmentRecord.ps1')
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
    function Invoke-IACGraphRequest {
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
        $script:ScopeTagLookup = @{}
        Mock Write-Host {}
        Mock Get-IntuneEntities { @() }
        Mock Get-IntuneAssignments { @() }
        Mock Add-IntentTemplateFamilyInfo {}
        Mock Get-TransitiveGroupMembership { @() }
        Mock Get-GroupInfo {
            [PSCustomObject]@{
                Id = $GroupId; DisplayName = 'Sales Team'; GroupType = 'Security'; MembershipType = 'Assigned'
                IsMicrosoft365 = $false; Mail = $null; Success = $true
            }
        }
        Mock Export-ResultsIfRequested { $script:capturedExport = @($ExportData) }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*mobileApps*isAssigned eq true*') {
                return @{
                    value = @(
                        [PSCustomObject]@{ id = 'app-inc'; displayName = 'Included App'; isFeatured = $false; isBuiltIn = $false; roleScopeTagIds = @('0', 'tag-finance') }
                        [PSCustomObject]@{ id = 'app-exc'; displayName = 'Excluded Only App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-both'; displayName = 'Included And Excluded App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-exc-uninstall'; displayName = 'Excluded Uninstall App'; isFeatured = $false; isBuiltIn = $false }
                        [PSCustomObject]@{ id = 'app-featured-required'; displayName = 'Featured Required App'; isFeatured = $true; roleScopeTagIds = @('0') }
                        [PSCustomObject]@{ id = 'app-featured-available'; displayName = 'Featured Available App'; isFeatured = $true; roleScopeTagIds = @('0') }
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
            if ($Uri -like "*mobileApps('app-featured-required')/assignments*") {
                return @{ value = @(
                        @{ intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupGuid; deviceAndAppManagementAssignmentFilterId = 'shared-filter'; deviceAndAppManagementAssignmentFilterType = 'include' } }
                    )
                }
            }
            if ($Uri -like "*mobileApps('app-featured-available')/assignments*") {
                return @{ value = @(
                        @{ intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $script:groupGuid; deviceAndAppManagementAssignmentFilterId = 'shared-filter'; deviceAndAppManagementAssignmentFilterType = 'include' } }
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
        $script:capturedExport[0].GroupId | Should -BeExactly $script:groupGuid
        $script:capturedExport[0].GroupName | Should -BeExactly 'Sales Team'
        $script:capturedExport[0].GroupType | Should -BeExactly 'Security'
        $script:capturedExport[0].MembershipType | Should -BeExactly 'Assigned'
    }

    It 'recognizes a Microsoft 365 group by object ID and exports its metadata' {
        Mock Get-GroupInfo {
            [PSCustomObject]@{
                Id = $GroupId; DisplayName = 'Messaging Team'; GroupType = 'Microsoft 365'; MembershipType = 'Dynamic'
                IsMicrosoft365 = $true; Mail = 'messaging@contoso.com'; Success = $true
            }
        }

        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $groupRow = $script:capturedExport[0]
        $groupRow.Item | Should -BeExactly "Messaging Team (ID: $($script:groupGuid))"
        $groupRow.GroupType | Should -BeExactly 'Microsoft 365'
        $groupRow.MembershipType | Should -BeExactly 'Dynamic'
        $groupRow.GroupMail | Should -BeExactly 'messaging@contoso.com'
        Should -Invoke Write-Host -ParameterFilter {
            $Object -eq 'Group details: Type: Microsoft 365; Membership: Dynamic; Mail: messaging@contoso.com'
        }

        $csvPath = Join-Path $TestDrive 'm365-group.csv'
        $script:capturedExport | Export-Csv -Path $csvPath -NoTypeInformation
        $csvGroupRow = Import-Csv -Path $csvPath | Where-Object Category -eq 'Group'
        $csvGroupRow.GroupType | Should -BeExactly 'Microsoft 365'
        $csvGroupRow.GroupMail | Should -BeExactly 'messaging@contoso.com'
        $csvPolicyRow = Import-Csv -Path $csvPath | Where-Object Category -ne 'Group' | Select-Object -First 1
        $csvPolicyRow.GroupId | Should -BeExactly $script:groupGuid
        $csvPolicyRow.GroupName | Should -BeExactly 'Messaging Team'
        $csvPolicyRow.GroupType | Should -BeExactly 'Microsoft 365'
        $csvPolicyRow.MembershipType | Should -BeExactly 'Dynamic'
        $csvPolicyRow.GroupMail | Should -BeExactly 'messaging@contoso.com'
    }

    It 'recognizes a Microsoft 365 group by display name without filtering it out' {
        Mock Invoke-IACGraphRequest {
            @{
                value = @([PSCustomObject]@{
                        id = 'm365-by-name'; displayName = 'Messaging Team'; groupTypes = @('Unified')
                        mailEnabled = $true; securityEnabled = $false; mail = 'messaging@contoso.com'
                    })
            }
        } -ParameterFilter { $Uri -like '*/beta/groups?*displayName eq*' }

        Get-IntuneGroupAssignment -GroupNames 'Messaging Team' -IncludeNestedGroups

        $groupRow = $script:capturedExport[0]
        $groupRow.Item | Should -BeExactly 'Messaging Team (ID: m365-by-name)'
        $groupRow.GroupType | Should -BeExactly 'Microsoft 365'
        $groupRow.GroupMail | Should -BeExactly 'messaging@contoso.com'
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like '*/beta/groups?*' -and
            $Uri -match '\$select=id,displayName,groupTypes,mailEnabled,securityEnabled,mail'
        }
    }

    It 'attributes every policy row in a multi-group export to its source group' {
        $secondGroupGuid = '22222222-2222-2222-2222-222222222222'
        Mock Get-GroupInfo {
            if ($GroupId -eq $script:groupGuid) {
                return [PSCustomObject]@{
                    Id = $GroupId; DisplayName = 'Messaging Team'; GroupType = 'Microsoft 365'; MembershipType = 'Assigned'
                    IsMicrosoft365 = $true; Mail = 'messaging@contoso.com'; Success = $true
                }
            }
            [PSCustomObject]@{
                Id = $GroupId; DisplayName = 'Security Team'; GroupType = 'Security'; MembershipType = 'Dynamic'
                IsMicrosoft365 = $false; Mail = $null; Success = $true
            }
        }
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                return @([PSCustomObject]@{ id = 'cfg-shared'; displayName = 'Shared Configuration' })
            }
            @()
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'cfg-shared') {
                $targetGroupId = @($GroupIds)[0]
                return @([PSCustomObject]@{
                        Reason = 'Direct Assignment'; GroupId = $targetGroupId; FilterId = $null; FilterType = $null
                    })
            }
            @()
        }

        Get-IntuneGroupAssignment -GroupNames "$($script:groupGuid),$secondGroupGuid" -IncludeNestedGroups

        $policyRows = @($script:capturedExport | Where-Object { $_.Item -eq 'Shared Configuration (ID: cfg-shared)' })
        $policyRows | Should -HaveCount 2
        ($policyRows | Where-Object GroupId -eq $script:groupGuid).GroupName | Should -BeExactly 'Messaging Team'
        ($policyRows | Where-Object GroupId -eq $script:groupGuid).GroupType | Should -BeExactly 'Microsoft 365'
        ($policyRows | Where-Object GroupId -eq $secondGroupGuid).GroupName | Should -BeExactly 'Security Team'
        ($policyRows | Where-Object GroupId -eq $secondGroupGuid).GroupType | Should -BeExactly 'Security'
        @($script:capturedExport | Where-Object {
                -not $_.PSObject.Properties['GroupId'] -or -not $_.PSObject.Properties['GroupName'] -or
                -not $_.PSObject.Properties['GroupType'] -or -not $_.PSObject.Properties['MembershipType'] -or
                -not $_.PSObject.Properties['GroupMail']
            }) | Should -HaveCount 0
    }

    It 'keeps exclusion-only apps under the excluding assignment intent (issue #126)' {
        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $availableRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Available Apps' })
        $excludedAvailableRow = $availableRows | Where-Object { $_.Item -eq 'Excluded Only App (ID: app-exc)' }
        @($excludedAvailableRow).Count | Should -Be 1
        $excludedAvailableRow.AssignmentReason | Should -BeExactly 'Group Exclusion'

        $uninstallRows = @($script:capturedExport | Where-Object { $_.Category -eq 'Uninstall Apps' })
        $uninstallRows.Count | Should -Be 1
        $uninstallRows[0].Item | Should -BeExactly 'Excluded Uninstall App (ID: app-exc-uninstall)'
        $uninstallRows[0].AssignmentReason | Should -BeExactly 'Group Exclusion'
    }

    It 'requests and exports every application scope tag (issue #131)' {
        $script:ScopeTagLookup = @{ '0' = 'Default'; 'tag-finance' = 'Finance' }

        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $appRow = $script:capturedExport | Where-Object { $_.Item -eq 'Included App (ID: app-inc)' }
        $appRow.ScopeTags | Should -BeExactly 'Default, Finance'
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like '*deviceAppManagement/mobileApps?*' -and
            $Uri -match '\$select=[^&]*roleScopeTagIds'
        }
    }

    It 'returns paged featured required and available apps assigned through the same group and filter (issue #134)' {
        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $requiredRow = $script:capturedExport | Where-Object { $_.Item -eq 'Featured Required App (ID: app-featured-required)' }
        $availableRow = $script:capturedExport | Where-Object { $_.Item -eq 'Featured Available App (ID: app-featured-available)' }

        $requiredRow.Category | Should -BeExactly 'Required Apps'
        $availableRow.Category | Should -BeExactly 'Available Apps'
        $requiredRow.AssignmentReason | Should -BeExactly 'Direct Assignment (Filter: Unknown Filter (shared-filter) [Include])'
        $availableRow.AssignmentReason | Should -BeExactly 'Direct Assignment (Filter: Unknown Filter (shared-filter) [Include])'
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter { $Uri -like '*mobileApps*isAssigned eq true*' }
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

    It 'returns custom and mixed Imported Administrative Templates but excludes built-in-only configurations' {
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'groupPolicyConfigurations') {
                return @(
                    [PSCustomObject]@{ id = 'iat-custom'; displayName = 'Imported Chrome ADMX'; policyConfigurationIngestionType = 'custom'; roleScopeTagIds = @('0') }
                    [PSCustomObject]@{ id = 'iat-mixed'; displayName = 'Mixed Office ADMX'; policyConfigurationIngestionType = 'mixed'; roleScopeTagIds = @('0') }
                    [PSCustomObject]@{ id = 'iat-built-in'; displayName = 'Built-in Policy'; policyConfigurationIngestionType = 'builtIn'; roleScopeTagIds = @('0') }
                )
            }
            @()
        }
        Mock Get-IntuneAssignments {
            if ($EntityType -eq 'groupPolicyConfigurations' -and $EntityId -in @('iat-custom', 'iat-mixed')) {
                return @([PSCustomObject]@{ Reason = 'Direct Assignment'; GroupId = $script:groupGuid; FilterId = $null; FilterType = $null })
            }
            @()
        }

        Get-IntuneGroupAssignment -GroupNames $script:groupGuid -IncludeNestedGroups

        $rows = @($script:capturedExport | Where-Object { $_.Category -eq 'Imported Administrative Template' })
        @($rows | ForEach-Object { $_.Item }) | Should -Be @('Imported Chrome ADMX (ID: iat-custom)', 'Mixed Office ADMX (ID: iat-mixed)')
        @($rows.AssignmentReason | Select-Object -Unique) | Should -Be @('Direct Assignment')
        Should -Invoke Get-IntuneAssignments -Exactly 0 -ParameterFilter {
            $EntityType -eq 'groupPolicyConfigurations' -and $EntityId -eq 'iat-built-in'
        }
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
