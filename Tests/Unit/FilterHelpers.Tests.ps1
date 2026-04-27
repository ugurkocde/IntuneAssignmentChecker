#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'

    . (Join-Path $modulePrivate 'Format-AssignmentFilter.ps1')
    . (Join-Path $modulePrivate 'Format-AssignmentSummaryLine.ps1')
    . (Join-Path $modulePrivate 'Get-AllTargetReason.ps1')
    . (Join-Path $modulePrivate 'Resolve-AssignmentReason.ps1')
    . (Join-Path $modulePrivate 'Get-GroupAssignmentReasons.ps1')
    . (Join-Path $modulePrivate 'Resolve-SimulatedAssignmentDelta.ps1')

    function Get-GroupInfo {
        param($GroupId)
        return @{ DisplayName = "MockGroup-$GroupId"; Success = $true }
    }

    $script:AssignmentFilterLookup = @{
        'filter-win11' = [PSCustomObject]@{ Name = 'Windows 11 Corp'; Platform = 'windows10AndLater' }
        'filter-kiosk' = [PSCustomObject]@{ Name = 'Kiosk Devices';  Platform = 'windows10AndLater' }
    }

    function New-Assignment {
        param(
            [string]$Reason,
            [string]$GroupId,
            [string]$FilterId,
            [string]$FilterType
        )
        [PSCustomObject]@{
            Reason     = $Reason
            GroupId    = $GroupId
            FilterId   = $FilterId
            FilterType = $FilterType
        }
    }
}

Describe 'Format-AssignmentFilter' {
    Context 'no filter' {
        It 'returns empty string when FilterType is null' {
            Format-AssignmentFilter -FilterId $null -FilterType $null | Should -BeExactly ''
        }

        It 'returns empty string when FilterType is "none"' {
            Format-AssignmentFilter -FilterId 'filter-win11' -FilterType 'none' | Should -BeExactly ''
        }

        It 'returns empty string when FilterId is missing but FilterType is set' {
            Format-AssignmentFilter -FilterId $null -FilterType 'include' | Should -BeExactly ''
        }

        It 'returns empty string when FilterId is empty string' {
            Format-AssignmentFilter -FilterId '' -FilterType 'include' | Should -BeExactly ''
        }
    }

    Context 'include filter' {
        It 'formats known filter with Include label' {
            $r = Format-AssignmentFilter -FilterId 'filter-win11' -FilterType 'include'
            $r | Should -BeExactly ' (Filter: Windows 11 Corp [Include])'
        }

        It 'begins with a leading space for inline concatenation' {
            $r = Format-AssignmentFilter -FilterId 'filter-win11' -FilterType 'include'
            $r | Should -Match '^\s'
        }
    }

    Context 'exclude filter' {
        It 'formats known filter with Exclude label' {
            $r = Format-AssignmentFilter -FilterId 'filter-kiosk' -FilterType 'exclude'
            $r | Should -BeExactly ' (Filter: Kiosk Devices [Exclude])'
        }
    }

    Context 'unknown filter ID' {
        It 'falls back to "Unknown Filter (id)" label' {
            $r = Format-AssignmentFilter -FilterId 'does-not-exist' -FilterType 'include'
            $r | Should -BeExactly ' (Filter: Unknown Filter (does-not-exist) [Include])'
        }
    }

    Context 'lookup not initialized' {
        It 'still returns Unknown Filter marker rather than throwing' {
            $saved = $script:AssignmentFilterLookup
            $script:AssignmentFilterLookup = $null
            try {
                $r = Format-AssignmentFilter -FilterId 'filter-win11' -FilterType 'include'
                $r | Should -BeExactly ' (Filter: Unknown Filter (filter-win11) [Include])'
            }
            finally {
                $script:AssignmentFilterLookup = $saved
            }
        }
    }
}

Describe 'Format-AssignmentSummaryLine' {
    It 'formats All Users with no filter' {
        $a = New-Assignment -Reason 'All Users'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'All Users'
    }

    It 'formats All Devices with a filter' {
        $a = New-Assignment -Reason 'All Devices' -FilterId 'filter-win11' -FilterType 'include'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'All Devices (Filter: Windows 11 Corp [Include])'
    }

    It 'formats Group Assignment with a group name' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'Group Assignment - MockGroup-g1'
    }

    It 'formats Group Assignment with a filter' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1' -FilterId 'filter-win11' -FilterType 'include'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'Group Assignment - MockGroup-g1 (Filter: Windows 11 Corp [Include])'
    }

    It 'formats Group Exclusion' {
        $a = New-Assignment -Reason 'Group Exclusion' -GroupId 'g2'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'Group Exclusion - MockGroup-g2'
    }

    It 'formats Direct Assignment (from Get-IntuneAssignments when GroupIds are specified)' {
        $a = New-Assignment -Reason 'Direct Assignment' -GroupId 'g1' -FilterId 'filter-win11' -FilterType 'exclude'
        Format-AssignmentSummaryLine -Assignment $a | Should -BeExactly 'Direct Assignment - MockGroup-g1 (Filter: Windows 11 Corp [Exclude])'
    }
}

Describe 'Resolve-AssignmentReason' {
    It 'returns null when no assignment matches' {
        Resolve-AssignmentReason -Assignments @() -GroupMembershipIds @('g1') -IncludeReasons @('All Users') |
            Should -BeNullOrEmpty
    }

    It 'returns "All Users" when the user matches an All Users assignment' {
        $a = New-Assignment -Reason 'All Users'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g1') -IncludeReasons @('All Users') |
            Should -BeExactly 'All Users'
    }

    It 'appends filter suffix when the matched assignment has a filter' {
        $a = New-Assignment -Reason 'All Users' -FilterId 'filter-win11' -FilterType 'include'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g1') -IncludeReasons @('All Users') |
            Should -BeExactly 'All Users (Filter: Windows 11 Corp [Include])'
    }

    It 'returns "Group Assignment" when user is in a matching group' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g1') -IncludeReasons @('All Users') |
            Should -BeExactly 'Group Assignment'
    }

    It 'includes filter suffix on a Group Assignment match' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1' -FilterId 'filter-win11' -FilterType 'include'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g1') -IncludeReasons @('All Users') |
            Should -BeExactly 'Group Assignment (Filter: Windows 11 Corp [Include])'
    }

    It 'returns "Excluded" when the user is in an excluded group, overriding inclusion' {
        $include = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        $exclude = New-Assignment -Reason 'Group Exclusion'  -GroupId 'g2'
        Resolve-AssignmentReason -Assignments @($include, $exclude) -GroupMembershipIds @('g1', 'g2') -IncludeReasons @('All Users') |
            Should -BeExactly 'Excluded'
    }

    It 'includes filter suffix on the excluding assignment' {
        $include = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        $exclude = New-Assignment -Reason 'Group Exclusion'  -GroupId 'g2' -FilterId 'filter-kiosk' -FilterType 'exclude'
        Resolve-AssignmentReason -Assignments @($include, $exclude) -GroupMembershipIds @('g1', 'g2') -IncludeReasons @('All Users') |
            Should -BeExactly 'Excluded (Filter: Kiosk Devices [Exclude])'
    }

    It 'returns null when user is not in any matched group and there is no All Users assignment' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g99') -IncludeReasons @('All Users') |
            Should -BeNullOrEmpty
    }

    It 'honors custom IncludeReasons (All Devices)' {
        $a = New-Assignment -Reason 'All Devices'
        Resolve-AssignmentReason -Assignments @($a) -GroupMembershipIds @('g1') -IncludeReasons @('All Devices') |
            Should -BeExactly 'All Devices'
    }
}

Describe 'Get-AllTargetReason' {
    It 'returns null when no All Users assignment exists' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        Get-AllTargetReason -Assignments @($a) -TargetReason 'All Users' | Should -BeNullOrEmpty
    }

    It 'returns null when Assignments is empty' {
        Get-AllTargetReason -Assignments @() -TargetReason 'All Users' | Should -BeNullOrEmpty
    }

    It 'returns "All Users" when matched with no filter' {
        $a = New-Assignment -Reason 'All Users'
        Get-AllTargetReason -Assignments @($a) -TargetReason 'All Users' | Should -BeExactly 'All Users'
    }

    It 'returns "All Users (Filter: ...)" when matched with a filter' {
        $a = New-Assignment -Reason 'All Users' -FilterId 'filter-win11' -FilterType 'include'
        Get-AllTargetReason -Assignments @($a) -TargetReason 'All Users' |
            Should -BeExactly 'All Users (Filter: Windows 11 Corp [Include])'
    }

    It 'returns "All Devices" variant correctly' {
        $a = New-Assignment -Reason 'All Devices' -FilterId 'filter-kiosk' -FilterType 'exclude'
        Get-AllTargetReason -Assignments @($a) -TargetReason 'All Devices' |
            Should -BeExactly 'All Devices (Filter: Kiosk Devices [Exclude])'
    }

    It 'picks the first matching assignment when multiple exist' {
        $a1 = New-Assignment -Reason 'All Users' -FilterId 'filter-win11' -FilterType 'include'
        $a2 = New-Assignment -Reason 'All Users' -FilterId 'filter-kiosk' -FilterType 'exclude'
        Get-AllTargetReason -Assignments @($a1, $a2) -TargetReason 'All Users' |
            Should -BeExactly 'All Users (Filter: Windows 11 Corp [Include])'
    }
}

Describe 'Get-GroupAssignmentReasons' {
    It 'returns empty for no assignments' {
        $result = Get-GroupAssignmentReasons -Assignments @() -DirectGroupId 'g1' -ParentGroupMap @{}
        $result | Should -BeNullOrEmpty
    }

    It 'returns "Direct Assignment" for a matching direct group' {
        $a = New-Assignment -Reason 'Direct Assignment' -GroupId 'g1'
        $result = @(Get-GroupAssignmentReasons -Assignments @($a) -DirectGroupId 'g1' -ParentGroupMap @{})
        $result[0] | Should -BeExactly 'Direct Assignment'
    }

    It 'returns "Direct Assignment (Filter: ...)" when the assignment has a filter' {
        $a = New-Assignment -Reason 'Direct Assignment' -GroupId 'g1' -FilterId 'filter-win11' -FilterType 'include'
        $result = @(Get-GroupAssignmentReasons -Assignments @($a) -DirectGroupId 'g1' -ParentGroupMap @{})
        $result[0] | Should -BeExactly 'Direct Assignment (Filter: Windows 11 Corp [Include])'
    }

    It 'returns "Inherited (via parent)" for a parent group match' {
        $a = New-Assignment -Reason 'Direct Assignment' -GroupId 'parent1'
        $result = @(Get-GroupAssignmentReasons -Assignments @($a) -DirectGroupId 'g1' -ParentGroupMap @{ 'parent1' = 'ParentName' })
        $result[0] | Should -BeExactly 'Inherited (via ParentName)'
    }

    It 'returns "Inherited Exclusion (via parent)" with filter suffix' {
        $a = New-Assignment -Reason 'Direct Exclusion' -GroupId 'parent2' -FilterId 'filter-kiosk' -FilterType 'exclude'
        $result = @(Get-GroupAssignmentReasons -Assignments @($a) -DirectGroupId 'g1' -ParentGroupMap @{ 'parent2' = 'ParentExclude' })
        $result[0] | Should -BeExactly 'Inherited Exclusion (via ParentExclude) (Filter: Kiosk Devices [Exclude])'
    }

    It 'skips assignments with non-Direct reasons' {
        $a1 = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        $a2 = New-Assignment -Reason 'Direct Assignment' -GroupId 'g1'
        $result = @(Get-GroupAssignmentReasons -Assignments @($a1, $a2) -DirectGroupId 'g1' -ParentGroupMap @{})
        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly 'Direct Assignment'
    }
}

Describe 'Resolve-SimulatedAssignmentDelta' {
    It 'flags a new policy when simulated group grants access the user currently lacks' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'target-group'
        $delta = Resolve-SimulatedAssignmentDelta `
            -Assignments @($a) `
            -CurrentGroupIds @('other-group') `
            -SimulatedGroupIds @('other-group', 'target-group') `
            -TargetGroupIds @('target-group')
        $delta.IsNewPolicy | Should -BeTrue
        $delta.IsLostPolicy | Should -BeFalse
    }

    It 'flags a lost policy when the user loses their only inclusion' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1'
        $delta = Resolve-SimulatedAssignmentDelta `
            -Assignments @($a) `
            -CurrentGroupIds @('g1') `
            -SimulatedGroupIds @() `
            -TargetGroupIds @('g1')
        $delta.IsLostPolicy | Should -BeTrue
        $delta.IsNewPolicy | Should -BeFalse
    }

    It 'flags neither when status is unchanged' {
        $a = New-Assignment -Reason 'All Users'
        $delta = Resolve-SimulatedAssignmentDelta `
            -Assignments @($a) `
            -CurrentGroupIds @('g1') `
            -SimulatedGroupIds @('g1', 'g2')
        $delta.IsNewPolicy | Should -BeFalse
        $delta.IsLostPolicy | Should -BeFalse
    }

    It 'treats "Excluded (Filter: ...)" the same as "Excluded" when detecting new policy' {
        # Previously, -eq "Excluded" would fail when the string had a filter suffix.
        # This test protects against a regression in that equality check.
        $exclude = New-Assignment -Reason 'Group Exclusion' -GroupId 'g-excl' -FilterId 'filter-kiosk' -FilterType 'exclude'
        $include = New-Assignment -Reason 'Group Assignment' -GroupId 'g-incl'

        # Current state: user is in g-excl (excluded with filter suffix); not in g-incl
        # Simulated state: user is also in g-incl (no exclusion from the simulated membership)
        $delta = Resolve-SimulatedAssignmentDelta `
            -Assignments @($exclude, $include) `
            -CurrentGroupIds @('g-excl') `
            -SimulatedGroupIds @('g-incl') `
            -TargetGroupIds @('g-incl')

        $delta.CurrentStatus | Should -Match '^Excluded'
        $delta.IsNewPolicy | Should -BeTrue
    }

    It 'detects lost policy correctly when the current reason carries a filter suffix' {
        $a = New-Assignment -Reason 'Group Assignment' -GroupId 'g1' -FilterId 'filter-win11' -FilterType 'include'
        $delta = Resolve-SimulatedAssignmentDelta `
            -Assignments @($a) `
            -CurrentGroupIds @('g1') `
            -SimulatedGroupIds @() `
            -TargetGroupIds @('g1')
        $delta.CurrentStatus | Should -Match 'Filter: Windows 11 Corp'
        $delta.IsLostPolicy | Should -BeTrue
    }
}

Describe 'Add-ExportData regex for FilterName/FilterType extraction' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private/Get-ScopeTagNames.ps1')
        . (Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private/Add-ExportData.ps1')
        $script:ScopeTagLookup = @{ '0' = 'Default' }
    }

    It 'extracts FilterName and FilterType from an AssignmentReason string containing a filter suffix' {
        $items = @([PSCustomObject]@{
            id               = 'item-1'
            displayName      = 'Test Policy'
            roleScopeTagIds  = @('0')
            AssignmentReason = 'Group Assignment - Marketing (Filter: Windows 11 Corp [Include])'
        })
        $export = [System.Collections.ArrayList]::new()
        Add-ExportData -ExportData $export -Category 'Device Configuration' -Items $items
        $export.Count | Should -Be 1
        $export[0].FilterName | Should -BeExactly 'Windows 11 Corp'
        $export[0].FilterType | Should -BeExactly 'Include'
    }

    It 'returns empty FilterName/FilterType for an AssignmentReason without a filter' {
        $items = @([PSCustomObject]@{
            id               = 'item-2'
            displayName      = 'Unfiltered Policy'
            roleScopeTagIds  = @('0')
            AssignmentReason = 'All Users'
        })
        $export = [System.Collections.ArrayList]::new()
        Add-ExportData -ExportData $export -Category 'Device Configuration' -Items $items
        $export[0].FilterName | Should -BeExactly ''
        $export[0].FilterType | Should -BeExactly ''
    }

    It 'extracts Exclude FilterType correctly' {
        $items = @([PSCustomObject]@{
            id               = 'item-3'
            displayName      = 'Kiosk Policy'
            roleScopeTagIds  = @('0')
            AssignmentReason = 'All Devices (Filter: Kiosk Devices [Exclude])'
        })
        $export = [System.Collections.ArrayList]::new()
        Add-ExportData -ExportData $export -Category 'Compliance Policy' -Items $items
        $export[0].FilterName | Should -BeExactly 'Kiosk Devices'
        $export[0].FilterType | Should -BeExactly 'Exclude'
    }
}
