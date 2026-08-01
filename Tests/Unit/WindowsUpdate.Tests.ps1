#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $private = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'
    . (Join-Path $private 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $private 'Get-IntuneAssignments.ps1')
    $script:GraphEndpoint = 'https://graph.test'
    function Invoke-IACGraphRequest { param($Uri, $Method) @{ value = @() } }
}

Describe 'Windows Update assignment coverage' {
    BeforeEach {
        Mock Write-Warning {}
        Mock Invoke-IACGraphRequest {
            @{
                value = @(
                    [PSCustomObject]@{
                        id = 'assignment-include'
                        target = [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId = 'group-1'
                            deviceAndAppManagementAssignmentFilterId = 'filter-1'
                            deviceAndAppManagementAssignmentFilterType = 'include'
                        }
                    }
                    [PSCustomObject]@{
                        id = 'assignment-exclude'
                        target = [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'
                            groupId = 'group-2'
                            deviceAndAppManagementAssignmentFilterId = $null
                            deviceAndAppManagementAssignmentFilterType = 'none'
                        }
                    }
                    [PSCustomObject]@{
                        id = 'assignment-all-devices'
                        target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
                    }
                )
            }
        }
    }

    It 'uses the live-verified resource-path assignments endpoint for every workload' -ForEach @(
        @{ EntityType = 'windowsFeatureUpdateProfiles' }
        @{ EntityType = 'windowsQualityUpdateProfiles' }
        @{ EntityType = 'windowsDriverUpdateProfiles' }
        @{ EntityType = 'windowsQualityUpdatePolicies' }
    ) {
        $assignments = @(Get-IntuneAssignments -EntityType $EntityType -EntityId 'profile-1')

        $assignments | Should -HaveCount 3
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq "https://graph.test/beta/deviceManagement/$EntityType/profile-1/assignments" -and $Method -eq 'Get'
        }
    }

    It 'normalizes aggregated assignment responses for groups, exclusions, filters, and All Devices' {
        $assignments = @(Get-IntuneAssignments -EntityType windowsFeatureUpdateProfiles -EntityId profile-1)

        $assignments.Reason | Should -Be @('Group Assignment', 'Group Exclusion', 'All Devices')
        $assignments.AssignmentMode | Should -Be @('Include', 'Exclude', 'Include')
        $assignments.TargetType | Should -Be @('Group', 'Group', 'AllDevices')
        $assignments[0].FilterId | Should -BeExactly filter-1
        $assignments[0].FilterType | Should -BeExactly include
    }

    It 'preserves group-specific filtering semantics' {
        $assignments = @(Get-IntuneAssignments -EntityType windowsFeatureUpdateProfiles -EntityId profile-1 -GroupIds @('group-2'))
        $assignments | Should -HaveCount 1
        $assignments[0].Reason | Should -BeExactly 'Direct Exclusion'
    }

    It 'wires every workload through all required presentation and export surfaces' {
        $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
        $paths = @(
            'Public/Get-IntuneUserAssignment.ps1', 'Public/Get-IntuneGroupAssignment.ps1',
            'Public/Get-IntuneDeviceAssignment.ps1', 'Public/Get-IntuneAllPolicies.ps1',
            'Public/Get-IntuneAllUsersAssignment.ps1', 'Public/Get-IntuneAllDevicesAssignment.ps1',
            'Public/Get-IntuneUnassignedPolicy.ps1', 'Public/Get-IntuneUserDeviceAssignment.ps1',
            'Public/Compare-IntuneGroupAssignment.ps1', 'Public/Test-IntuneGroupMembership.ps1',
            'Public/Test-IntuneGroupRemoval.ps1', 'html-export.ps1'
        )
        foreach ($path in $paths) {
            $source = Get-Content -Raw (Join-Path $moduleRoot $path)
            foreach ($bucket in @('WindowsFeatureUpdates', 'WindowsQualityUpdates', 'WindowsDriverUpdates', 'WindowsQualityUpdatePolicies')) {
                $source | Should -Match ([regex]::Escape($bucket))
            }
        }
    }
}
