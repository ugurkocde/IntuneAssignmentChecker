#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Get-IntuneAssignments.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')

    $script:GraphEndpoint = 'https://graph.test'

    function Invoke-IACGraphRequest {
        param([string]$Uri, [string]$Method)
        @{ value = @() }
    }
}

Describe 'Test-ImportedAdministrativeTemplate' {
    It 'recognizes custom and mixed configurations only' {
        Test-ImportedAdministrativeTemplate -Policy ([PSCustomObject]@{ policyConfigurationIngestionType = 'custom' }) | Should -BeTrue
        Test-ImportedAdministrativeTemplate -Policy ([PSCustomObject]@{ policyConfigurationIngestionType = 'mixed' }) | Should -BeTrue
        Test-ImportedAdministrativeTemplate -Policy ([PSCustomObject]@{ policyConfigurationIngestionType = 'builtIn' }) | Should -BeFalse
        Test-ImportedAdministrativeTemplate -Policy ([PSCustomObject]@{ policyConfigurationIngestionType = 'unknownFutureValue' }) | Should -BeFalse
    }

    It 'keeps every hand-wired reporting surface on the shared classification helper' {
        $relativePaths = @(
            'Public/Get-IntuneUserDeviceAssignment.ps1'
            'Public/Get-IntuneUnassignedPolicy.ps1'
            'Public/Get-IntuneEmptyGroup.ps1'
            'html-export.ps1'
        )

        foreach ($relativePath in $relativePaths) {
            $source = Get-Content -Path (Join-Path $moduleRoot $relativePath) -Raw
            $source | Should -Match 'Get-IntuneEntities -EntityType "groupPolicyConfigurations"'
            $source | Should -Match 'Where-Object \{ Test-ImportedAdministrativeTemplate -Policy \$_ \}'
        }
    }

    It 'keeps manual buckets, exports, Windows gating, and HTML output wired to the imported category' {
        $userDeviceSource = Get-Content -Path (Join-Path $moduleRoot 'Public/Get-IntuneUserDeviceAssignment.ps1') -Raw
        $userDeviceSource | Should -Match '(?s)if \(-not \$deviceOS -or \$deviceOS -eq ''Windows''\) \{\s+Write-Host "  Imported Administrative Templates\.\.\.".*?relevantPolicies\.ImportedAdministrativeTemplates\.Add'
        $userDeviceSource | Should -Match 'Category "Imported Administrative Template"\s+-Items \$relevantPolicies\.ImportedAdministrativeTemplates'

        $unassignedSource = Get-Content -Path (Join-Path $moduleRoot 'Public/Get-IntuneUnassignedPolicy.ps1') -Raw
        $unassignedSource | Should -Match 'unassignedPolicies\.ImportedAdministrativeTemplates'
        $unassignedSource | Should -Match 'Category "Imported Administrative Template"'

        $emptyGroupSource = Get-Content -Path (Join-Path $moduleRoot 'Public/Get-IntuneEmptyGroup.ps1') -Raw
        $emptyGroupSource | Should -Match 'emptyGroupAssignments\.ImportedAdministrativeTemplates'
        $emptyGroupSource | Should -Match 'Category "Imported Administrative Template"'

        $htmlSource = Get-Content -Path (Join-Path $moduleRoot 'html-export.ps1') -Raw
        $htmlSource | Should -Match 'policies\.ImportedAdministrativeTemplates'
        $htmlSource | Should -Match 'Platform\s+= "Windows"'
        $htmlSource | Should -Match "Key = 'ImportedAdministrativeTemplates'; Name = 'Imported Administrative Templates'"
        $htmlSource | Should -Match '\$\(\$policies\.ImportedAdministrativeTemplates\.Count\)'
    }
}

Describe 'Imported Administrative Template assignments' {
    BeforeEach {
        Mock Write-Warning {}
        Mock Invoke-IACGraphRequest { @{ value = @() } }
    }

    It 'uses the documented resource-path URI and follows assignment pagination' {
        $script:expectedGroupId = '11111111-1111-1111-1111-111111111111'
        $firstPage = 'https://graph.test/beta/deviceManagement/groupPolicyConfigurations/imported-1/assignments'
        Mock Invoke-IACGraphRequest {
            if ($Uri -eq $firstPage) {
                return @{
                    value = @(
                        [PSCustomObject]@{
                            target = [PSCustomObject]@{
                                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                                groupId = $script:expectedGroupId
                            }
                        }
                        [PSCustomObject]@{
                            target = [PSCustomObject]@{
                                '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'
                                groupId = $script:expectedGroupId
                            }
                        }
                    )
                }
            }
            throw "Unexpected URI: $Uri"
        }

        $assignments = @(Get-IntuneAssignments -EntityType 'groupPolicyConfigurations' -EntityId 'imported-1')

        $assignments.Reason | Should -Be @('Group Assignment', 'Group Exclusion')
        $assignments.GroupId | Should -Be @($script:expectedGroupId, $script:expectedGroupId)
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter { $Uri -eq $firstPage -and $Method -eq 'Get' }
    }

    It 'preserves group filtering semantics for an imported template' {
        $wantedGroup = '11111111-1111-1111-1111-111111111111'
        Mock Invoke-IACGraphRequest {
            @{
                value = @(
                    [PSCustomObject]@{ target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $wantedGroup } }
                    [PSCustomObject]@{ target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'other-group' } }
                )
            }
        }

        $assignments = @(Get-IntuneAssignments -EntityType 'groupPolicyConfigurations' -EntityId 'imported-2' -GroupIds @($wantedGroup))

        $assignments | Should -HaveCount 1
        $assignments[0].Reason | Should -BeExactly 'Direct Assignment'
        $assignments[0].GroupId | Should -BeExactly $wantedGroup
    }
}
