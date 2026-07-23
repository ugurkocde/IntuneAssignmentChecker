#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'

    function Invoke-MgGraphRequest {
        param([string]$Uri, [string]$Method)
        $null = $Uri
        $null = $Method
        @{ value = @() }
    }

    . (Join-Path $modulePrivate 'Get-TransitiveGroupMembership.ps1')

    $script:GraphEndpoint = 'https://graph.test'
}

Describe 'Get-TransitiveGroupMembership' {
    BeforeEach {
        $script:requestedUris = [System.Collections.Generic.List[string]]::new()

        Mock Invoke-MgGraphRequest {
            $script:requestedUris.Add($Uri)

            if ($Uri -eq 'https://graph.test/v1.0/groups/group-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName') {
                return @{
                    value = @(
                        [PSCustomObject]@{ id = 'parent-1'; displayName = 'Parent One' }
                    )
                    '@odata.nextLink' = 'https://graph.test/v1.0/groups/group-1/transitiveMemberOf/microsoft.graph.group?$skiptoken=next'
                }
            }

            return @{
                value = @(
                    [PSCustomObject]@{ id = 'parent-2'; displayName = 'Parent Two' }
                )
            }
        }
    }

    It 'uses the tested transitive group endpoint and follows pagination' {
        $result = @(Get-TransitiveGroupMembership -GroupId 'group-1')

        $result.Count | Should -Be 2
        $result[0].id | Should -BeExactly 'parent-1'
        $result[1].id | Should -BeExactly 'parent-2'
        $script:requestedUris | Should -Be @(
            'https://graph.test/v1.0/groups/group-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName'
            'https://graph.test/v1.0/groups/group-1/transitiveMemberOf/microsoft.graph.group?$skiptoken=next'
        )
        Should -Invoke Invoke-MgGraphRequest -Exactly 2 -ParameterFilter { $Method -eq 'Get' }
    }
}
