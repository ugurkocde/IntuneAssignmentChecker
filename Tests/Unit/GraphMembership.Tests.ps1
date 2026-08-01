#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'

    function Invoke-IACGraphRequest {
        param([string]$Uri, [string]$Method)
        $null = $Uri
        $null = $Method
        @{ value = @() }
    }

    . (Join-Path $modulePrivate 'Get-TransitiveGroupMembership.ps1')
    . (Join-Path $modulePrivate 'Get-GroupMemberships.ps1')
    . (Join-Path $modulePrivate 'Get-IACDirectoryDevice.ps1')

    $script:GraphEndpoint = 'https://graph.test'
}

Describe 'Get-GroupMemberships' {
    BeforeEach {
        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{ id = 'group-1'; displayName = 'Group One' }) }
        }
    }

    It 'uses the typed beta transitive-group endpoint for a user' {
        $result = @(Get-GroupMemberships -ObjectId user-1 -ObjectType User)

        $result.Count | Should -Be 1
        $result[0].id | Should -BeExactly group-1
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/users/user-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName' -and $Method -eq 'Get'
        }
    }

    It 'uses the typed beta transitive-group endpoint for a directory device' {
        $null = Get-GroupMemberships -ObjectId directory-1 -ObjectType Device

        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/devices/directory-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName' -and $Method -eq 'Get'
        }
    }
}

Describe 'Get-IACDirectoryDevice' {
    It 'maps a managed-device azureADDeviceId to the Entra directory object through beta' {
        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{ id = 'directory-1'; displayName = 'WIN-01'; deviceId = 'aad-device-1' }) }
        }

        $result = Get-IACDirectoryDevice -AzureADDeviceId aad-device-1

        $result.Success | Should -BeTrue
        $result.Device.id | Should -BeExactly directory-1
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/devices?$filter=deviceId%20eq%20%27aad-device-1%27&$select=id,displayName,deviceId' -and $Method -eq 'Get'
        }
    }

    It 'returns an explicit failure for zero or ambiguous mappings' {
        Mock Invoke-IACGraphRequest { @{ value = @() } }
        (Get-IACDirectoryDevice -AzureADDeviceId missing).Reason | Should -Match '^No Entra device maps'

        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{ id = 'one' }, [PSCustomObject]@{ id = 'two' }) }
        }
        (Get-IACDirectoryDevice -AzureADDeviceId duplicate).Reason | Should -Match '^Multiple Entra devices'
    }

    It 'escapes quotes before URL-encoding the OData deviceId filter' {
        Mock Invoke-IACGraphRequest { @{ value = @() } }

        $null = Get-IACDirectoryDevice -AzureADDeviceId "device'id"

        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/devices?$filter=deviceId%20eq%20%27device%27%27id%27&$select=id,displayName,deviceId'
        }
    }
}

Describe 'Get-TransitiveGroupMembership' {
    BeforeEach {
        $script:requestedUris = [System.Collections.Generic.List[string]]::new()

        Mock Invoke-IACGraphRequest {
            $script:requestedUris.Add($Uri)

            if ($Uri -eq 'https://graph.test/beta/groups/group-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName') {
                return @{
                    value = @(
                        [PSCustomObject]@{ id = 'parent-1'; displayName = 'Parent One' }
                        [PSCustomObject]@{ id = 'parent-2'; displayName = 'Parent Two' }
                    )
                }
            }
            throw "Unexpected URI: $Uri"
        }
    }

    It 'uses the tested transitive group endpoint and follows pagination' {
        $result = @(Get-TransitiveGroupMembership -GroupId 'group-1')

        $result.Count | Should -Be 2
        $result[0].id | Should -BeExactly 'parent-1'
        $result[1].id | Should -BeExactly 'parent-2'
        $script:requestedUris | Should -Be @(
            'https://graph.test/beta/groups/group-1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName'
        )
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter { $Method -eq 'Get' }
    }
}
