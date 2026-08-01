#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'

    function Invoke-MgGraphRequest {
        param([string]$Uri, [string]$Method)
        $null = $Uri
        $null = $Method
    }

    . (Join-Path $modulePrivate 'ConvertTo-IntuneGroupInfo.ps1')
    . (Join-Path $modulePrivate 'Get-GroupInfo.ps1')

    $script:GraphEndpoint = 'https://graph.test'
}

Describe 'ConvertTo-IntuneGroupInfo' {
    It 'classifies assigned and dynamic Microsoft 365 groups from the Unified group type' {
        $assigned = ConvertTo-IntuneGroupInfo -Group ([PSCustomObject]@{
                id = 'm365-assigned'; displayName = 'Messaging'; groupTypes = @('Unified')
                mailEnabled = $true; securityEnabled = $false; mail = 'messaging@contoso.com'
            })
        $dynamic = ConvertTo-IntuneGroupInfo -Group ([PSCustomObject]@{
                id = 'm365-dynamic'; displayName = 'Dynamic Messaging'; groupTypes = @('Unified', 'DynamicMembership')
                mailEnabled = $true; securityEnabled = $true; mail = 'dynamic@contoso.com'
            })

        $assigned.GroupType | Should -BeExactly 'Microsoft 365'
        $assigned.MembershipType | Should -BeExactly 'Assigned'
        $assigned.IsMicrosoft365 | Should -BeTrue
        $assigned.Mail | Should -BeExactly 'messaging@contoso.com'
        $dynamic.GroupType | Should -BeExactly 'Microsoft 365'
        $dynamic.MembershipType | Should -BeExactly 'Dynamic'
        $dynamic.IsMicrosoft365 | Should -BeTrue
    }

    It 'distinguishes the other Microsoft Graph group types' -ForEach @(
        @{ Expected = 'Security'; MailEnabled = $false; SecurityEnabled = $true }
        @{ Expected = 'Mail-enabled Security'; MailEnabled = $true; SecurityEnabled = $true }
        @{ Expected = 'Distribution'; MailEnabled = $true; SecurityEnabled = $false }
        @{ Expected = 'Unknown'; MailEnabled = $false; SecurityEnabled = $false }
    ) {
        $result = ConvertTo-IntuneGroupInfo -Group ([PSCustomObject]@{
                id = 'group-1'; displayName = 'Group'; groupTypes = @()
                mailEnabled = $MailEnabled; securityEnabled = $SecurityEnabled
            })

        $result.GroupType | Should -BeExactly $Expected
        $result.IsMicrosoft365 | Should -BeFalse
    }

    It 'marks a partial Graph payload without an Object ID as unsuccessful' {
        $result = ConvertTo-IntuneGroupInfo -Group ([PSCustomObject]@{
                displayName = 'Incomplete Group'; groupTypes = @('Unified')
                mailEnabled = $true; securityEnabled = $false
            })

        $result.Success | Should -BeFalse
    }
}

Describe 'Get-GroupInfo' {
    BeforeEach {
        $script:GroupInfoCache = $null
        Mock Write-Warning {}
        Mock Invoke-MgGraphRequest {
            [PSCustomObject]@{
                id = 'm365-1'; displayName = 'Messaging Team'; groupTypes = @('Unified')
                mailEnabled = $true; securityEnabled = $false; mail = 'messaging@contoso.com'
            }
        }
    }

    It 'requests the Microsoft 365 classification fields and caches the enriched result' {
        $first = Get-GroupInfo -GroupId 'm365-1'
        $second = Get-GroupInfo -GroupId 'm365-1'

        $first.GroupType | Should -BeExactly 'Microsoft 365'
        $first.Mail | Should -BeExactly 'messaging@contoso.com'
        $second | Should -Be $first
        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter {
            $Method -eq 'Get' -and
            $Uri -eq 'https://graph.test/v1.0/groups/m365-1?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,mail'
        }
    }

    It 'returns a complete unknown result when Graph lookup fails' {
        Mock Invoke-MgGraphRequest { throw 'service unavailable' }

        $result = Get-GroupInfo -GroupId 'missing-group'

        $result.Success | Should -BeFalse
        $result.GroupType | Should -BeExactly 'Unknown'
        $result.MembershipType | Should -BeExactly 'Unknown'
        $result.IsMicrosoft365 | Should -BeFalse
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter {
            $Message -like "Group 'missing-group' lookup failed:*service unavailable*"
        }
    }

    It 'does not warn when Graph reports a message-only 404 for a stale group assignment' {
        Mock Invoke-MgGraphRequest { throw '404 Request_ResourceNotFound: Group was not found' }

        $result = Get-GroupInfo -GroupId 'deleted-group'

        $result.Success | Should -BeFalse
        $result.DisplayName | Should -BeExactly 'Unknown Group'
        Should -Invoke Write-Warning -Exactly 0
    }

    It 'rejects and diagnoses a successful response that omits the group Object ID' {
        Mock Invoke-MgGraphRequest {
            [PSCustomObject]@{ displayName = 'Incomplete'; groupTypes = @('Unified'); mailEnabled = $true }
        }

        $result = Get-GroupInfo -GroupId 'incomplete-group'

        $result.Success | Should -BeFalse
        $result.DisplayName | Should -BeExactly 'Unknown Group'
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter {
            $Message -like "Group 'incomplete-group' lookup failed:*without an Object ID*"
        }
    }
}
