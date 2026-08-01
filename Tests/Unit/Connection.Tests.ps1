#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePublic = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Public'

    function Connect-MgGraph {
        [CmdletBinding()]
        param(
            [string[]]$Scopes,
            [string]$TenantId,
            [string]$ClientId,
            [string]$CertificateThumbprint,
            [PSCredential]$ClientSecretCredential,
            [SecureString]$AccessToken,
            [string]$Environment,
            [switch]$NoWelcome
        )
    }

    function Get-MgContext { }
    function Invoke-IACGraphRequest { }
    function Set-Environment { }
    function Get-ScopeTagLookup { }
    function Get-AssignmentFilterLookup { }

    . (Join-Path $modulePublic 'Connect-IntuneAssignmentChecker.ps1')
}

Describe 'Connect-IntuneAssignmentChecker interactive authentication' {
    BeforeEach {
        $script:RequiredPermissions = @(
            @{ Permission = 'User.Read.All'; Reason = 'Test permission' }
            @{ Permission = 'GroupMember.Read.All'; Reason = 'Second test permission' }
        )
        $script:GraphEnvironment = 'Global'
        $script:GraphEndpoint = 'https://graph.microsoft.com'
        $script:contextCallCount = 0

        Mock Write-Host
        Mock Find-Module { throw 'Offline during unit test' }
        Mock Get-Module {
            [PSCustomObject]@{ Version = [version]'4.3.1' }
        } -ParameterFilter { $Name -eq 'IntuneAssignmentChecker' }
        Mock Read-Host { 'y' }
        Mock Set-Environment {
            $script:GraphEnvironment = 'Global'
            'https://graph.microsoft.com'
        }
        Mock Get-MgContext {
            $script:contextCallCount++
            if ($script:contextCallCount -eq 1) {
                return $null
            }

            [PSCustomObject]@{
                Environment = 'Global'
                Scopes      = @('User.Read.All', 'GroupMember.Read.All')
                TenantId    = 'tenant-from-context'
                Account     = 'user@contoso.com'
            }
        }
        Mock Connect-MgGraph
        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{ displayName = 'Contoso' }) }
        }
        Mock Get-ScopeTagLookup { @{} }
        Mock Get-AssignmentFilterLookup { @{} }
    }

    It 'uses an AppId supplied by itself for delegated interactive sign-in' {
        Connect-IntuneAssignmentChecker -AppId 'custom-client-id'

        Should -Invoke Connect-MgGraph -Exactly 1 -ParameterFilter {
            $ClientId -eq 'custom-client-id' -and
            [string]::IsNullOrEmpty($TenantId) -and
            $Scopes.Count -eq 1 -and
            $Scopes[0] -eq 'User.Read.All, GroupMember.Read.All' -and
            $Environment -eq 'Global' -and
            $NoWelcome
        }
    }

    It 'also forwards TenantId when AppId-only delegated sign-in is tenant-scoped' {
        Connect-IntuneAssignmentChecker -AppId 'custom-client-id' -TenantId 'custom-tenant-id'

        Should -Invoke Connect-MgGraph -Exactly 1 -ParameterFilter {
            $ClientId -eq 'custom-client-id' -and
            $TenantId -eq 'custom-tenant-id' -and
            $Scopes.Count -eq 1 -and
            $Scopes[0] -eq 'User.Read.All, GroupMember.Read.All'
        }
    }

    It 'keeps the default Graph PowerShell interactive app when no AppId is supplied' {
        Connect-IntuneAssignmentChecker

        Should -Invoke Connect-MgGraph -Exactly 1 -ParameterFilter {
            [string]::IsNullOrEmpty($ClientId) -and
            [string]::IsNullOrEmpty($TenantId) -and
            $Scopes.Count -eq 1 -and
            $Scopes[0] -eq 'User.Read.All, GroupMember.Read.All'
        }
    }

    It 'preserves certificate-based app-only authentication' {
        Connect-IntuneAssignmentChecker -AppId 'certificate-client-id' -TenantId 'certificate-tenant-id' -CertificateThumbprint 'ABC123'

        Should -Invoke Connect-MgGraph -Exactly 1 -ParameterFilter {
            $ClientId -eq 'certificate-client-id' -and
            $TenantId -eq 'certificate-tenant-id' -and
            $CertificateThumbprint -eq 'ABC123' -and
            $null -eq $Scopes
        }
    }
}
