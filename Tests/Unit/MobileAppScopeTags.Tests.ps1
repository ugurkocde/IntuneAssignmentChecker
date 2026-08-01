#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'Add-ExportData.ps1')
    . (Join-Path $modulePrivate 'Test-ImportedAdministrativeTemplate.ps1')
    . (Join-Path $moduleRoot 'Public/Get-IntuneUnassignedPolicy.ps1')

    function Get-IntuneEntities { param([string]$EntityType) @() }
    function Get-IntuneAssignments { param([string]$EntityType, [string]$EntityId) @() }
    function Get-AppProtectionAssignmentUri { param($Policy) $null }
    function Add-IntentTemplateFamilyInfo { param($IntentPolicies) }
    function Invoke-IACGraphRequest { param([string]$Uri, [string]$Method) @{ value = @() } }
    function Filter-ByScopeTag { param($Items) $Items }
    function Export-ResultsIfRequested {
        param(
            [System.Collections.ArrayList]$ExportData,
            [string]$DefaultFileName,
            [switch]$ForceExport,
            [string]$CustomExportPath,
            [switch]$ExportToCSV,
            [switch]$ParameterMode
        )
    }

    $script:GraphEndpoint = 'https://graph.test'
}

Describe 'Mobile application scope tags' {
    BeforeEach {
        $script:ScopeTagLookup = @{ '0' = 'Default'; 'tag-finance' = 'Finance' }
        $script:capturedExport = $null

        Mock Write-Host
        Mock Get-IntuneEntities { @() }
        Mock Get-IntuneAssignments { @() }
        Mock Add-IntentTemplateFamilyInfo
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*deviceAppManagement/mobileApps?*isAssigned eq false*') {
                return @{
                    value = @(
                        [PSCustomObject]@{
                            id              = 'unassigned-app'
                            displayName     = 'Unassigned App'
                            isFeatured      = $false
                            roleScopeTagIds = @('0', 'tag-finance')
                            '@odata.type'   = '#microsoft.graph.win32LobApp'
                        }
                    )
                }
            }
            @{ value = @() }
        }
        Mock Export-ResultsIfRequested {
            $script:capturedExport = @($ExportData)
        }
    }

    It 'requests roleScopeTagIds in every active mobile-app collection query' {
        $relativePaths = @(
            'Private/Invoke-IntuneCategoryScan.ps1'
            'Public/Get-IntuneUnassignedPolicy.ps1'
            'Public/Get-IntuneUserDeviceAssignment.ps1'
            'html-export.ps1'
        )

        foreach ($relativePath in $relativePaths) {
            $source = Get-Content -Path (Join-Path $moduleRoot $relativePath) -Raw
            $source | Should -Match 'deviceAppManagement/mobileApps\?[^"\r\n]*\$select=[^"\r\n]*roleScopeTagIds'
        }
    }

    It 'exports all scope tags for an unassigned application' {
        Get-IntuneUnassignedPolicy -ExportToCSV

        $appRow = $script:capturedExport | Where-Object { $_.Item -eq 'Unassigned App (ID: unassigned-app)' }
        $appRow.ScopeTags | Should -BeExactly 'Default, Finance'
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like '*deviceAppManagement/mobileApps?*' -and
            $Uri -match '\$select=[^&]*roleScopeTagIds'
        }
    }

    It 'exports unassigned custom and mixed imported templates but never queries built-in-only assignments' {
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'groupPolicyConfigurations') {
                return @(
                    [PSCustomObject]@{ id = 'iat-custom'; displayName = 'Imported Chrome'; policyConfigurationIngestionType = 'custom' }
                    [PSCustomObject]@{ id = 'iat-mixed'; displayName = 'Imported Office'; policyConfigurationIngestionType = 'mixed' }
                    [PSCustomObject]@{ id = 'iat-built-in'; displayName = 'Built-in Policy'; policyConfigurationIngestionType = 'builtIn' }
                )
            }
            @()
        }

        Get-IntuneUnassignedPolicy -ExportToCSV

        @($script:capturedExport | Where-Object { $_.Category -eq 'Imported Administrative Template' } | ForEach-Object { $_.Item }) |
            Should -Be @('Imported Chrome (ID: iat-custom)', 'Imported Office (ID: iat-mixed)')
        Should -Invoke Get-IntuneAssignments -Exactly 0 -ParameterFilter { $EntityId -eq 'iat-built-in' }
    }
}
