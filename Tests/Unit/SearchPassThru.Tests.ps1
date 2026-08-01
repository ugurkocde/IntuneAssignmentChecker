#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $private = Join-Path $moduleRoot Private
    foreach ($name in @(
            'Get-PolicyPlatform.ps1', 'Get-ScopeTagNames.ps1', 'New-IACAssignmentRecord.ps1',
            'ConvertTo-IACAssignmentRecord.ps1', 'ConvertTo-IACNormalizedAssignment.ps1', 'Get-IACNoAssignmentPlaceholder.ps1',
            'Select-IACAssignmentRecord.ps1', 'Format-AssignmentFilter.ps1', 'Get-Separator.ps1',
            'Get-AppProtectionAssignmentUri.ps1', 'Test-ImportedAdministrativeTemplate.ps1',
            'Get-IntuneCategoryDefinition.ps1', 'Invoke-IntuneCategoryScan.ps1')) {
        . (Join-Path $private $name)
    }
    . (Join-Path $moduleRoot 'Public/Search-IntunePolicy.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    $script:ScopeTagLookup = @{}
    $script:AssignmentFilterLookup = @{}
    function Get-IntuneEntities { param([string]$EntityType, [switch]$Quiet) @() }
    function Get-IntuneAssignments { param([string]$EntityType, [string]$EntityId, [string[]]$GroupIds = @()) @() }
    function Add-IntentTemplateFamilyInfo { param($IntentPolicies) }
    function Invoke-IACGraphRequest { param($Uri, $Method) @{ value = @() } }
    function Get-GroupInfo { param([string]$GroupId) [PSCustomObject]@{ DisplayName = 'Group' } }
    function Export-ResultsIfRequested { param($ExportData, $DefaultFileName, $ForceExport, $CustomExportPath, $ExportToCSV, $ParameterMode) }
}

Describe 'Search-IntunePolicy PassThru' {
    BeforeEach {
        Mock Write-Host {}
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                @(
                    [PSCustomObject]@{ id = 'assigned'; displayName = 'Baseline Assigned' }
                    [PSCustomObject]@{ id = 'empty'; displayName = 'Baseline Empty' }
                )
            }
            else { @() }
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'assigned') {
                @([PSCustomObject]@{ Reason = 'All Users'; AssignmentMode = 'Include'; TargetType = 'AllUsers' })
            }
            else { @() }
        }
        Mock Export-ResultsIfRequested {}
    }

    It 'streams assigned and unassigned canonical records with stable category ids' {
        $records = @(Search-IntunePolicy -PolicySearchTerm Baseline -PassThru)

        $records.Count | Should -Be 2
        @($records.CategoryId | Sort-Object -Unique) | Should -Be @('DeviceConfigurations')
        ($records | Where-Object PolicyId -eq assigned).AssignmentMode | Should -BeExactly Include
        ($records | Where-Object PolicyId -eq empty).AssignmentMode | Should -BeExactly None
        @($records | Where-Object { $_.PSObject.TypeNames[0] -ne 'IntuneAssignmentChecker.AssignmentRecord' }) | Should -BeNullOrEmpty
    }
}
