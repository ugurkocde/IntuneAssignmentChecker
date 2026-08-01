#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'
    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'ConvertTo-IACNormalizedAssignment.ps1')
    . (Join-Path $modulePrivate 'Select-IACAssignmentRecord.ps1')

    $script:CurrentTenantId = 'tenant-1'
    $script:CurrentTenantName = 'Contoso'
    $script:ScopeTagLookup = @{ '1' = 'Finance'; '2' = 'Security' }
    $script:AssignmentFilterLookup = @{
        'filter-1' = [PSCustomObject]@{
            Name = 'Corporate Windows'; Platform = 'windows10AndLater'
            Rule = '(device.deviceOwnership -eq "Corporate")'
        }
    }
    function Get-GroupInfo {
        param([string]$GroupId)
        [PSCustomObject]@{ DisplayName = 'Finance Devices' }
    }
}

Describe 'IntuneAssignmentChecker.AssignmentRecord' {
    It 'pins schema version 1, property order, and the PowerShell type name' {
        $record = New-IACAssignmentRecord -CategoryId Configuration -Category 'Configuration Policy' -PolicyId policy-1 -PolicyName Baseline -AssignmentMode Include -TargetType AllDevices -TargetName 'All Devices'

        $record.PSObject.TypeNames[0] | Should -BeExactly 'IntuneAssignmentChecker.AssignmentRecord'
        $record.SchemaVersion | Should -Be 1
        $record.TenantId | Should -BeExactly 'tenant-1'
        @($record.PSObject.Properties.Name) | Should -Be @(
            'SchemaVersion', 'TenantId', 'TenantName', 'SubjectType', 'SubjectId', 'SubjectName',
            'CategoryId', 'Category', 'PolicyId', 'PolicyName', 'Platform', 'ScopeTagIds', 'ScopeTags',
            'AssignmentId', 'AssignmentMode', 'TargetType', 'TargetId', 'TargetName', 'Intent',
            'FilterId', 'FilterName', 'FilterMode', 'FilterRule', 'FilterPlatform',
            'EffectiveState', 'ReasonChain',
            'AssignmentReason', 'Source'
        )
        $record.EffectiveState | Should -BeNullOrEmpty
        $record.ReasonChain | Should -BeNullOrEmpty
    }

    It 'allows unnamed or partial Graph entities without aborting the pipeline' {
        { New-IACAssignmentRecord -CategoryId '' -Category '' -PolicyId '' -PolicyName '' -AssignmentMode None -TargetType None } | Should -Not -Throw
    }

    It 'keeps scope tag ids and names in matching source order' {
        $record = New-IACAssignmentRecord -CategoryId c -Category c -PolicyId p -PolicyName n -ScopeTagIds @('2', '1') -ScopeTags @('Security', 'Finance')
        $record.ScopeTagIds | Should -Be @('2', '1')
        $record.ScopeTags | Should -Be @('Security', 'Finance')
    }

    It 'normalizes Graph targets once without confusing filter mode and assignment mode' {
        $raw = [PSCustomObject]@{
            id = 'assignment-1'; intent = 'required'
            target = [PSCustomObject]@{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1'
                deviceAndAppManagementAssignmentFilterId = 'filter-1'
                deviceAndAppManagementAssignmentFilterType = 'exclude'
            }
        }
        $assignment = ConvertTo-IACNormalizedAssignment -Assignment $raw

        $assignment.AssignmentMode | Should -BeExactly Include
        $assignment.TargetType | Should -BeExactly Group
        $assignment.TargetId | Should -BeExactly group-1
        $assignment.FilterType | Should -BeExactly exclude
        $assignment.Intent | Should -BeExactly required
    }

    It 'filters group targets structurally even when a group name contains reserved words' {
        $raw = [PSCustomObject]@{ id = 'a'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-all-users-exclusions' } }
        $assignment = ConvertTo-IACNormalizedAssignment -Assignment $raw -GroupIds @('group-all-users-exclusions')
        $assignment.AssignmentMode | Should -BeExactly Include
        $assignment.TargetType | Should -BeExactly Group
        $assignment.Reason | Should -BeExactly 'Direct Assignment'
    }

    It 'hydrates policy, platform, filter, target, and scope metadata from structured data' {
        $category = [PSCustomObject]@{ Id = 'SettingsCatalog'; ExportCategory = 'Settings Catalog Policy'; DisplayName = 'Settings Catalog' }
        $entity = [PSCustomObject]@{
            id = 'policy-1'; name = 'Security baseline'; roleScopeTagIds = @('1')
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationPolicy'; platforms = @('windows10')
        }
        $assignment = [PSCustomObject]@{
            AssignmentId = 'assignment-1'; Reason = 'Group Assignment'; AssignmentMode = 'Include'
            TargetType = 'Group'; TargetId = 'group-1'; GroupId = 'group-1'; Intent = 'required'
            FilterId = 'filter-1'; FilterType = 'exclude'
        }

        $record = ConvertTo-IACAssignmentRecord -Category $category -Entity $entity -Assignment $assignment -ResolveTargetName
        $record.CategoryId | Should -BeExactly SettingsCatalog
        $record.TargetName | Should -BeExactly 'Finance Devices'
        $record.FilterName | Should -BeExactly 'Corporate Windows'
        $record.FilterRule | Should -Match deviceOwnership
        $record.ScopeTags | Should -Be @('Finance')
        $record.Platform | Should -BeExactly windows10
    }

    It 'selects visible records, applies subject context, and streams an empty result safely' {
        $record = New-IACAssignmentRecord -CategoryId SettingsCatalog -Category Policy -PolicyId p1 -PolicyName One -AssignmentMode Include -TargetType AllUsers
        $buckets = @{ Results = @([PSCustomObject]@{ id = 'p1' }) }
        $selected = @(Select-IACAssignmentRecord -Records @($record) -Buckets $buckets -TargetTypes AllUsers -SubjectType User -SubjectId u1 -Source Test)
        $empty = @(Select-IACAssignmentRecord -Records @() -Buckets @{} -SubjectType User -Source Test)
        $groupRecord = New-IACAssignmentRecord -CategoryId c -Category c -PolicyId p1 -PolicyName One -AssignmentMode Include -TargetType Group -TargetId g1
        $noGroupMatch = @(Select-IACAssignmentRecord -Records @($groupRecord) -Buckets $buckets -TargetTypes Group -GroupIds @() -SubjectType User -Source Test)

        $selected.Count | Should -Be 1
        $selected[0].SubjectId | Should -BeExactly u1
        $selected[0].PSObject.TypeNames[0] | Should -BeExactly 'IntuneAssignmentChecker.AssignmentRecord'
        $empty.Count | Should -Be 0
        $noGroupMatch.Count | Should -Be 0
    }

    It 'exposes PassThru and OutputType on the supported primary commands' {
        $commandFiles = @(
            'Get-IntuneUserAssignment.ps1', 'Get-IntuneGroupAssignment.ps1',
            'Get-IntuneDeviceAssignment.ps1', 'Get-IntuneAllPolicies.ps1',
            'Get-IntuneAllUsersAssignment.ps1', 'Get-IntuneAllDevicesAssignment.ps1',
            'Get-IntuneUnassignedPolicy.ps1', 'Search-IntunePolicy.ps1'
        )
        foreach ($file in $commandFiles) {
            $errors = $null; $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $moduleRoot "Public/$file"), [ref]$tokens, [ref]$errors)
            $errors | Should -BeNullOrEmpty
            $parameters = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ParameterAst] }, $true)
            @($parameters.Name.VariablePath.UserPath) | Should -Contain PassThru
            Get-Content -Raw (Join-Path $moduleRoot "Public/$file") | Should -Match "\[OutputType\('IntuneAssignmentChecker\.AssignmentRecord'\)\]"
        }
    }
}
