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
    . (Join-Path $modulePrivate 'ConvertTo-IACCsvSafeValue.ps1')
    . (Join-Path $modulePrivate 'Get-IACNoAssignmentPlaceholder.ps1')
    . (Join-Path $modulePrivate 'Test-IACAssignmentFilter.ps1')
    . (Join-Path $modulePrivate 'Resolve-IACEffectiveAssignment.ps1')
    . (Join-Path $moduleRoot 'Public/Get-IntuneEffectiveAssignment.ps1')

    $script:ScopeTagLookup = @{}
    $script:CurrentTenantId = 'tenant-1'
    $script:CurrentTenantName = 'Contoso'
    $script:GraphEndpoint = 'https://graph.test'

    function Get-UserInfo { param([string]$UserPrincipalName) }
    function Get-IACManagedDevice { param([string]$Identity) }
    function Get-IACDirectoryDevice { param([string]$AzureADDeviceId) }
    function Get-GroupMemberships { param([string]$ObjectId, [string]$ObjectType) @() }
    function Get-AssignmentFilterLookup { @{} }
    function Get-IntuneCategoryDefinition { param([string]$Audience) @() }
    function Invoke-IntuneCategoryScan {
        param([object[]]$Categories, [scriptblock]$ProcessEntity, [hashtable]$EntityCache, [switch]$ShowProgress, [string]$ProgressVerb)
        [PSCustomObject]@{ Errors = @() }
    }

    function New-EffectiveTestCategory {
        param([string]$Id = 'DeviceConfigurations', [string]$ExportCategory = 'Device Configuration')
        [PSCustomObject]@{
            Id = $Id
            ExportCategory = $ExportCategory
            DisplayName = $ExportCategory
            Platform = $null
        }
    }

    function New-EffectiveTestEntity {
        param([string]$Id = 'policy-1', [string]$Name = 'Policy One')
        [PSCustomObject]@{
            id = $Id
            displayName = $Name
            roleScopeTagIds = @()
            '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration'
        }
    }

    function New-EffectiveTestAssignment {
        param(
            [string]$Id = 'assignment-1',
            [ValidateSet('Include', 'Exclude')][string]$Mode = 'Include',
            [ValidateSet('AllUsers', 'AllDevices', 'Group')][string]$TargetType = 'Group',
            [string]$TargetId = 'group-1',
            [string]$Intent,
            [string]$FilterId,
            [string]$FilterType
        )
        [PSCustomObject]@{
            AssignmentId = $Id
            Reason = if ($Mode -eq 'Exclude') { 'Group Exclusion' } else { 'Group Assignment' }
            AssignmentMode = $Mode
            TargetType = $TargetType
            TargetId = $TargetId
            GroupId = $TargetId
            Intent = $Intent
            FilterId = $FilterId
            FilterType = $FilterType
        }
    }

    function Invoke-EffectiveTestResolution {
        param(
            [object[]]$Assignments,
            [hashtable]$MembershipSources = @{},
            [bool]$HasUser = $true,
            [bool]$HasDevice = $false,
            [bool]$UserMembershipKnown = $true,
            [bool]$DeviceMembershipKnown = $true,
            [AllowNull()]$ManagedDevice = $null
        )
        Resolve-IACEffectiveAssignment -Category (New-EffectiveTestCategory) -Entity (New-EffectiveTestEntity) `
            -Assignments $Assignments -MembershipSources $MembershipSources `
            -HasUser:$HasUser -HasDevice:$HasDevice `
            -UserMembershipKnown $UserMembershipKnown -DeviceMembershipKnown $DeviceMembershipKnown `
            -ManagedDevice $ManagedDevice -SubjectType $(if ($HasUser -and $HasDevice) { 'UserDevice' } elseif ($HasUser) { 'User' } else { 'Device' }) `
            -SubjectId 'subject-1' -SubjectName 'Subject One'
    }
}

Describe 'Resolve-IACEffectiveAssignment' {
    BeforeEach {
        $script:AssignmentFilterLookup = @{}
        $script:windowsDevice = [PSCustomObject]@{
            id = 'managed-1'
            deviceName = 'WIN-01'
            operatingSystem = 'Windows'
            managedDeviceOwnerType = 'company'
            model = 'Surface Pro 9'
        }
    }

    It 'includes All Users only when a user subject is present' {
        $assignment = New-EffectiveTestAssignment -TargetType AllUsers -TargetId $null

        (Invoke-EffectiveTestResolution -Assignments @($assignment) -HasUser $true).EffectiveState | Should -BeExactly Included
        (Invoke-EffectiveTestResolution -Assignments @($assignment) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice).EffectiveState | Should -BeExactly NotTargeted
    }

    It 'includes All Devices only when a managed-device subject is present' {
        $assignment = New-EffectiveTestAssignment -TargetType AllDevices -TargetId $null

        (Invoke-EffectiveTestResolution -Assignments @($assignment) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice).EffectiveState | Should -BeExactly Included
        (Invoke-EffectiveTestResolution -Assignments @($assignment) -HasUser $true).EffectiveState | Should -BeExactly NotTargeted
    }

    It 'records both membership sources for a shared transitive group' {
        $sources = @{
            'group-shared' = [PSCustomObject]@{ Name = 'Shared'; Sources = @('User', 'Device') }
        }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetId 'group-shared'
        ) -MembershipSources $sources -HasUser $true -HasDevice $true -ManagedDevice $script:windowsDevice

        $result.EffectiveState | Should -BeExactly Included
        $result.TargetName | Should -BeExactly Shared
        $result.ReasonChain[0].MembershipSources | Should -Be @('User', 'Device')
    }

    It 'honors a matching exclusion over a matching inclusion' {
        $sources = @{ 'excluded-group' = [PSCustomObject]@{ Name = 'Excluded'; Sources = @('User') } }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -Id include-all -TargetType AllUsers -TargetId $null
            New-EffectiveTestAssignment -Id exclude-group -Mode Exclude -TargetId excluded-group
        ) -MembershipSources $sources

        $result.EffectiveState | Should -BeExactly Excluded
        $result.AssignmentId | Should -BeExactly exclude-group
        $result.ReasonChain[-1].Code | Should -BeExactly Decision.Excluded
    }

    It 'returns NotTargeted when only an exclusion matches' {
        $sources = @{ 'excluded-group' = [PSCustomObject]@{ Name = 'Excluded'; Sources = @('User') } }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -Id exclude-only -Mode Exclude -TargetId excluded-group
        ) -MembershipSources $sources

        $result.EffectiveState | Should -BeExactly NotTargeted
        $result.TargetType | Should -BeExactly None
        $result.AssignmentReason | Should -BeExactly 'No Matching Assignment'
        $result.ReasonChain[-1].Code | Should -BeExactly Decision.NotTargeted
    }

    It 'returns Unknown when user and device inclusion and exclusion dimensions conflict' {
        $sources = @{ 'device-exclusion' = [PSCustomObject]@{ Name = 'Device Exclusion'; Sources = @('Device') } }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -Id include-user -TargetType AllUsers -TargetId $null
            New-EffectiveTestAssignment -Id exclude-device -Mode Exclude -TargetId device-exclusion
        ) -MembershipSources $sources -HasUser $true -HasDevice $true -ManagedDevice $script:windowsDevice

        $result.EffectiveState | Should -BeExactly Unknown
        $result.ReasonChain[-1].Code | Should -BeExactly Decision.CrossDimensionUnknown
    }

    It 'treats a nested group returned by transitive membership as included' {
        $sources = @{ 'nested-parent' = [PSCustomObject]@{ Name = 'Nested Parent'; Sources = @('User') } }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetId nested-parent
        ) -MembershipSources $sources

        $result.EffectiveState | Should -BeExactly Included
        $result.ReasonChain[0].Code | Should -BeExactly Target.TransitiveGroupMembership
    }

    It 'applies include and exclude assignment-filter semantics' {
        $script:AssignmentFilterLookup = @{
            corporate = [PSCustomObject]@{
                Id = 'corporate'; Name = 'Corporate'; Platform = 'windows10AndLater'
                Rule = '(device.deviceOwnership -eq "Corporate")'; AssignmentFilterManagementType = 'devices'
            }
        }

        $includeResult = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetType AllDevices -TargetId $null -FilterId corporate -FilterType include
        ) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice
        $excludeResult = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetType AllDevices -TargetId $null -FilterId corporate -FilterType exclude
        ) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice

        $includeResult.EffectiveState | Should -BeExactly Included
        $includeResult.ReasonChain[0].FilterResult | Should -BeExactly Match
        $excludeResult.EffectiveState | Should -BeExactly NotTargeted
        $excludeResult.ReasonChain[0].FilterResult | Should -BeExactly NotMatch
    }

    It 'treats zero-GUID and none filter metadata as unfiltered' {
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetType AllDevices -TargetId $null `
                -FilterId '00000000-0000-0000-0000-000000000000' -FilterType none
        ) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice

        $result.EffectiveState | Should -BeExactly Included
        $result.ReasonChain[0].FilterCode | Should -BeExactly Filter.None
    }

    It 'accepts every target, mode, and filter token emitted by the real Graph assignment normalizer' {
        $specs = @(
            @{ Type = '#microsoft.graph.allLicensedUsersAssignmentTarget'; TargetType = 'AllUsers'; Mode = 'Include' }
            @{ Type = '#microsoft.graph.allDevicesAssignmentTarget'; TargetType = 'AllDevices'; Mode = 'Include' }
            @{ Type = '#microsoft.graph.groupAssignmentTarget'; TargetType = 'Group'; Mode = 'Include'; GroupId = 'group-include' }
            @{ Type = '#microsoft.graph.exclusionGroupAssignmentTarget'; TargetType = 'Group'; Mode = 'Exclude'; GroupId = 'group-exclude' }
        )
        $normalizedByType = @{}
        foreach ($spec in $specs) {
            $target = [PSCustomObject]@{
                '@odata.type' = $spec.Type
                groupId = $spec.GroupId
                deviceAndAppManagementAssignmentFilterId = '00000000-0000-0000-0000-000000000000'
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
            $normalized = ConvertTo-IACNormalizedAssignment -Assignment ([PSCustomObject]@{
                    id = $spec.Type; target = $target
                })
            $normalizedByType[$spec.Type] = $normalized
            $normalized.TargetType | Should -BeExactly $spec.TargetType
            $normalized.AssignmentMode | Should -BeExactly $spec.Mode
            $normalized.FilterId | Should -BeNullOrEmpty
        }

        $includeFilter = ConvertTo-IACNormalizedAssignment -Assignment ([PSCustomObject]@{
                id = 'filter-include'
                target = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-include'
                    deviceAndAppManagementAssignmentFilterId = 'filter-1'
                    deviceAndAppManagementAssignmentFilterType = 'include'
                }
            })
        $excludeFilter = ConvertTo-IACNormalizedAssignment -Assignment ([PSCustomObject]@{
                id = 'filter-exclude'
                target = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-include'
                    deviceAndAppManagementAssignmentFilterId = 'filter-2'
                    deviceAndAppManagementAssignmentFilterType = 'exclude'
                }
            })
        $includeFilter.FilterType | Should -BeExactly include
        $excludeFilter.FilterType | Should -BeExactly exclude

        $sources = @{ 'group-exclude' = [PSCustomObject]@{ Name = 'Excluded'; Sources = @('User') } }
        $result = Invoke-EffectiveTestResolution -Assignments @(
            $normalizedByType['#microsoft.graph.allLicensedUsersAssignmentTarget']
            $normalizedByType['#microsoft.graph.exclusionGroupAssignmentTarget']
        ) -MembershipSources $sources
        $result.EffectiveState | Should -BeExactly Excluded
    }

    It 'returns Unknown for an unknown assignment mode instead of dropping the candidate' {
        $assignment = New-EffectiveTestAssignment -TargetType AllUsers -TargetId $null
        $assignment.AssignmentMode = 'Unknown'

        $result = Invoke-EffectiveTestResolution -Assignments @($assignment)

        $result.EffectiveState | Should -BeExactly Unknown
        $result.ReasonChain[-1].Code | Should -BeExactly Decision.UnknownAssignmentMode
    }

    It 'returns Unknown when a real filter id has no filter mode' {
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetType AllDevices -TargetId $null -FilterId real-filter -FilterType ''
        ) -HasUser $false -HasDevice $true -ManagedDevice $script:windowsDevice

        $result.EffectiveState | Should -BeExactly Unknown
        $result.ReasonChain[0].FilterCode | Should -BeExactly Filter.UnsupportedMode
    }

    It 'returns Unknown when membership or a filter cannot be evaluated safely' {
        $membershipUnknown = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetId unknown-group
        ) -UserMembershipKnown $false
        $filterUnknown = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -TargetType AllUsers -TargetId $null -FilterId missing-filter -FilterType include
        )

        $membershipUnknown.EffectiveState | Should -BeExactly Unknown
        $membershipUnknown.ReasonChain[0].Code | Should -BeExactly Target.GroupMembershipUnknown
        $filterUnknown.EffectiveState | Should -BeExactly Unknown
        $filterUnknown.ReasonChain[0].FilterResult | Should -BeExactly Unknown
        $filterUnknown.ReasonChain[0].FilterCode | Should -BeExactly Filter.NoDevice
    }

    It 'lets a possible exclusion make an otherwise active inclusion Unknown' {
        $result = Invoke-EffectiveTestResolution -Assignments @(
            New-EffectiveTestAssignment -Id include-all -TargetType AllUsers -TargetId $null
            New-EffectiveTestAssignment -Id maybe-excluded -Mode Exclude -TargetId unknown-group
        ) -UserMembershipKnown $false

        $result.EffectiveState | Should -BeExactly Unknown
        $result.ReasonChain[-1].Code | Should -BeExactly Decision.UnresolvedExclusion
    }

    It 'returns NotTargeted with a reason chain when a policy has no assignments' {
        $result = Invoke-EffectiveTestResolution -Assignments @()

        $result.EffectiveState | Should -BeExactly NotTargeted
        $result.AssignmentMode | Should -BeExactly None
        $result.ReasonChain[-1].Message | Should -BeExactly 'The policy has no assignments.'
    }
}

Describe 'Get-IntuneEffectiveAssignment orchestration' {
    BeforeEach {
        $script:AssignmentFilterLookup = @{}
        $script:effectiveContexts = @(
            [PSCustomObject]@{
                Category = New-EffectiveTestCategory
                Entity = New-EffectiveTestEntity
                Assignments = @(New-EffectiveTestAssignment -TargetId shared-group)
            }
        )
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-UserInfo {
            @{ Success = $true; Id = 'user-1'; UserPrincipalName = 'user@contoso.com' }
        }
        Mock Get-IACManagedDevice {
            [PSCustomObject]@{
                Success = $true
                Device = [PSCustomObject]@{
                    id = 'managed-1'; deviceName = 'WIN-01'; azureADDeviceId = 'aad-device-1'
                    operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'
                }
                Reason = $null
            }
        }
        Mock Get-IACDirectoryDevice {
            [PSCustomObject]@{ Success = $true; Device = [PSCustomObject]@{ id = 'directory-1'; deviceId = 'aad-device-1' }; Reason = $null }
        }
        Mock Get-GroupMemberships {
            @([PSCustomObject]@{ id = 'shared-group'; displayName = 'Shared Group' })
        }
        Mock Get-IntuneCategoryDefinition { @(New-EffectiveTestCategory) }
        $script:effectiveScanErrors = @()
        Mock Invoke-IntuneCategoryScan {
            foreach ($context in $script:effectiveContexts) { & $ProcessEntity $context }
            [PSCustomObject]@{ Errors = @($script:effectiveScanErrors) }
        }
    }

    It 'unions user and device transitive membership without leaking collection indices' {
        $result = @(Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -DeviceName WIN-01 -PassThru)

        $result.Count | Should -Be 1
        $result[0].PSObject.TypeNames | Should -Contain IntuneAssignmentChecker.AssignmentRecord
        $result[0].SubjectType | Should -BeExactly UserDevice
        $result[0].EffectiveState | Should -BeExactly Included
        $result[0].ReasonChain[0].MembershipSources | Should -Be @('User', 'Device')
        Should -Invoke Write-Host -Exactly 0
        Should -Invoke Get-GroupMemberships -Exactly 1 -ParameterFilter { $ObjectType -eq 'User' -and $ObjectId -eq 'user-1' }
        Should -Invoke Get-GroupMemberships -Exactly 1 -ParameterFilter { $ObjectType -eq 'Device' -and $ObjectId -eq 'directory-1' }
    }

    It 'marks group targeting Unknown when directory-device mapping is unavailable' {
        Mock Get-IACDirectoryDevice {
            [PSCustomObject]@{ Success = $false; Device = $null; Reason = 'not mapped' }
        }

        $result = @(Get-IntuneEffectiveAssignment -DeviceName WIN-01 -PassThru)

        $result.Count | Should -Be 1
        $result[0].EffectiveState | Should -BeExactly Unknown
        Should -Invoke Write-Warning -ParameterFilter { $Message -eq 'not mapped' }
    }

    It 'splits application results by intent' {
        $script:effectiveContexts = @(
            [PSCustomObject]@{
                Category = New-EffectiveTestCategory -Id Applications -ExportCategory Application
                Entity = New-EffectiveTestEntity -Id app-1 -Name 'Company Portal'
                Assignments = @(
                    New-EffectiveTestAssignment -Id required -TargetType AllUsers -TargetId $null -Intent required
                    New-EffectiveTestAssignment -Id available -TargetType AllUsers -TargetId $null -Intent available
                )
            }
        )

        $result = @(Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -PassThru)

        $result.Count | Should -Be 2
        $result.Category | Should -Contain 'Required App'
        $result.Category | Should -Contain 'Available App'
    }

    It 'exports formula-safe CSV with a JSON reason chain' {
        $script:effectiveContexts[0].Entity.displayName = '=danger'
        $path = Join-Path $TestDrive 'effective.csv'

        $result = @(Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -PassThru -ExportPath $path)
        $csv = Import-Csv $path

        $result.Count | Should -Be 1
        $csv.Count | Should -Be 1
        $csv[0].PolicyName | Should -BeExactly "'=danger"
        $csv[0].CategoryId | Should -BeExactly DeviceConfigurations
        $csv[0].TargetName | Should -BeExactly 'Shared Group'
        $csv[0].EffectiveState | Should -BeExactly Included
        $csv[0].DecisionCode | Should -BeExactly Decision.Included
        $csv[0].ReasonChain | Should -Match '^\['
        ($csv[0].ReasonChain | ConvertFrom-Json)[-1].Code | Should -BeExactly Decision.Included
    }

    It 'keeps a one-entry no-assignment reason chain as a JSON array' {
        $script:effectiveContexts[0].Assignments = @()
        $path = Join-Path $TestDrive 'empty-assignment.csv'

        $null = Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -ExportPath $path
        $csv = Import-Csv $path

        $csv[0].ReasonChain | Should -Match '^\['
        @($csv[0].ReasonChain | ConvertFrom-Json).Count | Should -Be 1
        ($csv[0].ReasonChain | ConvertFrom-Json)[0].Code | Should -BeExactly Decision.NotTargeted
    }

    It 'returns a machine-readable Unknown record for every failed category' {
        $script:effectiveContexts = @()
        $script:effectiveScanErrors = @([PSCustomObject]@{
                CategoryId = 'DeviceConfigurations'
                DisplayName = 'Device Configurations'
                Message = 'Graph returned 403 Forbidden'
            })

        $result = @(Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -PassThru)

        $result.Count | Should -Be 1
        $result[0].PSObject.TypeNames | Should -Contain IntuneAssignmentChecker.AssignmentRecord
        $result[0].EffectiveState | Should -BeExactly Unknown
        $result[0].ReasonChain[0].Code | Should -BeExactly Scan.CategoryFailed
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'DeviceConfigurations.*403 Forbidden' }
    }

    It 'rejects invalid export paths before resolving subjects or scanning the tenant' {
        $errors = @()
        Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -ExportPath './wrong.json' `
            -ErrorVariable +errors -ErrorAction SilentlyContinue

        $errors.Exception.Message | Should -Contain 'ExportPath must be a .csv file.'
        Should -Invoke Get-UserInfo -Exactly 0
        Should -Invoke Invoke-IntuneCategoryScan -Exactly 0
    }

    It 'requires at least one subject before making Graph calls' {
        $errors = @()
        Get-IntuneEffectiveAssignment -ErrorVariable +errors -ErrorAction SilentlyContinue

        $errors.Exception.Message | Should -Contain 'Supply -UserPrincipalName, -DeviceName, or both.'
        Should -Invoke Get-UserInfo -Exactly 0
        Should -Invoke Get-IACManagedDevice -Exactly 0
    }

    It 'requires a module connection before resolving a subject' {
        $savedEndpoint = $script:GraphEndpoint
        $script:GraphEndpoint = $null
        try {
            $errors = @()
            Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com `
                -ErrorVariable +errors -ErrorAction SilentlyContinue

            $errors.Exception.Message | Should -Contain 'Connect first with Connect-IntuneAssignmentChecker.'
            Should -Invoke Get-UserInfo -Exactly 0
            Should -Invoke Invoke-IntuneCategoryScan -Exactly 0
        }
        finally { $script:GraphEndpoint = $savedEndpoint }
    }

    It 'uses the default CSV name when ExportToCSV is supplied without ExportPath' {
        Push-Location $TestDrive
        try {
            $null = Get-IntuneEffectiveAssignment -UserPrincipalName user@contoso.com -ExportToCSV
            Test-Path (Join-Path $TestDrive 'IntuneEffectiveAssignments.csv') | Should -BeTrue
        }
        finally { Pop-Location }
    }
}
