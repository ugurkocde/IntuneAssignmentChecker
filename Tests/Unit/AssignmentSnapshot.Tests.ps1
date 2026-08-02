#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot Private

    . (Join-Path $modulePrivate 'New-IACAssignmentRecord.ps1')
    . (Join-Path $modulePrivate 'AssignmentSnapshot.ps1')
    . (Join-Path $moduleRoot 'Public/Export-IntuneAssignmentSnapshot.ps1')
    . (Join-Path $moduleRoot 'Public/Compare-IntuneAssignmentSnapshot.ps1')

    function Get-AssignmentFilterLookup { @{} }
    function Get-IntuneCategoryDefinition { param([string]$Audience) @() }
    function Invoke-IntuneCategoryScan {
        param([object[]]$Categories, [scriptblock]$ProcessEntity, [hashtable]$EntityCache, [switch]$ShowProgress, [string]$ProgressVerb, [switch]$BuildRecords)
        [PSCustomObject]@{ Records = @(); Errors = @(); Skipped = @() }
    }

    function New-SnapshotTestRecord {
        param(
            [string]$PolicyId = 'policy-1',
            [string]$PolicyName = 'Policy One',
            [string]$AssignmentId = 'assignment-1',
            [string]$Intent = 'required',
            [string]$TargetId = 'group-1',
            [string]$CategoryId = 'DeviceConfigurations'
        )
        New-IACAssignmentRecord -CategoryId $CategoryId -Category 'Device Configuration' `
            -PolicyId $PolicyId -PolicyName $PolicyName -Platform Windows `
            -AssignmentId $AssignmentId -AssignmentMode Include -TargetType Group `
            -TargetId $TargetId -TargetName 'Group One' -Intent $Intent `
            -AssignmentReason 'Group Assignment' -Source MicrosoftGraph
    }

    $script:GraphEndpoint = 'https://graph.test'
    $script:CurrentTenantId = 'tenant-1'
    $script:CurrentTenantName = 'Contoso'
    $script:AssignmentFilterLookup = @{}
    $script:fixedCapture = [datetimeoffset]'2026-08-01T10:00:00Z'
}

Describe 'Export-IntuneAssignmentSnapshot' {
    BeforeEach {
        $script:CurrentTenantId = 'tenant-1'
        $script:CurrentTenantName = 'Contoso'
        $script:GraphEndpoint = 'https://graph.test'
        $script:AssignmentFilterLookup = @{}
        Mock Get-IntuneCategoryDefinition { @() }
        Mock Invoke-IntuneCategoryScan { [PSCustomObject]@{ Records = @(); Errors = @(); Skipped = @() } }
    }

    It 'round-trips schema, tenant, version, coverage, and canonical records' {
        $path = Join-Path $TestDrive 'snapshot.json'
        $record = New-SnapshotTestRecord

        $snapshot = $record | Export-IntuneAssignmentSnapshot -Path $path `
            -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture -PassThru
        $loaded = Read-IACAssignmentSnapshot -Path $path

        $snapshot.PSObject.TypeNames | Should -Contain IntuneAssignmentChecker.AssignmentSnapshot
        $loaded.SchemaName | Should -BeExactly IntuneAssignmentChecker.AssignmentSnapshot
        $loaded.SchemaVersion | Should -Be 2
        $loaded.CapturedAtUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') |
            Should -BeExactly '2026-08-01T10:00:00.0000000Z'
        $loaded.ModuleVersion | Should -BeExactly '5.0.0'
        $loaded.Tenant.Id | Should -BeExactly tenant-1
        $loaded.Coverage.Complete | Should -BeTrue
        $loaded.Coverage.RecordCount | Should -Be 1
        $loaded.Coverage.Categories[0].CategoryId | Should -BeExactly DeviceConfigurations
        $loaded.Records[0].PolicyId | Should -BeExactly policy-1
        $loaded.Records[0].PSObject.Properties.Name | Should -Be (Get-IACAssignmentRecordPropertyNames)
        @($loaded.Records[0].ReasonChain).Count | Should -Be 0
        @($loaded.Records[0].ScopeTagIds).Count | Should -Be 0
        @($loaded.Records[0].ScopeTags).Count | Should -Be 0
    }

    It 'migrates a v1 snapshot and validates the migrated document against the v2 schema' {
        $path = Join-Path $TestDrive 'snapshot-v1.json'
        $record = New-SnapshotTestRecord
        $record | Export-IntuneAssignmentSnapshot -Path $path -CoverageCategory DeviceConfigurations `
            -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 30
        $document.SchemaVersion = 1
        $document.Records[0].SchemaVersion = 1
        foreach ($propertyName in @('SchemaName', 'RecordId', 'GraphApiVersion')) {
            $document.Records[0].PSObject.Properties.Remove($propertyName)
        }
        [IO.File]::WriteAllText($path, ($document | ConvertTo-Json -Depth 30))

        $migrated = Read-IACAssignmentSnapshot -Path $path
        $schemaPath = Join-Path $moduleRoot 'Schemas/assignment-snapshot.v2.schema.json'
        $snapshotSchema = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json -Depth 40
        $recordSchema = Get-Content -LiteralPath (Join-Path $moduleRoot 'Schemas/assignment-record.v2.schema.json') -Raw | ConvertFrom-Json -Depth 40
        $snapshotSchema.properties.Records.items = $recordSchema

        $migrated.SchemaVersion | Should -Be 2
        $migrated.MigratedFromSchemaVersion | Should -Be 1
        $migrated.Records[0].SchemaVersion | Should -Be 2
        $migrated.Records[0].RecordId | Should -Match '^[0-9a-f]{64}$'
        Test-Json -Json ($migrated | ConvertTo-Json -Depth 30) -Schema ($snapshotSchema | ConvertTo-Json -Depth 40) | Should -BeTrue
    }

    It 'reads the installed version without validating external module dependencies' {
        Mock Get-Module { $null }
        Mock Import-PowerShellDataFile { @{ ModuleVersion = '9.8.7' } } -ParameterFilter {
            $LiteralPath -like '*IntuneAssignmentChecker.psd1'
        }
        Mock Test-ModuleManifest { throw 'Required module is unavailable' }

        Get-IACInstalledModuleVersion | Should -BeExactly '9.8.7'

        Should -Invoke Import-PowerShellDataFile -Exactly 1 -ParameterFilter {
            $LiteralPath -like '*IntuneAssignmentChecker.psd1'
        }
        Should -Invoke Test-ModuleManifest -Exactly 0
    }

    It 'writes byte-identical JSON for the same records and capture metadata regardless of input order' {
        $firstPath = Join-Path $TestDrive 'first.json'
        $secondPath = Join-Path $TestDrive 'second.json'
        $records = @(
            New-SnapshotTestRecord -PolicyId policy-b -PolicyName 'Policy B' -AssignmentId assignment-b
            New-SnapshotTestRecord -PolicyId policy-a -PolicyName 'Policy A' -AssignmentId assignment-a
        )

        $savedCulture = [System.Globalization.CultureInfo]::CurrentCulture
        $savedUiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
        try {
            [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]'tr-TR'
            [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]'tr-TR'
            $records | Export-IntuneAssignmentSnapshot -Path $firstPath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture

            [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]'en-US'
            [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]'en-US'
            @($records[1], $records[0]) | Export-IntuneAssignmentSnapshot -Path $secondPath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture
        }
        finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $savedCulture
            [System.Globalization.CultureInfo]::CurrentUICulture = $savedUiCulture
        }

        [System.IO.File]::ReadAllBytes($firstPath) | Should -Be ([System.IO.File]::ReadAllBytes($secondPath))
    }

    It 'allowlists the canonical schema and excludes arbitrary secret or token fields' {
        $path = Join-Path $TestDrive 'safe.json'
        $record = New-SnapshotTestRecord
        $record | Add-Member -NotePropertyName AccessToken -NotePropertyValue 'super-secret-token'
        $record | Add-Member -NotePropertyName ClientSecret -NotePropertyValue 'super-secret-client-value'

        $record | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $raw = Get-Content -LiteralPath $path -Raw

        $raw | Should -Not -Match 'super-secret'
        $raw | Should -Not -Match 'AccessToken|ClientSecret'
    }

    It 'preserves case-distinct array values and sorts arrays and reason chains ordinally' {
        $path = Join-Path $TestDrive 'arrays.json'
        $record = New-SnapshotTestRecord
        $record.ScopeTagIds = @('b', 'A', 'a')
        $record.ScopeTags = @('Zulu', 'istanbul', 'Istanbul')
        $record.ReasonChain = @(
            [PSCustomObject]@{ Sequence = 2; Code = 'Second'; MembershipSources = @('device', 'Device') }
            [PSCustomObject]@{ Sequence = 1; Code = 'First' }
        )

        $record | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $loaded = Read-IACAssignmentSnapshot $path

        $loaded.Records[0].ScopeTagIds | Should -Be @('A', 'a', 'b')
        $loaded.Records[0].ScopeTags | Should -Be @('Istanbul', 'Zulu', 'istanbul')
        $loaded.Records[0].ReasonChain.Code | Should -Be @('First', 'Second')
        $loaded.Records[0].ReasonChain[0].MembershipSources | Should -BeNullOrEmpty
        (Get-Content -LiteralPath $path -Raw) | Should -Match '"MembershipSources":\s*\[\]'
        $loaded.Records[0].ReasonChain[1].MembershipSources | Should -Be @('Device', 'device')
    }

    It 'keeps subject-scoped records distinct in the stable identity' {
        $path = Join-Path $TestDrive 'subjects.json'
        $userOne = New-SnapshotTestRecord
        $userOne.SubjectType = 'User'; $userOne.SubjectId = 'user-1'; $userOne.SubjectName = 'One'
        $userTwo = New-SnapshotTestRecord
        $userTwo.SubjectType = 'User'; $userTwo.SubjectId = 'user-2'; $userTwo.SubjectName = 'Two'

        @($userOne, $userTwo) | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $loaded = Read-IACAssignmentSnapshot $path

        @($loaded.Records).Count | Should -Be 2
        (Get-IACAssignmentIdentityKey $loaded.Records[0]) | Should -Not -BeExactly (Get-IACAssignmentIdentityKey $loaded.Records[1])
    }

    It 'resolves relative paths against the PowerShell location and supports Force overwrite' {
        Push-Location $TestDrive
        try {
            Export-IntuneAssignmentSnapshot -Path './relative/snapshot.json' -InputObject @() `
                -CoverageComplete -CapturedAtUtc $script:fixedCapture
            Test-Path './relative/snapshot.json' | Should -BeTrue
            @(Compare-IntuneAssignmentSnapshot -ReferencePath './relative/snapshot.json' `
                    -DifferencePath './relative/snapshot.json').Count | Should -Be 0

            Export-IntuneAssignmentSnapshot -Path './relative/snapshot.json' -InputObject @() `
                -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-02T10:00:00Z') -Force
            (Read-IACAssignmentSnapshot './relative/snapshot.json').CapturedAtUtc.ToUniversalTime().Day | Should -Be 2
        }
        finally { Pop-Location }
    }

    It 'rejects declared coverage that omits a supplied record category' {
        $path = Join-Path $TestDrive 'bad-coverage.json'
        $records = @(
            New-SnapshotTestRecord -CategoryId DeviceConfigurations
            New-SnapshotTestRecord -PolicyId compliance-1 -AssignmentId compliance-a -CategoryId CompliancePolicies
        )

        { $records | Export-IntuneAssignmentSnapshot -Path $path `
                -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture } |
            Should -Throw '*does not include record categories*CompliancePolicies*'
    }

    It 'defaults supplied records to incomplete coverage and accepts explicit coverage errors' {
        $path = Join-Path $TestDrive 'provided-incomplete.json'
        $record = New-SnapshotTestRecord
        $coverageError = [PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = 'HTTP 403' }

        $snapshot = $record | Export-IntuneAssignmentSnapshot -Path $path `
            -CoverageCategory DeviceConfigurations -CoverageError $coverageError `
            -CapturedAtUtc $script:fixedCapture -PassThru

        $snapshot.Coverage.Complete | Should -BeFalse
        ($snapshot.Coverage.Categories | Where-Object CategoryId -eq CompliancePolicies).Status | Should -BeExactly Failed
        (Read-IACAssignmentSnapshot -Path $path).Coverage.Categories.CategoryId | Should -Contain CompliancePolicies
        { Compare-IntuneAssignmentSnapshot -ReferencePath $path -DifferencePath $path } |
            Should -Throw '*incomplete category coverage*'
        @(Compare-IntuneAssignmentSnapshot -ReferencePath $path -DifferencePath $path -AllowIncompleteCoverage).Count | Should -Be 0
    }

    It 'rejects empty supplied coverage errors before writing' {
        $path = Join-Path $TestDrive 'empty-error.json'
        $record = New-SnapshotTestRecord
        $emptyError = [PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = '' }

        { $record | Export-IntuneAssignmentSnapshot -Path $path -CoverageError $emptyError `
                -CapturedAtUtc $script:fixedCapture } | Should -Throw '*requires non-empty CategoryId and Message*'
        Test-Path $path | Should -BeFalse
    }

    It 'round-trips legal four-component PowerShell module versions' {
        $path = Join-Path $TestDrive 'four-part-version.json'
        Mock Get-IACInstalledModuleVersion { '4.4.0.1' }

        Export-IntuneAssignmentSnapshot -Path $path -InputObject @() -CoverageComplete -CapturedAtUtc $script:fixedCapture

        (Read-IACAssignmentSnapshot -Path $path).ModuleVersion | Should -BeExactly '4.4.0.1'
    }

    It 'requires a tenant identity and covers no-id fallback identities' {
        $path = Join-Path $TestDrive 'fallback.json'
        $fallbackOne = New-SnapshotTestRecord -PolicyId policy-fallback -AssignmentId '' -TargetId group-1
        $fallbackTwo = New-SnapshotTestRecord -PolicyId policy-fallback -AssignmentId '' -TargetId group-2
        $fallbackOne.AssignmentMode = 'include'
        $fallbackOne.TargetType = 'group'
        $fallbackOne.EffectiveState = 'included'
        (Get-IACAssignmentIdentityKey $fallbackOne) | Should -Not -BeExactly (Get-IACAssignmentIdentityKey $fallbackTwo)

        @($fallbackOne, $fallbackTwo) | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $loaded = Read-IACAssignmentSnapshot $path
        @($loaded.Records).Count | Should -Be 2
        ($loaded.Records | Where-Object TargetId -eq group-1).AssignmentMode | Should -BeExactly Include
        ($loaded.Records | Where-Object TargetId -eq group-1).TargetType | Should -BeExactly Group
        ($loaded.Records | Where-Object TargetId -eq group-1).EffectiveState | Should -BeExactly Included

        $script:CurrentTenantId = $null
        $script:CurrentTenantName = $null
        $tenantless = New-SnapshotTestRecord
        { $tenantless | Export-IntuneAssignmentSnapshot -Path (Join-Path $TestDrive 'tenantless.json') `
                -CoverageComplete -CapturedAtUtc $script:fixedCapture } | Should -Throw '*tenant ID is required*'
    }

    It 'captures the shared tenant scan and records per-category coverage failures' {
        $path = Join-Path $TestDrive 'tenant.json'
        $record = New-SnapshotTestRecord
        Mock Get-IntuneCategoryDefinition {
            @(
                [PSCustomObject]@{ Id = 'DeviceConfigurations'; DisplayName = 'Device Configurations' }
                [PSCustomObject]@{ Id = 'CompliancePolicies'; DisplayName = 'Compliance Policies' }
            )
        }
        Mock Invoke-IntuneCategoryScan {
            [PSCustomObject]@{
                Records = @($record)
                Errors = @([PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = 'HTTP 403' })
            }
        }

        $snapshot = Export-IntuneAssignmentSnapshot -Path $path -CapturedAtUtc $script:fixedCapture -PassThru

        $snapshot.Coverage.Mode | Should -BeExactly TenantScan
        $snapshot.Coverage.Complete | Should -BeFalse
        ($snapshot.Coverage.Categories | Where-Object CategoryId -eq CompliancePolicies).Status | Should -BeExactly Failed
        $snapshot.Coverage.Errors[0].Message | Should -BeExactly 'HTTP 403'
        (Read-IACAssignmentSnapshot -Path $path).Coverage.Complete | Should -BeFalse
        Should -Invoke Get-IntuneCategoryDefinition -Exactly 1 -ParameterFilter { $Audience -eq 'Effective' }
        Should -Invoke Invoke-IntuneCategoryScan -Exactly 1 -ParameterFilter { $BuildRecords }
    }

    It 'treats null scanner records and errors as empty collections' {
        $path = Join-Path $TestDrive 'null-scan.json'
        Mock Get-IntuneCategoryDefinition { @() }
        Mock Invoke-IntuneCategoryScan { [PSCustomObject]@{ Records = $null; Errors = $null } }

        $snapshot = Export-IntuneAssignmentSnapshot -Path $path -CapturedAtUtc $script:fixedCapture -PassThru
        $loaded = Read-IACAssignmentSnapshot -Path $path

        $snapshot.Coverage.Complete | Should -BeTrue
        @($loaded.Records).Count | Should -Be 0
        @($loaded.Coverage.Errors).Count | Should -Be 0
    }

    It 'marks skipped optional categories incomplete and excludes them from comparison' {
        $baselinePath = Join-Path $TestDrive 'optional-baseline.json'
        $currentPath = Join-Path $TestDrive 'optional-current.json'
        $record = New-SnapshotTestRecord -CategoryId WindowsFeatureUpdates
        $record | Export-IntuneAssignmentSnapshot -Path $baselinePath -CoverageCategory WindowsFeatureUpdates `
            -CoverageComplete -CapturedAtUtc $script:fixedCapture
        Mock Get-IntuneCategoryDefinition {
            @([PSCustomObject]@{ Id = 'WindowsFeatureUpdates'; DisplayName = 'Windows Feature Updates' })
        }
        Mock Invoke-IntuneCategoryScan {
            [PSCustomObject]@{
                Records = @()
                Errors = @()
                Skipped = @([PSCustomObject]@{ CategoryId = 'WindowsFeatureUpdates'; Message = 'HTTP 503' })
            }
        }

        $snapshot = Export-IntuneAssignmentSnapshot -Path $currentPath -CapturedAtUtc $script:fixedCapture -PassThru

        $snapshot.Coverage.Complete | Should -BeFalse
        $snapshot.Coverage.Categories[0].Status | Should -BeExactly Skipped
        $snapshot.Coverage.Errors[0].Message | Should -BeExactly 'HTTP 503'
        $removalChanges = @(Compare-IntuneAssignmentSnapshot -ReferencePath $baselinePath `
                -DifferencePath $currentPath -WarningVariable removalWarnings)
        $additionChanges = @(Compare-IntuneAssignmentSnapshot -ReferencePath $currentPath `
                -DifferencePath $baselinePath -WarningVariable additionWarnings)
        $removalChanges.Count | Should -Be 0
        $additionChanges.Count | Should -Be 0
        @($removalWarnings).Count | Should -Be 1
        "$removalWarnings" | Should -Match 'WindowsFeatureUpdates'
        @($additionWarnings).Count | Should -Be 1
    }

    It 'rejects blank category ids and scan errors outside tenant coverage before writing' {
        $blankPath = Join-Path $TestDrive 'blank-category.json'
        Mock Get-IntuneCategoryDefinition { @([PSCustomObject]@{ Id = ''; DisplayName = 'Broken' }) }
        Mock Invoke-IntuneCategoryScan { [PSCustomObject]@{ Records = @(); Errors = @() } }
        { Export-IntuneAssignmentSnapshot -Path $blankPath -CapturedAtUtc $script:fixedCapture } |
            Should -Throw '*category definition without Id*'

        $outsidePath = Join-Path $TestDrive 'outside-error.json'
        Mock Get-IntuneCategoryDefinition { @([PSCustomObject]@{ Id = 'DeviceConfigurations'; DisplayName = 'Device Configurations' }) }
        Mock Invoke-IntuneCategoryScan {
            [PSCustomObject]@{
                Records = @()
                Errors = @([PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = 'HTTP 403' })
            }
        }
        { Export-IntuneAssignmentSnapshot -Path $outsidePath -CapturedAtUtc $script:fixedCapture } |
            Should -Throw '*errors outside declared coverage*CompliancePolicies*'
    }

    It 'rejects invalid reason-chain sequences with an actionable error' {
        $path = Join-Path $TestDrive 'invalid-sequence.json'
        $record = New-SnapshotTestRecord
        $record.ReasonChain = @([PSCustomObject]@{ Sequence = 'first'; Code = 'Bad' })

        { $record | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete -CapturedAtUtc $script:fixedCapture } |
            Should -Throw "*reason-chain entry with invalid Sequence 'first'*"
    }

    It 'supports empty snapshots and refuses accidental overwrites' {
        $path = Join-Path $TestDrive 'empty.json'

        $snapshot = Export-IntuneAssignmentSnapshot -Path $path -InputObject @() `
            -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture -PassThru

        @($snapshot.Records).Count | Should -Be 0
        $snapshot.Coverage.RecordCount | Should -Be 0
        { Export-IntuneAssignmentSnapshot -Path $path -InputObject @() -CapturedAtUtc $script:fixedCapture } |
            Should -Throw '*already exists*use -Force*'
    }
}

Describe 'Compare-IntuneAssignmentSnapshot' {
    BeforeEach {
        $script:CurrentTenantId = 'tenant-1'
        $script:CurrentTenantName = 'Contoso'
    }

    It 'reports deterministic Added, Removed, and Changed assignment records' {
        $beforePath = Join-Path $TestDrive 'before.json'
        $afterPath = Join-Path $TestDrive 'after.json'
        $before = @(
            New-SnapshotTestRecord -PolicyId policy-change -AssignmentId assignment-change -Intent required
            New-SnapshotTestRecord -PolicyId policy-remove -AssignmentId assignment-remove
        )
        $after = @(
            New-SnapshotTestRecord -PolicyId policy-change -AssignmentId assignment-change -Intent available
            New-SnapshotTestRecord -PolicyId policy-add -AssignmentId assignment-add
        )
        $before | Export-IntuneAssignmentSnapshot -Path $beforePath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $after | Export-IntuneAssignmentSnapshot -Path $afterPath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture

        $changes = @(Compare-IntuneAssignmentSnapshot -ReferencePath $beforePath -DifferencePath $afterPath)

        $changes.ChangeType | Should -Be @('Added', 'Removed', 'Changed')
        $changes[0].PolicyId | Should -BeExactly policy-add
        $changes[1].PolicyId | Should -BeExactly policy-remove
        $changes[2].PolicyId | Should -BeExactly policy-change
        $changes[2].ChangedFields | Should -Contain Intent
        $changes[2].Before.Intent | Should -BeExactly required
        $changes[2].After.Intent | Should -BeExactly available
        $changes[0].PSObject.TypeNames | Should -Contain IntuneAssignmentChecker.AssignmentSnapshotDifference
    }

    It 'detects changes in array-valued canonical fields' {
        $beforePath = Join-Path $TestDrive 'arrays-before.json'
        $afterPath = Join-Path $TestDrive 'arrays-after.json'
        $before = New-SnapshotTestRecord
        $before.ScopeTagIds = @('0', '1')
        $before.ReasonChain = @(
            [PSCustomObject]@{ Sequence = 1; Code = 'One' }
            [PSCustomObject]@{ Sequence = 2; Code = 'Two' }
        )
        $after = New-SnapshotTestRecord
        $after.ScopeTagIds = @('0')
        $after.ReasonChain = @([PSCustomObject]@{ Sequence = 1; Code = 'One' })
        $before | Export-IntuneAssignmentSnapshot -Path $beforePath -CoverageComplete -CapturedAtUtc $script:fixedCapture
        $after | Export-IntuneAssignmentSnapshot -Path $afterPath -CoverageComplete -CapturedAtUtc $script:fixedCapture

        $change = Compare-IntuneAssignmentSnapshot -ReferencePath $beforePath -DifferencePath $afterPath

        $change.ChangeType | Should -BeExactly Changed
        $change.ChangedFields | Should -Contain ScopeTagIds
        $change.ChangedFields | Should -Contain ReasonChain
    }

    It 'returns no differences for empty compatible snapshots' {
        $beforePath = Join-Path $TestDrive 'empty-before.json'
        $afterPath = Join-Path $TestDrive 'empty-after.json'
        Export-IntuneAssignmentSnapshot -Path $beforePath -InputObject @() -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture
        Export-IntuneAssignmentSnapshot -Path $afterPath -InputObject @() -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture

        @(Compare-IntuneAssignmentSnapshot -ReferencePath $beforePath -DifferencePath $afterPath).Count | Should -Be 0
    }

    It 'rejects malformed JSON and unsupported snapshot schemas with actionable errors' {
        $malformedPath = Join-Path $TestDrive 'malformed.json'
        $unsupportedPath = Join-Path $TestDrive 'unsupported.json'
        $nonNumericVersionPath = Join-Path $TestDrive 'non-numeric-version.json'
        $missingRecordsPath = Join-Path $TestDrive 'missing-records.json'
        [System.IO.File]::WriteAllText($malformedPath, '{not-json')
        [System.IO.File]::WriteAllText($unsupportedPath, '{"SchemaName":"IntuneAssignmentChecker.AssignmentSnapshot","SchemaVersion":3}')
        [System.IO.File]::WriteAllText($nonNumericVersionPath, '{"SchemaName":"IntuneAssignmentChecker.AssignmentSnapshot","SchemaVersion":"v1"}')
        [System.IO.File]::WriteAllText($missingRecordsPath, '{"SchemaName":"IntuneAssignmentChecker.AssignmentSnapshot","SchemaVersion":1,"CapturedAtUtc":"2026-08-01T10:00:00Z","ModuleVersion":"4.4.0","Tenant":{},"Coverage":{}}')

        { Read-IACAssignmentSnapshot -Path $malformedPath } | Should -Throw '*not valid JSON*'
        { Read-IACAssignmentSnapshot -Path $unsupportedPath } | Should -Throw '*unsupported schema version*expected version 1 or 2*'
        { Read-IACAssignmentSnapshot -Path $nonNumericVersionPath } | Should -Throw '*unsupported schema version*expected version 1 or 2*'
        { Read-IACAssignmentSnapshot -Path $missingRecordsPath } | Should -Throw "*missing 'Records'*"
    }

    It 'rejects non-canonical coverage mode and status casing' {
        $path = Join-Path $TestDrive 'coverage-casing.json'
        New-SnapshotTestRecord | Export-IntuneAssignmentSnapshot -Path $path -CoverageComplete `
            -CapturedAtUtc $script:fixedCapture
        $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
        $parsed.Coverage.Categories[0].Status = 'provided'
        $parsed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path

        { Read-IACAssignmentSnapshot -Path $path } | Should -Throw '*unsupported coverage status*provided*'

        $parsed.Coverage.Categories[0].Status = 'Provided'
        $parsed.Coverage.Mode = 'providedrecords'
        $parsed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path

        { Read-IACAssignmentSnapshot -Path $path } | Should -Throw '*unsupported Coverage.Mode*providedrecords*'
    }

    It 'rejects cross-tenant, incomplete, and mismatched coverage by default' {
        $tenantOnePath = Join-Path $TestDrive 'tenant-one.json'
        $tenantTwoPath = Join-Path $TestDrive 'tenant-two.json'
        $recordOne = New-SnapshotTestRecord
        $recordOne | Export-IntuneAssignmentSnapshot -Path $tenantOnePath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc $script:fixedCapture

        $script:CurrentTenantId = 'tenant-2'
        $script:CurrentTenantName = 'Fabrikam'
        $recordTwo = New-SnapshotTestRecord -CategoryId CompliancePolicies
        $recordTwo | Export-IntuneAssignmentSnapshot -Path $tenantTwoPath -CoverageCategory CompliancePolicies -CoverageComplete -CapturedAtUtc $script:fixedCapture

        { Compare-IntuneAssignmentSnapshot -ReferencePath $tenantOnePath -DifferencePath $tenantTwoPath } |
            Should -Throw '*different tenants*'

        $script:CurrentTenantId = 'tenant-1'
        $script:CurrentTenantName = 'Contoso'
        $parsed = Get-Content -LiteralPath $tenantOnePath -Raw | ConvertFrom-Json -Depth 20
        $parsed.Coverage.Complete = $false
        $parsed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tenantOnePath
        { Compare-IntuneAssignmentSnapshot -ReferencePath $tenantOnePath -DifferencePath $tenantOnePath } |
            Should -Throw '*incomplete category coverage*'

        $parsed.Coverage.Complete = $true
        $parsed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tenantOnePath
        $coverageTwoPath = Join-Path $TestDrive 'coverage-two.json'
        $recordOne | Export-IntuneAssignmentSnapshot -Path $coverageTwoPath `
            -CoverageCategory DeviceConfigurations, CompliancePolicies -CoverageComplete -CapturedAtUtc $script:fixedCapture
        { Compare-IntuneAssignmentSnapshot -ReferencePath $tenantOnePath -DifferencePath $coverageTwoPath } |
            Should -Throw '*different category sets*'
    }
}

Describe 'Assignment snapshot public surface' {
    It 'exports both snapshot commands from the module manifest' {
        $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $moduleRoot 'IntuneAssignmentChecker.psd1')
        $manifestData.FunctionsToExport | Should -Contain Export-IntuneAssignmentSnapshot
        $manifestData.FunctionsToExport | Should -Contain Compare-IntuneAssignmentSnapshot
    }
}
