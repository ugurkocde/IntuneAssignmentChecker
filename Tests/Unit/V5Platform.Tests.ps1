#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $manifestPath = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/IntuneAssignmentChecker.psd1'
    Import-Module $manifestPath -Force
}

AfterAll {
    Remove-Module IntuneAssignmentChecker -Force -ErrorAction SilentlyContinue
}

Describe 'v5 terminal UI parity' {
    It 'discovers every exported operation except its own catalog and UI infrastructure' {
        $module = Get-Module IntuneAssignmentChecker
        $expected = @($module.ExportedFunctions.Keys | Where-Object {
                $_ -notin @('Get-IntuneAssignmentOperation', 'Invoke-IntuneAssignmentChecker', 'Start-IntuneAssignmentCheckerTui')
            } | Sort-Object)
        $actual = @((Get-IntuneAssignmentOperation).Name | Sort-Object)

        $actual | Should -Be $expected
    }

    It 'exposes parameter sets and editable parameter metadata from the real command' {
        $operation = Get-IntuneAssignmentOperation -Name Test-IntuneAssignmentGovernance

        $operation.ParameterSets.Count | Should -BeGreaterThan 1
        @($operation.ParameterSets.Parameters.Name) | Should -Contain 'SnapshotPath'
        @($operation.ParameterSets.Parameters.Name) | Should -Contain 'FailOnSeverity'
    }

    It 'accepts multiple ValidateSet choices for array parameters' {
        Mock Read-Host -ModuleName IntuneAssignmentChecker { 'Core,Audit' }
        Mock Write-Host -ModuleName IntuneAssignmentChecker {}
        $parameter = [PSCustomObject]@{
            Name = 'Capability'; Type = 'System.String[]'; TypeName = 'String[]'; Mandatory = $false
            ValidateSet = @('Core', 'Audit', 'Full'); IsSwitch = $false; IsArray = $true
            HelpMessage = $null
        }

        $value = & (Get-Module IntuneAssignmentChecker) {
            param($Parameter)
            Read-IACTuiParameterValue -Parameter $Parameter -CommandName Connect-IntuneAssignmentChecker
        } $parameter

        $value.Supplied | Should -BeTrue
        $value.Value | Should -Be @('Core', 'Audit')
    }

    It 'uses concise descriptions and parameter help instead of generated syntax' {
        $operations = @(Get-IntuneAssignmentOperation)
        @($operations | Where-Object { $_.Synopsis -match '[\r\n]' -or $_.Synopsis.StartsWith($_.Name) }).Count | Should -Be 0
        $governance = $operations | Where-Object Name -EQ Test-IntuneAssignmentGovernance
        $snapshotParameter = @($governance.ParameterSets.Parameters | Where-Object Name -EQ SnapshotPath)[0]
        $snapshotParameter.HelpMessage | Should -Match 'snapshot'
    }
}

Describe 'v5 capability profiles' {
    It 'resolves Core without unrelated optional permissions' {
        $permissions = @(& (Get-Module IntuneAssignmentChecker) {
                @(Resolve-IACCapabilityPermission -Capability Core).Permission
            })

        $permissions | Should -Contain 'User.Read.All'
        $permissions | Should -Contain 'GroupMember.Read.All'
        $permissions | Should -Contain 'DeviceManagementConfiguration.Read.All'
        $permissions | Should -Contain 'DeviceManagementServiceConfig.Read.All'
        $permissions | Should -Not -Contain 'CloudPC.Read.All'
        $permissions | Should -Not -Contain 'DeviceManagementApps.Read.All'
    }

    It 'reports requested, unavailable, and skipped capability states' {
        $states = @(& (Get-Module IntuneAssignmentChecker) {
            $script:RequestedCapabilities = @('Core')
            Get-IACCapabilityStatus -GrantedPermission @('User.Read.All')
        })

        ($states | Where-Object Name -EQ Core).Status | Should -BeExactly 'Unavailable'
        ($states | Where-Object Name -EQ Core).MissingPermissions | Should -Contain 'GroupMember.Read.All'
        ($states | Where-Object Name -EQ CloudPC).Status | Should -BeExactly 'Skipped'
    }
}

Describe 'v5 governance and simulation objects' {
    BeforeAll {
        $script:testGovernanceRecord = [PSCustomObject]@{
            SchemaName = 'IntuneAssignmentChecker.AssignmentRecord'; SchemaVersion = 2
            PolicyId = 'app-1'; PolicyName = 'Required App'; CategoryId = 'Applications'
            AssignmentId = 'assignment-1'; AssignmentMode = 'Include'; TargetType = 'AllUsers'
            TargetId = $null; TargetName = 'All Users'; Intent = 'required'; ReasonChain = @()
        }
    }

    It 'emits stable evidence-bearing governance findings' {
        $findings = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance)

        $findings.RuleId | Should -Contain 'IAC001'
        $findings.RuleId | Should -Contain 'IAC003'
        $findings[0].FindingId | Should -Match '^[0-9a-f]{24}$'
        $findings[0].Remediation | Should -Not -BeNullOrEmpty
    }

    It 'validates canonical records and findings against the shipped JSON Schemas' {
        $recordSchema = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Schemas/assignment-record.v2.schema.json'
        $findingSchema = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Schemas/governance-finding.v1.schema.json'
        $canonicalRecord = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications `
                -PolicyId app-1 -PolicyName 'Required App' -AssignmentMode Include -TargetType AllUsers
        }
        $finding = @($canonicalRecord | Test-IntuneAssignmentGovernance)[0]

        Test-Json -Json ($canonicalRecord | ConvertTo-Json -Depth 20) -SchemaFile $recordSchema | Should -BeTrue
        Test-Json -Json ($finding | ConvertTo-Json -Depth 20) -SchemaFile $findingSchema | Should -BeTrue
    }

    It 'models a broad required assignment without performing a write' {
        $simulation = $script:testGovernanceRecord | Test-IntuneAssignmentChange -ChangeType AddAssignment -PolicyId app-1 -TargetType AllDevices -Intent required

        $simulation.ReadOnly | Should -BeTrue
        $simulation.Risk | Should -BeExactly 'Critical'
        $simulation.After.TargetType | Should -BeExactly 'AllDevices'
        $simulation.After.ReasonChain[-1].Message | Should -Match 'no Microsoft Graph write'
    }

    It 'suppresses active waivers, restores expired findings, and rejects invalid expiry values' {
        $activePath = Join-Path $TestDrive 'active-waiver.json'
        $expiredPath = Join-Path $TestDrive 'expired-waiver.json'
        $invalidPath = Join-Path $TestDrive 'invalid-waiver.json'
        $baseWaiver = [ordered]@{ RuleId = 'IAC001'; PolicyId = 'app-1'; Owner = 'security@example.test'; Justification = 'Approved test'; ExpiresAtUtc = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        [IO.File]::WriteAllText($activePath, (@{ Waivers = @([PSCustomObject]$baseWaiver) } | ConvertTo-Json -Depth 10))
        $expired = [ordered]@{} + $baseWaiver; $expired.ExpiresAtUtc = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o')
        [IO.File]::WriteAllText($expiredPath, (@{ Waivers = @([PSCustomObject]$expired) } | ConvertTo-Json -Depth 10))
        $invalid = [ordered]@{} + $baseWaiver; $invalid.ExpiresAtUtc = 'not-a-date'
        [IO.File]::WriteAllText($invalidPath, (@{ Waivers = @([PSCustomObject]$invalid) } | ConvertTo-Json -Depth 10))

        $active = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $activePath -IncludeSuppressed)
        $expiredFindings = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $expiredPath -IncludeSuppressed)

        ($active | Where-Object RuleId -EQ IAC001).Suppressed | Should -BeTrue
        ($expiredFindings | Where-Object RuleId -EQ IAC001).Suppressed | Should -BeFalse
        { $script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $invalidPath } | Should -Throw '*not a valid UTC date-time*'
    }
}

Describe 'v5 structured output and drift' {
    It 'writes JSON, JSON Lines, and formula-safe CSV from the same object model' {
        $item = [PSCustomObject]@{ PolicyName = '=HYPERLINK("https://example.test")'; Evidence = @{ Value = '+SUM(1,1)' }; Count = 2 }
        $jsonPath = Join-Path $TestDrive 'result.json'
        $jsonLinesPath = Join-Path $TestDrive 'result.jsonl'
        $csvPath = Join-Path $TestDrive 'result.csv'
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format Json } $item $jsonPath | Out-Null
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format JsonLines } $item $jsonLinesPath | Out-Null
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format Csv } $item $csvPath | Out-Null

        (Get-Content $jsonPath -Raw | ConvertFrom-Json)[0].PolicyName | Should -BeExactly $item.PolicyName
        (Get-Content $jsonLinesPath -Raw | ConvertFrom-Json).Evidence.Value | Should -BeExactly '+SUM(1,1)'
        (Import-Csv $csvPath).PolicyName | Should -BeExactly "'$($item.PolicyName)"
    }

    It 'classifies broad added assignments and correlates beta audit evidence' {
        $baselinePath = Join-Path $TestDrive 'drift-baseline.json'
        $currentPath = Join-Path $TestDrive 'drift-current.json'
        $record = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications -PolicyId app-1 -PolicyName 'Required App' `
                -AssignmentId assignment-1 -AssignmentMode Include -TargetType AllUsers -Intent required
        }
        Export-IntuneAssignmentSnapshot -Path $baselinePath -InputObject @() -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        $record | Export-IntuneAssignmentSnapshot -Path $currentPath -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T11:00:00Z')
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker {
            @{ value = @([PSCustomObject]@{ id = 'audit-1'; displayName = 'Create assignment'; activityDateTime = '2026-08-01T10:30:00Z'; actor = [PSCustomObject]@{ userPrincipalName = 'admin@example.test' }; resources = @([PSCustomObject]@{ resourceId = 'app-1'; displayName = 'Required App' }) }) }
        }

        $event = Get-IntuneAssignmentDrift -BaselinePath $baselinePath -CurrentSnapshotPath $currentPath -IncludeAuditAttribution

        $event.Risk | Should -BeExactly 'Critical'
        $event.Attribution | Should -BeExactly 'Correlated'
        $event.AuditActor | Should -BeExactly 'admin@example.test'
    }

    It 'refuses non-HTTPS drift webhooks before transmitting data' {
        $path = Join-Path $TestDrive 'same-snapshot.json'
        & (Get-Module IntuneAssignmentChecker) { $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One' }
        Export-IntuneAssignmentSnapshot -Path $path -InputObject @() -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        Mock Invoke-RestMethod -ModuleName IntuneAssignmentChecker

        { Get-IntuneAssignmentDrift -BaselinePath $path -CurrentSnapshotPath $path -WebhookUri 'http://example.test/hook' -Confirm:$false } |
            Should -Throw '*absolute HTTPS URI*'
        Should -Invoke Invoke-RestMethod -ModuleName IntuneAssignmentChecker -Exactly 0
    }
}

Describe 'v5 delivery health normalization' {
    It 'maps live report numeric states and string states consistently' {
        $states = & (Get-Module IntuneAssignmentChecker) {
            ConvertTo-IACDeliveryState 2
            ConvertTo-IACDeliveryState 3
            ConvertTo-IACDeliveryState conflict
            ConvertTo-IACDeliveryState notApplicable
        }
        $states | Should -Be @('Succeeded', 'Failed', 'Conflict', 'NotApplicable')
    }

    It 'maps schema columns to report values by position' {
        $row = & (Get-Module IntuneAssignmentChecker) {
            $report = [PSCustomObject]@{
                Schema = @([PSCustomObject]@{ Column = 'DeviceId' }, [PSCustomObject]@{ Column = 'PolicyStatus' })
                Values = @(, @('device-1', 2))
            }
            ConvertFrom-IACReportRows -Report $report
        }

        $row.DeviceId | Should -BeExactly 'device-1'
        $row.PolicyStatus | Should -Be 2
    }
}

Describe 'v5 resumable scan runner' {
    It 'writes a token-free category checkpoint and returns run diagnostics' {
        $checkpointPath = Join-Path $TestDrive 'scan.json'
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CurrentTenantId = 'tenant-1'
            $script:CurrentTenantName = 'Tenant One'
        }
        Mock Get-IntuneCategoryDefinition -ModuleName IntuneAssignmentChecker {
            @(
                [PSCustomObject]@{ Id = 'One'; DisplayName = 'One' }
                [PSCustomObject]@{ Id = 'Two'; DisplayName = 'Two' }
            )
        }
        Mock Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{ Records = @(); Errors = @(); Skipped = @() }
        }

        $run = Invoke-IntuneAssignmentScan -CheckpointPath $checkpointPath -KeepCheckpoint

        $run.Complete | Should -BeTrue
        $run.Completed | Should -Be @('One', 'Two')
        $run.Diagnostics.ProviderCount | Should -Be 2
        Test-Path -LiteralPath $checkpointPath | Should -BeTrue
        (Get-Content -LiteralPath $checkpointPath -Raw) | Should -Not -Match '(?i)access.?token|client.?secret|password'
        Should -Invoke Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker -Exactly 2

        $resumed = Invoke-IntuneAssignmentScan -CheckpointPath $checkpointPath -Resume -KeepCheckpoint
        $resumed.Complete | Should -BeTrue
        $resumed.Completed | Should -Be @('One', 'Two')
        Should -Invoke Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker -Exactly 2
    }
}

Describe 'v5 coverage-aware commands' {
    It 'treats optional skipped workloads as transparent but non-blocking coverage' {
        $snapshotPath = Join-Path $TestDrive 'optional-skip.json'
        $filterPath = Join-Path $TestDrive 'optional-filters.json'
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CurrentTenantId = 'tenant-1'
            $script:CurrentTenantName = 'Tenant One'
        }
        Mock Get-IntuneCategoryDefinition -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ Id = 'CloudPCProvisioningPolicies'; DisplayName = 'Cloud PC Provisioning Policies' })
        }
        Mock Get-AssignmentFilterLookup -ModuleName IntuneAssignmentChecker { @{} }
        Mock Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{
                Records = @(); Errors = @()
                Skipped = @([PSCustomObject]@{ CategoryId = 'CloudPCProvisioningPolicies'; Message = 'Workload is not licensed.' })
            }
        }
        Export-IntuneAssignmentSnapshot -Path $snapshotPath -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        [IO.File]::WriteAllText($filterPath, (@{ Filters = @(@{ Id = 'filter-1'; Name = 'Unused'; Platform = 'windows10AndLater'; Rule = '(device.osVersion -startsWith "10.")'; AssignmentFilterManagementType = 'devices' }) } | ConvertTo-Json -Depth 10))

        $governance = @(Test-IntuneAssignmentGovernance -SnapshotPath $snapshotPath)
        $filters = @(Test-IntuneAssignmentFilterSet -SnapshotPath $snapshotPath -FilterDefinitionPath $filterPath)
        $approval = Get-IntuneAssignmentDrift -BaselinePath (Join-Path $TestDrive 'approved-optional.json') `
            -CurrentSnapshotPath $snapshotPath -ApproveBaseline

        $governance.RuleId | Should -Not -Contain IAC007
        $filters.RuleId | Should -Contain IAF001
        $filters.RuleId | Should -Not -Contain IAF007
        $approval.Complete | Should -BeTrue
    }

    It 'fails a tenant entry without unattended credentials and continues the fleet result contract' {
        $configurationPath = Join-Path $TestDrive 'fleet.json'
        [IO.File]::WriteAllText($configurationPath, (@{ schemaVersion = 1; tenants = @(@{ TenantId = 'tenant-1' }) } | ConvertTo-Json -Depth 10))
        Mock Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker
        Mock Disconnect-MgGraph -ModuleName IntuneAssignmentChecker
        Mock Read-Host -ModuleName IntuneAssignmentChecker { throw 'Interactive prompt was reached.' }

        $errors = @()
        $result = Invoke-IntuneAssignmentFleetScan -ConfigurationPath $configurationPath -ErrorVariable +errors

        $result.Status | Should -BeExactly 'Failed'
        $result.Error | Should -Match 'unattended'
        Should -Invoke Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker -Exactly 0
        Should -Invoke Read-Host -ModuleName IntuneAssignmentChecker -Exactly 0
    }

    It 'suppresses unused-filter findings when assignment coverage is incomplete' {
        $snapshotPath = Join-Path $TestDrive 'filter-partial.json'
        $filterPath = Join-Path $TestDrive 'filters.json'
        $record = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications -PolicyId app-1 -PolicyName App `
                -AssignmentId assignment-1 -AssignmentMode Include -TargetType Group -TargetId group-1
        }
        $coverageError = [PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = 'HTTP 403' }
        $record | Export-IntuneAssignmentSnapshot -Path $snapshotPath -CoverageCategory Applications,CompliancePolicies -CoverageError $coverageError -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        [IO.File]::WriteAllText($filterPath, (@{ Filters = @(@{ Id = 'filter-1'; Name = 'Unused'; Platform = 'windows10AndLater'; Rule = '(device.osVersion -startsWith "10.")'; AssignmentFilterManagementType = 'devices' }) } | ConvertTo-Json -Depth 10))

        $findings = @(Test-IntuneAssignmentFilterSet -SnapshotPath $snapshotPath -FilterDefinitionPath $filterPath)

        $findings.RuleId | Should -Contain IAF007
        $findings.RuleId | Should -Not -Contain IAF001
    }

    It 'collapses broad RBAC access to one result while preserving policy count' {
        $snapshotPath = Join-Path $TestDrive 'access.json'
        $records = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId DeviceConfigurations -Category Configuration -PolicyId policy-1 -PolicyName One -AssignmentMode None -TargetType None
            New-IACAssignmentRecord -CategoryId DeviceConfigurations -Category Configuration -PolicyId policy-2 -PolicyName Two -AssignmentMode None -TargetType None
        }
        $records | Export-IntuneAssignmentSnapshot -Path $snapshotPath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com'; $script:CurrentTenantId = 'tenant-1' }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker {
            if ($Uri -like '*roleDefinitions*') { return @{ value = @([PSCustomObject]@{ id = 'definition-1'; displayName = 'Intune Administrator'; roleAssignments = @([PSCustomObject]@{ id = 'role-1' }) }) } }
            @{ value = @([PSCustomObject]@{ id = 'role-1'; displayName = 'Broad administrators'; members = @('group-1'); resourceScopes = @(); roleScopeTagIds = @('0') }) }
        }

        $access = @(Get-IntuneAssignmentAccess -SnapshotPath $snapshotPath)

        $access.Count | Should -Be 1
        $access[0].BoundaryStatus | Should -BeExactly 'Broad'
        $access[0].MatchingPolicyCount | Should -Be 2
    }

    It 'reports inventory permission failures as failed health coverage' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker { throw 'HTTP 403 Forbidden' }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        $health.Count | Should -Be 1
        $health[0].RecordType | Should -BeExactly 'Coverage'
        $health[0].CoverageStatus | Should -BeExactly 'Failed'
        $health[0].CoverageMessage | Should -Match '403'
    }

    It 'keeps legitimate multi-user rows for the same managed device' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ id = 'policy-1'; displayName = 'Shared device policy' })
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportResponse -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportRows -ModuleName IntuneAssignmentChecker {
            @(
                [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'SharedPC'; UPN = 'one@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
                [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'SharedPC'; UPN = 'two@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
            )
        }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        @($health | Where-Object RecordType -EQ Status).Count | Should -Be 2
        ($health | Where-Object RecordType -EQ Coverage).CoverageStatus | Should -BeExactly 'Complete'
    }

    It 'stops an exact repeated health row and reports failed coverage' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ id = 'policy-1'; displayName = 'Repeated report policy' })
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportResponse -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportRows -ModuleName IntuneAssignmentChecker {
            $row = [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'PC'; UPN = 'one@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
            @($row, $row.PSObject.Copy())
        }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        @($health | Where-Object RecordType -EQ Status).Count | Should -Be 0
        ($health | Where-Object RecordType -EQ Coverage).CoverageStatus | Should -BeExactly 'Failed'
        ($health | Where-Object RecordType -EQ Coverage).CoverageMessage | Should -Match 'repeated device rows'
    }
}

Describe 'v5 environment diagnostics' {
    It 'uses first-page-only beta probes for every applicable workload' {
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CapabilityStatus = @()
        }
        Mock Get-MgContext -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{ TenantId = 'tenant-1'; Environment = 'Global' }
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{ value = @() } }

        $diagnostics = @(Test-IntuneAssignmentCheckerEnvironment)

        @($diagnostics | Where-Object Check -Like 'Graph.*' | Where-Object Check -NE GraphConnection).Count | Should -Be 4
        Should -Invoke Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker -Exactly 4 -ParameterFilter {
            $Method -eq 'GET' -and $FirstPageOnly
        }
    }
}
