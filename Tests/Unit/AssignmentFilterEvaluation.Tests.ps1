#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    . (Join-Path $moduleRoot 'Private/Test-IACAssignmentFilter.ps1')
    . (Join-Path $moduleRoot 'Private/Get-AssignmentFilterLookup.ps1')
    . (Join-Path $moduleRoot 'Private/Get-IACManagedDevice.ps1')
    . (Join-Path $moduleRoot 'Public/Test-IntuneAssignmentFilter.ps1')

    $script:GraphEndpoint = 'https://graph.test'
    function Invoke-IACGraphRequest { param([string]$Uri, [string]$Method) @{ value = @() } }

    function New-FilterTestDevice {
        [PSCustomObject]@{
            id                        = 'managed-device-1'
            deviceName                = 'SURFACE-01'
            operatingSystem           = 'Windows'
            manufacturer              = 'Microsoft Corporation'
            model                     = 'Surface Pro 9'
            osVersion                 = '10.0.26100.1742'
            managedDeviceOwnerType    = 'company'
            enrollmentProfileName     = $null
            deviceCategoryDisplayName = 'Engineering devices'
            processorArchitecture     = 'amd64'
            joinType                  = 'azureADJoined'
            jailBroken                = 'False'
            skuNumber                 = 48
            deviceEnrollmentType      = 'windowsAzureADJoin'
        }
    }
}

Describe 'Get-AssignmentFilterLookup metadata' {
    It 'caches the live-verified rule, platform, and management type fields' {
        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{
                        id = 'filter-1'
                        displayName = 'Corporate Windows'
                        platform = 'windows10AndLater'
                        rule = '(device.deviceOwnership -eq "Corporate")'
                        assignmentFilterManagementType = 'devices'
                    }) }
        }

        $lookup = Get-AssignmentFilterLookup

        $lookup['filter-1'].Id | Should -BeExactly filter-1
        $lookup['filter-1'].Name | Should -BeExactly 'Corporate Windows'
        $lookup['filter-1'].Platform | Should -BeExactly windows10AndLater
        $lookup['filter-1'].Rule | Should -Match deviceOwnership
        $lookup['filter-1'].AssignmentFilterManagementType | Should -BeExactly devices
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/deviceManagement/assignmentFilters?$select=id,displayName,platform,rule,assignmentFilterManagementType' -and
            $Method -eq 'Get'
        }
    }
}

Describe 'Test-IACAssignmentFilter' {
    BeforeEach {
        $script:device = New-FilterTestDevice
    }

    Context 'parser precedence and grouping' {
        It 'treats and as higher precedence than or' {
            $rule = '(device.manufacturer -eq "Microsoft Corporation") or (device.model -eq "Nope") and (device.deviceOwnership -eq "Personal")'
            (Test-IACAssignmentFilter -Rule $rule -Device $script:device).Result | Should -BeExactly Match
        }

        It 'honors nested parentheses over default precedence' {
            $rule = '((device.manufacturer -eq "Microsoft Corporation") or (device.model -eq "Nope")) and (device.deviceOwnership -eq "Personal")'
            (Test-IACAssignmentFilter -Rule $rule -Device $script:device).Result | Should -BeExactly NotMatch
        }

        It 'accepts documented logical and comparison aliases without hyphens' {
            $rule = '(device.manufacturer equals "MICROSOFT CORPORATION") AND (device.model startsWith "surface")'
            (Test-IACAssignmentFilter -Rule $rule -Device $script:device).Result | Should -BeExactly Match
        }
    }

    Context 'value and operator semantics' {
        It 'compares strings case-insensitively with equality and inequality' {
            (Test-IACAssignmentFilter -Rule '(device.model -eq "surface pro 9")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.model -ne "surface pro 8")' -Device $script:device).Result | Should -BeExactly Match
        }

        It 'supports contains, notContains, and startsWith' {
            (Test-IACAssignmentFilter -Rule '(device.manufacturer -contains "soft corp")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.manufacturer -notContains "apple")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.deviceName -startsWith "surface")' -Device $script:device).Result | Should -BeExactly Match
        }

        It 'supports in and notIn arrays' {
            (Test-IACAssignmentFilter -Rule '(device.model -in ["Latitude", "Surface Pro 9"])' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.model -notIn ["Latitude", "ThinkPad"])' -Device $script:device).Result | Should -BeExactly Match
        }

        It 'supports null and $null with eq and ne' {
            (Test-IACAssignmentFilter -Rule '(device.enrollmentProfileName -eq $null)' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.enrollmentProfileName -ne Null)' -Device $script:device).Result | Should -BeExactly NotMatch
        }

        It 'compares arbitrary numeric version components rather than strings' {
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemVersion -gt 10.0.9999.9999)' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemVersion -le 10.0.26100.1742)' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemVersion -eq 10.0.26100.1742.0)' -Device $script:device).Result | Should -BeExactly Unknown
        }

        It 'treats legacy osVersion as a string and rejects version-only ordering operators' {
            (Test-IACAssignmentFilter -Rule '(device.osVersion -startsWith "10.0.26100")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.osVersion -gt 10.0.22000)' -Device $script:device).Result | Should -BeExactly Unknown
        }
    }

    Context 'explicit managed-device property map' {
        It 'maps ownership, join type, SKU, rooted state, architecture, and category values' {
            $rule = @'
(device.deviceOwnership -eq "Corporate") and
(device.deviceTrustType -eq "Azure AD joined") and
(device.operatingSystemSKU -eq "Professional") and
(device.isRooted -eq "False") and
(device.cpuArchitecture -eq "amd64") and
(device.deviceCategory -contains "Engineering")
'@
            (Test-IACAssignmentFilter -Rule $rule -Device $script:device).Result | Should -BeExactly Match
        }

        It 'returns Unknown when a documented property is absent from the Graph response' {
            $device = [PSCustomObject]@{ manufacturer = 'Microsoft' }
            $result = Test-IACAssignmentFilter -Rule '(device.model -eq "Surface")' -Device $device

            $result.Result | Should -BeExactly Unknown
            $result.Reason | Should -Match 'does not contain a source field'
        }

        It 'returns Unknown for a management type that cannot be mapped without guessing' {
            $script:device.deviceEnrollmentType = 'androidEnterpriseDedicatedDevice'
            (Test-IACAssignmentFilter -Rule '(device.deviceManagementType -eq "Corporate-owned dedicated devices with Entra ID Shared mode")' -Device $script:device).Result |
                Should -BeExactly Unknown
        }

        It 'maps the live beta AOSP enrollment enum names' {
            $script:device.deviceEnrollmentType = 'androidAOSPUserOwnedDeviceEnrollment'
            (Test-IACAssignmentFilter -Rule '(device.deviceManagementType -eq "AOSP user-associated devices")' -Device $script:device).Result |
                Should -BeExactly Match
            $script:device.deviceEnrollmentType = 'androidAOSPUserlessDeviceEnrollment'
            (Test-IACAssignmentFilter -Rule '(device.deviceManagementType -eq "AOSP userless devices")' -Device $script:device).Result |
                Should -BeExactly Match
        }

        It 'maps skuNumber one-to-one and refuses a coarse skuFamily fallback' {
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemSKU -eq "Professional")' -Device $script:device).Result | Should -BeExactly Match
            $device = [PSCustomObject]@{ skuFamily = 'Pro' }
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemSKU -eq "Professional")' -Device $device).Result | Should -BeExactly Unknown
        }

        It 'pins documented Unknown ownership and trust values while rejecting unknown enrollment mappings' {
            $script:device.managedDeviceOwnerType = 'unknown'
            $script:device.joinType = 'unknown'
            $script:device.deviceEnrollmentType = 'windowsCoManagement'

            (Test-IACAssignmentFilter -Rule '(device.deviceOwnership -eq "Unknown")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.deviceTrustType -eq "Unknown")' -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule '(device.deviceManagementType -eq "Unknown")' -Device $script:device).Result | Should -BeExactly Unknown
        }
    }

    Context 'tri-state propagation' {
        It 'never turns unsupported properties into a definitive answer' {
            (Test-IACAssignmentFilter -Rule '(device.serialNumber -eq "secret")' -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule '(app.deviceModel -eq "Surface")' -Device $script:device).Result | Should -BeExactly Unknown
        }

        It 'uses three-valued and/or truth tables' {
            $unknown = '(device.serialNumber -eq "x")'
            (Test-IACAssignmentFilter -Rule ($unknown + ' and (device.model -eq "Nope")') -Device $script:device).Result | Should -BeExactly NotMatch
            (Test-IACAssignmentFilter -Rule ($unknown + ' and (device.model -eq "Surface Pro 9")') -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule ($unknown + ' or (device.model -eq "Surface Pro 9")') -Device $script:device).Result | Should -BeExactly Match
            (Test-IACAssignmentFilter -Rule ($unknown + ' or (device.model -eq "Nope")') -Device $script:device).Result | Should -BeExactly Unknown
        }

        It 'returns Unknown for invalid versions, operators, and array shapes' {
            $script:device.osVersion = '26.0 (25A5349a)'
            (Test-IACAssignmentFilter -Rule '(device.operatingSystemVersion -gt 25.0)' -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule '(device.model -endsWith "9")' -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule '(device.model -in "Surface Pro 9")' -Device $script:device).Result | Should -BeExactly Unknown
        }
    }

    Context 'include and exclude filter semantics' {
        It 'preserves rule results for include filters and inverts them for exclude filters' {
            $rule = '(device.deviceOwnership -eq "Corporate")'
            $include = Test-IACAssignmentFilter -Rule $rule -Device $script:device -FilterMode include
            $exclude = Test-IACAssignmentFilter -Rule $rule -Device $script:device -FilterMode exclude

            $include.RuleResult | Should -BeExactly Match
            $include.Result | Should -BeExactly Match
            $exclude.RuleResult | Should -BeExactly Match
            $exclude.Result | Should -BeExactly NotMatch
        }

        It 'returns Match without parsing when no filter is applied' {
            (Test-IACAssignmentFilter -Rule 'hostile syntax' -Device $script:device -FilterMode none).Result | Should -BeExactly Match
        }

        It 'keeps Unknown unknown under exclude semantics' {
            (Test-IACAssignmentFilter -Rule '(device.unsupported -eq "x")' -Device $script:device -FilterMode exclude).Result | Should -BeExactly Unknown
        }

        It 'uses cached filter metadata and rejects managed-app filters for a device' {
            $filter = [PSCustomObject]@{
                Id = 'filter-app'
                Name = 'Managed app filter'
                Platform = 'iOSMobileApplicationManagement'
                Rule = '(app.deviceModel -eq "iPhone")'
                AssignmentFilterManagementType = 'apps'
            }
            $result = Test-IACAssignmentFilter -Filter $filter -Device $script:device -FilterMode include

            $result.Result | Should -BeExactly Unknown
            $result.FilterId | Should -BeExactly filter-app
            $result.ManagementType | Should -BeExactly apps
        }

        It 'evaluates a cached managed-device filter object end to end' {
            $filter = [PSCustomObject]@{
                Id = 'filter-device'
                Name = 'Corporate devices'
                Platform = 'windows10AndLater'
                Rule = '(device.deviceOwnership -eq "Corporate")'
                AssignmentFilterManagementType = 'devices'
            }
            $result = Test-IACAssignmentFilter -Filter $filter -Device $script:device -FilterMode include

            $result.Result | Should -BeExactly Match
            $result.DeviceId | Should -BeExactly managed-device-1
            $result.DeviceName | Should -BeExactly SURFACE-01
            $result.FilterName | Should -BeExactly 'Corporate devices'
        }

        It 'returns Unknown when the filter platform does not apply to the device OS' {
            $filter = [PSCustomObject]@{
                Id = 'filter-macos'; Name = 'macOS corporate'; Platform = 'macOS'
                Rule = '(device.deviceOwnership -eq "Corporate")'; AssignmentFilterManagementType = 'devices'
            }
            $result = Test-IACAssignmentFilter -Filter $filter -Device $script:device -FilterMode include

            $result.Result | Should -BeExactly Unknown
            $result.Reason | Should -Match "not evaluated by Intune for device operating system 'Windows'"
        }
    }

    Context 'hostile and malformed input' {
        It 'does not execute tenant-provided rule text' {
            $marker = Join-Path $TestDrive 'executed.txt'
            $rules = @(
                "(device.model -eq `"Surface Pro 9`"); Set-Content -Path '$marker' -Value pwned"
                "`$(Set-Content -Path '$marker' -Value pwned)"
                '(device.model -eq "Surface Pro 9") | Out-Null'
                '(device.model -eq "Surface Pro 9") { Get-Process }'
            )

            foreach ($rule in $rules) {
                (Test-IACAssignmentFilter -Rule $rule -Device $script:device).Result | Should -BeExactly Unknown
            }
            $literal = "`$(Set-Content -Path '$marker' -Value pwned)"
            $script:device.model = $literal
            (Test-IACAssignmentFilter -Rule "(device.model -eq '`$`(Set-Content -Path ''$marker'' -Value pwned)')" -Device $script:device).Result |
                Should -BeExactly Match
            $marker | Should -Not -Exist
            (Get-Content -Raw (Join-Path $moduleRoot 'Private/Test-IACAssignmentFilter.ps1')) |
                Should -Not -Match 'Invoke-Expression|\biex\b|ScriptBlock\]::Create'
        }

        It 'returns Unknown for malformed strings, delimiters, and excessive input' {
            (Test-IACAssignmentFilter -Rule '(device.model -eq "unterminated)' -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule '((device.model -eq "Surface Pro 9")' -Device $script:device).Result | Should -BeExactly Unknown
            (Test-IACAssignmentFilter -Rule ('x' * 8193) -Device $script:device).Result | Should -BeExactly Unknown
        }

        It 'enforces nesting and token safety limits' {
            $nested = ('(' * 65) + '(device.model -eq "Surface Pro 9")' + (')' * 65)
            $tokenHeavy = (('x ' * 1025).Trim())

            (Test-IACAssignmentFilter -Rule $nested -Device $script:device).Reason | Should -Match '64-level safety limit'
            (Test-IACAssignmentFilter -Rule $tokenHeavy -Device $script:device).Reason | Should -Match '1024-token safety limit'
        }
    }
}

Describe 'Test-IntuneAssignmentFilter public workflow' {
    BeforeEach {
        $script:AssignmentFilterLookup = @{
            'filter-1' = [PSCustomObject]@{
                Id = 'filter-1'; Name = 'Corporate Windows'; Platform = 'windows10AndLater'
                Rule = '(device.deviceOwnership -eq "Corporate")'; AssignmentFilterManagementType = 'devices'
            }
        }
        Mock Invoke-IACGraphRequest {
            @{ value = @([PSCustomObject]@{
                        id = 'managed-1'; deviceName = 'SURFACE-01'; operatingSystem = 'Windows'; osVersion = '10.0.26100.1742'
                        manufacturer = 'Microsoft'; model = 'Surface Pro 9'; managedDeviceOwnerType = 'company'
                        enrollmentProfileName = $null; skuNumber = 48; deviceCategoryDisplayName = 'Engineering'
                        jailBroken = 'False'; processorArchitecture = 'amd64'; joinType = 'azureADJoined'
                        deviceEnrollmentType = 'windowsAzureADJoin'; managementAgent = 'mdm'
                    }) }
        }
    }

    It 'resolves a beta managed device and evaluates a cached filter' {
        $result = Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -FilterId filter-1

        $result.Result | Should -BeExactly Match
        $result.FilterId | Should -BeExactly filter-1
        $result.DeviceId | Should -BeExactly managed-1
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like 'https://graph.test/beta/deviceManagement/managedDevices?*' -and
            $Uri -match '\$filter=deviceName%20eq%20%27SURFACE-01%27' -and
            $Uri -match '\$select=.*skuNumber' -and
            $Uri -notmatch 'skuFamily|deviceOwnership'
        }
    }

    It 'OData-escapes quotes and URL-encodes device-name metacharacters' {
        Test-IntuneAssignmentFilter -DeviceName "R&D + 100% #1 O'Brien" -Rule '(device.model -eq "Surface Pro 9")' | Out-Null

        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -match '\$filter=deviceName%20eq%20%27R%26D%20%2B%20100%25%20%231%20O%27%27Brien%27' -and
            $Uri -notmatch "R&D|O'Brien"
        }
    }

    It 'validates and applies the documented ad hoc platform vocabulary' {
        $result = Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -Rule '(device.model -eq "Surface Pro 9")' -Platform windows10AndLater

        $result.Result | Should -BeExactly Match
        { Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -Rule '(device.model -eq "Surface Pro 9")' -Platform Windows } |
            Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }

    It 'returns Unknown when managed-device resolution is ambiguous' {
        Mock Invoke-IACGraphRequest { @{ value = @(@{ id = 'one' }, @{ id = 'two' }) } }

        $result = Test-IntuneAssignmentFilter -DeviceName 'DUPLICATE' -FilterId filter-1

        $result.Result | Should -BeExactly Unknown
        $result.Reason | Should -Match 'Multiple managed devices'
    }

    It 'returns Unknown when a filter id is not cached' {
        $result = Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -FilterId missing

        $result.Result | Should -BeExactly Unknown
        $result.Reason | Should -Match "filter 'missing' was not found"
        $result.ManagementType | Should -BeNullOrEmpty
    }

    It 'preserves the empty-rule reason for a filter that is present in the cache' {
        $script:AssignmentFilterLookup['empty'] = [PSCustomObject]@{
            Id = 'empty'; Name = 'Empty rule'; Platform = 'windows10AndLater'; Rule = ''; AssignmentFilterManagementType = 'devices'
        }

        $result = Test-IntuneAssignmentFilter -DeviceName 'SURFACE-01' -FilterId empty

        $result.Result | Should -BeExactly Unknown
        $result.Reason | Should -BeExactly 'The assignment filter rule is empty.'
    }

    It 'uses the direct single-object beta route for a managed-device GUID' {
        $managedDeviceId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Invoke-IACGraphRequest {
            [PSCustomObject]@{
                id = $managedDeviceId; deviceName = 'DIRECT-01'; operatingSystem = 'Windows'
                managedDeviceOwnerType = 'company'; skuNumber = 48
            }
        } -ParameterFilter { $Uri -like "*/managedDevices/$managedDeviceId*" }

        $result = Test-IntuneAssignmentFilter -DeviceName $managedDeviceId -FilterId filter-1

        $result.Result | Should -BeExactly Match
        $result.DeviceId | Should -BeExactly $managedDeviceId
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like "https://graph.test/beta/deviceManagement/managedDevices/$managedDeviceId`?*" -and
            $Uri -match '\$select=.*skuNumber' -and $Uri -notmatch 'skuFamily|deviceOwnership'
        }
    }

    It 'returns Unknown when a managed-device GUID does not resolve' {
        $managedDeviceId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Invoke-IACGraphRequest { @{} } -ParameterFilter { $Uri -like "*/managedDevices/$managedDeviceId*" }

        $result = Test-IntuneAssignmentFilter -DeviceName $managedDeviceId -FilterId filter-1

        $result.Result | Should -BeExactly Unknown
        $result.Reason | Should -BeExactly "Managed device '$managedDeviceId' was not found."
    }
}
