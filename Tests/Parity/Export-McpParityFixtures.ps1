#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'assignment-parity.v1.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePrivate = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Private'
foreach ($fileName in @(
        'Get-PolicyPlatform.ps1'
        'Get-ScopeTagNames.ps1'
        'New-IACAssignmentRecord.ps1'
        'ConvertTo-IACAssignmentRecord.ps1'
        'ConvertTo-IACNormalizedAssignment.ps1'
    )) {
    . (Join-Path $modulePrivate $fileName)
}

$script:CurrentTenantId = '00000000-0000-0000-0000-000000000001'
$script:CurrentTenantName = 'Parity Fixture Tenant'
$script:ScopeTagLookup = @{
    '0' = 'Default'
    '7' = 'Security'
}
$script:AssignmentFilterLookup = @{}
$script:ParityGroupLookup = @{}

function Get-GroupInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GroupId)

    [PSCustomObject]@{
        Id          = $GroupId
        DisplayName = $script:ParityGroupLookup[$GroupId]
    }
}

$categories = @{
    configurationPolicy = [PSCustomObject][ordered]@{
        Id             = 'configurationPolicy'
        DisplayName    = 'Settings Catalog and Endpoint Security'
        ExportCategory = 'Settings Catalog and Endpoint Security'
        Platform       = 'Windows'
    }
    deviceConfiguration = [PSCustomObject][ordered]@{
        Id             = 'deviceConfiguration'
        DisplayName    = 'Device Configuration'
        ExportCategory = 'Device Configuration'
        Platform       = $null
    }
    compliancePolicy = [PSCustomObject][ordered]@{
        Id             = 'compliancePolicy'
        DisplayName    = 'Compliance Policy'
        ExportCategory = 'Compliance Policy'
        Platform       = $null
    }
    application = [PSCustomObject][ordered]@{
        Id             = 'application'
        DisplayName    = 'Application'
        ExportCategory = 'Application'
        Platform       = $null
    }
    appConfiguration = [PSCustomObject][ordered]@{
        Id             = 'appConfiguration'
        DisplayName    = 'App Configuration Policy'
        ExportCategory = 'App Configuration Policy'
        Platform       = $null
    }
}

$cases = @(
    [PSCustomObject][ordered]@{
        Name       = 'configuration group include with assignment filter'
        Category   = 'configurationPolicy'
        Policy     = [PSCustomObject][ordered]@{
            id              = '11111111-1111-1111-1111-111111111111'
            name            = 'Windows security baseline'
            displayName     = $null
            platforms       = 'windows10'
            technologies    = 'mdm'
            roleScopeTagIds = @('0', '7')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-group-include'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                                  = '#microsoft.graph.groupAssignmentTarget'
                groupId                                        = '22222222-2222-2222-2222-222222222222'
                deviceAndAppManagementAssignmentFilterId       = '33333333-3333-3333-3333-333333333333'
                deviceAndAppManagementAssignmentFilterType     = 'include'
            }
        }
        Groups     = @(
            [PSCustomObject][ordered]@{
                id          = '22222222-2222-2222-2222-222222222222'
                displayName = 'Pilot Devices'
            }
        )
        Filters    = @(
            [PSCustomObject][ordered]@{
                id          = '33333333-3333-3333-3333-333333333333'
                displayName = 'Corporate Windows'
                platform    = 'windows10AndLater'
                rule        = '(device.deviceOwnership -eq "Corporate")'
            }
        )
    }
    [PSCustomObject][ordered]@{
        Name       = 'configuration group exclusion'
        Category   = 'configurationPolicy'
        Policy     = [PSCustomObject][ordered]@{
            id              = '44444444-4444-4444-4444-444444444444'
            name            = 'Windows update ring'
            displayName     = $null
            platforms       = 'windows10'
            technologies    = 'mdm'
            roleScopeTagIds = @('0')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-group-exclude'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.exclusionGroupAssignmentTarget'
                groupId                                    = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                deviceAndAppManagementAssignmentFilterId   = $null
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
        }
        Groups     = @(
            [PSCustomObject][ordered]@{
                id          = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                displayName = 'Excluded Devices'
            }
        )
        Filters    = @()
    }
    [PSCustomObject][ordered]@{
        Name       = 'all licensed users target'
        Category   = 'configurationPolicy'
        Policy     = [PSCustomObject][ordered]@{
            id              = '55555555-5555-5555-5555-555555555555'
            name            = 'User certificate policy'
            displayName     = $null
            platforms       = 'windows10'
            technologies    = 'mdm'
            roleScopeTagIds = @()
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-all-users'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.allLicensedUsersAssignmentTarget'
                deviceAndAppManagementAssignmentFilterId   = '33333333-3333-3333-3333-333333333333'
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
        }
        Groups     = @()
        Filters    = @(
            [PSCustomObject][ordered]@{
                id          = '33333333-3333-3333-3333-333333333333'
                displayName = 'Corporate Windows'
                platform    = 'windows10AndLater'
                rule        = '(device.deviceOwnership -eq "Corporate")'
            }
        )
    }
    [PSCustomObject][ordered]@{
        Name       = 'all devices target suppresses empty filter sentinel'
        Category   = 'configurationPolicy'
        Policy     = [PSCustomObject][ordered]@{
            id              = '66666666-6666-6666-6666-666666666666'
            name            = 'Device restrictions'
            displayName     = $null
            platforms       = 'windows10'
            technologies    = 'mdm'
            roleScopeTagIds = @('7')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-all-devices'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.allDevicesAssignmentTarget'
                deviceAndAppManagementAssignmentFilterId   = '00000000-0000-0000-0000-000000000000'
                deviceAndAppManagementAssignmentFilterType = 'include'
            }
        }
        Groups     = @()
        Filters    = @()
    }
    [PSCustomObject][ordered]@{
        Name       = 'mobile application assignment intent and platform'
        Category   = 'application'
        Policy     = [PSCustomObject][ordered]@{
            id              = '77777777-7777-7777-7777-777777777777'
            name            = $null
            displayName     = 'Contoso Agent'
            '@odata.type'   = '#microsoft.graph.win32LobApp'
            roleScopeTagIds = @('0')
            isAssigned      = $true
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-app-required'
            intent = 'required'
            source = 'direct'
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                groupId                                    = '22222222-2222-2222-2222-222222222222'
                deviceAndAppManagementAssignmentFilterId   = $null
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
        }
        Groups     = @(
            [PSCustomObject][ordered]@{
                id          = '22222222-2222-2222-2222-222222222222'
                displayName = 'Pilot Devices'
            }
        )
        Filters    = @()
    }
    [PSCustomObject][ordered]@{
        Name       = 'device configuration with unresolved group name'
        Category   = 'deviceConfiguration'
        Policy     = [PSCustomObject][ordered]@{
            id              = '88888888-8888-8888-8888-888888888888'
            name            = $null
            displayName     = 'Legacy device restrictions'
            '@odata.type'   = '#microsoft.graph.windows10GeneralConfiguration'
            roleScopeTagIds = @('7')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-unresolved-group'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                groupId                                    = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
                deviceAndAppManagementAssignmentFilterId   = $null
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
        }
        Groups     = @()
        Filters    = @()
    }
    [PSCustomObject][ordered]@{
        Name       = 'Android compliance assignment with exclude filter'
        Category   = 'compliancePolicy'
        Policy     = [PSCustomObject][ordered]@{
            id              = '99999999-9999-9999-9999-999999999999'
            name            = $null
            displayName     = 'Corporate Android compliance'
            '@odata.type'   = '#microsoft.graph.androidDeviceOwnerCompliancePolicy'
            roleScopeTagIds = @('0')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-compliance-filter-exclude'
            intent = $null
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                groupId                                    = '22222222-2222-2222-2222-222222222222'
                deviceAndAppManagementAssignmentFilterId   = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
                deviceAndAppManagementAssignmentFilterType = 'exclude'
            }
        }
        Groups     = @(
            [PSCustomObject][ordered]@{
                id          = '22222222-2222-2222-2222-222222222222'
                displayName = 'Pilot Devices'
            }
        )
        Filters    = @(
            [PSCustomObject][ordered]@{
                id          = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
                displayName = 'Personally owned Android'
                platform    = 'androidForWork'
                rule        = '(device.deviceOwnership -eq "Personal")'
            }
        )
    }
    [PSCustomObject][ordered]@{
        Name       = 'Android app configuration assigned to all devices'
        Category   = 'appConfiguration'
        Policy     = [PSCustomObject][ordered]@{
            id                 = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
            name               = $null
            displayName        = 'Managed browser configuration'
            '@odata.type'      = '#microsoft.graph.androidManagedStoreAppConfiguration'
            roleScopeTagIds    = @()
            targetedMobileApps = @('77777777-7777-7777-7777-777777777777')
        }
        Assignment = [PSCustomObject][ordered]@{
            id     = 'assignment-app-configuration-all-devices'
            intent = $null
            source = 'direct'
            target = [PSCustomObject][ordered]@{
                '@odata.type'                              = '#microsoft.graph.allDevicesAssignmentTarget'
                deviceAndAppManagementAssignmentFilterId   = $null
                deviceAndAppManagementAssignmentFilterType = 'none'
            }
        }
        Groups     = @()
        Filters    = @()
    }
)

foreach ($case in $cases) {
    foreach ($group in @($case.Groups)) {
        $script:ParityGroupLookup["$($group.id)"] = "$($group.displayName)"
    }
    foreach ($filter in @($case.Filters)) {
        $script:AssignmentFilterLookup["$($filter.id)"] = [PSCustomObject]@{
            Name     = $filter.displayName
            Platform = $filter.platform
            Rule     = $filter.rule
        }
    }
}

function ConvertTo-CanonicalParityRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Record)

    function ConvertTo-NullableString {
        param([AllowNull()]$Value)
        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace("$Value")) { return $null }
        return "$Value"
    }

    [PSCustomObject][ordered]@{
        categoryId       = $Record.CategoryId
        category         = $Record.Category
        policyId         = $Record.PolicyId
        policyName       = $Record.PolicyName
        platform         = $Record.Platform
        roleScopeTagIds  = @($Record.ScopeTagIds)
        assignmentId     = ConvertTo-NullableString $Record.AssignmentId
        assignmentMode   = $Record.AssignmentMode
        targetType       = $Record.TargetType
        targetId         = ConvertTo-NullableString $Record.TargetId
        targetName       = ConvertTo-NullableString $Record.TargetName
        intent           = ConvertTo-NullableString $Record.Intent
        filterId         = ConvertTo-NullableString $Record.FilterId
        filterName       = ConvertTo-NullableString $Record.FilterName
        filterMode       = ConvertTo-NullableString $Record.FilterMode
        filterRule       = ConvertTo-NullableString $Record.FilterRule
        filterPlatform   = ConvertTo-NullableString $Record.FilterPlatform
        source           = $Record.Source
    }
}

$exportedCases = foreach ($case in $cases) {
    $normalized = ConvertTo-IACNormalizedAssignment -Assignment $case.Assignment
    if ($null -eq $normalized) {
        throw "Parity case '$($case.Name)' did not produce a normalized PowerShell assignment."
    }
    $record = ConvertTo-IACAssignmentRecord `
        -Category $categories[$case.Category] `
        -Entity $case.Policy `
        -Assignment $normalized `
        -ResolveTargetName

    [PSCustomObject][ordered]@{
        name       = $case.Name
        category   = $case.Category
        policy     = $case.Policy
        assignment = $case.Assignment
        lookups    = [PSCustomObject][ordered]@{
            groups  = @($case.Groups)
            filters = @($case.Filters)
        }
        expected   = ConvertTo-CanonicalParityRecord -Record $record
    }
}

$fixture = [PSCustomObject][ordered]@{
    contractName    = 'IntuneAssignmentChecker.McpAssignmentParity'
    contractVersion = 1
    graphApiVersion = 'beta'
    generatedBy     = 'IntuneAssignmentChecker PowerShell reference implementation'
    cases           = @($exportedCases)
}

$json = ($fixture | ConvertTo-Json -Depth 20).Replace("`r`n", "`n") + "`n"
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
[System.IO.File]::WriteAllText(
    $resolvedOutputPath,
    $json,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output $resolvedOutputPath
