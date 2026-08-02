function Get-IACOperationCategory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    switch -Regex ($Name) {
        '^(Connect-|Switch-IntuneAssignmentCheckerTenant)' { return 'Connection' }
        '(Governance|Change|FilterSet|Access|Fleet)' { return 'Governance' }
        '(Snapshot|Drift)' { return 'Drift' }
        '(Health|Failed)' { return 'Delivery health' }
        '^(Search-|Update-IntuneSettingDefinition)' { return 'Discovery' }
        '^(Export-|New-)' { return 'Reporting' }
        '^(Test-)' { return 'Simulation' }
        default { return 'Assignments' }
    }
}

function Get-IACOperationCapability {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    switch -Regex ($Name) {
        '^(Connect-|Switch-IntuneAssignmentCheckerTenant)' { return @('Core') }
        '(Access|ScopeTag)' { return @('ScopeTags') }
        '(Drift|Governance)' { return @('Core', 'Audit') }
        '(Health|Failed)' { return @('Applications', 'Devices') }
        '(Application|App|Protection)' { return @('Applications') }
        '(Device|Filter)' { return @('Devices') }
        '(Script|Setting)' { return @('Scripts') }
        '(CloudPC)' { return @('CloudPC') }
        default { return @('Core') }
    }
}

function Get-IACOperationCatalog {
    [CmdletBinding()]
    param()

    $infrastructureCommands = @(
        'Get-IntuneAssignmentOperation',
        'Invoke-IntuneAssignmentChecker',
        'Start-IntuneAssignmentCheckerTui'
    )
    $commonParameters = @([System.Management.Automation.PSCmdlet]::CommonParameters) +
        @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
    $module = Get-Module -Name IntuneAssignmentChecker | Select-Object -First 1
    if (-not $module) {
        throw 'The IntuneAssignmentChecker module must be imported before its operation catalog can be created.'
    }
    $legacySynopsis = @{
        'Compare-IntuneGroupAssignment' = 'Compares the Intune assignments that target two or more groups.'
        'Connect-IntuneAssignmentChecker' = 'Connects to Microsoft Graph with the selected capability profile.'
        'Get-IntuneAllDevicesAssignment' = 'Lists policies and applications assigned to all devices.'
        'Get-IntuneAllPolicies' = 'Lists every supported Intune policy and its assignments.'
        'Get-IntuneAllUsersAssignment' = 'Lists policies and applications assigned to all users.'
        'Get-IntuneDeviceAssignment' = 'Finds effective Intune assignments for one or more devices.'
        'Get-IntuneEmptyGroup' = 'Finds assigned groups that currently have no members.'
        'Get-IntuneFailedAssignment' = 'Reports failed Intune policy and application deployments.'
        'Get-IntuneGroupAssignment' = 'Finds Intune assignments that include or exclude selected groups.'
        'Get-IntuneUnassignedPolicy' = 'Finds supported Intune policies that have no assignments.'
        'Get-IntuneUserAssignment' = 'Finds effective Intune assignments for one or more users.'
        'New-IntuneHTMLReport' = 'Creates HTML and optional CSV assignment reports.'
        'Search-IntunePolicy' = 'Searches supported Intune policies and their assignments.'
        'Search-IntuneSetting' = 'Searches Intune policy settings by keyword.'
        'Test-IntuneGroupMembership' = 'Simulates the assignment impact of adding a user or device to a group.'
        'Test-IntuneGroupRemoval' = 'Simulates the assignment impact of removing a user or device from a group.'
        'Update-IntuneSettingDefinition' = 'Refreshes the local Intune setting-definition catalog.'
    }

    foreach ($command in @($module.ExportedFunctions.Values | Sort-Object Name)) {
        if ($command.Name -in $infrastructureCommands) { continue }

        $help = Get-Help -Name $command.Name -ErrorAction SilentlyContinue
        $parameterSets = foreach ($parameterSet in @($command.ParameterSets)) {
            $parameters = foreach ($parameter in @($parameterSet.Parameters | Where-Object Name -NotIn $commonParameters)) {
                $validateSet = @($parameter.Attributes | Where-Object {
                        $_ -is [System.Management.Automation.ValidateSetAttribute]
                    } | ForEach-Object ValidValues)
                $helpMessage = @($parameter.Attributes | Where-Object {
                        $_ -is [System.Management.Automation.ParameterAttribute]
                    } | ForEach-Object HelpMessage | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -First 1)
                if ($helpMessage.Count -eq 0 -and $help -and $help.Parameters) {
                    $parameterHelp = @($help.Parameters.Parameter | Where-Object Name -EQ $parameter.Name | Select-Object -First 1)
                    $parameterDescription = @($parameterHelp.Description.Text | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
                    if (-not [string]::IsNullOrWhiteSpace($parameterDescription)) { $helpMessage = @($parameterDescription.Trim()) }
                }

                [PSCustomObject][ordered]@{
                    Name              = $parameter.Name
                    Type              = $parameter.ParameterType.FullName
                    TypeName          = $parameter.ParameterType.Name
                    Mandatory         = [bool]$parameter.IsMandatory
                    Position          = $parameter.Position
                    ValueFromPipeline = [bool]$parameter.ValueFromPipeline
                    IsSwitch          = $parameter.ParameterType -eq [System.Management.Automation.SwitchParameter]
                    IsArray           = $parameter.ParameterType.IsArray
                    ValidateSet       = @($validateSet)
                    HelpMessage       = if ($helpMessage.Count -gt 0) { "$($helpMessage[0])" } else { $null }
                }
            }

            [PSCustomObject][ordered]@{
                Name       = $parameterSet.Name
                IsDefault  = [bool]$parameterSet.IsDefault
                Parameters = @($parameters)
            }
        }

        $synopsis = if ($help -and $help.Synopsis) { "$($help.Synopsis)".Trim() } else { '' }
        if ([string]::IsNullOrWhiteSpace($synopsis) -or $synopsis.StartsWith($command.Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            $synopsis = if ($legacySynopsis.ContainsKey($command.Name)) { $legacySynopsis[$command.Name] } else { $command.Name }
        }
        $descriptor = [PSCustomObject][ordered]@{
            SchemaVersion = 1
            Name          = $command.Name
            Category      = Get-IACOperationCategory -Name $command.Name
            Capabilities  = @(Get-IACOperationCapability -Name $command.Name)
            Synopsis      = $synopsis
            Description   = if ($help -and $help.Description) {
                (@($help.Description.Text) -join [Environment]::NewLine).Trim()
            }
            else { $null }
            ParameterSets = @($parameterSets)
        }
        $descriptor.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.OperationDescriptor')
        $descriptor
    }
}
