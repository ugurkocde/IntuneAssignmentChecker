function New-IACTuiActionDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][char]$Key,
        [Parameter(Mandatory)][string]$Description,
        [string[]]$Commands = @(),
        [switch]$Primary
    )

    [PSCustomObject][ordered]@{
        Id          = $Id
        Label       = $Label
        Key         = [char]::ToUpperInvariant($Key)
        Description = $Description
        Commands    = @($Commands)
        Primary     = [bool]$Primary
    }
}

function New-IACTuiFeatureDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter(Mandatory)][string[]]$Capabilities,
        [Parameter(Mandatory)][object[]]$Actions,
        [string[]]$Commands = @()
    )

    $mappedCommands = @($Commands) + @($Actions | ForEach-Object Commands)
    [PSCustomObject][ordered]@{
        Id           = $Id
        Title        = $Title
        Summary      = $Summary
        Capabilities = @($Capabilities)
        Actions      = @($Actions)
        Commands     = @($mappedCommands | Where-Object { $_ } | Select-Object -Unique)
    }
}

function Get-IACTuiFeatureRegistry {
    [CmdletBinding()]
    param()

    @(
        New-IACTuiFeatureDefinition -Id Overview -Title 'Overview' -Capabilities Core `
            -Summary 'Tenant posture, coverage, priority findings, drift, and delivery health.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshOverview -Label 'Refresh posture' -Key R -Primary `
                    -Description 'Refresh the connected tenant posture from shared governance and coverage data.' `
                    -Commands @('Test-IntuneAssignmentGovernance')
                New-IACTuiActionDefinition -Id ResumeScan -Label 'Resume scan' -Key C `
                    -Description 'Continue a checkpointed assignment scan within a time budget.' `
                    -Commands @('Invoke-IntuneAssignmentScan')
            )

        New-IACTuiFeatureDefinition -Id Assignments -Title 'Assignments' -Capabilities @('Core', 'Applications', 'Devices') `
            -Summary 'Search policies and inspect targeting for users, groups, and devices.' `
            -Actions @(
                New-IACTuiActionDefinition -Id SearchAssignments -Label 'Search policies' -Key R -Primary `
                    -Description 'Find policies and applications by name and inspect their targets.' `
                    -Commands @('Search-IntunePolicy')
                New-IACTuiActionDefinition -Id FindUserAssignments -Label 'Find user' -Key U `
                    -Description 'Resolve assignments applying to one or more users.' `
                    -Commands @('Get-IntuneUserAssignment')
                New-IACTuiActionDefinition -Id FindDeviceAssignments -Label 'Find device' -Key D `
                    -Description 'Resolve assignments applying to one or more devices.' `
                    -Commands @('Get-IntuneDeviceAssignment')
                New-IACTuiActionDefinition -Id FindGroupAssignments -Label 'Find group' -Key G `
                    -Description 'Inspect assignments that include or exclude selected groups.' `
                    -Commands @('Get-IntuneGroupAssignment')
                New-IACTuiActionDefinition -Id ExplainEffectiveAssignment -Label 'Explain effective state' -Key E `
                    -Description 'Trace effective targeting for a user, a device, or both.' `
                    -Commands @('Get-IntuneEffectiveAssignment', 'Get-IntuneUserDeviceAssignment')
                New-IACTuiActionDefinition -Id BrowseAssignmentInventory -Label 'Browse inventory' -Key I `
                    -Description 'Review all policies, broad assignments, gaps, and empty target groups.' `
                    -Commands @('Get-IntuneAllPolicies', 'Get-IntuneAllUsersAssignment', 'Get-IntuneAllDevicesAssignment', 'Get-IntuneUnassignedPolicy', 'Get-IntuneEmptyGroup')
                New-IACTuiActionDefinition -Id CompareGroupTargeting -Label 'Compare groups' -Key C `
                    -Description 'Compare targeting patterns across selected groups.' `
                    -Commands @('Compare-IntuneGroupAssignment')
                New-IACTuiActionDefinition -Id SearchConfiguredSettings -Label 'Search settings' -Key S `
                    -Description 'Search configured setting values across supported policies.' `
                    -Commands @('Search-IntuneSetting')
            )

        New-IACTuiFeatureDefinition -Id Governance -Title 'Governance' -Capabilities @('Core', 'Audit') `
            -Summary 'Prioritize assignment risk with evidence, remediation, and approved exceptions.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshGovernance -Label 'Run governance scan' -Key R -Primary `
                    -Description 'Evaluate the connected tenant or a saved snapshot against governance rules.' `
                    -Commands @('Test-IntuneAssignmentGovernance')
            )

        New-IACTuiFeatureDefinition -Id Simulator -Title 'Change simulator' -Capabilities @('Core', 'Devices') `
            -Summary 'Model proposed targeting changes and prove their blast radius without Graph writes.' `
            -Actions @(
                New-IACTuiActionDefinition -Id SimulateAssignmentChange -Label 'Propose assignment change' -Key R -Primary `
                    -Description 'Compare before and after states for a proposed assignment mutation.' `
                    -Commands @('Test-IntuneAssignmentChange')
                New-IACTuiActionDefinition -Id SimulateMembershipAdd -Label 'Add group membership' -Key A `
                    -Description 'Show assignments gained when a user or device joins a group.' `
                    -Commands @('Test-IntuneGroupMembership')
                New-IACTuiActionDefinition -Id SimulateMembershipRemoval -Label 'Remove group membership' -Key D `
                    -Description 'Show assignments lost when a user or device leaves a group.' `
                    -Commands @('Test-IntuneGroupRemoval')
            )

        New-IACTuiFeatureDefinition -Id Drift -Title 'Drift' -Capabilities @('Core', 'Audit') `
            -Summary 'Manage approved baselines and investigate who changed assignment state.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshDrift -Label 'Compare baseline' -Key R -Primary `
                    -Description 'Capture or load current state and compare it with an approved baseline.' `
                    -Commands @('Get-IntuneAssignmentDrift')
                New-IACTuiActionDefinition -Id ApproveBaseline -Label 'Approve baseline' -Key A `
                    -Description 'Promote a reviewed snapshot to the approved drift baseline.' `
                    -Commands @('Get-IntuneAssignmentDrift')
                New-IACTuiActionDefinition -Id CaptureSnapshot -Label 'Capture snapshot' -Key C `
                    -Description 'Save deterministic assignment state for later review.' `
                    -Commands @('Invoke-IntuneAssignmentScan', 'Export-IntuneAssignmentSnapshot')
                New-IACTuiActionDefinition -Id CompareSnapshots -Label 'Compare snapshots' -Key F `
                    -Description 'Compare two saved assignment snapshots.' `
                    -Commands @('Compare-IntuneAssignmentSnapshot')
            )

        New-IACTuiFeatureDefinition -Id Health -Title 'Delivery health' -Capabilities @('Applications', 'Devices') `
            -Summary 'Separate assignment targeting from deployment success, failure, conflict, and staleness.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshHealth -Label 'Load delivery health' -Key R -Primary `
                    -Description 'Correlate targeting with policy and application delivery status.' `
                    -Commands @('Get-IntuneAssignmentHealth')
                New-IACTuiActionDefinition -Id LoadFailures -Label 'Show failures' -Key F `
                    -Description 'Review failed policy and application deployments.' `
                    -Commands @('Get-IntuneFailedAssignment')
            )

        New-IACTuiFeatureDefinition -Id Access -Title 'RBAC & scope' -Capabilities ScopeTags `
            -Summary 'Trace administrators through roles, scopes, scope tags, and manageable policies.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshAccess -Label 'Analyze access' -Key R -Primary `
                    -Description 'Explain administrative access to assignment records.' `
                    -Commands @('Get-IntuneAssignmentAccess')
            )

        New-IACTuiFeatureDefinition -Id Filters -Title 'Filters' -Capabilities Devices `
            -Summary 'Audit filter inventory, references, compatibility, and real-device evaluations.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RefreshFilters -Label 'Audit filter set' -Key R -Primary `
                    -Description 'Find unused, duplicate, invalid, overly broad, and ineffective filters.' `
                    -Commands @('Test-IntuneAssignmentFilterSet')
                New-IACTuiActionDefinition -Id EvaluateFilter -Label 'Evaluate device' -Key E `
                    -Description 'Test an assignment filter safely against a selected managed device.' `
                    -Commands @('Test-IntuneAssignmentFilter')
            )

        New-IACTuiFeatureDefinition -Id Fleet -Title 'Fleet' -Capabilities Core `
            -Summary 'Run isolated tenant scans and compare governance posture across the fleet.' `
            -Actions @(
                New-IACTuiActionDefinition -Id RunFleetScan -Label 'Scan tenant fleet' -Key R -Primary `
                    -Description 'Scan configured tenants independently and consolidate their findings.' `
                    -Commands @('Invoke-IntuneAssignmentFleetScan')
            )

        New-IACTuiFeatureDefinition -Id Reports -Title 'Reports & data' -Capabilities Core `
            -Summary 'Create human-readable reports and migrate saved assignment records.' `
            -Actions @(
                New-IACTuiActionDefinition -Id CreateHtmlReport -Label 'Create HTML report' -Key R -Primary `
                    -Description 'Generate an assignment report and optional CSV companion.' `
                    -Commands @('New-IntuneHTMLReport')
                New-IACTuiActionDefinition -Id MigrateRecords -Label 'Migrate records' -Key M `
                    -Description 'Convert saved version 1 records to the canonical version 2 schema.' `
                    -Commands @('ConvertTo-IntuneAssignmentRecord')
                New-IACTuiActionDefinition -Id ExportWorkspaceData -Label 'Save current results' -Key E `
                    -Description 'Export loaded workspace results as JSON, JSON Lines, or CSV.'
            )

        New-IACTuiFeatureDefinition -Id Settings -Title 'Settings' -Capabilities Core `
            -Summary 'Manage tenant connection, capability profile, diagnostics, and local data.' `
            -Actions @(
                New-IACTuiActionDefinition -Id ConnectTenant -Label 'Connect tenant' -Key C -Primary `
                    -Description 'Connect with a least-privilege capability profile.' `
                    -Commands @('Connect-IntuneAssignmentChecker')
                New-IACTuiActionDefinition -Id SwitchTenant -Label 'Switch tenant' -Key T `
                    -Description 'Clear tenant-scoped state and connect to another tenant.' `
                    -Commands @('Switch-IntuneAssignmentCheckerTenant')
                New-IACTuiActionDefinition -Id RunDiagnostics -Label 'Run diagnostics' -Key D `
                    -Description 'Validate the runtime, Graph connection, capabilities, and beta workloads.' `
                    -Commands @('Test-IntuneAssignmentCheckerEnvironment')
                New-IACTuiActionDefinition -Id RefreshSettingDefinitions -Label 'Refresh setting catalog' -Key U `
                    -Description 'Refresh the local Settings Catalog definition cache.' `
                    -Commands @('Update-IntuneSettingDefinition')
                New-IACTuiActionDefinition -Id ConfigureScopeFilter -Label 'Set scope filter' -Key S `
                    -Description 'Limit supported assignment searches to one scope-tag name.'
            )
    )
}

function Test-IACTuiFeatureParity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$CommandName,
        [object[]]$Feature = @(Get-IACTuiFeatureRegistry)
    )

    $mapped = @($Feature.Commands | Where-Object { $_ } | Sort-Object -Unique)
    $expected = @($CommandName | Sort-Object -Unique)
    $missing = @($expected | Where-Object { $_ -notin $mapped })
    $unknown = @($mapped | Where-Object { $_ -notin $expected })
    $duplicates = @($Feature.Commands | Group-Object | Where-Object Count -GT 1 | ForEach-Object Name)

    [PSCustomObject][ordered]@{
        Complete   = $missing.Count -eq 0 -and $unknown.Count -eq 0
        Expected   = $expected
        Mapped     = $mapped
        Missing    = $missing
        Unknown    = $unknown
        Duplicates = $duplicates
    }
}
