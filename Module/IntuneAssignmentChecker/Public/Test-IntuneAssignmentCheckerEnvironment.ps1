function Test-IntuneAssignmentCheckerEnvironment {
    <#
    .SYNOPSIS
    Validates the local runtime, Graph connection, capabilities, and beta endpoints.

    .DESCRIPTION
    Returns one structured result per diagnostic check. When Microsoft Graph is
    connected, read-only beta probes verify organization, assignment-filter, RBAC,
    and audit availability according to the requested capability profiles.

    .PARAMETER OutputPath
    Optional directory whose existence and write access should be checked.

    .PARAMETER SkipGraphProbe
    Reports connection and permission state without sending endpoint probes.

    .PARAMETER FailOnError
    Throws after returning diagnostics when any check failed.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.EnvironmentDiagnostic')]
    param(
        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [switch]$SkipGraphProbe,

        [Parameter()]
        [switch]$FailOnError
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $addResult = {
        param($Check, $Status, $Detail, $Remediation, $Capability)
        $item = [PSCustomObject][ordered]@{
            SchemaName    = 'IntuneAssignmentChecker.EnvironmentDiagnostic'
            SchemaVersion = 1
            Check         = $Check
            Status        = $Status
            Capability    = $Capability
            Detail        = $Detail
            Remediation   = $Remediation
            CheckedAtUtc  = [datetimeoffset]::UtcNow.ToString('o')
        }
        $item.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.EnvironmentDiagnostic')
        [void]$results.Add($item)
    }

    & $addResult 'PowerShellVersion' $(if ($PSVersionTable.PSVersion.Major -ge 7) { 'Passed' } else { 'Failed' }) "$($PSVersionTable.PSVersion)" 'Install PowerShell 7 or newer.' 'Core'
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    & $addResult 'GraphAuthenticationModule' $(if ($graphModule) { 'Passed' } else { 'Failed' }) $(if ($graphModule) { "$($graphModule.Version)" } else { 'Not installed' }) 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' 'Core'

    $context = Get-MgContext -ErrorAction SilentlyContinue
    & $addResult 'GraphConnection' $(if ($context -and $script:GraphEndpoint) { 'Passed' } else { 'Failed' }) $(if ($context) { "Tenant $($context.TenantId) in $($context.Environment)" } else { 'Not connected' }) 'Run Connect-IntuneAssignmentChecker.' 'Core'
    & $addResult 'BetaTransport' $(if ($script:GraphEndpoint) { 'Passed' } else { 'Skipped' }) $(if ($script:GraphEndpoint) { "$($script:GraphEndpoint.TrimEnd('/'))/beta" } else { 'No active Graph endpoint' }) 'Connect before running Graph diagnostics.' 'Core'

    foreach ($capability in @($script:CapabilityStatus)) {
        $capabilityResult = switch ($capability.Status) { 'Available' { 'Passed' } 'Unavailable' { 'Failed' } default { $capability.Status } }
        $capabilityDetail = if ($capability.MissingPermissions.Count -gt 0) { "Missing: $($capability.MissingPermissions -join ', ')" } else { $capability.Status }
        & $addResult "Capability.$($capability.Name)" $capabilityResult $capabilityDetail 'Reconnect with the required capability profile after granting its listed permissions.' $capability.Name
    }

    if ($OutputPath) {
        try {
            $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
            if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Container)) {
                throw "Directory '$resolvedOutput' does not exist."
            }
            $probePath = Join-Path $resolvedOutput ".iac-write-probe-$([guid]::NewGuid().ToString('N'))"
            [System.IO.File]::WriteAllText($probePath, 'probe', [System.Text.UTF8Encoding]::new($false))
            Remove-Item -LiteralPath $probePath -Force
            & $addResult 'OutputPath' 'Passed' $resolvedOutput 'Choose a writable output directory.' 'Core'
        }
        catch {
            & $addResult 'OutputPath' 'Failed' $_.Exception.Message 'Choose a writable output directory.' 'Core'
        }
    }

    if (-not $SkipGraphProbe -and $context -and $script:GraphEndpoint) {
        $probes = @(
            [PSCustomObject]@{ Check = 'Graph.Organization'; Capability = 'Core'; Uri = '/organization?$select=id,displayName&$top=1' }
            [PSCustomObject]@{ Check = 'Graph.AssignmentFilters'; Capability = 'Devices'; Uri = '/deviceManagement/assignmentFilters?$select=id,displayName,platform,rule&$top=1' }
            [PSCustomObject]@{ Check = 'Graph.RoleAssignments'; Capability = 'ScopeTags'; Uri = '/deviceManagement/roleAssignments?$select=id,displayName,members,resourceScopes,roleScopeTagIds&$top=1' }
            [PSCustomObject]@{ Check = 'Graph.AuditEvents'; Capability = 'Audit'; Uri = '/deviceManagement/auditEvents?$select=id,displayName,activityDateTime,actor,resources&$top=1' }
        )
        foreach ($probe in $probes) {
            $capabilityState = $script:CapabilityStatus | Where-Object Name -EQ $probe.Capability | Select-Object -First 1
            if ($capabilityState -and $capabilityState.Status -eq 'Skipped') {
                & $addResult $probe.Check 'Skipped' "Capability $($probe.Capability) was not requested." "Reconnect with -Capability $($probe.Capability)." $probe.Capability
                continue
            }
            try {
                $response = Invoke-IACGraphRequest -Uri $probe.Uri -Method GET -FirstPageOnly -ErrorAction Stop
                $count = if ($null -ne $response.value) { @($response.value).Count } else { 1 }
                & $addResult $probe.Check 'Passed' "Beta endpoint responded; sample count $count." 'No action required.' $probe.Capability
            }
            catch {
                & $addResult $probe.Check 'Failed' $_.Exception.Message "Verify the $($probe.Capability) permission profile and tenant workload availability." $probe.Capability
            }
        }
    }

    $results | Write-Output
    if ($FailOnError -and @($results | Where-Object Status -EQ 'Failed').Count -gt 0) {
        throw 'One or more IntuneAssignmentChecker environment diagnostics failed.'
    }
}
