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

    $loadedModule = $MyInvocation.MyCommand.Module
    if (-not $loadedModule -or [string]::IsNullOrWhiteSpace($loadedModule.Path)) {
        $loadedModule = Get-Module -Name IntuneAssignmentChecker -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.Path) } |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }
    $availableModules = @(
        Get-Module -ListAvailable -Name IntuneAssignmentChecker -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.Path) }
    )
    $scopePathComparer = [StringComparer]::OrdinalIgnoreCase
    $getModuleBase = {
        param($Module)
        $moduleBase = if ($Module -and -not [string]::IsNullOrWhiteSpace($Module.ModuleBase)) {
            $Module.ModuleBase
        }
        elseif ($Module -and -not [string]::IsNullOrWhiteSpace($Module.Path)) {
            [IO.Path]::GetDirectoryName($Module.Path)
        }
        else {
            $null
        }
        if ($moduleBase) {
            [IO.Path]::GetFullPath($moduleBase).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            )
        }
    }
    $loadedBase = & $getModuleBase $loadedModule
    $availableLoadedBase = @(
        $availableModules | Where-Object {
            $availableBase = & $getModuleBase $_
            $loadedBase -and $availableBase -and $scopePathComparer.Equals($availableBase, $loadedBase)
        }
    )
    if ($loadedModule -and $availableLoadedBase.Count -eq 0) {
        $availableModules = @($loadedModule) + $availableModules
    }

    $moduleSearchRootPaths = [Collections.Generic.HashSet[string]]::new($scopePathComparer)
    $moduleSearchRoots = @(
        foreach ($searchRoot in @($env:PSModulePath -split [IO.Path]::PathSeparator)) {
            if (-not [string]::IsNullOrWhiteSpace($searchRoot)) {
                $normalizedRoot = [IO.Path]::GetFullPath($searchRoot).TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar
                )
                if ($moduleSearchRootPaths.Add($normalizedRoot)) {
                    $normalizedRoot
                }
            }
        }
    )
    $moduleSearchRoots = @($moduleSearchRoots | Sort-Object Length -Descending)
    $moduleIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $moduleInstallations = @(
        $availableModules |
            ForEach-Object {
                $prerelease = "$($_.PrivateData.PSData.Prerelease)"
                $displayVersion = "$($_.Version)"
                if (-not [string]::IsNullOrWhiteSpace($prerelease)) {
                    $displayVersion += "-$prerelease"
                }
                $moduleBase = & $getModuleBase $_
                [PSCustomObject]@{
                    Version        = [version]$_.Version
                    IsStable       = [string]::IsNullOrWhiteSpace($prerelease)
                    Prerelease     = $prerelease
                    DisplayVersion = $displayVersion
                    Path           = [IO.Path]::GetFullPath($_.Path)
                    ModuleBase     = $moduleBase
                    Identity       = "$moduleBase|$displayVersion"
                }
            } |
            Sort-Object -Property @(
                @{ Expression = { $_.Version }; Descending = $true }
                @{ Expression = { $_.IsStable }; Descending = $true }
                @{ Expression = { $_.Prerelease }; Descending = $true }
                @{ Expression = { $_.Path }; Ascending = $true }
            ) |
            Where-Object { $moduleIdentities.Add($_.Identity) }
    )
    $moduleScopes = [Collections.Generic.HashSet[string]]::new($scopePathComparer)
    foreach ($installation in $moduleInstallations) {
        $installationPath = [IO.Path]::GetFullPath($installation.Path)
        $scopeRoot = $null
        foreach ($searchRoot in $moduleSearchRoots) {
            $searchPrefix = $searchRoot + [IO.Path]::DirectorySeparatorChar
            if ($installationPath.StartsWith($searchPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                $scopeRoot = $searchRoot
                break
            }
        }
        if (-not $scopeRoot) {
            $manifestDirectory = [IO.Path]::GetDirectoryName($installationPath)
            $scopeRoot = [IO.Path]::GetDirectoryName($manifestDirectory)
            $versionDirectoryName = [IO.Path]::GetFileName($manifestDirectory)
            $isVersionDirectory = $false
            try {
                [void][version]$versionDirectoryName
                $isVersionDirectory = $true
            }
            catch {
                try {
                    [void][System.Management.Automation.SemanticVersion]$versionDirectoryName
                    $isVersionDirectory = $true
                }
                catch {
                    # A non-versioned module lives directly beneath its scope root.
                }
            }
            if ($isVersionDirectory) {
                $scopeRoot = [IO.Path]::GetDirectoryName($scopeRoot)
            }
        }
        [void]$moduleScopes.Add($scopeRoot)
    }
    $installationDetails = @(
        foreach ($installation in $moduleInstallations) {
            $installationPath = [IO.Path]::GetFullPath($installation.Path)
            $isLoaded = $loadedBase -and $installation.ModuleBase -and $scopePathComparer.Equals($installation.ModuleBase, $loadedBase)
            $loadedLabel = if ($isLoaded) { ' [loaded]' } else { '' }
            "v$($installation.DisplayVersion) at $installationPath$loadedLabel"
        }
    )
    $installationStatus = if ($moduleScopes.Count -gt 1) { 'Warning' } elseif ($moduleInstallations.Count -ge 1) { 'Passed' } else { 'Failed' }
    $installationDetail = if ($installationDetails.Count -gt 0) { $installationDetails -join '; ' } else { 'No installation was discovered.' }
    $installationRemediation = if ($moduleScopes.Count -gt 1) {
        'Keep one installation scope, or remove the extra copy with the package manager that installed it (Uninstall-Module or winget uninstall).'
    }
    else {
        'Install from PowerShell Gallery or WinGet if the module is unavailable.'
    }
    & $addResult 'ModuleInstallations' $installationStatus $installationDetail $installationRemediation 'Core'

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
