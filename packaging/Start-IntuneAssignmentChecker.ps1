#Requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = 'Launch')]
param(
    [Parameter(ParameterSetName = 'Launch')]
    [switch]$DisableMouse,

    [Parameter(Mandatory, ParameterSetName = 'Check')]
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$moduleName = 'IntuneAssignmentChecker'

$scopePathComparer = [StringComparer]::OrdinalIgnoreCase
$seenScopeRoots = [Collections.Generic.HashSet[string]]::new($scopePathComparer)
$moduleSearchRoots = @(
    foreach ($searchRoot in @($env:PSModulePath -split [IO.Path]::PathSeparator)) {
        if (-not [string]::IsNullOrWhiteSpace($searchRoot)) {
            $normalizedRoot = [IO.Path]::GetFullPath($searchRoot).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            )
            if ($seenScopeRoots.Add($normalizedRoot)) {
                $normalizedRoot
            }
        }
    }
)
$moduleSearchRoots = @($moduleSearchRoots | Sort-Object Length -Descending)

$machineModuleRoot = $null
$machineProgramFiles = if (-not [string]::IsNullOrWhiteSpace($env:ProgramW6432)) {
    $env:ProgramW6432
}
else {
    $env:ProgramFiles
}
if (-not [string]::IsNullOrWhiteSpace($machineProgramFiles)) {
    $machineModuleRoot = [IO.Path]::GetFullPath(
        (Join-Path $machineProgramFiles 'PowerShell/Modules/IntuneAssignmentChecker')
    ).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

$pathComparer = [StringComparer]::OrdinalIgnoreCase
$seenPaths = [Collections.Generic.HashSet[string]]::new($pathComparer)
$candidates = @(
    Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.Path) } |
        ForEach-Object {
            $candidatePath = [IO.Path]::GetFullPath($_.Path)
            if ($seenPaths.Add($candidatePath)) {
                $isMachineInstallation = $false
                if ($machineModuleRoot) {
                    $machinePrefix = $machineModuleRoot + [IO.Path]::DirectorySeparatorChar
                    $isMachineInstallation = $candidatePath.StartsWith(
                        $machinePrefix,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }

                $scopeRoot = $null
                foreach ($searchRoot in $moduleSearchRoots) {
                    $searchPrefix = $searchRoot + [IO.Path]::DirectorySeparatorChar
                    if ($candidatePath.StartsWith($searchPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                        $scopeRoot = $searchRoot
                        break
                    }
                }
                if (-not $scopeRoot) {
                    $manifestDirectory = [IO.Path]::GetDirectoryName($candidatePath)
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

                $prerelease = "$($_.PrivateData.PSData.Prerelease)"
                $displayVersion = "$($_.Version)"
                if (-not [string]::IsNullOrWhiteSpace($prerelease)) {
                    $displayVersion += "-$prerelease"
                }

                [PSCustomObject]@{
                    Path                  = $candidatePath
                    Version               = [version]$_.Version
                    IsStable              = [string]::IsNullOrWhiteSpace($prerelease)
                    Prerelease            = $prerelease
                    DisplayVersion        = $displayVersion
                    IsMachineInstallation = $isMachineInstallation
                    ScopeRoot             = $scopeRoot
                }
            }
        }
)

if ($candidates.Count -eq 0) {
    [Console]::Error.WriteLine('IntuneAssignmentChecker is not installed.')
    [Console]::Error.WriteLine("Install it with 'winget install --id UgurKoc.IntuneAssignmentChecker --exact' or 'Install-Module IntuneAssignmentChecker -Scope CurrentUser'.")
    exit 1
}

$selected = @(
    $candidates | Sort-Object -Property @(
        @{ Expression = { $_.Version }; Descending = $true }
        @{ Expression = { $_.IsStable }; Descending = $true }
        @{ Expression = { $_.Prerelease }; Descending = $true }
        @{ Expression = { $_.IsMachineInstallation }; Descending = $true }
        @{ Expression = { $_.Path }; Ascending = $true }
    )
)[0]

$installationScopes = [Collections.Generic.HashSet[string]]::new($scopePathComparer)
foreach ($candidate in $candidates) {
    [void]$installationScopes.Add($candidate.ScopeRoot)
}

$launchNotice = $null
if ($installationScopes.Count -gt 1) {
    $launchNotice = (
        'IntuneAssignmentChecker was found in multiple module scopes. ' +
        "Using version $($selected.DisplayVersion) from '$($selected.Path)'. " +
        'Run Test-IntuneAssignmentCheckerEnvironment for the complete installation list.'
    )
    if ($Check) {
        Write-Warning $launchNotice
    }
    else {
        [Environment]::SetEnvironmentVariable('IAC_LAUNCH_NOTICE', $launchNotice, 'Process')
    }
}

$loadedModule = Import-Module -Name $selected.Path -Force -PassThru -ErrorAction Stop

if ($Check) {
    [Console]::Out.WriteLine(
        ('Intune Assignment Checker {0} is ready in PowerShell {1}.' -f $selected.DisplayVersion, $PSVersionTable.PSVersion)
    )
    [Console]::Out.WriteLine(('Source: {0}' -f $selected.Path))
    return
}

try {
    if ($DisableMouse) {
        Start-IntuneAssignmentCheckerTui -DisableMouse
    }
    else {
        Start-IntuneAssignmentCheckerTui
    }
}
finally {
    if ($launchNotice) {
        [Environment]::SetEnvironmentVariable('IAC_LAUNCH_NOTICE', $null, 'Process')
    }
}
