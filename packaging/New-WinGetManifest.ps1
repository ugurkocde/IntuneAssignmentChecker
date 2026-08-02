#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [uri]$InstallerUrl,

    [Parameter()]
    [string]$Version = '5.0.0',

    [Parameter(Mandatory)]
    [ValidatePattern('^\{[0-9A-Fa-f-]{36}\}$')]
    [string]$ProductCode,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../artifacts/winget')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) { throw "Installer '$InstallerPath' does not exist." }
$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$sha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
$schemaBase = 'https://aka.ms/winget-manifest'

$versionManifest = @"
# Created by IntuneAssignmentChecker release automation. Do not edit the installer hash manually.
# yaml-language-server: `$schema=$schemaBase.version.1.10.0.schema.json
PackageIdentifier: UgurKoc.IntuneAssignmentChecker
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.10.0
"@

$installerManifest = @"
# yaml-language-server: `$schema=$schemaBase.installer.1.10.0.schema.json
PackageIdentifier: UgurKoc.IntuneAssignmentChecker
PackageVersion: $Version
InstallerType: wix
Scope: machine
InstallModes:
- silent
- silentWithProgress
UpgradeBehavior: install
Commands:
- IntuneAssignmentChecker
ReleaseDate: $([datetime]::UtcNow.ToString('yyyy-MM-dd'))
Dependencies:
  PackageDependencies:
  - PackageIdentifier: Microsoft.PowerShell
    MinimumVersion: 7.0.0.0
Installers:
- Architecture: x64
  InstallerUrl: $InstallerUrl
  InstallerSha256: $sha256
  ProductCode: '$ProductCode'
  AppsAndFeaturesEntries:
  - DisplayName: Intune Assignment Checker
    Publisher: Ugur Koc
    DisplayVersion: $Version
    ProductCode: '$ProductCode'
ManifestType: installer
ManifestVersion: 1.10.0
"@

$localeManifest = @"
# yaml-language-server: `$schema=$schemaBase.defaultLocale.1.10.0.schema.json
PackageIdentifier: UgurKoc.IntuneAssignmentChecker
PackageVersion: $Version
PackageLocale: en-US
Publisher: Ugur Koc
PublisherUrl: https://github.com/ugurkocde
PublisherSupportUrl: https://github.com/ugurkocde/IntuneAssignmentChecker/issues
Author: Ugur Koc
PackageName: Intune Assignment Checker
PackageUrl: https://github.com/ugurkocde/IntuneAssignmentChecker
License: MIT
LicenseUrl: https://github.com/ugurkocde/IntuneAssignmentChecker/blob/v$Version/LICENSE
ShortDescription: Audit, simulate, and govern Microsoft Intune assignments from PowerShell or its terminal command center.
Description: A PowerShell-native, read-only assignment governance platform for Microsoft Intune with a task-oriented mouse and keyboard terminal UI, snapshots, drift analysis, change simulation, delivery health, and multi-tenant scans.
InstallationNotes: Open a new terminal after installation and run IntuneAssignmentChecker. The launcher automatically uses PowerShell 7, including when it is called from Windows PowerShell 5.1.
Moniker: intune-assignment-checker
Tags:
- intune
- microsoft-graph
- powershell
- security
- terminal-ui
ReleaseNotesUrl: https://github.com/ugurkocde/IntuneAssignmentChecker/releases/tag/v$Version
ManifestType: defaultLocale
ManifestVersion: 1.10.0
"@

$files = [ordered]@{
    'UgurKoc.IntuneAssignmentChecker.yaml'               = $versionManifest
    'UgurKoc.IntuneAssignmentChecker.installer.yaml'     = $installerManifest
    'UgurKoc.IntuneAssignmentChecker.locale.en-US.yaml'  = $localeManifest
}
foreach ($entry in $files.GetEnumerator()) {
    [IO.File]::WriteAllText((Join-Path $resolvedOutput $entry.Key), $entry.Value.Trim() + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
Get-ChildItem -LiteralPath $resolvedOutput -File | Sort-Object Name
