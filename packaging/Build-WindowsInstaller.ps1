#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = '5.0.0',

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../artifacts'),

    [Parameter()]
    [string]$GraphAuthenticationVersion = '2.38.1',

    [Parameter()]
    [switch]$SkipDependencyDownload
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$moduleSource = Join-Path $repositoryRoot 'Module/IntuneAssignmentChecker'
$manifestPath = Join-Path $moduleSource 'IntuneAssignmentChecker.psd1'
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
if ("$($manifest.ModuleVersion)" -cne $Version) {
    throw "Installer version '$Version' does not match module version '$($manifest.ModuleVersion)'."
}

# ProductCode changes deterministically with the package version while UpgradeCode
# remains stable, allowing MSI major upgrades without hand-maintained identifiers.
$algorithm = [Security.Cryptography.SHA256]::Create()
try {
    $productCodeHash = $algorithm.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("B9D9989C-00DE-474C-B085-3E8848CBE173|$Version")
    )
}
finally {
    $algorithm.Dispose()
}
[byte[]]$productCodeBytes = @($productCodeHash[0..15])
$productCodeBytes[7] = ($productCodeBytes[7] -band 0x0f) -bor 0x50
$productCodeBytes[8] = ($productCodeBytes[8] -band 0x3f) -bor 0x80
$productCode = '{' + ([guid]::new($productCodeBytes)).ToString().ToUpperInvariant() + '}'
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "WiX is required. Install the pinned tool with 'dotnet tool install --global wix --version 6.0.2'."
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$stagingRoot = Join-Path $resolvedOutput 'windows-package-staging'
if (Test-Path -LiteralPath $stagingRoot) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
$moduleStagingRoot = Join-Path $stagingRoot 'modules'
$launcherStagingRoot = Join-Path $stagingRoot 'launcher'
New-Item -ItemType Directory -Path $moduleStagingRoot -Force | Out-Null
New-Item -ItemType Directory -Path $launcherStagingRoot -Force | Out-Null

$moduleDestination = Join-Path $moduleStagingRoot "IntuneAssignmentChecker/$Version"
New-Item -ItemType Directory -Path $moduleDestination -Force | Out-Null
Copy-Item -Path (Join-Path $moduleSource '*') -Destination $moduleDestination -Recurse -Force

if (-not $SkipDependencyDownload) {
    Save-Module -Name Microsoft.Graph.Authentication -RequiredVersion $GraphAuthenticationVersion `
        -Repository PSGallery -Path $moduleStagingRoot -Force -ErrorAction Stop
}
elseif (-not (Test-Path -LiteralPath (Join-Path $moduleStagingRoot 'Microsoft.Graph.Authentication'))) {
    Write-Warning 'Microsoft.Graph.Authentication was not staged because -SkipDependencyDownload was used.'
}

# cmd.exe parsing is sensitive to batch-file line endings. Normalize the MSI
# payload independently of the maintainer's checkout platform or Git settings.
$launcherSource = Join-Path $PSScriptRoot 'IntuneAssignmentChecker.cmd'
$launcherDestination = Join-Path $launcherStagingRoot 'IntuneAssignmentChecker.cmd'
$launcherText = [IO.File]::ReadAllText($launcherSource)
$launcherText = $launcherText.Replace("`r`n", "`n").Replace("`r", "`n").Replace("`n", "`r`n")
[IO.File]::WriteAllText($launcherDestination, $launcherText, [Text.UTF8Encoding]::new($false))
$bootstrapSource = Join-Path $PSScriptRoot 'Start-IntuneAssignmentChecker.ps1'
$bootstrapDestination = Join-Path $launcherStagingRoot 'Start-IntuneAssignmentChecker.ps1'
Copy-Item -LiteralPath $bootstrapSource -Destination $bootstrapDestination -Force

$outputPath = Join-Path $resolvedOutput "IntuneAssignmentChecker-$Version-x64.msi"
$wixOutput = @(& wix build (Join-Path $PSScriptRoot 'IntuneAssignmentChecker.wxs') -arch x64 `
    -d "ProductVersion=$Version" -d "ProductCode=$productCode" `
    -bindpath "ModuleSource=$moduleStagingRoot" -bindpath "LauncherSource=$launcherStagingRoot" -o $outputPath 2>&1)
$wixExitCode = $LASTEXITCODE
$wixOutput | ForEach-Object { Write-Host $_ }
if ($wixExitCode -ne 0 -or -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    $diagnostics = if ($wixOutput.Count -gt 0) { $wixOutput -join [Environment]::NewLine } else { 'No diagnostic output was returned.' }
    throw "WiX failed to create '$outputPath' (exit code $wixExitCode).$([Environment]::NewLine)$diagnostics"
}

$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
[PSCustomObject][ordered]@{
    Path                       = $outputPath
    Version                    = $Version
    Architecture               = 'x64'
    ProductCode                = $productCode
    Sha256                     = $hash
    GraphAuthenticationVersion = $GraphAuthenticationVersion
}
