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

$moduleDestination = Join-Path $stagingRoot "IntuneAssignmentChecker/$Version"
New-Item -ItemType Directory -Path $moduleDestination -Force | Out-Null
Copy-Item -Path (Join-Path $moduleSource '*') -Destination $moduleDestination -Recurse -Force

if (-not $SkipDependencyDownload) {
    Save-Module -Name Microsoft.Graph.Authentication -RequiredVersion $GraphAuthenticationVersion `
        -Repository PSGallery -Path $stagingRoot -Force -ErrorAction Stop
}
elseif (-not (Test-Path -LiteralPath (Join-Path $stagingRoot 'Microsoft.Graph.Authentication'))) {
    Write-Warning 'Microsoft.Graph.Authentication was not staged because -SkipDependencyDownload was used.'
}

$outputPath = Join-Path $resolvedOutput "IntuneAssignmentChecker-$Version-x64.msi"
& wix build (Join-Path $PSScriptRoot 'IntuneAssignmentChecker.wxs') -arch x64 `
    -d "ProductVersion=$Version" -d "ProductCode=$productCode" `
    -bindpath "ModuleSource=$stagingRoot" -output $outputPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    throw "WiX failed to create '$outputPath'."
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
