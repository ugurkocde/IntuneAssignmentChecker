#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $moduleRoot = Join-Path $repoRoot 'Module/IntuneAssignmentChecker'
    $manifestPath = Join-Path $moduleRoot 'IntuneAssignmentChecker.psd1'
    $manifestData = Import-PowerShellDataFile -Path $manifestPath
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop

    function Get-OrdinalSortedString {
        param([object[]]$InputObject)
        $values = [System.Collections.Generic.List[string]]::new()
        foreach ($item in @($InputObject)) {
            if ($null -ne $item) { [void]$values.Add("$item") }
        }
        $values.Sort([System.StringComparer]::Ordinal)
        return , $values.ToArray()
    }

    $publicFunctionNames = @(Get-ChildItem (Join-Path $moduleRoot 'Public') -File -Filter '*.ps1' |
            ForEach-Object BaseName)
    $publicFunctionNames = @(Get-OrdinalSortedString -InputObject $publicFunctionNames)
    $manifestFunctionNames = @(Get-OrdinalSortedString -InputObject $manifestData.FunctionsToExport)
}

AfterAll {
    Remove-Module IntuneAssignmentChecker -Force -ErrorAction SilentlyContinue
}

Describe 'IntuneAssignmentChecker release package' {
    It 'has a valid supported module version and matching release notes' {
        $manifest.Name | Should -BeExactly IntuneAssignmentChecker
        $manifest.Version.ToString() | Should -BeExactly "$($manifestData.ModuleVersion)"
        $manifest.Version | Should -BeGreaterOrEqual ([version]'4.4.0')
        $manifestData.PowerShellVersion | Should -BeExactly '7.0'
        $releaseHeading = '(?m)^Version ' + [regex]::Escape("$($manifestData.ModuleVersion)") + ':'
        $manifestData.PrivateData.PSData.ReleaseNotes | Should -Match $releaseHeading
    }

    It 'declares every public function exactly once with no wildcard exports' {
        $manifestData.FunctionsToExport | Should -Not -Contain '*'
        @($manifestFunctionNames | Select-Object -Unique).Count | Should -Be $manifestFunctionNames.Count
        ($manifestFunctionNames -join "`n") | Should -BeExactly ($publicFunctionNames -join "`n")
    }

    It 'references package files that exist inside the module root' {
        Test-Path -LiteralPath (Join-Path $moduleRoot $manifestData.RootModule) -PathType Leaf | Should -BeTrue
        foreach ($relativePath in @($manifestData.FormatsToProcess) + @($manifestData.FileList)) {
            $resolvedFile = Join-Path $moduleRoot $relativePath
            $moduleBoundary = [System.IO.Path]::GetFullPath($moduleRoot) + [System.IO.Path]::DirectorySeparatorChar
            [System.IO.Path]::GetFullPath($resolvedFile).StartsWith(
                $moduleBoundary,
                [System.StringComparison]::Ordinal
            ) | Should -BeTrue
            Test-Path -LiteralPath $resolvedFile -PathType Leaf | Should -BeTrue -Because "$relativePath is declared in the manifest"
        }
    }

    It 'imports from the package path and exposes only the manifest contract' {
        $importedModule = Import-Module $manifestPath -Force -PassThru -ErrorAction Stop
        $importedFunctions = @(Get-OrdinalSortedString -InputObject $importedModule.ExportedFunctions.Keys)
        $importedAliases = @(Get-OrdinalSortedString -InputObject $importedModule.ExportedAliases.Keys)

        ($importedFunctions -join "`n") | Should -BeExactly ($manifestFunctionNames -join "`n")
        $importedAliases | Should -BeExactly @('IntuneAssignmentChecker')
        (Get-Command IntuneAssignmentChecker -CommandType Alias).Definition |
            Should -BeExactly Invoke-IntuneAssignmentChecker
    }

    It 'keeps the Windows distribution PowerShell-native' {
        Test-Path -LiteralPath (Join-Path $repoRoot 'packaging/IntuneAssignmentChecker.wxs') -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $repoRoot 'packaging/Build-WindowsInstaller.ps1') -PathType Leaf | Should -BeTrue
        @(Get-ChildItem $repoRoot -Recurse -File -Include '*.csproj', '*.cs', '*.exe').Count | Should -Be 0
        (Get-Content (Join-Path $repoRoot 'packaging/README.md') -Raw) | Should -Match 'does not compile or wrap'
    }

    It 'ships a PowerShell 7 command handoff without duplicating application logic' {
        $launcherPath = Join-Path $repoRoot 'packaging/IntuneAssignmentChecker.cmd'
        Test-Path -LiteralPath $launcherPath -PathType Leaf | Should -BeTrue
        $launcher = Get-Content -LiteralPath $launcherPath -Raw
        $launcher | Should -Match 'pwsh\.exe'
        $launcher | Should -Match 'Start-IntuneAssignmentCheckerTui'
        $launcher | Should -Match 'requires PowerShell 7'
        $launcher | Should -Not -Match '(?i)powershell\.exe'

        $wix = Get-Content (Join-Path $repoRoot 'packaging/IntuneAssignmentChecker.wxs') -Raw
        $wix | Should -Match 'LauncherSource'
        $wix | Should -Match 'Name="PATH"'
        $wix | Should -Match 'System="yes"'

        $buildScript = Get-Content (Join-Path $repoRoot 'packaging/Build-WindowsInstaller.ps1') -Raw
        $buildScript | Should -Match 'launcherStagingRoot'
        $buildScript | Should -Match 'Replace\("`r`n", "`n"\)'
        $buildScript | Should -Match 'UTF8Encoding.*false'
    }

    It 'publishes the launch command and PowerShell 5.1 guidance in WinGet metadata' {
        $fakeInstaller = Join-Path $TestDrive 'IntuneAssignmentChecker-5.0.0-x64.msi'
        Set-Content -LiteralPath $fakeInstaller -Value 'test installer' -NoNewline
        $outputDirectory = Join-Path $TestDrive 'winget'
        & (Join-Path $repoRoot 'packaging/New-WinGetManifest.ps1') `
            -InstallerPath $fakeInstaller `
            -InstallerUrl 'https://example.test/IntuneAssignmentChecker-5.0.0-x64.msi' `
            -ProductCode '{B7F62E8A-5838-4EBB-9EE0-2C3E1B36AE32}' `
            -OutputDirectory $outputDirectory | Out-Null

        $installerManifest = Get-Content (Join-Path $outputDirectory 'UgurKoc.IntuneAssignmentChecker.installer.yaml') -Raw
        $localeManifest = Get-Content (Join-Path $outputDirectory 'UgurKoc.IntuneAssignmentChecker.locale.en-US.yaml') -Raw
        $installerManifest | Should -Match '(?m)^Commands:\s*\r?\n- IntuneAssignmentChecker$'
        $installerManifest | Should -Match 'PackageIdentifier: Microsoft\.PowerShell'
        $localeManifest | Should -Match '(?m)^InstallationNotes:.*PowerShell 5\.1\.$'
    }
}
