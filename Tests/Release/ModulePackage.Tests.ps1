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

    It 'publishes an unsigned MSI without executable artifacts or signing secrets' {
        $workflow = Get-Content (Join-Path $repoRoot '.github/workflows/windows-package.yml') -Raw
        $packagingReadme = Get-Content (Join-Path $repoRoot 'packaging/README.md') -Raw

        $workflow | Should -Not -Match 'SIGNING_CERTIFICATE|SIGNING_PASSWORD|signtool|Authenticode'
        $workflow | Should -Match 'Reject executable artifacts'
        $workflow | Should -Match 'artifacts/\*\.msi'
        $workflow | Should -Not -Match 'artifacts/\*\.exe'
        $packagingReadme | Should -Match 'without Authenticode signing'
        $packagingReadme | Should -Match 'does not sign or host'
    }

    It 'ships a PowerShell 7 command handoff without duplicating application logic' {
        $launcherPath = Join-Path $repoRoot 'packaging/IntuneAssignmentChecker.cmd'
        $bootstrapPath = Join-Path $repoRoot 'packaging/Start-IntuneAssignmentChecker.ps1'
        Test-Path -LiteralPath $launcherPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $bootstrapPath -PathType Leaf | Should -BeTrue
        $launcher = Get-Content -LiteralPath $launcherPath -Raw
        $bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw
        $launcher | Should -Match 'pwsh\.exe'
        $launcher | Should -Match 'Start-IntuneAssignmentChecker\.ps1'
        $launcher | Should -Match 'requires PowerShell 7'
        $launcher | Should -Not -Match '(?i)powershell\.exe'
        @([regex]::Matches($launcher, '-ExecutionPolicy Bypass')).Count | Should -Be 3
        $launcher | Should -Match ':bootstrap_not_found'
        $launcher | Should -Match 'winget install --id UgurKoc\.IntuneAssignmentChecker --exact --force'
        $bootstrap | Should -Match 'Start-IntuneAssignmentCheckerTui'
        $bootstrap | Should -Match 'Get-Module -ListAvailable'
        $bootstrap | Should -Match 'IsMachineInstallation'
        $bootstrap | Should -Match 'Import-Module -Name \$selected\.Path'
        $bootstrap | Should -Match 'IAC_LAUNCH_NOTICE'
        $tuiLauncher = Get-Content -LiteralPath (Join-Path $moduleRoot 'Public/Start-IntuneAssignmentCheckerTui.ps1') -Raw
        $tuiLauncher | Should -Match 'IAC_LAUNCH_NOTICE'

        $wix = Get-Content (Join-Path $repoRoot 'packaging/IntuneAssignmentChecker.wxs') -Raw
        $wix | Should -Match 'LauncherSource'
        $wix | Should -Match 'Start-IntuneAssignmentChecker\.ps1'
        $wix | Should -Match 'Component Id="PowerShellLauncher"'
        $wix | Should -Match 'Name="PATH"'
        $wix | Should -Match 'System="yes"'

        $buildScript = Get-Content (Join-Path $repoRoot 'packaging/Build-WindowsInstaller.ps1') -Raw
        $buildScript | Should -Match 'launcherStagingRoot'
        $buildScript | Should -Match 'bootstrapDestination'
        $buildScript | Should -Match 'Replace\("`r`n", "`n"\)'
        $buildScript | Should -Match 'UTF8Encoding.*false'
    }

    It 'selects the newest module and uses the MSI scope to break version ties' {
        $bootstrapPath = Join-Path $repoRoot 'packaging/Start-IntuneAssignmentChecker.ps1'
        $programFiles = Join-Path $TestDrive 'Program Files'
        $machineModules = Join-Path (Join-Path $programFiles 'PowerShell') 'Modules'
        $userModules = Join-Path $TestDrive 'UserModules'

        function Add-TestModule {
            param([string]$Root, [string]$Version, [string]$Prerelease)
            $versionRoot = Join-Path (Join-Path $Root 'IntuneAssignmentChecker') $Version
            New-Item -ItemType Directory -Path $versionRoot -Force | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $versionRoot 'IntuneAssignmentChecker.psm1'),
                'function Start-IntuneAssignmentCheckerTui { param([switch]$DisableMouse) }',
                [Text.UTF8Encoding]::new($false)
            )
            $manifestParameters = @{
                Path              = Join-Path $versionRoot 'IntuneAssignmentChecker.psd1'
                RootModule        = 'IntuneAssignmentChecker.psm1'
                ModuleVersion     = $Version
                FunctionsToExport = 'Start-IntuneAssignmentCheckerTui'
            }
            if ($Prerelease) { $manifestParameters.Prerelease = $Prerelease }
            New-ModuleManifest @manifestParameters
            return [IO.Path]::GetFullPath((Join-Path $versionRoot 'IntuneAssignmentChecker.psd1'))
        }

        $machineManifest = Add-TestModule -Root $machineModules -Version '5.0.0'
        $null = Add-TestModule -Root $userModules -Version '5.0.0'
        $pathSeparator = [IO.Path]::PathSeparator
        $savedModulePath = $env:PSModulePath
        $savedProgramFiles = $env:ProgramFiles
        $savedProgramW6432 = $env:ProgramW6432
        try {
            $env:PSModulePath = "$userModules$pathSeparator$machineModules"
            $env:ProgramFiles = Join-Path $TestDrive 'Program Files (x86)'
            $env:ProgramW6432 = $programFiles
            $tieOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $tieExitCode = $LASTEXITCODE

            $newestManifest = Add-TestModule -Root $userModules -Version '5.1.0'
            $newestOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $newestExitCode = $LASTEXITCODE

            $null = Add-TestModule -Root $machineModules -Version '5.1.0' -Prerelease 'preview1'
            $stableOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $stableExitCode = $LASTEXITCODE

            $fourPartManifest = Add-TestModule -Root $userModules -Version '5.2.0.1'
            $fourPartOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $fourPartExitCode = $LASTEXITCODE

            $env:PSModulePath = $userModules
            $singleScopeOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $singleScopeExitCode = $LASTEXITCODE

            $emptyModules = Join-Path $TestDrive 'EmptyModules'
            New-Item -ItemType Directory -Path $emptyModules -Force | Out-Null
            $env:PSModulePath = $emptyModules
            $notInstalledOutput = @(& pwsh -NoLogo -NoProfile -File $bootstrapPath -Check 2>&1)
            $notInstalledExitCode = $LASTEXITCODE
        }
        finally {
            $env:PSModulePath = $savedModulePath
            $env:ProgramFiles = $savedProgramFiles
            $env:ProgramW6432 = $savedProgramW6432
        }

        $tieExitCode | Should -Be 0
        ($tieOutput -join "`n") | Should -Match ([regex]::Escape($machineManifest))
        ($tieOutput -join "`n") | Should -Match 'multiple module scopes'
        $newestExitCode | Should -Be 0
        ($newestOutput -join "`n") | Should -Match ([regex]::Escape($newestManifest))
        $stableExitCode | Should -Be 0
        ($stableOutput -join "`n") | Should -Match ([regex]::Escape($newestManifest))
        ($stableOutput -join "`n") | Should -Not -Match '5\.1\.0-preview1'

        $singleScopeExitCode | Should -Be 0
        ($singleScopeOutput -join "`n") | Should -Not -Match 'multiple module scopes'
        ($singleScopeOutput -join "`n") | Should -Match ([regex]::Escape($fourPartManifest))
        $fourPartExitCode | Should -Be 0
        ($fourPartOutput -join "`n") | Should -Match ([regex]::Escape($fourPartManifest))
        ($fourPartOutput -join "`n") | Should -Match '5\.2\.0\.1'
        $notInstalledExitCode | Should -Not -Be 0
        ($notInstalledOutput -join "`n") | Should -Match 'UgurKoc\.IntuneAssignmentChecker'
        ($notInstalledOutput -join "`n") | Should -Match 'Install-Module'
        ($notInstalledOutput -join "`n") | Should -Match 'IntuneAssignmentChecker -Scope CurrentUser'
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
