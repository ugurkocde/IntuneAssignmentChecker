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
}
