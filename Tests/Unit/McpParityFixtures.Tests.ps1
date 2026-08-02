#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $exporter = Join-Path $PSScriptRoot '../Parity/Export-McpParityFixtures.ps1'
    $committedFixture = Join-Path $PSScriptRoot '../Parity/assignment-parity.v1.json'
    $generatedFixture = Join-Path ([System.IO.Path]::GetTempPath()) "iac-mcp-parity-$([guid]::NewGuid().ToString('N')).json"
}

AfterAll {
    if (Test-Path -LiteralPath $generatedFixture) {
        Remove-Item -LiteralPath $generatedFixture -Force
    }
}

Describe 'MCP parity fixture contract' {
    It 'is regenerated deterministically from the PowerShell normalization engine' {
        & $exporter -OutputPath $generatedFixture | Out-Null

        Test-Path -LiteralPath $committedFixture | Should -BeTrue
        $generatedContent = [System.IO.File]::ReadAllText($generatedFixture).Replace("`r`n", "`n")
        $committedContent = [System.IO.File]::ReadAllText($committedFixture).Replace("`r`n", "`n")
        $generatedContent | Should -BeExactly $committedContent
    }

    It 'uses the versioned beta contract and covers every supported category and assignment target mode' {
        $fixture = Get-Content -LiteralPath $committedFixture -Raw | ConvertFrom-Json -Depth 20

        $fixture.contractName | Should -BeExactly 'IntuneAssignmentChecker.McpAssignmentParity'
        $fixture.contractVersion | Should -Be 1
        $fixture.graphApiVersion | Should -BeExactly 'beta'
        @($fixture.cases).Count | Should -BeGreaterOrEqual 8
        $assignmentModes = @($fixture.cases.expected.assignmentMode | Sort-Object -Unique)
        foreach ($expectedMode in @('Exclude', 'Include')) {
            $assignmentModes | Should -Contain $expectedMode
        }
        $targetTypes = @($fixture.cases.expected.targetType | Sort-Object -Unique)
        foreach ($expectedTargetType in @('AllDevices', 'AllUsers', 'Group')) {
            $targetTypes | Should -Contain $expectedTargetType
        }
        $categoryIds = @($fixture.cases.category | Sort-Object -Unique)
        foreach ($expectedCategory in @(
                'configurationPolicy'
                'deviceConfiguration'
                'compliancePolicy'
                'application'
                'appConfiguration'
            )) {
            $categoryIds | Should -Contain $expectedCategory
        }
    }
}
