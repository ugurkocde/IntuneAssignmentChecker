#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
    $modulePrivate = Join-Path $moduleRoot 'Private'

    . (Join-Path $modulePrivate 'Get-PolicyPlatform.ps1')
    . (Join-Path $modulePrivate 'Get-ScopeTagNames.ps1')
    . (Join-Path $moduleRoot 'html-export.ps1')
    . (Join-Path $moduleRoot 'Public/New-IntuneHTMLReport.ps1')
    . (Join-Path $moduleRoot 'Public/Invoke-IntuneAssignmentChecker.ps1')

    $script:GraphEndpoint = 'https://graph.test'

    function Get-IntuneEntities { param([string]$EntityType) @() }
    function Get-IntuneAssignments { param([string]$EntityType, [string]$EntityId) @() }
    function Get-AppProtectionAssignmentUri { param($Policy) $null }
    function Add-IntentTemplateFamilyInfo { param($IntentPolicies) }
    function Invoke-IACGraphRequest { param([string]$Uri, [string]$Method) @{ value = @() } }
    function Get-GroupInfo { param([string]$GroupId) @{ DisplayName = "Group $GroupId"; Success = $true } }
    function Connect-IntuneAssignmentChecker {}
    function Get-MgContext { @{ Account = 'test@contoso.com' } }
}

Describe 'HTML report CSV companion' {
    BeforeEach {
        $script:ScopeTagLookup = @{ '0' = 'Default'; 'tag-ops' = 'Operations' }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-IntuneEntities {
            if ($EntityType -eq 'deviceConfigurations') {
                return @([PSCustomObject]@{
                        id = 'cfg-1'
                        displayName = 'Déploiement Baseline'
                        roleScopeTagIds = @('0', 'tag-ops')
                        '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration'
                    })
            }
            @()
        }
        Mock Get-IntuneAssignments {
            if ($EntityId -eq 'cfg-1') {
                return @([PSCustomObject]@{
                        Reason = 'All Users'
                        GroupId = $null
                        FilterId = $null
                        FilterType = $null
                    })
            }
            @()
        }
        Mock Get-AppProtectionAssignmentUri { $null }
        Mock Add-IntentTemplateFamilyInfo {}
        Mock Invoke-IACGraphRequest { @{ value = @() } }
    }

    It 'exports the requested stable CSV schema with the same report data' {
        $htmlPath = Join-Path $TestDrive 'reports/report.html'
        $csvPath = Join-Path $TestDrive 'central/intune.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null

        Export-HTMLReport -FilePath $htmlPath -CSVReportPath $csvPath

        $htmlPath | Should -Exist
        $csvPath | Should -Exist
        $rows = @(Import-Csv -Path $csvPath)
        $rows | Should -HaveCount 1
        @($rows[0].PSObject.Properties.Name) | Should -Be @(
            'Category', 'Name', 'ID', 'Type', 'Platform', 'ScopeTags', 'AssignmentType', 'AssignedTo', 'Filter'
        )
        $rows[0].Category | Should -BeExactly 'Device Configurations'
        $rows[0].Name | Should -BeExactly 'Déploiement Baseline'
        $rows[0].ID | Should -BeExactly 'cfg-1'
        $rows[0].Type | Should -BeExactly 'Device Configuration'
        $rows[0].Platform | Should -BeExactly 'Windows'
        $rows[0].ScopeTags | Should -BeExactly 'Default, Operations'
        $rows[0].AssignmentType | Should -BeExactly 'All Users'
        $rows[0].AssignedTo | Should -BeExactly 'All Users'
        $rows[0].Filter | Should -BeExactly 'None'
    }

    It 'uses the HTML base path for the CSV companion by default' {
        $htmlPath = Join-Path $TestDrive 'default/report.html'
        $expectedCsvPath = Join-Path $TestDrive 'default/report.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null

        Export-HTMLReport -FilePath $htmlPath

        $htmlPath | Should -Exist
        $expectedCsvPath | Should -Exist
    }

    It 'writes the stable header when the report contains no rows' {
        Mock Get-IntuneEntities { @() }
        $htmlPath = Join-Path $TestDrive 'empty/report.html'
        $csvPath = Join-Path $TestDrive 'empty/report.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null

        Export-HTMLReport -FilePath $htmlPath -CSVReportPath $csvPath

        (Get-Content -Path $csvPath -Raw).Trim() | Should -BeExactly '"Category","Name","ID","Type","Platform","ScopeTags","AssignmentType","AssignedTo","Filter"'
    }

    It 'keeps a completed HTML report when the CSV path cannot be created' {
        $htmlPath = Join-Path $TestDrive 'partial/report.html'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null
        Mock Export-Csv { throw 'simulated CSV write failure' }

        { Export-HTMLReport -FilePath $htmlPath } | Should -Not -Throw

        $htmlPath | Should -Exist
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter { $Message -like "Failed to export CSV report*" }
    }

    It 'isolates an unusable CSV path when called through the public cmdlet' {
        $htmlPath = Join-Path $TestDrive 'public/report.html'
        $invalidCsvPath = Join-Path $TestDrive 'existing-file-without-csv-extension'
        Set-Content -Path $invalidCsvPath -Value 'file'

        { New-IntuneHTMLReport -HTMLReportPath $htmlPath -CSVReportPath $invalidCsvPath } | Should -Not -Throw

        $htmlPath | Should -Exist
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter { $Message -like "Failed to export CSV report*existing file without a .csv extension*" }
    }

    It 'supports a central directory path and derives the CSV name from the HTML report' {
        $htmlPath = Join-Path $TestDrive 'named/custom-report.html'
        $csvDirectory = Join-Path $TestDrive 'central-directory'

        New-IntuneHTMLReport -HTMLReportPath $htmlPath -CSVReportPath $csvDirectory

        $htmlPath | Should -Exist
        (Join-Path $csvDirectory 'custom-report.csv') | Should -Exist
    }

    It 'resolves relative report paths against the PowerShell location' {
        $workingDirectory = Join-Path $TestDrive 'relative-location'
        New-Item -ItemType Directory -Path $workingDirectory -Force | Out-Null

        Push-Location $workingDirectory
        try {
            New-IntuneHTMLReport -HTMLReportPath 'relative-report.html' -CSVReportPath 'relative-report.csv'
        }
        finally {
            Pop-Location
        }

        (Join-Path $workingDirectory 'relative-report.html') | Should -Exist
        (Join-Path $workingDirectory 'relative-report.csv') | Should -Exist
    }

    It 'rejects a mistyped CSV file extension without blocking HTML output' {
        $htmlPath = Join-Path $TestDrive 'mistyped/report.html'
        $mistypedCsvPath = Join-Path $TestDrive 'mistyped/intune.cvs'

        New-IntuneHTMLReport -HTMLReportPath $htmlPath -CSVReportPath $mistypedCsvPath

        $htmlPath | Should -Exist
        $mistypedCsvPath | Should -Not -Exist
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter { $Message -like 'Failed to export CSV report*must be a .csv file*' }
    }

    It 'supports explicit HTML-only report generation' {
        $htmlPath = Join-Path $TestDrive 'html-only/report.html'
        $csvPath = Join-Path $TestDrive 'html-only/report.csv'

        New-IntuneHTMLReport -HTMLReportPath $htmlPath -NoCSVReport

        $htmlPath | Should -Exist
        $csvPath | Should -Not -Exist
    }

    It 'rejects conflicting CSV options at parameter binding before report generation starts' {
        $htmlPath = Join-Path $TestDrive 'conflict/report.html'
        $csvPath = Join-Path $TestDrive 'conflict/report.csv'

        { New-IntuneHTMLReport -HTMLReportPath $htmlPath -CSVReportPath $csvPath -NoCSVReport } |
            Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])

        $htmlPath | Should -Not -Exist
        $csvPath | Should -Not -Exist
        Should -Invoke Write-Host -Exactly 0 -ParameterFilter { $Object -eq 'Generating HTML Report...' }
    }

    It 'notifies before replacing an existing CSV companion without using the warning stream' {
        $htmlPath = Join-Path $TestDrive 'overwrite/report.html'
        $csvPath = Join-Path $TestDrive 'overwrite/report.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null
        Set-Content -Path $csvPath -Value 'old data'

        Export-HTMLReport -FilePath $htmlPath

        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { $Object -like 'Replacing existing CSV report*' }
        Should -Invoke Write-Warning -Exactly 0
        @(Import-Csv -Path $csvPath) | Should -HaveCount 1
    }

    It 'neutralizes spreadsheet formula prefixes in tenant-controlled CSV values' {
        foreach ($value in @('=1+1', '+SUM(A1:A2)', '-2+3', '@cmd', "`tformula", "`rformula")) {
            (ConvertTo-IntuneCsvSafeValue $value) | Should -BeExactly "'$value"
        }
        ConvertTo-IntuneCsvSafeValue 'Normal value' | Should -BeExactly 'Normal value'
    }

    It 'keeps filters positionally aligned with their assignment targets' {
        $script:AssignmentFilterLookup = @{ 'filter-corp' = @{ Name = 'Corporate Devices' } }
        $assignmentInfo = Get-HtmlAssignmentInfo -Assignments @(
            [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'group-a'; FilterId = $null; FilterType = $null }
            [PSCustomObject]@{ Reason = 'Group Assignment'; GroupId = 'group-b'; FilterId = 'filter-corp'; FilterType = 'include' }
        )

        $assignmentInfo.Target | Should -BeExactly 'Group group-a; Group group-b'
        $assignmentInfo.Filter | Should -BeExactly 'None; Corporate Devices [Include]'
    }

    It 'uses an empty platform and a consistent None sentinel when no assignment filter exists' {
        Mock Get-PolicyPlatform { '' }
        Mock Get-IntuneAssignments { @() }
        $htmlPath = Join-Path $TestDrive 'empty-values/report.html'
        $csvPath = Join-Path $TestDrive 'empty-values/report.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null

        Export-HTMLReport -FilePath $htmlPath -CSVReportPath $csvPath

        $row = @(Import-Csv -Path $csvPath)[0]
        $row.Platform | Should -BeExactly ''
        $row.Filter | Should -BeExactly 'None'
    }

    It 'retains mobile-app type metadata for platform classification in report rows' {
        Mock Get-IntuneEntities { @() }
        Mock Invoke-IACGraphRequest {
            if ($Uri -like '*deviceAppManagement/mobileApps?*isAssigned*') {
                return @{ value = @([PSCustomObject]@{
                            id = 'app-ios'
                            displayName = 'iOS Store App'
                            roleScopeTagIds = @('tag-ops')
                            '@odata.type' = '#microsoft.graph.iosStoreApp'
                        }) }
            }
            if ($Uri -like "*mobileApps('app-ios')/assignments*") {
                return @{ value = @([PSCustomObject]@{
                            intent = 'required'
                            target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
                        }) }
            }
            @{ value = @() }
        }
        $htmlPath = Join-Path $TestDrive 'app-platform/report.html'
        $csvPath = Join-Path $TestDrive 'app-platform/report.csv'
        New-Item -ItemType Directory -Path (Split-Path $htmlPath -Parent) -Force | Out-Null

        Export-HTMLReport -FilePath $htmlPath -CSVReportPath $csvPath

        $row = @(Import-Csv -Path $csvPath | Where-Object ID -EQ 'app-ios')
        $row | Should -HaveCount 1
        $row[0].Category | Should -BeExactly 'Required Applications'
        $row[0].Platform | Should -BeExactly 'iOS/iPadOS'
        Should -Invoke Invoke-IACGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -like '*deviceAppManagement/mobileApps?*' -and $Uri -like '*$select=id,displayName,roleScopeTagIds*'
        }
    }

    It 'exposes CSVReportPath through both public entry points' {
        (Get-Command New-IntuneHTMLReport).Parameters.Keys | Should -Contain 'CSVReportPath'
        (Get-Command New-IntuneHTMLReport).Parameters.Keys | Should -Contain 'NoCSVReport'
        (Get-Command Invoke-IntuneAssignmentChecker).Parameters.Keys | Should -Contain 'CSVReportPath'
        (Get-Command Invoke-IntuneAssignmentChecker).Parameters.Keys | Should -Contain 'NoCSVReport'
    }

    Context 'Invoke-IntuneAssignmentChecker report dispatch' {
        BeforeEach {
            Mock Connect-IntuneAssignmentChecker {}
            Mock Get-MgContext { @{ Account = 'test@contoso.com' } }
            Mock New-IntuneHTMLReport {}
        }

        It 'dispatches default companion report generation without inactive parameters' {
            Invoke-IntuneAssignmentChecker -GenerateHTMLReport

            Should -Invoke New-IntuneHTMLReport -Exactly 1 -ParameterFilter {
                -not $HTMLReportPath -and -not $CSVReportPath -and -not $NoCSVReport
            }
        }

        It 'dispatches an explicit CSV destination to the report cmdlet' {
            $csvPath = Join-Path $TestDrive 'dispatch/central.csv'

            Invoke-IntuneAssignmentChecker -CSVReportPath $csvPath

            Should -Invoke New-IntuneHTMLReport -Exactly 1 -ParameterFilter {
                $CSVReportPath -eq $csvPath -and -not $NoCSVReport
            }
        }

        It 'dispatches HTML-only generation without supplying a CSV path' {
            Invoke-IntuneAssignmentChecker -GenerateHTMLReport -NoCSVReport

            Should -Invoke New-IntuneHTMLReport -Exactly 1 -ParameterFilter {
                $NoCSVReport -and -not $CSVReportPath
            }
        }

        It 'treats NoCSVReport by itself as an HTML-only report request' {
            Invoke-IntuneAssignmentChecker -NoCSVReport

            Should -Invoke New-IntuneHTMLReport -Exactly 1 -ParameterFilter {
                $NoCSVReport -and -not $CSVReportPath
            }
        }

        It 'rejects contradictory report options before attempting authentication' {
            $csvPath = Join-Path $TestDrive 'dispatch/conflict.csv'

            { Invoke-IntuneAssignmentChecker -GenerateHTMLReport -CSVReportPath $csvPath -NoCSVReport } |
                Should -Throw '*-NoCSVReport cannot be combined with -CSVReportPath*'

            Should -Invoke Connect-IntuneAssignmentChecker -Exactly 0
            Should -Invoke New-IntuneHTMLReport -Exactly 0
        }
    }
}
