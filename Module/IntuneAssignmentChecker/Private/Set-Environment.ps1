function Set-Environment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    if ($EnvironmentName) {
        switch ($EnvironmentName) {
            'Global' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGov' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGovDoD' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            default {
                Write-Host "Invalid environment name. Using interactive selection." -ForegroundColor Yellow
                # Fall through to interactive selection
            }
        }
    }

    # Interactive selection if no valid environment name was provided
    do {
        Write-Host "Select Intune Tenant Environment:" -ForegroundColor Cyan
        Write-Host "  [1] Global" -ForegroundColor White
        Write-Host "  [2] USGov" -ForegroundColor White
        Write-Host "  [3] USGovDoD" -ForegroundColor White
        Write-Host ""
        Write-Host "  [0] Exit" -ForegroundColor White
        Write-Host ""
        Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline

        $selection = Read-Host

        switch ($selection) {
            '1' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '2' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '3' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '0' {
                Write-Host "Thank you for using IntuneAssignmentChecker! 👋" -ForegroundColor Green
                Write-Host "If you found this tool helpful, please consider:" -ForegroundColor Cyan
                Write-Host "- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor White
                Write-Host "- Supporting the project: https://github.com/sponsors/ugurkocde" -ForegroundColor White
                Write-Host ""
                exit
            }
            default {
                Write-Host "Invalid choice, please select 1,2,3, or 0" -ForegroundColor Red
            }
        }
    } while ($selection -ne '0')
}
