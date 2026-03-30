function New-IntuneHTMLReport {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$HTMLReportPath
    )

    Write-Host "Generating HTML Report..." -ForegroundColor Green

    # Dot-source html-export.ps1 shipped with the module
    $htmlExportScript = Join-Path $PSScriptRoot '..' 'html-export.ps1'

    try {
        . $htmlExportScript

        $defaultFileName = "IntuneAssignmentReport.html"

        if ($HTMLReportPath) {
            # Resolve to absolute path to avoid writing to CWD (e.g. System32 on Windows)
            $HTMLReportPath = [System.IO.Path]::GetFullPath($HTMLReportPath)

            if (Test-Path $HTMLReportPath -PathType Container) {
                # Existing directory - append default filename
                $filePath = Join-Path $HTMLReportPath $defaultFileName
            }
            elseif ($HTMLReportPath -match '\.(html?)$') {
                # Has an HTML file extension - use as-is, create parent dir if needed
                $parentDir = Split-Path $HTMLReportPath -Parent
                if ($parentDir -and -not (Test-Path $parentDir)) {
                    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                }
                $filePath = $HTMLReportPath
            }
            else {
                # No HTML extension, treat as directory path - create it and append default filename
                if (-not (Test-Path $HTMLReportPath)) {
                    New-Item -ItemType Directory -Path $HTMLReportPath -Force | Out-Null
                }
                $filePath = Join-Path $HTMLReportPath $defaultFileName
            }
        }
        else {
            # Default behavior: save to Documents folder
            $defaultReportPath = $HOME
            if ($IsWindows -or $env:OS -match "Windows") {
                $documentsPath = [Environment]::GetFolderPath('MyDocuments')
                if ($documentsPath -and (Test-Path $documentsPath)) {
                    $defaultReportPath = $documentsPath
                }
            }
            elseif (Test-Path "$HOME/Documents") {
                $defaultReportPath = "$HOME/Documents"
            }
            $filePath = Join-Path $defaultReportPath $defaultFileName
        }

        Write-Host "Report will be saved to: $filePath" -ForegroundColor Cyan
        Export-HTMLReport -FilePath $filePath
    }
    catch {
        Write-Host "Error: Failed to generate the HTML report. $($_.Exception.Message)" -ForegroundColor Red
    }
}
