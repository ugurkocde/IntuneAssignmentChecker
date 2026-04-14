function Export-ResultsIfRequested {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$DefaultFileName,
        [switch]$ForceExport,
        [string]$CustomExportPath
    )

    if ($ForceExport -or $ExportToCSV) {
        $exportPath = if ($CustomExportPath) {
            $CustomExportPath
        }
        else {
            Show-SaveFileDialog -DefaultFileName $DefaultFileName
        }

        if ($exportPath) {
            Export-PolicyData -ExportData $ExportData -FilePath $exportPath
        }
    }
    elseif (-not $parameterMode) {
        $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
        if ($export -match '^[Yy]') {
            $exportPath = Show-SaveFileDialog -DefaultFileName $DefaultFileName
            if ($exportPath) {
                Export-PolicyData -ExportData $ExportData -FilePath $exportPath
            }
        }
    }
}
