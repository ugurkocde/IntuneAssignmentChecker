# Public/Export.ps1
# Export functions for Intune Assignment Checker
# These functions handle data export to CSV and file dialogs

function Show-SaveFileDialog {
    param (
        [string]$DefaultFileName
    )

    Add-Type -AssemblyName System.Windows.Forms
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Excel files (*.xlsx)|*.xlsx|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $saveFileDialog.FileName = $DefaultFileName
    $saveFileDialog.Title = "Save Policy Report"

    if ($saveFileDialog.ShowDialog() -eq 'OK') {
        return $saveFileDialog.FileName
    }
    return $null
}

function Export-PolicyData {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$ExportData,
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()

    if ($extension -eq '.xlsx') {
        # Check if ImportExcel module is installed
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Host "The ImportExcel module is required for Excel export. Would you like to install it? (y/n)" -ForegroundColor Yellow
            $install = Read-Host
            if ($install -eq 'y') {
                try {
                    Install-Module -Name ImportExcel -Force -Scope CurrentUser
                    Write-Host "ImportExcel module installed successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to install ImportExcel module. Falling back to CSV export." -ForegroundColor Red
                    $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
                    $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
                    Write-Host "Results exported to $FilePath" -ForegroundColor Green
                    return
                }
            }
            else {
                Write-Host "Falling back to CSV export." -ForegroundColor Yellow
                $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
                $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
                Write-Host "Results exported to $FilePath" -ForegroundColor Green
                return
            }
        }

        try {
            $ExportData | Export-Excel -Path $FilePath -AutoSize -AutoFilter -WorksheetName "Intune Assignments" -TableName "IntuneAssignments"
            Write-Host "Results exported to $FilePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to export to Excel. Falling back to CSV export." -ForegroundColor Red
            $FilePath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
            $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
            Write-Host "Results exported to $FilePath" -ForegroundColor Green
        }
    }
    else {
        $ExportData | Export-Csv -Path $FilePath -NoTypeInformation
        Write-Host "Results exported to $FilePath" -ForegroundColor Green
    }
}

function Add-ExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Items,
        [Parameter(Mandatory = $false)]
        [object]$AssignmentReason = "N/A"
    )

    foreach ($item in $Items) {
        $itemName = if ($item.displayName) { $item.displayName } else { $item.name }

        # Handle different types of assignment reason input
        $reason = if ($AssignmentReason -is [scriptblock]) {
            & $AssignmentReason $item
        }
        elseif ($item.AssignmentReason) {
            $item.AssignmentReason
        }
        elseif ($item.AssignmentSummary) {
            $item.AssignmentSummary
        }
        else {
            $AssignmentReason
        }

        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$itemName (ID: $($item.id))"
                AssignmentReason = $reason
            })
    }
}

function Add-AppExportData {
    param (
        [System.Collections.ArrayList]$ExportData,
        [string]$Category,
        [object[]]$Apps,
        [string]$AssignmentReason = "N/A"
    )

    foreach ($app in $Apps) {
        $appName = if ($app.displayName) { $app.displayName } else { $app.name }
        $null = $ExportData.Add([PSCustomObject]@{
                Category         = $Category
                Item             = "$appName (ID: $($app.id))"
                AssignmentReason = "$AssignmentReason - $($app.AssignmentIntent)"
            })
    }
}

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
    else {
        $export = Read-Host "`nWould you like to export the results to CSV? (y/n)"
        if ($export -eq 'y') {
            $exportPath = Show-SaveFileDialog -DefaultFileName $DefaultFileName
            if ($exportPath) {
                Export-PolicyData -ExportData $ExportData -FilePath $exportPath
            }
        }
    }
}
