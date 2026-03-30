function Show-SaveFileDialog {
    param (
        [string]$DefaultFileName
    )

    # Check if running on Windows (Windows Forms only works on Windows)
    if ($IsWindows -or $env:OS -match "Windows") {
        try {
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
        catch {
            Write-Verbose "Windows Forms dialog unavailable, falling back to manual path entry"
        }
    }

    # Cross-platform fallback: prompt for path manually
    $defaultPath = $HOME
    if (Test-Path "$HOME/Documents") {
        $defaultPath = "$HOME/Documents"
    }
    $suggestedPath = Join-Path $defaultPath $DefaultFileName

    Write-Host "Enter the path to save the file (or press Enter for default):" -ForegroundColor Cyan
    Write-Host "Default: $suggestedPath" -ForegroundColor Gray
    $userPath = Read-Host "Path"

    if ([string]::IsNullOrWhiteSpace($userPath)) {
        return $suggestedPath
    }
    return $userPath
}
