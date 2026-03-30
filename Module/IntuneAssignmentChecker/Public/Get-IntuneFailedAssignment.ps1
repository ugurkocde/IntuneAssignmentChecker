function Get-IntuneFailedAssignment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

    Write-Host "Fetching all failed assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Get all failed assignments
    $failedAssignments = Get-AssignmentFailures

    if ($failedAssignments.Count -eq 0) {
        Write-Host "`nNo assignment failures found!" -ForegroundColor Green
    }
    else {
        Write-Host "`nFound $($failedAssignments.Count) assignment failures:" -ForegroundColor Yellow

        # Group by type for better display
        $groupedFailures = $failedAssignments | Group-Object -Property Type

        foreach ($group in $groupedFailures) {
            Write-Host "`n=== $($group.Name) Failures ($($group.Count)) ===" -ForegroundColor Cyan

            foreach ($failure in $group.Group) {
                Write-Host "`nPolicy: $($failure.PolicyName)" -ForegroundColor White
                Write-Host "Device: $($failure.Target -replace 'Device: ', '')" -ForegroundColor Gray
                Write-Host "Reason: $($failure.ErrorCode)" -ForegroundColor White
                if ($failure.LastAttempt -and $failure.LastAttempt -ne "01/01/0001 00:00:00") {
                    Write-Host "Last Attempt: $($failure.LastAttempt)" -ForegroundColor Gray
                }

                # Add to export data
                $null = $exportData.Add([PSCustomObject]@{
                        Type             = $failure.Type
                        PolicyName       = $failure.PolicyName
                        Target           = $failure.Target
                        ErrorCode        = $failure.ErrorCode
                        ErrorDescription = $failure.ErrorDescription
                        LastAttempt      = $failure.LastAttempt
                    })
            }
        }

        # Export if requested
        Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneFailedAssignments.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
    }
}
