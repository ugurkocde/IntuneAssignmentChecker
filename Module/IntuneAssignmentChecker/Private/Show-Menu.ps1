function Show-Menu {
    # Display current connection status
    if ($script:CurrentTenantName -and $script:CurrentUserUPN) {
        Write-Host "Connected to: " -ForegroundColor Green -NoNewline
        Write-Host "$script:CurrentTenantName" -ForegroundColor White
        Write-Host "Logged in as: " -ForegroundColor Green -NoNewline
        Write-Host "$script:CurrentUserUPN" -ForegroundColor White
        Write-Host ""
    }
    elseif ($script:CurrentUserUPN) {
        Write-Host "Logged in as: " -ForegroundColor Green -NoNewline
        Write-Host "$script:CurrentUserUPN" -ForegroundColor White
        Write-Host ""
    }
    else {
        Write-Host "Status: " -ForegroundColor Yellow -NoNewline
        Write-Host "Not Connected" -ForegroundColor Red
        Write-Host ""
    }

    Write-Host "Assignment Checks:" -ForegroundColor Cyan
    Write-Host "  [1] Check User(s) Assignments" -ForegroundColor White
    Write-Host "  [2] Check Group(s) Assignments" -ForegroundColor White
    Write-Host "  [3] Check Device(s) Assignments" -ForegroundColor White
    Write-Host ""

    Write-Host "Policy Overview:" -ForegroundColor Cyan
    Write-Host "  [4] Show All Policies and Their Assignments" -ForegroundColor White
    Write-Host "  [5] Show All 'All Users' Assignments" -ForegroundColor White
    Write-Host "  [6] Show All 'All Devices' Assignments" -ForegroundColor White
    Write-Host ""

    Write-Host "Advanced Options:" -ForegroundColor Cyan
    Write-Host "  [7] Generate HTML Report" -ForegroundColor White
    Write-Host "  [8] Show Policies and Apps Without Assignments" -ForegroundColor White
    Write-Host "  [9] Check for Empty Groups in Assignments" -ForegroundColor White
    Write-Host "  [10] Compare Assignments Between Groups" -ForegroundColor White
    Write-Host "  [11] Show All Failed Assignments" -ForegroundColor White
    Write-Host "  [12] Simulate Group Membership Impact" -ForegroundColor White
    Write-Host "  [13] Simulate Removing User from Group" -ForegroundColor White
    Write-Host "  [14] Search Policy Assignments" -ForegroundColor White
    Write-Host "  [15] Search for Specific Settings" -ForegroundColor White
    Write-Host ""

    Write-Host "System:" -ForegroundColor Cyan
    Write-Host "  [T] Switch Tenant" -ForegroundColor White
    Write-Host "  [0] Exit" -ForegroundColor White
    Write-Host "  [98] Support the Project  [99] Report a Bug or Request a Feature" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline
}
