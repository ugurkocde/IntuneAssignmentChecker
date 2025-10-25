# Public/UI.ps1
# User interface functions for Intune Assignment Checker
# These functions handle menu display and tenant switching

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
    Write-Host "  [8] Show Policies Without Assignments" -ForegroundColor White
    Write-Host "  [9] Check for Empty Groups in Assignments" -ForegroundColor White
    Write-Host "  [10] Compare Assignments Between Groups" -ForegroundColor White
    Write-Host "  [11] Show All Failed Assignments" -ForegroundColor White
    Write-Host ""

    Write-Host "System:" -ForegroundColor Cyan
    Write-Host "  [12] Disconnect and Connect to Different Tenant" -ForegroundColor White
    Write-Host "  [0] Exit" -ForegroundColor White
    Write-Host "  [98] Support the Project 💝" -ForegroundColor Magenta
    Write-Host "  [99] Report a Bug or Request a Feature" -ForegroundColor White
    Write-Host ""

    Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline
}

# Function to switch tenants
function Switch-Tenant {
    Write-Host "`nDisconnecting from current tenant..." -ForegroundColor Yellow

    try {
        # Disconnect from current Graph session
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

        # Clear tenant variables
        $script:CurrentTenantId = $null
        $script:CurrentTenantName = $null
        $script:CurrentUserUPN = $null

        Write-Host "Disconnected successfully." -ForegroundColor Green
        Write-Host ""

        # Prompt for new connection
        Write-Host "Please log in to connect to a different tenant..." -ForegroundColor Cyan

        # Get required permissions
        $permissionsList = ($requiredPermissions | ForEach-Object { $_.Permission }) -join ', '

        # Prompt for environment selection
        Set-Environment

        # Attempt new connection
        $connectionResult = Connect-MgGraph -Scopes $permissionsList -Environment $script:GraphEnvironment -NoWelcome -ErrorAction Stop

        # Get and store new tenant context
        $context = Get-MgContext
        if ($context) {
            $script:CurrentTenantId = $context.TenantId
            $script:CurrentUserUPN = $context.Account

            # Try to get tenant display name
            try {
                $org = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/v1.0/organization" -ErrorAction SilentlyContinue
                if ($org.value -and $org.value.Count -gt 0) {
                    $script:CurrentTenantName = $org.value[0].displayName
                }
            }
            catch {
                # If we can't get the display name, use tenant ID
                $script:CurrentTenantName = $context.TenantId
            }

            Write-Host "`nSuccessfully connected to new tenant!" -ForegroundColor Green
            Write-Host "Tenant: $script:CurrentTenantName" -ForegroundColor White
            Write-Host "User: $script:CurrentUserUPN" -ForegroundColor White
        }
    }
    catch {
        Write-Host "Failed to connect to new tenant: $_" -ForegroundColor Red
        Write-Host "You may need to reconnect manually." -ForegroundColor Yellow
    }
}
