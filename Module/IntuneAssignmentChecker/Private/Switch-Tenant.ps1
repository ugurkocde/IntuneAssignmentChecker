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
        $null = Connect-MgGraph -Scopes $permissionsList -Environment $script:GraphEnvironment -NoWelcome -ErrorAction Stop

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

            # Refresh scope tag lookup for the new tenant
            $script:ScopeTagLookup = Get-ScopeTagLookup
        }
    }
    catch {
        Write-Host "Failed to connect to new tenant: $_" -ForegroundColor Red
        Write-Host "You may need to reconnect manually." -ForegroundColor Yellow
    }
}
