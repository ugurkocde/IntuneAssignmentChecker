function Connect-IntuneAssignmentChecker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "App ID for authentication")]
        [string]$AppId,

        [Parameter(Mandatory = $false, HelpMessage = "Tenant ID for authentication")]
        [string]$TenantId,

        [Parameter(Mandatory = $false, HelpMessage = "Certificate Thumbprint for authentication")]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $false, HelpMessage = "Client Secret for authentication")]
        [string]$ClientSecret,

        [Parameter(Mandatory = $false, HelpMessage = "Environment (Global, USGov, USGovDoD)")]
        [ValidateSet("Global", "USGov", "USGovDoD")]
        [string]$Environment = "Global"
    )

    # ── Banner ────────────────────────────────────────────────────────────
    $localVersion = "4.1.0"

    Write-Host "INTUNE ASSIGNMENT CHECKER" -ForegroundColor Cyan
    Write-Host "Made by Ugur Koc" -NoNewline
    Write-Host " | Version" -NoNewline; Write-Host " $localVersion" -ForegroundColor Yellow -NoNewline
    Write-Host " | Last updated: " -NoNewline; Write-Host "2026-04-14" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Feedback & Issues: " -NoNewline -ForegroundColor Cyan
    Write-Host "https://github.com/ugurkocde/IntuneAssignmentChecker/issues" -ForegroundColor White
    Write-Host "Changelog: " -NoNewline -ForegroundColor Cyan
    Write-Host "https://github.com/ugurkocde/IntuneAssignmentChecker/releases" -ForegroundColor White
    Write-Host ""
    Write-Host "Support this Project: " -NoNewline -ForegroundColor Cyan
    Write-Host "https://github.com/sponsors/ugurkocde" -ForegroundColor White
    Write-Host ""
    Write-Host "DISCLAIMER: This script is provided AS IS without warranty of any kind." -ForegroundColor Yellow
    Write-Host ""

    # ── Version check via PSGallery ───────────────────────────────────────
    try {
        $galleryModule = Find-Module -Name 'IntuneAssignmentChecker' -Repository PSGallery -ErrorAction Stop
        $local  = [System.Version]::new($localVersion)
        $latest = [System.Version]::new($galleryModule.Version)

        if ($local -lt $latest) {
            Write-Host "A newer version is available on PSGallery: $($galleryModule.Version) (you are running $localVersion)" -ForegroundColor Yellow
            Write-Host "Run 'Update-Module IntuneAssignmentChecker' to upgrade." -ForegroundColor Yellow
            Write-Host ""
        }
        elseif ($local -gt $latest) {
            Write-Host "Note: You are running a pre-release version ($localVersion)" -ForegroundColor Magenta
            Write-Host ""
        }
    }
    catch {
        Write-Host "Unable to check for updates. Continue with current version..." -ForegroundColor Gray
    }

    # ── Determine if parameters provide app-based auth credentials ────────
    $hasAppId          = -not [string]::IsNullOrWhiteSpace($AppId)
    $hasTenantId       = -not [string]::IsNullOrWhiteSpace($TenantId)
    $hasClientSecret   = -not [string]::IsNullOrWhiteSpace($ClientSecret)
    $hasCertThumbprint = -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)
    $parameterMode     = $hasAppId -or $hasTenantId -or $hasClientSecret -or $hasCertThumbprint

    # ── Required permissions ──────────────────────────────────────────────
    $requiredPermissions = @(
        @{ Permission = "User.Read.All";                         Reason = "Required to read user profile information and check group memberships" }
        @{ Permission = "Group.Read.All";                        Reason = "Needed to read group information and memberships" }
        @{ Permission = "DeviceManagementConfiguration.Read.All"; Reason = "Allows reading Intune device configuration policies and their assignments" }
        @{ Permission = "DeviceManagementApps.Read.All";         Reason = "Necessary to read mobile app management policies and app configurations" }
        @{ Permission = "DeviceManagementManagedDevices.Read.All"; Reason = "Required to read managed device information and compliance policies" }
        @{ Permission = "Device.Read.All";                       Reason = "Needed to read device information from Entra ID" }
        @{ Permission = "DeviceManagementScripts.Read.All";      Reason = "Needed to read device management and health scripts" }
        @{ Permission = "CloudPC.Read.All";                      Reason = "Required to read Windows 365 Cloud PC provisioning policies and settings (optional if W365 not licensed)" }
        @{ Permission = "DeviceManagementRBAC.Read.All";         Reason = "Required to read role scope tags for scope tag display and filtering" }
    )

    # ── Connect to Microsoft Graph ────────────────────────────────────────
    try {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue

        if ($null -ne $graphContext) {
            Write-Host "Microsoft Graph is already connected, continuing to check permissions." -ForegroundColor Green
            # Set GraphEndpoint from existing connection environment
            $connectedEnv = $graphContext.Environment
            switch ($connectedEnv) {
                'USGov'    { $script:GraphEndpoint = "https://graph.microsoft.us"; $script:GraphEnvironment = "USGov" }
                'USGovDoD' { $script:GraphEndpoint = "https://dod-graph.microsoft.us"; $script:GraphEnvironment = "USGovDoD" }
                default    { $script:GraphEndpoint = "https://graph.microsoft.com"; $script:GraphEnvironment = "Global" }
            }
        }
        else {
            Write-Host "No existing Microsoft Graph connection found. Attempting connection..." -ForegroundColor Yellow

            if ($hasAppId -and $hasTenantId -and $hasClientSecret) {
                # Client Secret authentication
                Write-Host "Connecting using Client Secret authentication..." -ForegroundColor Yellow
                Set-Environment -EnvironmentName $Environment
                $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($AppId, $secureSecret)
                $null = Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -Environment $script:GraphEnvironment -NoWelcome -ErrorAction Stop
            }
            elseif ($hasAppId -and $hasTenantId -and $hasCertThumbprint) {
                # Certificate-based authentication
                Write-Host "Connecting using Certificate authentication..." -ForegroundColor Yellow
                Set-Environment -EnvironmentName $Environment
                $null = Connect-MgGraph -ClientId $AppId -TenantId $TenantId -Environment $script:GraphEnvironment -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            }
            else {
                # Interactive authentication fallback
                Write-Host "App ID, Tenant ID, or authentication credential (Certificate/Client Secret) is missing or not set correctly." -ForegroundColor Red
                $manualConnection = Read-Host "Would you like to attempt a manual interactive connection? (y/n)"
                if ($manualConnection -match '^[Yy]') {
                    Write-Host "Attempting manual interactive connection (you need privileges to consent permissions)..." -ForegroundColor Yellow
                    $permissionsList = ($requiredPermissions | ForEach-Object { $_.Permission }) -join ', '
                    if ($parameterMode) {
                        Set-Environment -EnvironmentName $Environment
                    }
                    else {
                        Set-Environment
                    }
                    $null = Connect-MgGraph -Scopes $permissionsList -Environment $script:GraphEnvironment -NoWelcome -ErrorAction Stop
                }
                else {
                    Write-Host "Connection cancelled by user." -ForegroundColor Red
                    return
                }
            }
            Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        }

        # ── Verify permissions ────────────────────────────────────────────
        $context = Get-MgContext
        $currentPermissions = $context.Scopes

        # Store tenant information
        if ($context) {
            $script:CurrentTenantId = $context.TenantId
            $script:CurrentUserUPN  = $context.Account

            try {
                $org = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/v1.0/organization" -ErrorAction SilentlyContinue
                if ($org.value -and $org.value.Count -gt 0) {
                    $script:CurrentTenantName = $org.value[0].displayName
                }
            }
            catch {
                $script:CurrentTenantName = $context.TenantId
            }
        }

        # For app-only auth, Scopes is null -- permissions come from the app registration
        if ($null -eq $currentPermissions -or $currentPermissions.Count -eq 0) {
            Write-Host "App-only authentication detected. Permissions are managed via the app registration." -ForegroundColor Yellow
            Write-Host "Ensure the required permissions are granted in the Azure Portal." -ForegroundColor Yellow
            Write-Host ""
        }
        else {
            Write-Host "Checking required permissions..." -ForegroundColor Cyan
            $missingPermissions = @()
            foreach ($permissionInfo in $requiredPermissions) {
                $permission = $permissionInfo.Permission
                $hasPermission = $currentPermissions -contains $permission -or $currentPermissions -contains $permission.Replace(".Read", ".ReadWrite")
                if (-not $hasPermission) {
                    $missingPermissions += $permission
                }
            }

            if ($missingPermissions.Count -eq 0) {
                Write-Host "All $($requiredPermissions.Count) required permissions verified." -ForegroundColor Green
                Write-Host ""
            }
            else {
                Write-Host "WARNING: The following permissions are missing:" -ForegroundColor Red
                $missingPermissions | ForEach-Object {
                    $missingPermission = $_
                    $reason = ($requiredPermissions | Where-Object { $_.Permission -eq $missingPermission }).Reason
                    Write-Host "  - $missingPermission" -ForegroundColor Yellow
                    Write-Host "    Reason: $reason" -ForegroundColor Gray
                }
                Write-Host "The script will continue, but it may not function correctly without these permissions." -ForegroundColor Red
                Write-Host "Please ensure these permissions are granted to the app registration for full functionality." -ForegroundColor Yellow

                $continueChoice = Read-Host "Do you want to continue anyway? (y/n)"
                if ($continueChoice -notmatch '^[Yy]') {
                    Write-Host "Connection cancelled by user." -ForegroundColor Red
                    return
                }
            }
        }
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph. Error: $_" -ForegroundColor Red

        if ($_.Exception.Message -like "*Certificate with thumbprint*was not found*") {
            Write-Host "The specified certificate was not found or has expired. Please check your certificate configuration." -ForegroundColor Yellow
        }

        if ($_.Exception.Message -like "*AADSTS7000215*" -or $_.Exception.Message -like "*Invalid client secret*") {
            Write-Host "The provided client secret is invalid or has expired. Please check your client secret configuration." -ForegroundColor Yellow
        }

        return
    }

    # ── Initialize scope tag lookup ───────────────────────────────────────
    $script:ScopeTagLookup = Get-ScopeTagLookup

    # ── Initialize assignment filter lookup ───────────────────────────────
    $script:AssignmentFilterLookup = Get-AssignmentFilterLookup
}
