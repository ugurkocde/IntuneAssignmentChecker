function Invoke-IntuneAssignmentChecker {
    [CmdletBinding()]
    param(
        # ── Authentication ────────────────────────────────────────────────
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
        [string]$Environment = "Global",

        # ── Feature switches ──────────────────────────────────────────────
        [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific users")]
        [switch]$CheckUser,

        [Parameter(Mandatory = $false, HelpMessage = "User Principal Names to check, comma-separated")]
        [string]$UserPrincipalNames,

        [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific groups")]
        [switch]$CheckGroup,

        [Parameter(Mandatory = $false, HelpMessage = "Group names or Object IDs to check, comma-separated")]
        [string]$GroupNames,

        [Parameter(Mandatory = $false, HelpMessage = "Check assignments for specific devices")]
        [switch]$CheckDevice,

        [Parameter(Mandatory = $false, HelpMessage = "Device names to check, comma-separated")]
        [string]$DeviceNames,

        [Parameter(Mandatory = $false, HelpMessage = "Show all policies and their assignments")]
        [switch]$ShowAllPolicies,

        [Parameter(Mandatory = $false, HelpMessage = "Show all 'All Users' assignments")]
        [switch]$ShowAllUsersAssignments,

        [Parameter(Mandatory = $false, HelpMessage = "Show all 'All Devices' assignments")]
        [switch]$ShowAllDevicesAssignments,

        [Parameter(Mandatory = $false, HelpMessage = "Generate HTML report")]
        [switch]$GenerateHTMLReport,

        [Parameter(Mandatory = $false, HelpMessage = "Path for the exported HTML report file")]
        [string]$HTMLReportPath,

        [Parameter(Mandatory = $false, HelpMessage = "Show policies and apps without assignments")]
        [switch]$ShowPoliciesWithoutAssignments,

        [Parameter(Mandatory = $false, HelpMessage = "Check for empty groups in assignments")]
        [switch]$CheckEmptyGroups,

        [Parameter(Mandatory = $false, HelpMessage = "Compare assignments between groups")]
        [switch]$CompareGroups,

        [Parameter(Mandatory = $false, HelpMessage = "Groups to compare assignments between, comma-separated")]
        [string]$CompareGroupNames,

        [Parameter(Mandatory = $false, HelpMessage = "Show all failed assignments")]
        [switch]$ShowFailedAssignments,

        [Parameter(Mandatory = $false, HelpMessage = "Simulate adding a user to a group and show new policy impact")]
        [switch]$SimulateGroupMembership,

        [Parameter(Mandatory = $false, HelpMessage = "Target group name or ID for group membership simulation")]
        [string]$SimulateTargetGroup,

        [Parameter(Mandatory = $false, HelpMessage = "Simulate removing a user from a group and show policies they would lose")]
        [switch]$SimulateRemoveFromGroup,

        [Parameter(Mandatory = $false, HelpMessage = "Target group name or ID for group removal simulation")]
        [string]$SimulateRemoveTargetGroup,

        [Parameter(Mandatory = $false, HelpMessage = "Search for policies by name and show assignment targets")]
        [switch]$SearchPolicy,

        [Parameter(Mandatory = $false, HelpMessage = "Policy name or partial name to search for")]
        [string]$PolicySearchTerm,

        [Parameter(Mandatory = $false, HelpMessage = "Search for a setting keyword across all Settings Catalog policies")]
        [switch]$SearchSetting,

        [Parameter(Mandatory = $false, HelpMessage = "Setting keyword to search for")]
        [string]$SettingKeyword,

        # ── Common output options ─────────────────────────────────────────
        [Parameter(Mandatory = $false, HelpMessage = "Export results to CSV")]
        [switch]$ExportToCSV,

        [Parameter(Mandatory = $false, HelpMessage = "Path for the exported CSV file")]
        [string]$ExportPath,

        [Parameter(Mandatory = $false, HelpMessage = "Include assignments inherited from parent groups")]
        [switch]$IncludeNestedGroups,

        [Parameter(Mandatory = $false, HelpMessage = "Filter results by scope tag name")]
        [string]$ScopeTagFilter
    )

    # ── Determine parameter mode ──────────────────────────────────────────
    $parameterMode  = $false
    $selectedOption = $null

    if ($CheckUser)                    { $parameterMode = $true; $selectedOption = '1' }
    elseif ($CheckGroup)               { $parameterMode = $true; $selectedOption = '2' }
    elseif ($CheckDevice)              { $parameterMode = $true; $selectedOption = '3' }
    elseif ($ShowAllPolicies)          { $parameterMode = $true; $selectedOption = '4' }
    elseif ($ShowAllUsersAssignments)  { $parameterMode = $true; $selectedOption = '5' }
    elseif ($ShowAllDevicesAssignments){ $parameterMode = $true; $selectedOption = '6' }
    elseif ($GenerateHTMLReport)       { $parameterMode = $true; $selectedOption = '7' }
    elseif ($ShowPoliciesWithoutAssignments) { $parameterMode = $true; $selectedOption = '8' }
    elseif ($CheckEmptyGroups)         { $parameterMode = $true; $selectedOption = '9' }
    elseif ($CompareGroups)            { $parameterMode = $true; $selectedOption = '10' }
    elseif ($ShowFailedAssignments)    { $parameterMode = $true; $selectedOption = '11' }
    elseif ($SimulateGroupMembership)  { $parameterMode = $true; $selectedOption = '12' }
    elseif ($SimulateRemoveFromGroup)  { $parameterMode = $true; $selectedOption = '13' }
    elseif ($SearchPolicy)             { $parameterMode = $true; $selectedOption = '14' }
    elseif ($SearchSetting)            { $parameterMode = $true; $selectedOption = '15' }

    # HTMLReportPath implies GenerateHTMLReport
    if (-not $parameterMode -and $HTMLReportPath) {
        $parameterMode  = $true
        $selectedOption = '7'
    }

    # ── Connect ───────────────────────────────────────────────────────────
    $connectParams = @{}
    if ($AppId)                 { $connectParams['AppId']                 = $AppId }
    if ($TenantId)              { $connectParams['TenantId']              = $TenantId }
    if ($CertificateThumbprint) { $connectParams['CertificateThumbprint'] = $CertificateThumbprint }
    if ($ClientSecret)          { $connectParams['ClientSecret']          = $ClientSecret }
    if ($Environment)           { $connectParams['Environment']           = $Environment }

    Connect-IntuneAssignmentChecker @connectParams

    # Abort if connection failed (no Graph context)
    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Host "Not connected to Microsoft Graph. Exiting." -ForegroundColor Red
        return
    }

    # ── Main loop ─────────────────────────────────────────────────────────
    do {
        if (-not $parameterMode) {
            Show-Menu
            $selection = Read-Host
        }
        else {
            $selection = $selectedOption
        }

        switch ($selection) {
            '1' {
                Get-IntuneUserAssignment `
                    -UserPrincipalNames $UserPrincipalNames `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '2' {
                Get-IntuneGroupAssignment `
                    -GroupNames $GroupNames `
                    -IncludeNestedGroups:$IncludeNestedGroups `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '3' {
                Get-IntuneDeviceAssignment `
                    -DeviceNames $DeviceNames `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '4' {
                Get-IntuneAllPolicies `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '5' {
                Get-IntuneAllUsersAssignment `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '6' {
                Get-IntuneAllDevicesAssignment `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '7' {
                New-IntuneHTMLReport `
                    -HTMLReportPath $HTMLReportPath
            }
            '8' {
                Get-IntuneUnassignedPolicy `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '9' {
                Get-IntuneEmptyGroup `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath
            }
            '10' {
                Compare-IntuneGroupAssignment `
                    -CompareGroupNames $CompareGroupNames `
                    -IncludeNestedGroups:$IncludeNestedGroups `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath
            }
            '11' {
                Get-IntuneFailedAssignment `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath
            }
            '12' {
                Test-IntuneGroupMembership `
                    -UserPrincipalNames $UserPrincipalNames `
                    -SimulateTargetGroup $SimulateTargetGroup `
                    -GroupNames $GroupNames `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '13' {
                Test-IntuneGroupRemoval `
                    -UserPrincipalNames $UserPrincipalNames `
                    -SimulateRemoveTargetGroup $SimulateRemoveTargetGroup `
                    -GroupNames $GroupNames `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath `
                    -ScopeTagFilter $ScopeTagFilter
            }
            '14' {
                Search-IntunePolicy `
                    -PolicySearchTerm $PolicySearchTerm `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath
            }
            '15' {
                Search-IntuneSetting `
                    -Keyword $SettingKeyword `
                    -ExportToCSV:$ExportToCSV `
                    -ExportPath $ExportPath
            }
            {$_ -eq 'T' -or $_ -eq 't'} {
                Switch-Tenant
            }
            '0' {
                Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Write-Host "Thank you for using IntuneAssignmentChecker!" -ForegroundColor Green
                Write-Host "If you found this tool helpful, please consider:" -ForegroundColor Cyan
                Write-Host "- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor White
                Write-Host "- Supporting the project: https://github.com/sponsors/ugurkocde" -ForegroundColor White
                Write-Host ""
                return
            }
            '98' {
                Write-Host "Opening GitHub Sponsor Page ..." -ForegroundColor Green
                Start-Process "https://github.com/sponsors/ugurkocde"
            }
            '99' {
                Write-Host "Opening GitHub Repository..." -ForegroundColor Green
                Start-Process "https://github.com/ugurkocde/IntuneAssignmentChecker"
            }
            default {
                Write-Host "Invalid choice, please select 1-15, T, 98, 99, or 0." -ForegroundColor Red
            }
        }

        # In parameter mode, exit after completing the task
        # In interactive mode, return to the menu unless exit was selected
        if ($selection -ne '0') {
            if ($parameterMode) {
                break
            }
            else {
                Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
                $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($selection -ne '0')
}
