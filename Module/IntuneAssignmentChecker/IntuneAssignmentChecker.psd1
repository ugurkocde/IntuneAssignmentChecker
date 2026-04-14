@{
    RootModule        = 'IntuneAssignmentChecker.psm1'
    ModuleVersion     = '4.0.0'
    GUID              = 'c6e25ec6-5787-45ef-95af-8abeb8a17daf'
    Author            = 'Ugur Koc'
    CompanyName       = 'Community'
    Copyright         = '(c) Ugur Koc. All rights reserved.'
    Description       = 'Analyze and audit Microsoft Intune policy assignments. Check user, group, and device assignments, simulate group membership changes, search policies and settings, generate HTML reports, and more.'
    PowerShellVersion = '7.0'
    RequiredModules   = @('Microsoft.Graph.Authentication')
    FunctionsToExport = @(
        'Invoke-IntuneAssignmentChecker'
        'Connect-IntuneAssignmentChecker'
        'Get-IntuneUserAssignment'
        'Get-IntuneGroupAssignment'
        'Get-IntuneDeviceAssignment'
        'Get-IntuneAllPolicies'
        'Get-IntuneAllUsersAssignment'
        'Get-IntuneAllDevicesAssignment'
        'New-IntuneHTMLReport'
        'Get-IntuneUnassignedPolicy'
        'Get-IntuneEmptyGroup'
        'Compare-IntuneGroupAssignment'
        'Get-IntuneFailedAssignment'
        'Test-IntuneGroupMembership'
        'Test-IntuneGroupRemoval'
        'Search-IntunePolicy'
        'Search-IntuneSetting'
        'Update-IntuneSettingDefinition'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @('IntuneAssignmentChecker')
    FileList           = @(
        'Data/SettingDefinitions.json'
        'html-export.ps1'
    )
    PrivateData = @{
        PSData = @{
            Tags         = @('Intune', 'MEM', 'Endpoint', 'Assignment', 'Policy', 'Settings', 'Audit', 'Microsoft', 'Graph')
            LicenseUri   = 'https://github.com/ugurkocde/IntuneAssignmentChecker/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/ugurkocde/IntuneAssignmentChecker'
            IconUri      = ''
            ReleaseNotes = @'
Version 4.0.0:
- BREAKING: Converted from script to PowerShell module (use Install-Module instead of Install-Script)
- Add Option 12: Simulate Group Membership Impact
- Add Option 13: Simulate Removing User from Group
- Add Option 14: Search Policy Assignments (reverse lookup)
- Add Option 15: Search for Specific Settings (across Settings Catalog and Endpoint Security)
- Add terminal-width-aware separators
- Add UPN format validation before network calls
- Normalize y/n prompts to accept Y/y/Yes/yes
- Fix app platform detection showing Windows apps (win32LobApp, winGetApp, microsoftStoreForBusinessApp, officeSuiteApp) as Multi-Platform in HTML report
- Remove deprecated groupPolicyConfigurations (Administrative Templates) policy type
- Migrate deviceStatuses API endpoints
- Fix hardcoded Graph URLs to use dynamic GraphEndpoint
- All features available as individual cmdlets (e.g., Get-IntuneUserAssignment, Search-IntuneSetting)
'@
        }
    }
}
