@{
    RootModule        = 'IntuneAssignmentChecker.psm1'
    ModuleVersion     = '4.3.1'
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
        'Get-IntuneUserDeviceAssignment'
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
Version 4.3.1:
Security:
- Replace the broad Group.Read.All permission with GroupMember.Read.All for group lookup, membership, and transitive membership operations. This preserves IntuneAssignmentChecker behavior without granting access to Microsoft 365 group content.

Upgrade notes:
- Interactive connections automatically request GroupMember.Read.All on the next sign-in. Administrator consent is still required.
- Existing app-only registrations that use a certificate, client secret, managed identity, or pre-fetched token must add GroupMember.Read.All and grant administrator consent before Group.Read.All is removed and revoked.
- Updating requiredResourceAccess alone might not remove an existing service principal consent grant. Confirm that Group.Read.All is revoked after the updated module works.
- Member.Read.Hidden remains optional and is needed only when hidden-membership groups must be resolved.

Version 4.3.0:
- Show applications where the checked group is excluded in Get-IntuneGroupAssignment; Compare-IntuneGroupAssignment now marks excluded apps with [EXCLUDED] (issue #126).
- Rebuild the ten category-walk cmdlets on a shared scan engine: entity sets are fetched once per run (dozens fewer Graph calls), transient per-category failures no longer abort a run, and errors are raised on the error stream for automation (issue #123).
- Fix App Protection policies showing for every user regardless of group membership, app intent misclassification, broken multi-device input, junk rows in CSV exports, missing pagination past 100 items in group memberships / comparisons / assignment failures, and Get-IntuneEmptyGroup categories that were displayed but never checked.
- Security hardening: HTML-encode report values, escape OData group-name filters, URL-encode guest UPNs, add -ClientSecretCredential (PSCredential) as the preferred client secret input.
- Fix EDR policies missing from HTML reports due to a template mapping typo.
- Switch-Tenant now connects with the correct permission scopes and refreshes cached filter and group lookups.
- Register-IntuneAssignmentCheckerApp grants all documented permissions, uses a cross-platform temp path, and cleans up its temporary client secret on failure (issue #124).

Version 4.2.0:
- Add -AccessToken (SecureString) parameter for non-interactive authentication using a pre-fetched Microsoft Graph token (Azure Automation managed identities, Azure Functions, federated credentials, parent-script Connect-MgGraph sessions).
- Extend Test-IntuneGroupMembership and Test-IntuneGroupRemoval to accept a Device in addition to a User. The simulation now unions user-side and device-side group memberships.
- Add Option 16: What-If for a User on a specific Device. Lists every policy and app that would apply to that user/device pair, with a Source column indicating whether each assignment came from the user, the device, or both.

Version 4.1.0:
- Show Intune assignment filters on all assignments (issue #122). Filter name and include/exclude type now appear in console output, CSV exports, and HTML reports across all assignment, simulation, and search cmdlets.
- Add Get-AssignmentFilterLookup to cache filter metadata at connection time.

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
