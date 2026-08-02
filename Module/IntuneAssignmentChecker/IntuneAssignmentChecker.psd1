@{
    RootModule        = 'IntuneAssignmentChecker.psm1'
    ModuleVersion     = '5.0.0'
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
        'Switch-IntuneAssignmentCheckerTenant'
        'Get-IntuneUserAssignment'
        'Get-IntuneGroupAssignment'
        'Get-IntuneDeviceAssignment'
        'Get-IntuneUserDeviceAssignment'
        'Get-IntuneEffectiveAssignment'
        'Export-IntuneAssignmentSnapshot'
        'Compare-IntuneAssignmentSnapshot'
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
        'Test-IntuneAssignmentFilter'
        'Search-IntunePolicy'
        'Search-IntuneSetting'
        'Update-IntuneSettingDefinition'
        'Get-IntuneAssignmentOperation'
        'Start-IntuneAssignmentCheckerTui'
        'Test-IntuneAssignmentCheckerEnvironment'
        'Test-IntuneAssignmentGovernance'
        'Test-IntuneAssignmentChange'
        'Get-IntuneAssignmentDrift'
        'Invoke-IntuneAssignmentFleetScan'
        'Test-IntuneAssignmentFilterSet'
        'Get-IntuneAssignmentAccess'
        'Get-IntuneAssignmentHealth'
        'ConvertTo-IntuneAssignmentRecord'
        'Invoke-IntuneAssignmentScan'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @('IntuneAssignmentChecker')
    FormatsToProcess   = @('IntuneAssignmentChecker.Format.ps1xml')
    FileList           = @(
        'Data/SettingDefinitions.json'
        'Data/GovernanceRules.json'
        'Schemas/assignment-record.v2.schema.json'
        'Schemas/assignment-snapshot.v2.schema.json'
        'Schemas/governance-finding.v1.schema.json'
        'Schemas/drift-event.v1.schema.json'
        'Schemas/README.md'
        'html-export.ps1'
    )
    PrivateData = @{
        PSData = @{
            Tags         = @('Intune', 'MEM', 'Endpoint', 'Assignment', 'Policy', 'Settings', 'Audit', 'Microsoft', 'Graph')
            LicenseUri   = 'https://github.com/ugurkocde/IntuneAssignmentChecker/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/ugurkocde/IntuneAssignmentChecker'
            IconUri      = ''
            ReleaseNotes = @'
Version 5.0.0:
- Add a mouse- and keyboard-enabled PowerShell terminal command center with native workspaces for every exported module capability.
- Add a non-executable Windows command launcher that hands PowerShell 5.1 and Command Prompt users off to the same module in PowerShell 7.
- Add structured -PassThru results to the remaining legacy assignment, simulation, failure, comparison, empty-group, and setting-search commands.
- Add assignment governance, change simulation, drift attribution, fleet orchestration, delivery health, RBAC analysis, filter-set governance, capability-based authentication, and environment diagnostics.
- Add schema-governed structured output, MSI packaging, and WinGet release automation without converting the module to an executable.

Version 4.4.0:
- Centralize every Microsoft Graph call behind a beta-only transport with automatic paging, bounded retry/backoff, nextLink validation, and structured error metadata (issue #136).
- Add schema-versioned IntuneAssignmentChecker.AssignmentRecord objects and non-interactive -PassThru output to the primary assignment and policy-search cmdlets (issue #137).
- Cover Windows Feature Update, Quality Update, Driver Update, and Quality Update policy assignments across shared scans, searches, comparisons, exports, and reports (issue #138).
- Add Test-IntuneAssignmentFilter for safe, local tri-state evaluation of documented managed-device filter rules without executing tenant-provided text (issue #139).
- Add Get-IntuneEffectiveAssignment with user/device targeting precedence, filter evaluation, machine-readable reason chains, PassThru, and CSV output (issue #140).
- Add deterministic, schema-versioned assignment snapshots and stable Added/Removed/Changed drift comparison (issue #141).
- Turn analyzer, cross-platform Pester, module-package, export-contract, and pre-publish validation into release gates; update GitHub Actions to supported runtimes (issue #142).

Version 4.3.2:
- Recognize Microsoft 365 (Unified) groups as first-class Intune assignment targets and expose group type, membership mode, and mail address in group checks and exports (issue #128).
- Restore Imported Administrative Template support across assignment views, simulations, search, CSV exports, and HTML reports; imported and mixed group policy configurations are included while built-in-only configurations remain excluded (issue #129).
- Allow delegated sign-in with an explicit application (client) ID, with or without a tenant ID, while preserving app-only certificate authentication (issue #130).
- Return every application scope tag by explicitly selecting roleScopeTagIds in Microsoft Graph mobile-app collection queries (issue #131).
- Generate a flat, formula-safe CSV companion alongside every HTML report, with -CSVReportPath for centralized ingestion/Azure Workbooks and -NoCSVReport for HTML-only automation (issue #132).
- Return assigned applications regardless of the unrelated isFeatured metadata flag so featured apps are no longer omitted from results (issue #134).

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
