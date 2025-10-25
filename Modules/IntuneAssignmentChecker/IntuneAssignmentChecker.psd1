@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'IntuneAssignmentChecker.psm1'

    # Version number of this module.
    ModuleVersion = '3.4.5'

    # ID used to uniquely identify this module
    GUID = 'c6e25ec6-5787-45ef-95af-8abeb8a17daf'

    # Author of this module
    Author = 'ugurk'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) ugurk. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'This module enables IT administrators to efficiently analyze and audit Intune assignments. It checks assignments for specific users, groups, or devices, displays all policies and their assignments, identifies unassigned policies, detects empty groups in assignments, and searches for specific settings across policies.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = 'Microsoft.Graph.Authentication'
            ModuleVersion = '1.0.0'
        }
    )

    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-IntuneAssignmentCheck'
        'Connect-IntuneEnvironment'
        'Export-PolicyData'
        'Show-SaveFileDialog'
        'Switch-Tenant'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for categorization
            Tags = @('Intune', 'Microsoft365', 'GraphAPI', 'DeviceManagement', 'Compliance')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/ugurkocde/IntuneAssignmentChecker/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/ugurkocde/IntuneAssignmentChecker'

            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 3.4.5:
- Refactored into modular structure for better maintainability
- Added tenant switching capability
- Menu now displays current connected tenant name and logged-in user
- New menu option [12] to switch between tenants mid-session

Version 3.4.4:
- Fix Permission Error for Health Scripts

Version 3.4.3:
- Fixed critical assignment accuracy issues affecting group policy checks
- Resolved Settings Catalog policies not showing in group assignments
- Fixed Compare Groups to properly detect and display excluded assignments
- Improved assignment processing to handle ALL assignments
'@
        }
    }
}
