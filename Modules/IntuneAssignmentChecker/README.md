# IntuneAssignmentChecker Module

## Overview

The IntuneAssignmentChecker module provides a collection of functions to analyze and audit Microsoft Intune policy and application assignments. This module has been refactored from a monolithic script into a modular structure for better maintainability and reusability.

## Module Structure

```
Modules/IntuneAssignmentChecker/
├── IntuneAssignmentChecker.psd1     # Module manifest
├── IntuneAssignmentChecker.psm1     # Main module file
├── Private/                          # Private helper functions (not exported)
│   ├── Core.ps1                     # Core helper functions
│   ├── GraphAPI.ps1                 # Microsoft Graph API functions
│   └── Assignments.ps1              # Assignment processing functions
└── Public/                           # Public functions (exported)
    ├── Export.ps1                   # Data export functions
    └── UI.ps1                       # User interface functions
```

## Functions

### Public Functions (Exported)

#### UI Functions (Public/UI.ps1)
- **Show-Menu** - Displays the interactive menu with all available options
- **Switch-Tenant** - Switches between different Microsoft 365 tenants

#### Export Functions (Public/Export.ps1)
- **Show-SaveFileDialog** - Shows a file save dialog for export operations
- **Export-PolicyData** - Exports policy data to CSV or Excel format
- **Export-ResultsIfRequested** - Handles export prompts and operations

### Private Functions (Internal Use Only)

#### Core Functions (Private/Core.ps1)
- **Get-PolicyPlatform** - Determines the platform type of a policy
- **Get-GroupInfo** - Retrieves group information from Graph API
- **Get-DeviceInfo** - Retrieves device information from Graph API
- **Get-UserInfo** - Retrieves user information from Graph API
- **Get-GroupMemberships** - Gets transitive group memberships

#### Graph API Functions (Private/GraphAPI.ps1)
- **Set-Environment** - Configures the Graph API environment (Global, USGov, etc.)
- **Get-IntuneAssignments** - Retrieves assignment information for Intune entities
- **Get-IntuneEntities** - Generic function for fetching Intune entities

#### Assignment Functions (Private/Assignments.ps1)
- **Process-MultipleAssignments** - Processes multiple policy assignments
- **Get-AssignmentInfo** - Retrieves detailed assignment information
- **Get-AssignmentFailures** - Fetches assignment failure data

## Requirements

- PowerShell 7.0 or higher
- Microsoft.Graph.Authentication module (v1.0.0 or higher)

## Usage

### Import the Module

```powershell
Import-Module "./Modules/IntuneAssignmentChecker/IntuneAssignmentChecker.psd1"
```

### Using the Main Script

The main `IntuneAssignmentChecker.ps1` script automatically imports this module and provides an interactive menu for all operations:

```powershell
.\IntuneAssignmentChecker.ps1
```

### Using Module Functions Directly

You can also use the exported functions directly after importing the module:

```powershell
# Show the interactive menu
Show-Menu

# Switch to a different tenant
Switch-Tenant

# Export data
Export-PolicyData -ExportData $data -FilePath "C:\Export\policies.csv"
```

## Version History

### Version 3.4.5
- Refactored into modular structure
- Separated functions into Private and Public modules
- Improved maintainability and code organization
- Added comprehensive documentation

## Benefits of Modular Structure

1. **Maintainability** - Functions are organized by purpose and easier to locate
2. **Reusability** - Functions can be used independently in other scripts
3. **Testability** - Individual functions can be unit tested
4. **Readability** - Clear separation between public API and internal helpers
5. **Scalability** - New features can be added without bloating a single file

## License

See the main project LICENSE file for details.
