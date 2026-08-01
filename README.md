# 🔍 Intune Assignment Checker

<div align="center">
  <p>
    <a href="https://twitter.com/UgurKocDe">
      <img src="https://img.shields.io/badge/Follow-@UgurKocDe-1DA1F2?style=flat&logo=x&logoColor=white" alt="Twitter Follow"/>
    </a>
    <a href="https://www.linkedin.com/in/ugurkocde/">
      <img src="https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin" alt="LinkedIn"/>
    </a>
    <img src="https://img.shields.io/github/license/ugurkocde/IntuneAssignmentChecker?style=flat" alt="License"/>
  </p>
  <a href="https://www.powershellgallery.com/packages/IntuneAssignmentChecker">
      <img src="https://img.shields.io/powershellgallery/v/IntuneAssignmentChecker?style=flat&label=PSGallery%20Version" alt="PowerShell Gallery Version"/>
    </a>
    <a href="https://www.powershellgallery.com/packages/IntuneAssignmentChecker">
      <img src="https://img.shields.io/powershellgallery/dt/IntuneAssignmentChecker?style=flat&label=PSGallery%20Downloads&color=brightgreen" alt="PowerShell Gallery Downloads"/>
    </a>
</div>

![IntuneAssignmentChecker_Header](https://github.com/user-attachments/assets/47d2231d-569f-4d22-bef5-944a4a74f7da)

## 📑 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [✨ Features](#-features)
- [📋 Prerequisites](#-prerequisites)
- [🔐 Authentication Options](#-authentication-options)
- [📖 Usage](#-usage)
- [💬 Community](#-community)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## Quick Start

> **Important**: All commands must be run in a PowerShell 7 session. The module will not work in PowerShell 5.1 or earlier versions.

### Option 1: Install from PowerShell Gallery (Recommended)

```powershell
# Install from PowerShell Gallery
Install-Module IntuneAssignmentChecker -Scope CurrentUser

# Launch the interactive menu
IntuneAssignmentChecker
```

The `IntuneAssignmentChecker` alias opens the menu-driven interface. Each feature is also available as a standalone cmdlet (see [Usage](#-usage)).

If you encounter any issues during installation, try reinstalling:

```powershell
Install-Module IntuneAssignmentChecker -Scope CurrentUser -Force
```

To update to the latest version:

```powershell
Update-Module IntuneAssignmentChecker
```

### Option 2: Manual Installation (from a local clone)

```powershell
# Install required Microsoft Graph SDK
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Import the module from your clone
Import-Module ./Module/IntuneAssignmentChecker -Force

# Launch the interactive menu
IntuneAssignmentChecker
```

> **Migrating from v3.x?** v3.x shipped as a single script installed via `Install-Script`. v4.x is a PowerShell module installed via `Install-Module`. If you previously used `Install-Script IntuneAssignmentChecker`, uninstall it first: `Uninstall-Script IntuneAssignmentChecker`.

## ✨ Features

- 🔍 Check assignments for users, groups, and devices
- 📱 View all 'All User' and 'All Device' assignments
- 🎯 See Intune assignment filters (name and Include/Exclude type) inline on every assignment, in the console, CSV exports, and HTML reports
- 🔐 Support for certificate-based and client secret authentication
- 🔄 Version check on connect with an update notice when a newer PSGallery release is available
- 📊 Detailed reporting of Configuration Profiles, Compliance Policies, and Applications
- 🧩 Imported Administrative Template coverage across assignment checks, search, CSV exports, and HTML reports
- 🔄 Windows Update for Business coverage for Feature Update, Quality Update, and Driver Update profiles plus Quality Update policies
- 👥 First-class Microsoft 365 group recognition with group type, membership mode, and mail address in group assignment checks and exports
- 📈 Interactive HTML reports with charts and filterable tables

## 🎥 Demo

<div align="center">
      <a href="https://www.youtube.com/watch?v=uHBIGfa8mIM">
     <img 
      src="https://img.youtube.com/vi/uHBIGfa8mIM/maxresdefault.jpg" 
      alt="IntuneAssignmentChecker" 
      style="width:100%;">
      </a>
</div>

## 📋 Prerequisites

### Required PowerShell Version

- **PowerShell 7.0 or higher is required**
  - The module will not work with PowerShell 5.1 or earlier versions
  - You can check your PowerShell version by running: `$PSVersionTable.PSVersion`
  - Download PowerShell 7 from: https://aka.ms/powershell-release?tag=stable

### Required PowerShell Modules

- Microsoft Graph PowerShell SDK
  - Specifically Microsoft.Graph.Authentication

### Required Permissions

Your Entra ID application registration needs these permissions:

| Permission | Type | Description |
|------------|------|-------------|
| User.Read.All | Application | Read all users' full profiles |
| GroupMember.Read.All | Application | Read group memberships and basic group properties |
| Device.Read.All | Application | Read all devices |
| DeviceManagementApps.Read.All | Application | Read Microsoft Intune apps |
| DeviceManagementConfiguration.Read.All | Application | Read Microsoft Intune device configuration and policies |
| DeviceManagementManagedDevices.Read.All | Application | Read Microsoft Intune devices |
| DeviceManagementScripts.Read.All | Application | Read device management and health scripts |
| CloudPC.Read.All | Application | Read Windows 365 Cloud PC provisioning policies and settings |
| DeviceManagementRBAC.Read.All | Application | Read role scope tags for scope tag display and filtering |

For interactive authentication, IntuneAssignmentChecker automatically requests the delegated versions of these permissions during sign-in. Administrator consent is still required.

For certificate, client secret, managed identity, or pre-fetched token authentication, configure the listed application permissions on the app registration and grant administrator consent. App-only authentication cannot add or consent permissions automatically.

`GroupMember.Read.All` provides the basic group properties and membership data used by IntuneAssignmentChecker without granting access to Microsoft 365 group conversations, files, calendars, or other group content.

> **Existing app registrations**: Add `GroupMember.Read.All` and grant administrator consent before removing `Group.Read.All`. After confirming the updated module works, remove `Group.Read.All` from the configured API permissions and revoke its application consent. Updating the app registration manifest alone might not remove an existing service principal consent grant.

> **Hidden memberships**: Reading groups with hidden membership requires the additional `Member.Read.Hidden` application permission. IntuneAssignmentChecker does not request this permission by default.

> **Note**: The automated setup script ([`Register-IntuneAssignmentCheckerApp.ps1`](./Register-IntuneAssignmentCheckerApp.ps1)) additionally grants `DeviceManagementServiceConfig.Read.All`, which covers Intune service configuration such as enrollment settings. It is not validated by `Connect-IntuneAssignmentChecker`, but granting it avoids gaps when reading enrollment-related configurations.

### Microsoft Graph API behavior

IntuneAssignmentChecker uses the Microsoft Graph `/beta` endpoint in every supported cloud. Starting with v4.4, all Graph traffic is routed through one internal transport that follows collection paging automatically, honors throttling responses, retries transient service and network failures, and preserves Graph request identifiers in structured errors for troubleshooting. The beta endpoint can change more frequently than a generally available endpoint, so validate a new module version in a test tenant before broad automation rollout.

## 🔐 Authentication Options

### Option 1: Certificate-Based Authentication (Recommended for automation)

Follow these steps if you want to use certificate authentication with an app registration:

1. Create an Entra ID App Registration:

   - Navigate to Azure Portal > Entra ID > App Registrations
   - Click "New Registration"
   - Name your application (e.g., "IntuneAssignmentChecker")
   - Select "Accounts in this organizational directory only"
   - Click "Register"

2. Grant required Application permissions:

   - In your app registration, go to "API Permissions"
   - Click "Add a permission" > "Microsoft Graph"
   - Select "Application permissions"
   - Add all required permissions listed in Prerequisites
   - Click "Grant admin consent"

3. Create and configure certificate authentication:

   ```powershell
   # Create self-signed certificate
   New-SelfSignedCertificate `
       -Subject "CN=IntuneAssignmentChecker" `
       -CertStoreLocation "cert:\CurrentUser\My" `
       -NotAfter (Get-Date).AddYears(2) `
       -KeySpec Signature `
       -KeyExportPolicy Exportable

   # Export the certificate
   $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*IntuneAssignmentChecker*"}
   Export-Certificate -Cert $cert -FilePath "C:\temp\IntuneAssignmentChecker.cer"
   ```

4. Upload certificate to your app registration:

   - In Azure Portal, go to your app registration
   - Click "Certificates & secrets"
   - Select "Certificates"
   - Click "Upload certificate"
   - Upload the .cer file you exported (C:\temp\IntuneAssignmentChecker.cer)

5. Connect using certificate authentication:
   ```powershell
   Connect-IntuneAssignmentChecker `
       -AppId '<YourAppIdHere>' `
       -TenantId '<YourTenantIdHere>' `
       -CertificateThumbprint '<YourThumbprint>'

   # Then run any cmdlet, or launch the menu
   IntuneAssignmentChecker
   ```

### Option 2: Client Secret Authentication

If you prefer a simpler setup than certificates but still need non-interactive authentication, you can use a client secret:

1. Create an Entra ID App Registration (same steps as Option 1, steps 1-2)

2. Create a client secret:

   - In Azure Portal, go to your app registration
   - Click "Certificates & secrets"
   - Select "Client secrets"
   - Click "New client secret"
   - Add a description and select an expiry period
   - Click "Add"
   - **Copy the secret value immediately** -- it will not be shown again

3. Connect using the client secret. The preferred way is `-ClientSecretCredential`, a PSCredential whose username is the App ID and whose password is the client secret, so the secret never appears as plain text:

   ```powershell
   $credential = Get-Credential -UserName 'your-app-id' -Message 'Enter the client secret as the password'
   Connect-IntuneAssignmentChecker `
       -TenantId 'your-tenant-id' `
       -ClientSecretCredential $credential
   ```

   Alternatively, the plain-text `-ClientSecret` parameter is retained for compatibility:

   ```powershell
   Connect-IntuneAssignmentChecker `
       -AppId 'your-app-id' `
       -TenantId 'your-tenant-id' `
       -ClientSecret 'your-client-secret'
   ```

> **Security Note**: Never hard-code client secrets in scripts or commit them to source control. Use secure methods such as Azure Key Vault, environment variables, or secure parameter input to manage secrets.

### Option 3: Interactive Authentication (Simpler setup)

If you prefer not to set up an app registration, you can use interactive authentication:

```powershell
# Opens a browser sign-in prompt using delegated permissions
Connect-IntuneAssignmentChecker

# Use your own public-client application ID for delegated sign-in
Connect-IntuneAssignmentChecker -AppId '<application-client-id>'

# Optionally constrain that delegated sign-in to a specific tenant
Connect-IntuneAssignmentChecker -AppId '<application-client-id>' -TenantId '<tenant-id>'

# Or just launch the menu and pick interactive auth when prompted
IntuneAssignmentChecker
```

You'll be asked for the Intune environment (Global, USGov, or USGovDoD). The permissions will be based on your user account's roles in Entra ID.

### Option 4: Pre-fetched Access Token (Managed Identity, Azure Functions, parent scripts)

If you already have a Microsoft Graph access token, for example from a managed identity in Azure Automation or Azure Functions, or from a parent script that handles authentication, you can pass it directly as a SecureString:

```powershell
# Acquire a token (here via Az.Accounts) and pass it as a SecureString
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token |
    ConvertTo-SecureString -AsPlainText -Force
Connect-IntuneAssignmentChecker -AccessToken $token
```

The token's permissions come from however it was issued (for example the managed identity's app role assignments), so make sure the identity has the required permissions listed in Prerequisites.

### Which Option Should I Choose?

- **Choose Certificate Authentication if you**:

  - Need to run the script unattended
  - Want the most secure non-interactive option
  - Need consistent permissions regardless of user
  - Are comfortable with certificate management

- **Choose Client Secret Authentication if you**:

  - Need to run the script unattended
  - Want a simpler setup than certificates
  - Are able to securely manage secret rotation before expiry
  - Prefer not to deal with certificate creation and installation

- **Choose Interactive Authentication if you**:

  - Want the simplest setup
  - Don't need automation
  - Are comfortable using your user credentials
  - Only need to run the script occasionally

- **Choose a Pre-fetched Access Token if you**:
  - Run in Azure Automation, Azure Functions, or another host with a managed identity
  - Already handle Microsoft Graph authentication in a parent script
  - Want to reuse an existing token instead of creating a new connection

> **Note**: Keep your certificate and app credentials secure! Anyone with access to these can access your Intune environment with the configured permissions.

## 📋 Prerequisites (Automated Setup Available)

> **Good news!** You can automate most prerequisites using the provided helper script.

### ✅ Automated Setup

You can use the provided PowerShell automation script [`Register-IntuneAssignmentCheckerApp.ps1`](./Register-IntuneAssignmentCheckerApp.ps1) to automatically:

- Create the Entra ID App Registration
- Assign all required Microsoft Graph permissions
- Generate a self-signed certificate
- Upload the certificate to the app registration
- Export the certificate for use with the script

#### Run the automation script:

```powershell
# Download the script from the repository
# Make sure to run with sufficient permissions (Global Admin)

.\Register-IntuneAssignmentCheckerApp.ps1
```
> **Note**: After the script completes, you still need to grant Admin Consent for the assigned API permissions in the Azure Portal:
Entra ID → App registrations → Your App → API permissions → "Grant admin consent for ...".

## 📖 Usage

The module can be used in two ways:

1. **Interactive Mode**: Menu-driven interface for manual exploration (`IntuneAssignmentChecker`)
2. **Cmdlet Mode**: Individual cmdlets for automation and scripting

### 🖥️ Cmdlet Reference

Connect once, then call any cmdlet:

```powershell
# Sign in (interactive, certificate, or client secret)
Connect-IntuneAssignmentChecker -AppId '<id>' -TenantId '<id>' -CertificateThumbprint '<thumbprint>'

# Check assignments for a specific user and export to CSV
Get-IntuneUserAssignment -UserPrincipalNames "user@contoso.com" -ExportToCSV -ExportPath "C:\Temp\UserAssignments.csv"

# Check assignments for multiple users
Get-IntuneUserAssignment -UserPrincipalNames "user1@contoso.com,user2@contoso.com"

# Check assignments for a specific group
Get-IntuneGroupAssignment -GroupNames "Marketing Team"

# Microsoft 365 (Unified) groups are resolved by name or Object ID like any other group
Get-IntuneGroupAssignment -GroupNames "Messaging Team" -ExportToCSV -ExportPath "C:\Temp\MessagingTeamAssignments.csv"

# Check assignments for a specific device
Get-IntuneDeviceAssignment -DeviceNames "Laptop123"

# Show all policies with 'All Users' assignments
Get-IntuneAllUsersAssignment -ExportToCSV

# Generate HTML report and a companion CSV at the same base path
New-IntuneHTMLReport -HTMLReportPath "C:\Temp\IntuneAssignmentReport.html"

# Store the CSV companion in a separate central location
New-IntuneHTMLReport -HTMLReportPath "C:\Temp\IntuneAssignmentReport.html" -CSVReportPath "C:\CentralReports\IntuneAssignments.csv"

# Preserve the previous HTML-only behavior when no CSV is wanted
New-IntuneHTMLReport -HTMLReportPath "C:\Temp\IntuneAssignmentReport.html" -NoCSVReport

# Simulate what policies a user would receive if added to a group
Test-IntuneGroupMembership -UserPrincipalNames "user@contoso.com" -SimulateTargetGroup "Marketing Team"

# Simulate what policies a device would receive if added to a group (user and device can be combined)
Test-IntuneGroupMembership -DeviceNames "Laptop123" -SimulateTargetGroup "Marketing Team"

# Simulate what policies a user would lose if removed from a group
Test-IntuneGroupRemoval -UserPrincipalNames "user@contoso.com" -SimulateRemoveTargetGroup "Marketing Team"

# Simulate what policies a device would lose if removed from a group
Test-IntuneGroupRemoval -DeviceNames "Laptop123" -SimulateRemoveTargetGroup "Marketing Team"

# Reverse lookup: find all assignment targets for a policy name
Search-IntunePolicy -PolicySearchTerm "BitLocker"

# Search configured settings across policies (Settings Catalog + Endpoint Security)
Search-IntuneSetting -SearchTerm "BitLocker"

# Return automation-friendly objects while retaining the normal console experience
$records = Get-IntuneAllPolicies -PassThru
$records | Where-Object AssignmentMode -eq 'Exclude'
```

`Get-IntuneUserAssignment`, `Get-IntuneGroupAssignment`,
`Get-IntuneDeviceAssignment`, `Get-IntuneAllPolicies`,
`Get-IntuneAllUsersAssignment`, `Get-IntuneAllDevicesAssignment`,
`Get-IntuneUnassignedPolicy`, and `Search-IntunePolicy` support `-PassThru`.
Using it also suppresses the interactive CSV-export prompt. Each object has the type name
`IntuneAssignmentChecker.AssignmentRecord` and schema version `1`. The stable
contract includes tenant and subject metadata, policy/category/platform, scope
tags, assignment target and include/exclude mode, application intent, assignment
filter metadata, the display reason, and source command. Console messages remain
on the information stream, so they do not contaminate pipeline object output.
Additive fields may be introduced without changing `SchemaVersion`; removing or
renaming a field, changing its meaning, or changing an enum value requires a schema
version increment. The existing CSV and HTML schemas remain backward-compatible;
shared-scan cmdlets create canonical records from the same structured Graph data
used for their console and CSV views, while the HTML report keeps its purpose-built
flat reporting schema. Treat `CategoryId` as the stable machine key; `Category` is
a presentation label and can vary where a cmdlet distinguishes app intents or uses
search-specific wording. `Get-IntuneUserDeviceAssignment` keeps its established
combined user/device presentation; the v4.4 effective-targeting cmdlet introduced
in issue #140 adds a canonical explanation model for those results.

`Get-IntuneGroupAssignment` CSV/Excel exports include `GroupId`, `GroupName`,
`GroupType`, `MembershipType`, and `GroupMail` on every group and policy/app
row. This keeps multi-group exports attributable and lets workbooks distinguish
Microsoft 365 groups from security, mail-enabled security, and distribution
groups without parsing display names.

HTML reports include a flat CSV companion by default. The CSV uses a stable
`Category`, `Name`, `ID`, `Type`, `Platform`, `ScopeTags`, `AssignmentType`,
`AssignedTo`, and `Filter` schema for Azure Log Analytics, workbooks, and other
automation. `-CSVReportPath` accepts either a `.csv` file or a directory; when a
directory is supplied, the HTML report's base name is reused. Missing values are
exported as empty fields, while the absence of an assignment filter is represented
consistently as `None`. Values beginning with spreadsheet formula prefixes are
escaped with a leading apostrophe. Use `-NoCSVReport` for HTML-only output.

Available cmdlets:

| Cmdlet                             | Description                                                           |
| ---------------------------------- | --------------------------------------------------------------------- |
| `Connect-IntuneAssignmentChecker`  | Sign in (interactive, certificate, or client secret)                  |
| `Get-IntuneUserAssignment`         | Check assignments for specific users                                  |
| `Get-IntuneGroupAssignment`        | Check assignments for specific groups                                 |
| `Get-IntuneDeviceAssignment`       | Check assignments for specific devices                                |
| `Get-IntuneAllPolicies`            | Show all policies and their assignments                               |
| `Get-IntuneAllUsersAssignment`     | Show all 'All Users' assignments                                      |
| `Get-IntuneAllDevicesAssignment`   | Show all 'All Devices' assignments                                    |
| `New-IntuneHTMLReport`             | Generate interactive HTML and flat CSV companion reports              |
| `Get-IntuneUnassignedPolicy`       | Show policies without assignments                                     |
| `Get-IntuneEmptyGroup`             | Check for empty groups used in assignments                            |
| `Get-IntuneFailedAssignment`       | Show all failed policy assignments                                    |
| `Compare-IntuneGroupAssignment`    | Compare assignments between two or more groups                        |
| `Test-IntuneGroupMembership`       | Simulate adding a user and/or device to a group and show resulting policies |
| `Test-IntuneGroupRemoval`          | Simulate removing a user and/or device from a group and show lost policies |
| `Search-IntunePolicy`              | Reverse lookup: find all assignment targets for a policy name         |
| `Search-IntuneSetting`             | Search configured settings across all policies                        |
| `Update-IntuneSettingDefinition`   | Refresh the local Settings Catalog definition cache                   |
| `Invoke-IntuneAssignmentChecker`   | Launch the interactive menu (aliased as `IntuneAssignmentChecker`)    |

Common parameters on assignment cmdlets:

| Parameter                | Description                                                |
| ------------------------ | ---------------------------------------------------------- |
| `-ExportToCSV`           | Export results to CSV                                      |
| `-ExportPath`            | Path to export the CSV file                                |
| `-ScopeTagFilter`        | Filter results by scope tag name                           |
| `-PassThru`              | Return `IntuneAssignmentChecker.AssignmentRecord` objects  |

Common parameters on `Connect-IntuneAssignmentChecker`:

| Parameter                | Description                                                |
| ------------------------ | ---------------------------------------------------------- |
| `-AppId`                 | Application ID for authentication                          |
| `-TenantId`              | Tenant ID for authentication                               |
| `-CertificateThumbprint` | Certificate Thumbprint for authentication                  |
| `-ClientSecret`          | Client Secret for authentication (plain text; retained for compatibility, prefer `-ClientSecretCredential`) |
| `-ClientSecretCredential`| PSCredential with the App ID as username and the client secret as password (preferred over `-ClientSecret`) |
| `-AccessToken`           | Pre-fetched Microsoft Graph access token (SecureString), for managed identities or token reuse |
| `-Environment`           | Environment (Global, USGov, USGovDoD) - defaults to Global |

### 📋 Interactive Menu Options

Running `IntuneAssignmentChecker` opens a menu-driven interface with the following options:

### 🎯 Assignment Checks

1. **Check User(s) Assignments**

   - View all policies and apps assigned to specific users
   - Supports checking multiple users (comma-separated)
   - Shows direct and group-based assignments

2. **Check Group(s) Assignments**

   - View all policies and apps assigned to specific groups
   - Supports checking multiple groups
   - Shows assignment types (Include/Exclude)
   - Recognizes Microsoft 365, security, mail-enabled security, and distribution groups
   - Shows group type, assigned/dynamic membership, and mail address in the console and CSV export
   - Covers Intune policy and app assignments only; Exchange, Teams, SharePoint, and other Microsoft 365 service policies/content are outside this module's scope

3. **Check Device(s) Assignments**
   - View all policies and apps assigned to specific devices
   - Supports checking multiple devices
   - Shows inherited assignments from device groups

### 📋 Policy Overview

4. **Show All Policies and Their Assignments**

   - Comprehensive view of all Intune policies
   - Grouped by policy type and platform
   - Includes assignment details

5. **Show All 'All Users' Assignments**

   - Lists policies assigned to all users
   - Includes apps and configurations
   - Helps identify broad-scope policies

6. **Show All 'All Devices' Assignments**
   - Lists policies assigned to all devices
   - Shows platform-specific assignments
   - Identifies universal device policies

### ⚙️ Advanced Options

7. **Generate HTML Report**

   - Creates interactive HTML report
   - Includes charts and graphs
   - Filterable tables with search functionality
   - Dark/Light mode toggle
   - Export capabilities to Excel/CSV

8. **Show Policies Without Assignments**

   - Identifies unassigned policies
   - Grouped by policy type
   - Helps clean up unused policies

9. **Check for Empty Groups in Assignments**
   - Finds assignments to empty groups
   - Helps identify ineffective policies
   - Supports CSV export of findings

10. **Compare Assignments Between Groups**

    - Compare policy and app assignments between two or more groups
    - Highlights differences and overlaps
    - Useful for auditing group consistency

11. **Show All Failed Assignments**

    - Displays all failed policy deployment assignments
    - Helps identify configuration issues
    - Supports CSV export of findings

12. **Simulate Group Membership Impact (User and/or Device)**

    - Preview what policies and apps a user and/or device would receive if added to a group
    - Shows deltas vs. the current assignments
    - Useful for validating planned group changes before applying them

13. **Simulate Removing from Group (User and/or Device)**

    - Preview what policies and apps a user and/or device would lose if removed from a group
    - Helps evaluate the impact of offboarding or group cleanup

14. **Search Policy Assignments**

    - Reverse lookup: search by policy name and see every assignment target
    - Works across Configuration Profiles, Compliance, Apps, and Endpoint Security

15. **Search for Specific Settings**

    - Search 17,000+ setting definitions across Settings Catalog and Endpoint Security policies
    - Shows which policies configure a given setting and the configured value
    - Supports abbreviation expansion and fuzzy matching

### 🛠️ System Options

- **[T] Switch Tenant**: Disconnect and connect to a different tenant without restarting
- **[0] Exit**: Safely disconnect and close
- **[98] Support the Project / [99] Report a Bug**: Opens the matching GitHub page

All operations support CSV export for detailed analysis and reporting.

## 🏃‍♂️ Example Runbook

The module can also be executed from an Azure Automation runbook. Below is a
minimal example that installs the module from the PowerShell Gallery (if it is
not already present) and then generates an HTML report using certificate-based
or client secret authentication.

```powershell
param(
    [string]$AppId,
    [string]$TenantId,
    [string]$CertificateThumbprint,
    [string]$ClientSecret,
    [string]$HTMLReportPath = "C:\Temp\IntuneAssignmentReport.html"
)

# Ensure IntuneAssignmentChecker is available
if (-not (Get-Module -ListAvailable -Name IntuneAssignmentChecker)) {
    Install-Module IntuneAssignmentChecker -Scope CurrentUser -Force
}
Import-Module IntuneAssignmentChecker

# Build auth params
$authParams = @{
    AppId    = $AppId
    TenantId = $TenantId
}

if ($CertificateThumbprint) {
    $authParams['CertificateThumbprint'] = $CertificateThumbprint
}
elseif ($ClientSecret) {
    $authParams['ClientSecret'] = $ClientSecret
}

# Connect, then generate the report
Connect-IntuneAssignmentChecker @authParams
New-IntuneHTMLReport -HTMLReportPath $HTMLReportPath
```

This runbook supports both certificate and client secret authentication. You can
extend it to upload the report to storage or send it via email once the file is
generated.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
