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

> **Important**: All commands must be run in a PowerShell 7 session. The script will not work in PowerShell 5.1 or earlier versions.

### Option 1: Install from PowerShell Gallery (Recommended)

```powershell
# Install from PowerShell Gallery
Install-PSResource IntuneAssignmentChecker

# Open a new PowerShell 7 session to run the script with
IntuneAssignmentChecker
```

If you encounter any issues during installation, try reinstalling:

```powershell
Install-PSResource IntuneAssignmentChecker -Reinstall
```

To update to the latest version:

```powershell
Update-PSResource IntuneAssignmentChecker
```

### Option 2: Manual Installation

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Download and run the script
.\IntuneAssignmentChecker_v3.ps1
```

## ✨ Features

- 🔍 Check assignments for users, groups, and devices
- 📱 View all 'All User' and 'All Device' assignments
- 🔐 Support for certificate-based authentication
- 🔄 Built-in auto-update functionality
- 📊 Detailed reporting of Configuration Profiles, Compliance Policies, and Applications
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
  - The script will not work with PowerShell 5.1 or earlier versions
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
| Group.Read.All | Application | Read all groups |
| Device.Read.All | Application | Read all devices |
| DeviceManagementApps.Read.All | Application | Read Microsoft Intune apps |
| DeviceManagementConfiguration.Read.All | Application | Read Microsoft Intune device configuration and policies |
| DeviceManagementManagedDevices.Read.All | Application | Read Microsoft Intune devices |
| DeviceManagementServiceConfig.Read.All | Application | 	Read Microsoft Intune configuration |

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

5. Configure the script with your app details:
   ```powershell
   # Update these values in the script
   $appid = '<YourAppIdHere>'           # Application (Client) ID
   $tenantid = '<YourTenantIdHere>'     # Directory (Tenant) ID
   $certThumbprint = '<YourThumbprint>' # Certificate Thumbprint
   ```

### Option 2: Interactive Authentication (Simpler setup)

If you prefer not to set up an app registration, you can use interactive authentication:

You can just run the script without any changes. It will ask for the intune environment you wish to connect (Global, USGov, or USGovDoD) and if you want to use interactive authentication where you will type "y" and press enter.

This will prompt you to sign in with your credentials when running the script. The permissions will be based on your user account's roles and permissions in Entra ID.

### Which Option Should I Choose?

- **Choose Certificate Authentication if you**:

  - Need to run the script unattended
  - Want to automate the process
  - Need consistent permissions regardless of user
  - Are comfortable with more complex setup

- **Choose Interactive Authentication if you**:
  - Want a simpler setup
  - Don't need automation
  - Are comfortable using your user credentials
  - Only need to run the script occasionally

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

The script can be used in two ways:

1. **Interactive Mode**: Menu-driven interface for manual exploration
2. **Command-Line Mode**: Parameter-based execution for automation and scripting

### 🖥️ Command-Line Parameters

You can run the script with parameters to automate tasks without user interaction:

```powershell
# Check assignments for a specific user and export to CSV
.\IntuneAssignmentChecker_v3.ps1 -CheckUser -UserPrincipalNames "user@contoso.com" -ExportToCSV -ExportPath "C:\Temp\UserAssignments.csv"

# Check assignments for multiple users
.\IntuneAssignmentChecker_v3.ps1 -CheckUser -UserPrincipalNames "user1@contoso.com,user2@contoso.com"

# Check assignments for a specific group
.\IntuneAssignmentChecker_v3.ps1 -CheckGroup -GroupNames "Marketing Team"

# Check assignments for a specific device
.\IntuneAssignmentChecker_v3.ps1 -CheckDevice -DeviceNames "Laptop123"

# Show all policies with 'All Users' assignments
.\IntuneAssignmentChecker_v3.ps1 -ShowAllUsersAssignments -ExportToCSV

# Generate HTML report
.\IntuneAssignmentChecker_v3.ps1 -GenerateHTMLReport

# Specify environment (Global, USGov, USGovDoD)
.\IntuneAssignmentChecker_v3.ps1 -CheckUser -UserPrincipalNames "user@contoso.com" -Environment "USGov"

# Use with certificate authentication
.\IntuneAssignmentChecker_v3.ps1 -CheckUser -UserPrincipalNames "user@contoso.com" -AppId "your-app-id" -TenantId "your-tenant-id" -CertificateThumbprint "your-cert-thumbprint"
```

Available parameters:

| Parameter                         | Description                                                |
| --------------------------------- | ---------------------------------------------------------- |
| `-CheckUser`                      | Check assignments for specific users                       |
| `-UserPrincipalNames`             | User Principal Names to check (comma-separated)            |
| `-CheckGroup`                     | Check assignments for specific groups                      |
| `-GroupNames`                     | Group names or IDs to check (comma-separated)              |
| `-CheckDevice`                    | Check assignments for specific devices                     |
| `-DeviceNames`                    | Device names to check (comma-separated)                    |
| `-ShowAllPolicies`                | Show all policies and their assignments                    |
| `-ShowAllUsersAssignments`        | Show all 'All Users' assignments                           |
| `-ShowAllDevicesAssignments`      | Show all 'All Devices' assignments                         |
| `-GenerateHTMLReport`             | Generate HTML report                                       |
| `-ShowPoliciesWithoutAssignments` | Show policies without assignments                          |
| `-CheckEmptyGroups`               | Check for empty groups in assignments                      |
| `-ShowAdminTemplates`             | Show all Administrative Templates                          |
| `-CompareGroups`                  | Compare assignments between groups                         |
| `-CompareGroupNames`              | Groups to compare assignments between (comma-separated)    |
| `-ExportToCSV`                    | Export results to CSV                                      |
| `-ExportPath`                     | Path to export the CSV file                                |
| `-AppId`                          | Application ID for authentication                          |
| `-TenantId`                       | Tenant ID for authentication                               |
| `-CertificateThumbprint`          | Certificate Thumbprint for authentication                  |
| `-Environment`                    | Environment (Global, USGov, USGovDoD) - defaults to Global |

### 📋 Interactive Menu Options

The script provides a comprehensive menu-driven interface with the following options:

### 🎯 Assignment Checks

1. **Check User(s) Assignments**

   - View all policies and apps assigned to specific users
   - Supports checking multiple users (comma-separated)
   - Shows direct and group-based assignments

2. **Check Group(s) Assignments**

   - View all policies and apps assigned to specific groups
   - Supports checking multiple groups
   - Shows assignment types (Include/Exclude)

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

### 🛠️ System Options

- **Exit (0)**: Safely disconnect and close
- **Report Bug (99)**: Opens GitHub issues page

All operations support CSV export for detailed analysis and reporting.

## 🏃‍♂️ Example Runbook

The script can also be executed from an Azure Automation runbook. Below is a
minimal example that installs the script from the PowerShell Gallery (if it is
not already present) and then generates an HTML report using certificate based
authentication.

```powershell
param(
    [string]$AppId,
    [string]$TenantId,
    [string]$CertificateThumbprint,
    [string]$ExportPath = "C:\\Temp\\IntuneAssignmentReport.html"
)

# Ensure IntuneAssignmentChecker is available
if (-not (Get-Command IntuneAssignmentChecker -ErrorAction SilentlyContinue)) {
    Install-PSResource IntuneAssignmentChecker -Force -AcceptLicense
}

IntuneAssignmentChecker -GenerateHTMLReport `
    -AppId $AppId `
    -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint `
    -ExportPath $ExportPath
```

This runbook assumes certificate authentication as outlined earlier. You can
extend it to upload the report to storage or send it via email once the file is
generated.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
