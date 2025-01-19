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
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## 🚀 Quick Start

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

You can just run the script without any changes. It will ask if you want to use interactive authentication where you will type "y" and press enter.

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

## 📖 Usage

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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
