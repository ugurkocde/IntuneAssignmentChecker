# 🔍Intune Assignment Checker

<div align="center">
  <p>
    <a href="https://twitter.com/UgurKocDe">
      <img src="https://img.shields.io/badge/Follow-@UgurKocDe-1DA1F2?style=flat&logo=x&logoColor=white" alt="Twitter Follow"/>
    </a>
    <a href="https://www.linkedin.com/in/ugurkocde/">
      <img src="https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin" alt="LinkedIn"/>
    </a>
    <a href="https://newsletter.ugurkoc.de/">
      <img src="https://img.shields.io/badge/Newsletter-Subscribe-FF6B6B?style=flat" alt="Newsletter"/>
    </a>
    <img src="https://img.shields.io/github/license/ugurkocde/IntuneAssignmentChecker?style=flat" alt="License"/>
  </p>
</div>

## 🚀 Quick Start

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
=======
---

# Overview

The `Intune Assignment Checker` script is here to simplify your life. It will provide a detailed overview of assigned Intune Configuration Profiles, Compliance Policies, and Applications for user, groups and devices.

Website: https://intuneassignmentchecker.ugurkoc.de/

## Demo

https://github.com/ugurkocde/IntuneAssignmentChecker/assets/43906965/3d0311f2-d537-4c31-9ef9-41c6500490a4

## Features

- Checks assignments for users, groups, and devices in Intune.
- Provides descriptions for each required permission.
- Shows all 'All User' and 'All Device' assignments.
- Supports certificate-based authentication.
- Includes an auto-update feature.

## Prerequisites

Before running this script, you need:

- PowerShell 5.1 or higher.
- Microsoft Graph PowerShell SDK installed. You can install it using `Install-Module Microsoft.Graph -Scope CurrentUser`.

## Authentication Options

The script supports two authentication methods:

### 1. Interactive Sign-in (Recommended for getting started)
- No additional setup required
- Uses your current user credentials
- Perfect for testing or occasional use

### 2. Certificate-based Authentication (Optional, for automated/production use)
If you plan to use the script in an automated way or need unattended access, you'll need:
- An Azure Application registration with the following permissions:
  - `User.Read.All`
  - `Group.Read.All`
  - `Device.Read.All`
  - `DeviceManagementApps.Read.All`
  - `DeviceManagementConfiguration.Read.All`
  - `DeviceManagementManagedDevices.Read.All`

## Setup

1. Clone this repository or download the `IntuneAssignmentChecker_v2.ps1` script.
2. (Optional) For certificate-based authentication, configure your app registration details:

```powershell
# Only required for certificate-based authentication
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your EntraID
$certThumbprint = '<YourCertificateThumbprintHere>' # Thumbprint of the certificate
```
# Download and run the script
.\IntuneAssignmentChecker_v2.ps1
```

## ✨ Features

- 🔍 Check assignments for users, groups, and devices
- 📱 View all 'All User' and 'All Device' assignments
- 🔐 Support for certificate-based authentication
- 🔄 Built-in auto-update functionality
- 📊 Detailed reporting of Configuration Profiles, Compliance Policies, and Applications

## 🎥 Demo

<div align="center">
  <video src="https://github.com/ugurkocde/IntuneAssignmentChecker/assets/43906965/3d0311f2-d537-4c31-9ef9-41c6500490a4" />
</div>

## 📋 Prerequisites

### Required PowerShell Modules
- PowerShell 7.0 or higher
- Microsoft Graph PowerShell SDK
  - Specifically Microsoft.Graph.Authentication

### Required Permissions
Your Entra ID application registration needs these permissions:
| Permission | Type | Description |
|------------|------|-------------|
| User.Read.All | Delegated | Read all users' full profiles |
| Group.Read.All | Delegated | Read all groups |
| Device.Read.All | Delegated | Read all devices |
| DeviceManagementApps.Read.All | Delegated | Read Microsoft Intune apps |
| DeviceManagementConfiguration.Read.All | Delegated | Read Microsoft Intune device configuration and policies |
| DeviceManagementManagedDevices.Read.All | Delegated | Read Microsoft Intune devices |

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
7. **Search for Assignments by Setting Name**
   - Search across all policy types
   - Find specific settings or configurations
   - Includes partial name matching

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
