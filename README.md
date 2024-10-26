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

  <a href="https://www.buymeacoffee.com/ugurkocde">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=ugurkocde&button_colour=FF5F5F&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" width="150" alt="Buy Me A Coffee"/>
  </a>
</div>

## 🚀 Quick Start

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

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

## 🛠️ Setup

1. Create an Entra ID App Registration
2. Grant and consent to required permissions
3. Configure the script:
```powershell
# Update these values in IntuneAssignmentChecker_v2.ps1
$appid = '<YourAppIdHere>'
$tenantid = '<YourTenantIdHere>'
$certThumbprint = '<YourCertificateThumbprintHere>'
```

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
