# 🔍Intune Assignment Checker

<div align="center">
  <a href="https://intuneassignmentchecker.ugurkoc.de/">
    <img src="path/to/logo.png" alt="Intune Assignment Checker Logo" width="200"/>
  </a>

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

  <h3>
    <a href="https://intuneassignmentchecker.ugurkoc.de/">Website</a>
    <span> · </span>
    <a href="#documentation">Documentation</a>
    <span> · </span>
    <a href="https://github.com/ugurkocde/IntuneAssignmentChecker/issues">Report Bug</a>
  </h3>
</div>

## 🚀 Quick Start

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

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
- PowerShell 5.1 or higher
- Microsoft Graph PowerShell SDK

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

Run the script and choose from these options:

1. 👤 Check User Assignments
2. 👥 Check Group Assignments
3. 💻 Check Device Assignments
4. 📱 View All User Assignments
5. 🖥️ View All Device Assignments
6. 🔍 Search by Setting Name
7. 🐛 Report Bug/Request Feature
8. ❌ Exit

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
