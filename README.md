# Intune Assignment Checker

<div align="center">
    <a href="https://twitter.com/UgurKocDe" target="_blank">
    <img src="https://img.shields.io/badge/Follow on Twitter-black?style=for-the-badge&logo=x&logoColor=white" alt="Twitter Badge" />
  </a>
  <a href="https://www.linkedin.com/in/ugurkocde/" target="_blank">
    <img src="https://img.shields.io/badge/Connect on LinkedIn-blue?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn Badge"/>
  </a>

<a href="https://www.buymeacoffee.com/ugurkocde"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=ugurkocde&button_colour=FF5F5F&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" style="width: 150px; height: 40px;" />
</a>

</div>

</div>

---

<div align="center">

Sign up for my newsletter to receive immediate notifications whenever I launch a new tool, script or update.  
[Sign up to the Newsletter](https://newsletter.ugurkoc.de/)

</div>

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
- An Entra ID application registration with the following permissions granted:
  - `User.Read.All`
  - `Group.Read.All`
  - `Device.Read.All`
  - `DeviceManagementApps.Read.All`
  - `DeviceManagementConfiguration.Read.All`
  - `DeviceManagementManagedDevices.Read.All`

Ensure that you have granted admin consent for these permissions in the Azure portal.

## Setup

1. Clone this repository or download the `IntuneAssignmentChecker_v2.ps1` script.
2. Fill in your Entra ID application registration details (App ID, Tenant ID, and Secret) at the beginning of the script.

```powershell
# Fill in your App ID, Tenant ID, and Secret
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your EntraID
$certThumbprint = '<YourCertificateThumbprintHere>' # Thumbprint of the certificate associated with the App Registration
```

3. Run the script in PowerShell.

## Usage

To run the script, open PowerShell and navigate to the directory containing IntuneAssignmentChecker.ps1. Run the script using:

```powershell
.\IntuneAssignmentChecker_v2.ps1
```

Follow the on-screen instructions to select the type of entity you want to check the assignments for in Intune:

1. User(s)
2. Group(s)
3. Device(s)
4. Show all 'All User' Assignments
5. Show all 'All Device' Assignments
6. Search for Assignments by Setting Name
7. Report a Bug or Request a Feature
8. Exit

## Contributing

Contributions to are welcome! Please feel free to submit pull requests or open issues to improve the script or suggest new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
