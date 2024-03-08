# Intune Assignment Checker

<div align="center">
    <a href="https://twitter.com/UgurKocDe" target="_blank">
    <img src="https://img.shields.io/badge/Follow on Twitter-black?style=for-the-badge&logo=x&logoColor=white" alt="Twitter Badge" style="width: 200px; height: 40px;" />
  </a>
  <a href="https://www.linkedin.com/in/ugurkocde/" target="_blank">
    <img src="https://img.shields.io/badge/Connect on LinkedIn-blue?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn Badge" style="width: 200px; height: 40px;" />
  </a>

  <a href="https://www.buymeacoffee.com/ugurkocde">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=ugurkocde&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" style="width: 200px; height: 40px;" />
  </a>
</div>


</div>

# Overview

The `Intune Assignment Checker` script is here to simplify your life. It will provide a detailed overview of assigned Intune Configuration Profiles, Compliance Policies, and Applications for user, groups and devices.

Website: https://intuneassignmentchecker.ugurkoc.de/

## Demo

https://github.com/ugurkocde/IntuneAssignmentChecker/assets/43906965/3d0311f2-d537-4c31-9ef9-41c6500490a4

## Features

- Checks which users or devices are assigned to specific Intune policies.
- Verifies the app registration permissions against Microsoft Graph to ensure it can retrieve the necessary information.
- Provides descriptions for each permission to explain why it's necessary.

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

1. Clone this repository or download the `IntuneAssignmentChecker.ps1` script.
2. Fill in your Entra ID application registration details (App ID, Tenant ID, and Secret) at the beginning of the script.

```powershell
# Fill in your App ID, Tenant ID, and Secret
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your Azure AD
$secret = '<YourSecretHere>' # Secret of the App Registration
```

3. Run the script in PowerShell.

## Usage

To run the script, open PowerShell and navigate to the directory containing IntuneAssignmentChecker.ps1. Run the script using:

```powershell
.\IntuneAssignmentChecker.ps1
```

Follow the on-screen instructions to select the type of entity you want to check the assignments for in Intune:

- 1 for Users
- 2 for Groups
- 3 for Devices
- 4 to Check Permissions
- 5 to Exit

## Contributing

Contributions to are welcome! Please feel free to submit pull requests or open issues to improve the script or suggest new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
