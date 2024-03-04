# Intune Assignments Checker

The `Intune Assignment Checker` script is here to simplify your life. It will provide a detailed overview of assigned Intune Configuration Profiles, Compliance Policies, and applications for user, groups and devices.

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
  - `DeviceManagementConfiguration.Read.All`
  - `DeviceManagementManagedDevices.Read.All`
  - `Device.Read.All`

Ensure that you have granted admin consent for these permissions in the Azure portal.

## Setup

1. Clone this repository or download the `IntuneAssignmentsChecker.ps1` script.
2. Fill in your Entra ID application registration details (App ID, Tenant ID, and Secret) at the beginning of the script.

```powershell
# Fill in your App ID, Tenant ID, and Secret
$appid = '<YourAppIdHere>' # App ID of the App Registration
$tenantid = '<YourTenantIdHere>' # Tenant ID of your Azure AD
$secret = '<YourSecretHere>' # Secret of the App Registration
```

3. Run the script in PowerShell.

## Usage

To run the script, open PowerShell and navigate to the directory containing IntuneAssignmentsChecker.ps1. Run the script using:

```powershell
.\IntuneAssignmentsChecker.ps1
```

Follow the on-screen instructions to select the type of entity you want to check the assignments for in Intune:

- 1 for Users
- 2 for Devices
- 3 to Check Permissions
- 4 to Exit

## Contributing

Contributions to are welcome! Please feel free to submit pull requests or open issues to improve the script or suggest new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
