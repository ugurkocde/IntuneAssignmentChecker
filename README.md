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

### Option 1: Install with WinGet on Windows

```powershell
winget install --id UgurKoc.IntuneAssignmentChecker --exact

# Open PowerShell 7, then launch the command center
pwsh
Start-IntuneAssignmentCheckerTui
```

The WinGet package is an MSI that installs the PowerShell module and its Graph
authentication dependency. It does not install or generate an executable version
of IntuneAssignmentChecker.

### Option 2: Install from PowerShell Gallery

```powershell
# Install from PowerShell Gallery
Install-Module IntuneAssignmentChecker -Scope CurrentUser

# Launch the assignment-governance command center
Start-IntuneAssignmentCheckerTui
```

The legacy `IntuneAssignmentChecker` alias remains available. The v5 terminal UI
organizes every module capability into native task workspaces: Overview, Assignments,
Governance, Change simulator, Drift, Delivery health, RBAC & scope, Filters, Fleet,
Reports & data, and Settings. It is implemented in the same PowerShell source as the
cmdlets, so there is no second application codebase or converted executable.

If you encounter any issues during installation, try reinstalling:

```powershell
Install-Module IntuneAssignmentChecker -Scope CurrentUser -Force
```

To update to the latest version:

```powershell
Update-Module IntuneAssignmentChecker
```

### Option 3: Manual Installation (from a local clone)

```powershell
# Install required Microsoft Graph SDK
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Import the module from your clone
Import-Module ./Module/IntuneAssignmentChecker -Force

# Launch the terminal UI
Start-IntuneAssignmentCheckerTui
```

> **Migrating from v3.x?** v3.x shipped as a single script installed via `Install-Script`. v4.x is a PowerShell module installed via `Install-Module`. If you previously used `Install-Script IntuneAssignmentChecker`, uninstall it first: `Uninstall-Script IntuneAssignmentChecker`.

## ✨ Features

- 🖥️ Full-parity PowerShell command center with purpose-built workflows, mouse support, and complete keyboard navigation
- 🛡️ Policy-as-code assignment governance with severity, evidence, remediation, waivers, and automation exit behavior
- 💥 Read-only pre-change simulation for target, filter, mode, and app-intent changes
- 🔭 Capture-and-compare drift monitoring with approved baselines, risk classification, audit attribution, JSON Lines, and webhooks
- 🏢 Multi-tenant fleet scans with tenant isolation, shared governance rules, and continue-on-error behavior
- 🔑 Capability-based least-privilege authentication (`Core`, `Applications`, `Devices`, `Scripts`, `CloudPC`, `ScopeTags`, `Audit`, or `Full`)
- 🚚 Assignment delivery-health correlation with explicit per-workload partial coverage
- 👮 Intune RBAC and scope-boundary analysis
- 🧪 Tenant-wide assignment-filter governance
- ⚙️ Resumable, budgeted high-scale scans with durable checkpoints, request caching, diagnostics, and a declarative workload registry
- 📐 Versioned JSON Schemas and deterministic v2 assignment records with v1 migration
- 🔍 Check assignments for users, groups, and devices
- 📱 View all 'All User' and 'All Device' assignments
- 🎯 See Intune assignment filters (name and Include/Exclude type) inline on every assignment, in the console, CSV exports, and HTML reports
- 🛡️ Safely test managed-device assignment-filter rules locally with `Test-IntuneAssignmentFilter` and tri-state `Match`, `NotMatch`, or `Unknown` results; tenant rule text is never executed
- 🧭 Explain effective targeting for a user, managed device, or both with exclusion precedence, transitive group membership, assignment filters, and machine-readable reason chains
- 📸 Capture deterministic assignment snapshots and compare Added, Removed, and Changed records between runs
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
| DeviceManagementServiceConfig.Read.All | Application | Read Autopilot deployment profiles and enrollment status page configurations |

For interactive authentication, IntuneAssignmentChecker automatically requests the delegated versions of these permissions during sign-in. Administrator consent is still required. The `Core` capability includes `DeviceManagementServiceConfig.Read.All` because Autopilot and enrollment status page profiles are part of the standard assignment scan.

For certificate, client secret, managed identity, or pre-fetched token authentication, configure the listed application permissions on the app registration and grant administrator consent. App-only authentication cannot add or consent permissions automatically.

`GroupMember.Read.All` provides the basic group properties and membership data used by IntuneAssignmentChecker without granting access to Microsoft 365 group conversations, files, calendars, or other group content.

> **Existing app registrations**: Add `GroupMember.Read.All` and grant administrator consent before removing `Group.Read.All`. After confirming the updated module works, remove `Group.Read.All` from the configured API permissions and revoke its application consent. Updating the app registration manifest alone might not remove an existing service principal consent grant.

> **Hidden memberships**: Reading groups with hidden membership requires the additional `Member.Read.Hidden` application permission. IntuneAssignmentChecker does not request this permission by default.

The automated setup script accepts the same capability profiles as
`Connect-IntuneAssignmentChecker`, so it only registers the selected application
permissions. For example: `./Register-IntuneAssignmentCheckerApp.ps1 -Capability Core,Applications,Audit`.

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

1. **Terminal UI**: Task-oriented command center with full feature parity (`Start-IntuneAssignmentCheckerTui`)
2. **Cmdlet Mode**: Individual cmdlets for automation and scripting

The TUI presents domain workflows instead of PowerShell syntax. Friendly dialogs
collect only the information each task needs, and results stay inside searchable
lists and detail panes. The workflows call the module's shared implementation, so
fixes apply to both the interactive and automation experiences. The separate
`Get-IntuneAssignmentOperation` command remains available as a metadata API for
documentation and integrations.

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

# Safely evaluate a cached tenant assignment filter for an Intune managed device
Test-IntuneAssignmentFilter -DeviceName 'Laptop123' -FilterId '<filter-id>' -FilterMode Include

# Or evaluate an ad hoc managed-device rule without executing it as PowerShell
Test-IntuneAssignmentFilter -DeviceName 'Laptop123' -Rule '(device.deviceOwnership -eq "Corporate")'

# Explain whether every discovered policy and assigned app targets a user on a managed device
Get-IntuneEffectiveAssignment -UserPrincipalName 'user@contoso.com' -DeviceName 'Laptop123'

# Export the explanation and retain typed records for automation
$effective = Get-IntuneEffectiveAssignment -UserPrincipalName 'user@contoso.com' `
    -DeviceName 'Laptop123' -PassThru -ExportPath 'C:\Temp\EffectiveAssignments.csv'
$effective | Where-Object EffectiveState -in 'Excluded', 'Unknown'

# Capture the tenant assignment baseline as deterministic, schema-versioned JSON
Export-IntuneAssignmentSnapshot -Path 'C:\IntuneSnapshots\assignments.json' -Force

# Compare a checked-in baseline with a newer scheduled capture
Compare-IntuneAssignmentSnapshot `
    -ReferencePath 'C:\IntuneSnapshots\baseline.json' `
    -DifferencePath 'C:\IntuneSnapshots\latest.json'

# Evaluate the built-in governance pack (or provide -RulePath/-WaiverPath)
Test-IntuneAssignmentGovernance -FailOnSeverity High -SetExitCode

# Prove the blast radius of a proposed change without writing to Intune
Get-Content ./records.json | ConvertFrom-Json |
    Test-IntuneAssignmentChange -ChangeType AddAssignment -PolicyId '<policy-id>' `
        -TargetType AllDevices -Intent required

# Capture current state, classify drift, and correlate matching Intune audit events
Get-IntuneAssignmentDrift -BaselinePath ./baseline.json -IncludeAuditAttribution `
    -OutputPath ./drift.jsonl -OutputFormat JsonLines

# Run the workload registry with a time budget and resumable checkpoint
Invoke-IntuneAssignmentScan -ScanBudgetSeconds 900 -CheckpointPath ./scan.json -KeepCheckpoint

# Correlate targeting with workload delivery status and transparent coverage records
Get-IntuneAssignmentHealth -Workload DeviceConfiguration,Compliance,Applications

# Audit RBAC boundaries and assignment-filter hygiene
Get-IntuneAssignmentAccess
Test-IntuneAssignmentFilterSet
```

`Get-IntuneUserAssignment`, `Get-IntuneGroupAssignment`,
`Get-IntuneDeviceAssignment`, `Get-IntuneAllPolicies`,
`Get-IntuneAllUsersAssignment`, `Get-IntuneAllDevicesAssignment`,
`Get-IntuneUnassignedPolicy`, `Get-IntuneEffectiveAssignment`, and
`Search-IntunePolicy` support `-PassThru`.
Using it also suppresses the interactive CSV-export prompt. Each object has the type name
`IntuneAssignmentChecker.AssignmentRecord` and schema version `2`. The stable
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
combined user/device presentation. `Get-IntuneEffectiveAssignment` adds a
canonical explanation model whose `EffectiveState` is `Included`, `Excluded`,
`NotTargeted`, or `Unknown` and whose `ReasonChain` records every evaluated
assignment and the final precedence decision. It unions user and device transitive
group memberships, evaluates All Users and All Devices, gives active or unresolved
exclusions precedence, and applies locally evaluated device assignment filters.
When an inclusion and exclusion match different user/device targeting dimensions,
the result is conservatively `Unknown` because that mixed targeting design cannot
be inferred safely. An exclusion without any matching or unresolved inclusion is
`NotTargeted`, not `Excluded`. For combined checks, `SubjectType` is `UserDevice`
and `SubjectId` is the user object ID and managed-device ID joined with `|`; use
`ReasonChain[*].MembershipSources` to distinguish user-side and device-side group
matches. Application analysis covers apps that have at least one tenant assignment;
unassigned apps remain available through `Get-IntuneUnassignedPolicy`.
This is targeting analysis: it does not prove delivery, platform applicability,
installation, execution, compliance, or device check-in.

If a non-optional workload cannot be scanned, `-PassThru` and CSV output include
one typed `Unknown` record with an empty `PolicyId`, `PolicyName` set to
`[Category scan failed]`, and reason code `Scan.CategoryFailed`. This prevents
automation from mistaking an unreadable category for a category with no matching
assignments. CSV rows also expose the final `DecisionCode`; inspect the full JSON
`ReasonChain` for every target, filter, and precedence decision.

Assignment snapshots use the `IntuneAssignmentChecker.AssignmentSnapshot` schema
version `2`. Version 1 records and snapshots are migrated in memory by
`ConvertTo-IntuneAssignmentRecord` and the snapshot reader. Snapshots contain the UTC capture time, module version, tenant identity,
per-category coverage and errors, and canonical assignment records sorted by a
stable identity key. Only the documented canonical fields are serialized; arbitrary
properties such as access tokens or client secrets are discarded. Apps are covered
when they have at least one tenant assignment, matching the shared assignment scan.
With a fixed `-CapturedAtUtc`, equivalent inputs produce byte-identical UTF-8 JSON
on every platform. The normal current-time value intentionally changes per capture.
Difference rows expose an opaque, versioned `IdentityKey`; compare it as a whole but
do not parse it. When Graph omits an assignment ID, the fallback identity includes
the assignment intent, so an intent change appears as an Added/Removed pair rather
than one Changed row.

For scheduled auditing, export to a dated file, compare it with the last accepted
baseline, and archive or commit the JSON to source control. `Compare-IntuneAssignmentSnapshot`
rejects malformed schemas, different tenants, failed or unknown scans, and mismatched
category coverage by default, so a permission or service failure cannot masquerade
as assignment removal. Optional workloads that cannot be fetched are marked
`Skipped`; comparison warns and excludes those categories from both snapshots, so
an unavailable optional workload produces neither false removals nor false additions.
Failed and unknown categories remain blocked. The explicit `-AllowIncompleteCoverage` and
`-AllowCoverageMismatch` switches are intended for investigated exceptions, not
routine automation. Snapshot files contain tenant configuration and names, so use
the same repository access controls as other Intune configuration exports.
Snapshots built from `-InputObject` default to incomplete because the exporter
cannot see an upstream command's error stream. Supply the full `-CoverageCategory`
set and `-CoverageComplete` only when the producer is known to have completed;
otherwise pass structured `-CoverageError` entries and keep the snapshot blocked
from routine comparison.

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

`Test-IntuneAssignmentFilter` reads the managed device from the Microsoft Graph
beta `managedDevices` endpoint and returns an
`IntuneAssignmentChecker.AssignmentFilterEvaluation` object. `Result` and
`RuleResult` are always `Match`, `NotMatch`, or `Unknown`; incomplete device data,
unsupported properties or operators, managed-app rules, filter/device platform
mismatches, ambiguous devices, and malformed input remain `Unknown` rather than
being guessed.

Available cmdlets:

| Cmdlet                             | Description                                                           |
| ---------------------------------- | --------------------------------------------------------------------- |
| `Connect-IntuneAssignmentChecker`  | Sign in (interactive, certificate, or client secret)                  |
| `Get-IntuneUserAssignment`         | Check assignments for specific users                                  |
| `Get-IntuneGroupAssignment`        | Check assignments for specific groups                                 |
| `Get-IntuneDeviceAssignment`       | Check assignments for specific devices                                |
| `Get-IntuneEffectiveAssignment`    | Explain effective targeting for a user, managed device, or both       |
| `Export-IntuneAssignmentSnapshot`  | Capture deterministic, schema-versioned assignment JSON              |
| `Compare-IntuneAssignmentSnapshot` | Report Added, Removed, and Changed records between snapshots          |
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
| `Test-IntuneAssignmentFilter`      | Safely evaluate a managed-device assignment filter with tri-state output  |
| `Search-IntunePolicy`              | Reverse lookup: find all assignment targets for a policy name         |
| `Search-IntuneSetting`             | Search configured settings across all policies                        |
| `Update-IntuneSettingDefinition`   | Refresh the local Settings Catalog definition cache                   |
| `Start-IntuneAssignmentCheckerTui` | Launch the task-oriented terminal command center with mouse and keyboard support |
| `Switch-IntuneAssignmentCheckerTenant` | Clear tenant-scoped state and connect the TUI or shell to another tenant |
| `Get-IntuneAssignmentOperation`    | Return operation and parameter metadata for automation integrations    |
| `Invoke-IntuneAssignmentScan`      | Run a budgeted, checkpointed assignment scan with coverage diagnostics |
| `Test-IntuneAssignmentGovernance`  | Evaluate assignment policy-as-code rules and waivers                  |
| `Test-IntuneAssignmentChange`      | Simulate a proposed assignment change without Graph writes           |
| `Get-IntuneAssignmentDrift`        | Capture, compare, classify, and optionally attribute assignment drift |
| `Invoke-IntuneAssignmentFleetScan` | Apply scans and governance across isolated tenant configurations       |
| `Get-IntuneAssignmentHealth`       | Correlate targeting with reported delivery health and coverage        |
| `Get-IntuneAssignmentAccess`       | Explain Intune RBAC role, scope, and policy boundaries                |
| `Test-IntuneAssignmentFilterSet`   | Audit unused, orphaned, duplicate, invalid, and ineffective filters   |
| `Test-IntuneAssignmentCheckerEnvironment` | Validate authentication, capabilities, beta workloads, paging, and output paths |
| `ConvertTo-IntuneAssignmentRecord` | Migrate v1 records into the canonical v2 schema                       |
| `Invoke-IntuneAssignmentChecker`   | Launch the terminal UI (aliased as `IntuneAssignmentChecker`)         |

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
| `-Capability`            | Least-privilege capability profiles to request; defaults to `Full` |
| `-SkipPermissionPrompt`  | Continue non-interactively while reporting unavailable capabilities |
| `-PassThru`              | Return structured connection and capability status                   |

### 📋 Terminal UI controls

Run `Start-IntuneAssignmentCheckerTui` or the `IntuneAssignmentChecker` alias. The
command center can open before authentication; connect or switch tenants from
Settings, or use offline snapshot workflows without signing in.

- Click workspaces, action buttons, result rows, and dialog choices with the mouse; use the wheel to scroll.
- Use Tab to switch focus, Up/Down or J/K to navigate, Page Up/Page Down to jump, and Enter to open the highlighted workspace. A highlighted result updates the detail pane immediately.
- Press `R` for the workspace's primary action, `/` to filter loaded results, `T` for Settings, `?` for help, or `Q` to quit.
- Press Escape to clear a result filter or move focus back to the workspace list. Ctrl+C also exits cleanly.
- Pass `-DisableMouse` when a terminal multiplexer or accessibility tool should retain mouse events; every feature remains keyboard-accessible.
- Resize the terminal to at least 90 columns by 26 rows for the full two-pane layout.
- Set an optional scope-tag filter in Settings, and save any loaded workspace results from Reports & data as JSON, JSON Lines, or CSV.

A central workflow registry maps every operational export to at least one task,
and release tests fail if that coverage is lost. Both interfaces remain one PowerShell
module codebase and share the same scanning, governance, simulation, and reporting logic.

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
