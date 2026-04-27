# IntuneAssignmentChecker Tests

Two layers, matched to actual risk.

## Layer 1: Unit tests (`Tests/Unit/`)

Pure-logic Pester tests for the private helpers. No Graph calls, no auth, no
network. Runs in well under a second.

**What it covers:**
- `Format-AssignmentFilter` - filter string formatting across include/exclude/none/unknown
- `Format-AssignmentSummaryLine` - summary line composition with and without filters
- `Get-AllTargetReason` - All Users / All Devices match resolution with filter suffix
- `Resolve-AssignmentReason` - inclusion/exclusion precedence, filter propagation
- `Get-GroupAssignmentReasons` - direct vs inherited vs excluded with filter info
- `Resolve-SimulatedAssignmentDelta` - new/lost/conflict detection against
  filter-suffixed status strings
- `Add-ExportData` - regex extraction of FilterName and FilterType from
  AssignmentReason into dedicated CSV columns

**Why these tests matter:** most regressions in this codebase are string-format
changes that slip past static analysis. Unit tests at this layer catch them.

### Run locally

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser
Invoke-Pester ./Tests/Unit
```

### CI

Runs automatically on push and PR to `main` when any file under `Module/` or
`Tests/` changes. Matrix is Ubuntu / Windows / macOS, all on PowerShell 7.
See `.github/workflows/pester.yml`.

## Layer 2: Smoke test (`Tests/Smoke/Run-Smoke.ps1`)

Read-only live Graph calls against a real tenant. Run manually by the
maintainer before tagging a release. Catches broken Graph URLs, missing
parameters, and wiring bugs that the unit layer cannot see.

**This is not a regression suite.** It is a fast go / no-go check. The
unit tests are the safety net; the smoke test is the final look before
shipping.

### Run

Interactive auth:

```powershell
./Tests/Smoke/Run-Smoke.ps1 -TestUpn user@contoso.com -TestGroupName 'Marketing Team'
```

App-based auth:

```powershell
./Tests/Smoke/Run-Smoke.ps1 `
    -AppId                $env:IAC_TEST_APPID `
    -TenantId             $env:IAC_TEST_TENANTID `
    -CertificateThumbprint $env:IAC_TEST_CERT `
    -TestUpn              $env:IAC_TEST_UPN `
    -TestGroupName        $env:IAC_TEST_GROUP
```

### What it checks

- `Connect-IntuneAssignmentChecker` succeeds and populates the internal
  assignment-filter lookup.
- `Get-IntuneAllPolicies` returns non-empty data.
- `Get-IntuneAllUsersAssignment`, `Get-IntuneAllDevicesAssignment`,
  `Get-IntuneUnassignedPolicy`, `Get-IntuneEmptyGroup`,
  `Get-IntuneFailedAssignment` run without throwing. Empty results are
  allowed because a tenant may legitimately have none.
- `Get-IntuneUserAssignment -UserPrincipalNames <TestUpn>` runs (skipped
  if `-TestUpn` is not provided).
- `Get-IntuneGroupAssignment -GroupNames <TestGroupName>` runs (skipped
  if `-TestGroupName` is not provided).
- `Search-IntunePolicy` and `Search-IntuneSetting` run without throwing.
- `New-IntuneHTMLReport` produces a non-empty HTML file that contains a
  `Filter` column header.

Exit code 0 on success, 1 on any failure (skips do not fail the run).

### What "100% pass" means

A pass means every exercised cmdlet ran without error and returned
something non-null where required. It does **not** guarantee that every
feature is semantically correct on your tenant - some features are only
testable with specific licenses, specific data (assignment filters, empty
groups, Cloud PC, failed assignments) or specific tenant shape. If your
tenant lacks those, the relevant cmdlets are still invoked but will
legitimately return empty results. Use the unit tests to verify logic
and the smoke test to verify wiring.
