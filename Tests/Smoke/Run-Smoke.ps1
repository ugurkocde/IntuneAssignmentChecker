#Requires -Version 7.0
<#
.SYNOPSIS
    Pre-release smoke test for IntuneAssignmentChecker against a live tenant.

.DESCRIPTION
    Runs a handful of read-only cmdlets and verifies they return data without
    throwing. Intended to be run manually by the maintainer before tagging a
    release, after the unit tests have already passed.

    This is NOT an integration test suite. It is a fast sanity check to catch
    things like broken Graph URLs, missing parameters, or wiring bugs that slip
    past the unit tests.

.PARAMETER AppId
    Optional App Registration (client) ID. If omitted, interactive auth is used.

.PARAMETER TenantId
    Optional Tenant ID. Required if AppId is provided.

.PARAMETER CertificateThumbprint
    Optional certificate thumbprint for app-auth.

.PARAMETER ClientSecret
    Optional client secret for app-auth. Prefer certificates.

.PARAMETER TestUpn
    A real user UPN in the tenant to probe with Get-IntuneUserAssignment.
    If omitted, Get-IntuneUserAssignment is skipped.

.PARAMETER TestGroupName
    A real group name in the tenant to probe with Get-IntuneGroupAssignment.
    If omitted, Get-IntuneGroupAssignment is skipped.

.EXAMPLE
    ./Tests/Smoke/Run-Smoke.ps1 -TestUpn user@contoso.com

.EXAMPLE
    ./Tests/Smoke/Run-Smoke.ps1 `
        -AppId $env:IAC_TEST_APPID `
        -TenantId $env:IAC_TEST_TENANTID `
        -CertificateThumbprint $env:IAC_TEST_CERT `
        -TestUpn $env:IAC_TEST_UPN `
        -TestGroupName $env:IAC_TEST_GROUP
#>
[CmdletBinding()]
param(
    [string]$AppId,
    [string]$TenantId,
    [string]$CertificateThumbprint,
    [string]$ClientSecret,
    [string]$TestUpn,
    [string]$TestGroupName
)

$ErrorActionPreference = 'Stop'
$script:SmokeResults = [System.Collections.Generic.List[object]]::new()

function Invoke-SmokeCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$AllowEmpty
    )

    Write-Host ""
    Write-Host "[ ] $Name" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $output = & $Action
        $sw.Stop()
        if (-not $AllowEmpty -and ($null -eq $output -or ($output -is [array] -and $output.Count -eq 0))) {
            throw "Command returned null/empty, expected data."
        }
        Write-Host "`r[PASS] $Name ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green
        $script:SmokeResults.Add([PSCustomObject]@{
            Name     = $Name
            Status   = 'Pass'
            Duration = $sw.ElapsedMilliseconds
            Error    = $null
        })
    }
    catch {
        $sw.Stop()
        Write-Host "`r[FAIL] $Name ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Red
        Write-Host "       $($_.Exception.Message)" -ForegroundColor DarkRed
        $script:SmokeResults.Add([PSCustomObject]@{
            Name     = $Name
            Status   = 'Fail'
            Duration = $sw.ElapsedMilliseconds
            Error    = $_.Exception.Message
        })
    }
}

function Skip-SmokeCheck {
    param([string]$Name, [string]$Reason)
    Write-Host ""
    Write-Host "[SKIP] $Name" -ForegroundColor Yellow
    Write-Host "       $Reason" -ForegroundColor DarkYellow
    $script:SmokeResults.Add([PSCustomObject]@{
        Name     = $Name
        Status   = 'Skip'
        Duration = 0
        Error    = $Reason
    })
}

# --- Module load ---
$moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'
Write-Host "=== IntuneAssignmentChecker Smoke Test ===" -ForegroundColor White
Write-Host "Module: $moduleRoot"
Write-Host ""

Import-Module $moduleRoot -Force

# --- Connect ---
$connectParams = @{}
if ($AppId)                 { $connectParams['AppId']                 = $AppId }
if ($TenantId)              { $connectParams['TenantId']              = $TenantId }
if ($CertificateThumbprint) { $connectParams['CertificateThumbprint'] = $CertificateThumbprint }
if ($ClientSecret)          { $connectParams['ClientSecret']          = $ClientSecret }

Write-Host "Connecting..." -ForegroundColor Cyan
Connect-IntuneAssignmentChecker @connectParams

# Verify the filter lookup was populated
$lookupVar = Get-Variable -Scope Script -Name AssignmentFilterLookup -ErrorAction SilentlyContinue
# The variable lives inside the module scope; reach it via the module.
$moduleState = Get-Module IntuneAssignmentChecker
$filterLookup = & $moduleState { $script:AssignmentFilterLookup }
if ($null -eq $filterLookup) {
    Write-Host "[WARN] AssignmentFilterLookup is null. Filter feature will not surface filter names." -ForegroundColor Yellow
}
else {
    Write-Host "AssignmentFilterLookup contains $($filterLookup.Count) filter(s)." -ForegroundColor Green
}

# --- Tests ---

Invoke-SmokeCheck -Name 'Get-IntuneAllPolicies returns policies' -Action {
    $p = Get-IntuneAllPolicies
    if (-not $p) { throw "No policies returned." }
    $p
}

Invoke-SmokeCheck -Name 'Get-IntuneAllUsersAssignment runs without error' -Action {
    # AllowEmpty because a fresh tenant may have no All Users assignments at all
    Get-IntuneAllUsersAssignment
} -AllowEmpty

Invoke-SmokeCheck -Name 'Get-IntuneAllDevicesAssignment runs without error' -Action {
    Get-IntuneAllDevicesAssignment
} -AllowEmpty

Invoke-SmokeCheck -Name 'Get-IntuneUnassignedPolicy runs without error' -Action {
    Get-IntuneUnassignedPolicy
} -AllowEmpty

Invoke-SmokeCheck -Name 'Get-IntuneEmptyGroup runs without error' -Action {
    Get-IntuneEmptyGroup
} -AllowEmpty

Invoke-SmokeCheck -Name 'Get-IntuneFailedAssignment runs without error' -Action {
    Get-IntuneFailedAssignment
} -AllowEmpty

if ($TestUpn) {
    Invoke-SmokeCheck -Name "Get-IntuneUserAssignment -UserPrincipalNames $TestUpn" -Action {
        Get-IntuneUserAssignment -UserPrincipalNames $TestUpn
    } -AllowEmpty
}
else {
    Skip-SmokeCheck -Name 'Get-IntuneUserAssignment' -Reason 'No -TestUpn provided.'
}

if ($TestGroupName) {
    Invoke-SmokeCheck -Name "Get-IntuneGroupAssignment -GroupNames $TestGroupName" -Action {
        Get-IntuneGroupAssignment -GroupNames $TestGroupName
    } -AllowEmpty
}
else {
    Skip-SmokeCheck -Name 'Get-IntuneGroupAssignment' -Reason 'No -TestGroupName provided.'
}

Invoke-SmokeCheck -Name 'Search-IntunePolicy -PolicySearchTerm "a"' -Action {
    Search-IntunePolicy -PolicySearchTerm 'a'
} -AllowEmpty

Invoke-SmokeCheck -Name 'Search-IntuneSetting -SearchTerm BitLocker' -Action {
    Search-IntuneSetting -SearchTerm 'BitLocker'
} -AllowEmpty

Invoke-SmokeCheck -Name 'New-IntuneHTMLReport generates a non-empty HTML file with a Filter column' -Action {
    $tempReport = Join-Path ([System.IO.Path]::GetTempPath()) "iac-smoke-$(Get-Date -Format yyyyMMddHHmmss).html"
    try {
        New-IntuneHTMLReport -HTMLReportPath $tempReport
        if (-not (Test-Path $tempReport)) { throw "HTML report was not created at $tempReport." }
        $content = Get-Content $tempReport -Raw
        if ($content.Length -lt 1000) { throw "HTML report is suspiciously short ($($content.Length) bytes)." }
        if ($content -notmatch '<th>\s*Filter\s*</th>') {
            throw "HTML report is missing the Filter column header."
        }
        @{ FilePath = $tempReport; SizeKB = [math]::Round($content.Length / 1KB, 1) }
    }
    finally {
        if ($tempReport -and (Test-Path $tempReport)) { Remove-Item $tempReport -Force }
    }
}

# --- Summary ---
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor White
$pass = ($SmokeResults | Where-Object Status -eq 'Pass').Count
$fail = ($SmokeResults | Where-Object Status -eq 'Fail').Count
$skip = ($SmokeResults | Where-Object Status -eq 'Skip').Count
Write-Host "Passed:  $pass" -ForegroundColor Green
Write-Host "Failed:  $fail" -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'DarkGray' })
Write-Host "Skipped: $skip" -ForegroundColor Yellow

if ($fail -gt 0) {
    Write-Host ""
    Write-Host "Failures:" -ForegroundColor Red
    $SmokeResults | Where-Object Status -eq 'Fail' | ForEach-Object {
        Write-Host "  - $($_.Name)"
        Write-Host "      $($_.Error)" -ForegroundColor DarkRed
    }
    exit 1
}

Write-Host ""
Write-Host "Smoke test passed." -ForegroundColor Green
exit 0
