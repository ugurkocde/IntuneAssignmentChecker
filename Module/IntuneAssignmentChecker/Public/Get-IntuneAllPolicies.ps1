function Get-IntuneAllPolicies {
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentRecord')]
    param (
        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ScopeTagFilter,

        [Parameter()]
        [switch]$PassThru
    )

    Write-Host "Fetching all policies and their assignments..." -ForegroundColor Green
    $exportData = [System.Collections.ArrayList]::new()

    # Function to process and display policy assignments
    function Invoke-PolicyAssignments {
        param (
            [Parameter(Mandatory = $false)]
            [object[]]$Policies,

            [Parameter(Mandatory = $true)]
            [string]$DisplayName
        )

        if ($null -eq $Policies -or $Policies.Count -eq 0) {
            Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
            Write-Host "No policies found for this category." -ForegroundColor Gray
            Write-Host ""
            return
        }

        Write-Host "`n------- $DisplayName -------" -ForegroundColor Cyan
        foreach ($policy in $Policies) {
            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Profile" }
            Write-Host "Policy Name: $policyName" -ForegroundColor White
            Write-Host "Policy ID: $($policy.id)" -ForegroundColor Gray
            if ($policy.AssignmentSummary) {
                Write-Host "Assignments: $($policy.AssignmentSummary)" -ForegroundColor Gray
            }
            else {
                Write-Host "No assignments found" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }

    $categories = Get-IntuneCategoryDefinition -Audience 'AllPolicies'

    $processEntity = {
        param($ctx)

        $entity = $ctx.Entity
        $bucketKey = $ctx.Category.BucketKeys[0]

        if ($ctx.Category.Id -eq 'AppProtectionPolicies') {
            # Historical App Protection summary: group names for assignments and
            # exclusions, no filter suffix, All Devices targets not listed, and
            # policies without any listed assignment are dropped from the output.
            $summaryLines = foreach ($assignment in $ctx.Assignments) {
                switch ($assignment.Reason) {
                    'All Users' { 'All Users' }
                    'Group Assignment' { "Group Assignment - $((Get-GroupInfo -GroupId $assignment.GroupId).DisplayName)" }
                    'Group Exclusion' { "Group Exclusion - $((Get-GroupInfo -GroupId $assignment.GroupId).DisplayName)" }
                }
            }
            if (-not $summaryLines) { return }
            $entity | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($summaryLines -join '; ') -Force
            $ctx.Buckets[$bucketKey].Add($entity)
            return
        }

        $summaryLines = if ($ctx.Category.Id -in @('DeploymentProfiles', 'ESPProfiles', 'CloudPCProvisioningPolicies', 'CloudPCUserSettings')) {
            # Historical summary for these categories: group name appended only for
            # inclusions, exclusions stay reason-only, no filter suffix.
            foreach ($assignment in $ctx.Assignments) {
                if ($assignment.Reason -eq 'Group Assignment') {
                    $groupInfo = Get-GroupInfo -GroupId $assignment.GroupId
                    "$($assignment.Reason) - $($groupInfo.DisplayName)"
                }
                else { $assignment.Reason }
            }
        }
        elseif ($ctx.Category.Kind -eq 'EndpointSecurity' -and $null -ne $ctx.RawAssignments) {
            # Legacy intent-based ES policies keep their historical wording
            # ("Group: X" / "Exclude Group: X" / "Unknown") with filter suffix.
            foreach ($assignment in $ctx.RawAssignments) {
                $reasonText = switch ($assignment.target.'@odata.type') {
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                    '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                    '#microsoft.graph.groupAssignmentTarget' { "Group: " + (Get-GroupInfo -GroupId $assignment.target.groupId).DisplayName }
                    '#microsoft.graph.exclusionGroupAssignmentTarget' { "Exclude Group: " + (Get-GroupInfo -GroupId $assignment.target.groupId).DisplayName }
                    default { "Unknown" }
                }
                $suffix = Format-AssignmentFilter -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -FilterType $assignment.target.deviceAndAppManagementAssignmentFilterType
                "$reasonText$suffix"
            }
        }
        else {
            foreach ($assignment in $ctx.Assignments) {
                Format-AssignmentSummaryLine -Assignment $assignment
            }
        }

        $entity | Add-Member -NotePropertyName 'AssignmentSummary' -NotePropertyValue ($summaryLines -join '; ') -Force
        $ctx.Buckets[$bucketKey].Add($entity)
    }

    $scanResult = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity -ShowProgress -BuildRecords:$PassThru
    $allPolicies = $scanResult.Buckets

    # Apply scope tag filter if specified
    if ($ScopeTagFilter) {
        foreach ($key in @($allPolicies.Keys)) {
            $allPolicies[$key] = @(Filter-ByScopeTag -Items $allPolicies[$key] -FilterTag $ScopeTagFilter -ScopeTagLookup $script:ScopeTagLookup)
        }
    }

    # Display all policies and their assignments
    Invoke-PolicyAssignments -Policies $allPolicies.DeviceConfigs -DisplayName "Device Configurations"
    Invoke-PolicyAssignments -Policies $allPolicies.ImportedAdministrativeTemplates -DisplayName "Imported Administrative Templates"
    Invoke-PolicyAssignments -Policies $allPolicies.SettingsCatalog -DisplayName "Settings Catalog Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.CompliancePolicies -DisplayName "Compliance Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.AppProtectionPolicies -DisplayName "App Protection Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.AppConfigurationPolicies -DisplayName "App Configuration Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.PlatformScripts -DisplayName "Platform Scripts"
    Invoke-PolicyAssignments -Policies $allPolicies.HealthScripts -DisplayName "Proactive Remediation Scripts"
    Invoke-PolicyAssignments -Policies $allPolicies.DeploymentProfiles -DisplayName "Autopilot Deployment Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.ESPProfiles -DisplayName "Enrollment Status Page Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.CloudPCProvisioningPolicies -DisplayName "Windows 365 Cloud PC Provisioning Policies"
    Invoke-PolicyAssignments -Policies $allPolicies.CloudPCUserSettings -DisplayName "Windows 365 Cloud PC User Settings"
    Invoke-PolicyAssignments -Policies $allPolicies.AntivirusProfiles -DisplayName "Endpoint Security - Antivirus Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.DiskEncryptionProfiles -DisplayName "Endpoint Security - Disk Encryption Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.FirewallProfiles -DisplayName "Endpoint Security - Firewall Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.EndpointDetectionProfiles -DisplayName "Endpoint Security - EDR Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.AttackSurfaceProfiles -DisplayName "Endpoint Security - ASR Profiles"
    Invoke-PolicyAssignments -Policies $allPolicies.AccountProtectionProfiles -DisplayName "Endpoint Security - Account Protection Profiles"

    # Add to export data
    Add-CategoryExportData -ExportData $exportData -Categories $categories -Buckets $allPolicies -AssignmentReason { param($item) $item.AssignmentSummary }

    # Export results if requested
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneAllPolicies.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath -ExportToCSV:$ExportToCSV -ParameterMode:($parameterMode -or $PassThru)
    if ($PassThru) {
        Select-IACAssignmentRecord -Records $scanResult.Records -Buckets $allPolicies -SubjectType 'Tenant' -SubjectName 'All Policies' -Source 'Get-IntuneAllPolicies'
    }
}
