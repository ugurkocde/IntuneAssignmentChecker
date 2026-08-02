function Get-IntuneAssignmentHealth {
    <#
    .SYNOPSIS
    Correlates assignment targeting with policy and application delivery status.

    .DESCRIPTION
    Uses workload-specific beta adapters for device configuration, compliance, and
    applications. Status and coverage records are returned together so an unavailable
    or tenant-failing endpoint is never mistaken for healthy deployment coverage.

    .PARAMETER Workload
    Workload adapters to run.

    .PARAMETER StaleAfter
    Age after which a reporting timestamp is classified as stale.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentHealth')]
    param(
        [Parameter()]
        [ValidateSet('DeviceConfiguration', 'Compliance', 'Applications')]
        [string[]]$Workload = @('DeviceConfiguration', 'Compliance', 'Applications'),

        [Parameter()]
        [string[]]$PolicyId = @(),

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$StaleAfterDays = 14,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'JsonLines'
    )

    if (-not $script:GraphEndpoint) { throw 'Connect first with Connect-IntuneAssignmentChecker.' }
    $staleAfter = [timespan]::FromDays($StaleAfterDays)
    $results = [System.Collections.Generic.List[object]]::new()

    if ($Workload -contains 'DeviceConfiguration') {
        try {
            $policies = @(Get-IntuneEntities -EntityType deviceConfigurations -ThrowOnError)
            if ($PolicyId.Count -gt 0) { $policies = @($policies | Where-Object id -In $PolicyId) }
            foreach ($policy in $policies) {
                $skip = 0
                $pageCount = 0
                $seenRows = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                do {
                    $pageCount++
                    if ($pageCount -gt 1000) { throw "Device configuration health paging exceeded 1000 pages for policy '$($policy.id)'." }
                    $body = @{
                        filter = "(PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') and (PolicyId eq '$($policy.id)')"
                        select = @('DeviceName', 'UPN', 'PolicyStatus', 'PspdpuLastModifiedTimeUtc', 'IntuneDeviceId')
                        skip = $skip
                        top = 100
                    } | ConvertTo-Json -Depth 10
                    $report = ConvertFrom-IACReportResponse -Response (Invoke-IACGraphRequest -Uri '/deviceManagement/reports/getConfigurationPolicyDevicesReport' -Method POST -Body $body)
                    $rows = @(ConvertFrom-IACReportRows -Report $report)
                    $newRows = @($rows | Where-Object {
                            $rowKey = @(
                                ConvertTo-IACIdentityComponent $_.IntuneDeviceId
                                ConvertTo-IACIdentityComponent $_.DeviceName
                                ConvertTo-IACIdentityComponent $_.UPN
                                ConvertTo-IACIdentityComponent $_.PolicyStatus
                                ConvertTo-IACIdentityComponent $_.PspdpuLastModifiedTimeUtc
                            ) -join '|'
                            $seenRows.Add($rowKey)
                        })
                    if ($newRows.Count -ne $rows.Count) {
                        throw "Device configuration health paging returned repeated device rows for policy '$($policy.id)'."
                    }
                    foreach ($row in $newRows) {
                        [void]$results.Add((New-IACAssignmentHealthRecord -Workload DeviceConfiguration -PolicyId "$($policy.id)" -PolicyName "$($policy.displayName)" -DeviceId "$($row.IntuneDeviceId)" -DeviceName "$($row.DeviceName)" -UserPrincipalName "$($row.UPN)" -RawStatus $row.PolicyStatus -LastReportedDateTime $row.PspdpuLastModifiedTimeUtc -StaleAfter $staleAfter))
                    }
                    $skip += $rows.Count
                } while ($rows.Count -eq 100)
            }
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload DeviceConfiguration -Status Complete -Message "Processed $($policies.Count) policies."))
        }
        catch {
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload DeviceConfiguration -Status Failed -Message $_.Exception.Message))
        }
    }

    if ($Workload -contains 'Compliance') {
        try {
            $policies = @(Get-IntuneEntities -EntityType deviceCompliancePolicies -ThrowOnError)
            if ($PolicyId.Count -gt 0) { $policies = @($policies | Where-Object id -In $PolicyId) }
            $failureCount = 0
            foreach ($policy in $policies) {
                try {
                    $statuses = @((Invoke-IACGraphRequest -Uri "/deviceManagement/deviceCompliancePolicies('$($policy.id)')/deviceStatuses?`$select=id,deviceDisplayName,userPrincipalName,status,lastReportedDateTime&`$top=100" -Method GET).value)
                    foreach ($status in $statuses) {
                        [void]$results.Add((New-IACAssignmentHealthRecord -Workload Compliance -PolicyId "$($policy.id)" -PolicyName "$($policy.displayName)" -DeviceId "$($status.id)" -DeviceName "$($status.deviceDisplayName)" -UserPrincipalName "$($status.userPrincipalName)" -RawStatus $status.status -LastReportedDateTime $status.lastReportedDateTime -StaleAfter $staleAfter))
                    }
                }
                catch { $failureCount++; Write-Warning "Compliance status unavailable for '$($policy.displayName)': $($_.Exception.Message)" }
            }
            $coverageStatus = if ($failureCount -eq 0) { 'Complete' } elseif ($failureCount -eq $policies.Count) { 'Failed' } else { 'Partial' }
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload Compliance -Status $coverageStatus -Message "Processed $($policies.Count - $failureCount) of $($policies.Count) policies; $failureCount endpoint failure(s)."))
        }
        catch {
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload Compliance -Status Failed -Message $_.Exception.Message))
        }
    }

    if ($Workload -contains 'Applications') {
        try {
            $apps = @((Invoke-IACGraphRequest -Uri '/deviceAppManagement/mobileApps?$select=id,displayName,isAssigned&$top=100' -Method GET).value | Where-Object isAssigned)
            if ($PolicyId.Count -gt 0) { $apps = @($apps | Where-Object id -In $PolicyId) }
            $failureCount = 0
            foreach ($app in $apps) {
                try {
                    $statuses = @((Invoke-IACGraphRequest -Uri "/deviceAppManagement/mobileApps/$($app.id)/deviceStatuses?`$select=id,deviceName,deviceId,lastSyncDateTime,mobileAppInstallStatusValue,installState,installStateDetail,errorCode,userPrincipalName&`$top=100" -Method GET).value)
                    foreach ($status in $statuses) {
                        $rawStatus = if ($status.installState) { $status.installState } else { $status.mobileAppInstallStatusValue }
                        $detail = @($status.installStateDetail, $(if ($status.errorCode) { "ErrorCode=$($status.errorCode)" }) | Where-Object { $_ }) -join '; '
                        [void]$results.Add((New-IACAssignmentHealthRecord -Workload Applications -PolicyId "$($app.id)" -PolicyName "$($app.displayName)" -DeviceId "$($status.deviceId)" -DeviceName "$($status.deviceName)" -UserPrincipalName "$($status.userPrincipalName)" -RawStatus $rawStatus -Detail $detail -LastReportedDateTime $status.lastSyncDateTime -StaleAfter $staleAfter))
                    }
                }
                catch { $failureCount++; Write-Warning "Application status unavailable for '$($app.displayName)': $($_.Exception.Message)" }
            }
            $coverageStatus = if ($failureCount -eq 0) { 'Complete' } elseif ($failureCount -eq $apps.Count) { 'Failed' } else { 'Partial' }
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload Applications -Status $coverageStatus -Message "Processed $($apps.Count - $failureCount) of $($apps.Count) assigned applications; $failureCount endpoint failure(s)."))
        }
        catch {
            [void]$results.Add((New-IACAssignmentHealthCoverage -Workload Applications -Status Failed -Message $_.Exception.Message))
        }
    }

    $ordered = @($results | Sort-Object Workload, RecordType, PolicyName, DeviceName)
    if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject $ordered -Path $OutputPath -Format $OutputFormat }
    $ordered | Write-Output
}
