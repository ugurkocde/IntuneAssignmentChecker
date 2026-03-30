function Get-AssignmentFailures {
    Write-Host "Fetching assignment failures..." -ForegroundColor Green

    $failedAssignments = [System.Collections.ArrayList]::new()

    # 1. Get App Install Failures
    # Note: App installation status endpoint requires specific permissions and may not be available in all environments
    <# Temporarily disabled due to endpoint availability
    Write-Host "Checking app installation failures..." -ForegroundColor Yellow
    try {
        $reportBody = @{
            filter = ""
            select = @(
                "DeviceName", "UserPrincipalName", "Platform", "AppVersion",
                "InstallState", "InstallStateDetail", "ErrorCode", "HexErrorCode",
                "ApplicationId", "AppInstallState", "AppInstallStateDetails",
                "LastModifiedDateTime", "DeviceId", "UserId", "UserName"
            )
            skip = 0
            top = 50
        } | ConvertTo-Json

        $allAppFailures = @()
        $skip = 0

        do {
            $reportBody = @{
                filter = ""
                select = @(
                    "DeviceName", "UserPrincipalName", "Platform", "AppVersion",
                    "InstallState", "InstallStateDetail", "ErrorCode", "HexErrorCode",
                    "ApplicationId", "AppInstallState", "AppInstallStateDetails",
                    "LastModifiedDateTime", "DeviceId", "UserId", "UserName"
                )
                skip = $skip
                top = 50
            } | ConvertTo-Json

            $uri = "$script:GraphEndpoint/beta/deviceManagement/reports/getMobileApplicationManagementAppStatusReport"
            $response = try {
                Invoke-MgGraphRequest -Uri $uri -Method POST -Body $reportBody
            } catch {
                # If the new endpoint fails, try the alternative endpoint
                $uri = "$script:GraphEndpoint/beta/deviceManagement/reports/getAppStatusOverviewReport"
                Invoke-MgGraphRequest -Uri $uri -Method POST -Body $reportBody
            }

            if ($response.values) {
                $appFailures = $response.values | Where-Object {
                    $_[6] -ne 0 -or  # ErrorCode
                    $_[4] -eq "failed" -or  # InstallState
                    $_[9] -eq "failed"  # AppInstallState
                }

                foreach ($failure in $appFailures) {
                    $allAppFailures += [PSCustomObject]@{
                        Type = "App"
                        PolicyName = "Application ID: $($failure[8])"  # ApplicationId
                        Target = if ($failure[1]) { "User: $($failure[1])" } else { "Device: $($failure[0])" }
                        ErrorCode = if ($failure[7]) { "Error: 0x$($failure[7])" } else { "Error: $($failure[6])" }  # HexErrorCode or ErrorCode
                        ErrorDescription = if ($failure[5] -and $failure[10]) { "$($failure[5]) - $($failure[10])" } elseif ($failure[5]) { $failure[5] } elseif ($failure[10]) { $failure[10] } else { "Installation failed" }
                        LastAttempt = $failure[11]  # LastModifiedDateTime
                    }
                }
                $skip += 50
            }
        } while ($response.values -and $response.values.Count -eq 50)

        Write-Host "Found $($allAppFailures.Count) app installation failures" -ForegroundColor Green
        $failedAssignments.AddRange($allAppFailures)
    }
    catch {
        Write-Host "Error fetching app installation failures: $($_.Exception.Message)" -ForegroundColor Red
    }
    #>

    # 2. Get Device Configuration Policy Failures
    Write-Host "Checking device configuration policy failures..." -ForegroundColor Yellow
    try {
        $configPoliciesUri = "$script:GraphEndpoint/beta/deviceManagement/deviceConfigurations"
        $configPolicies = (Invoke-MgGraphRequest -Uri $configPoliciesUri -Method GET).value

        foreach ($policy in $configPolicies) {
            $skip = 0
            do {
                $reportBody = @{
                    filter = "(PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') and (PolicyId eq '$($policy.id)')"
                    select = @("DeviceName", "UPN", "PolicyStatus", "PspdpuLastModifiedTimeUtc")
                    skip   = $skip
                    top    = 50
                } | ConvertTo-Json

                $uri = "$script:GraphEndpoint/beta/deviceManagement/reports/getConfigurationPolicyDevicesReport"
                $response = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $reportBody

                if ($response.values) {
                    $failures = $response.values | Where-Object {
                        $_[2] -in @("error", "conflict", "notApplicable")
                    }

                    foreach ($failure in $failures) {
                        $null = $failedAssignments.Add([PSCustomObject]@{
                                Type             = "Device Configuration"
                                PolicyName       = $policy.displayName
                                Target           = "Device: $($failure[0])"
                                ErrorCode        = "$($failure[2])"
                                ErrorDescription = if ($failure[1]) { "$($failure[1])" } else { "No additional details" }
                                LastAttempt      = $failure[3]
                            })
                    }
                    $skip += 50
                }
            } while ($response.values -and $response.values.Count -eq 50)
        }
    }
    catch {
        Write-Host "Error fetching device configuration failures: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 3. Get Compliance Policy Failures
    Write-Host "Checking compliance policy failures..." -ForegroundColor Yellow
    try {
        $compliancePoliciesUri = "$script:GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies"
        $compliancePolicies = (Invoke-MgGraphRequest -Uri $compliancePoliciesUri -Method GET).value

        foreach ($policy in $compliancePolicies) {
            $statusUri = "$script:GraphEndpoint/beta/deviceManagement/deviceCompliancePolicies('$($policy.id)')/deviceStatuses"
            $statuses = (Invoke-MgGraphRequest -Uri $statusUri -Method GET).value

            $failures = $statuses | Where-Object {
                $_.status -in @("error", "conflict", "notApplicable", "nonCompliant")
            }

            foreach ($failure in $failures) {
                $null = $failedAssignments.Add([PSCustomObject]@{
                        Type             = "Compliance Policy"
                        PolicyName       = $policy.displayName
                        Target           = "Device: $($failure.deviceDisplayName)"
                        ErrorCode        = "$($failure.status)"
                        ErrorDescription = if ($failure.userPrincipalName) { "$($failure.userPrincipalName)" } else { "No additional details" }
                        LastAttempt      = $failure.lastReportedDateTime
                    })
            }
        }
    }
    catch {
        Write-Host "Error fetching compliance policy failures: $($_.Exception.Message)" -ForegroundColor Red
    }

    return $failedAssignments
}
