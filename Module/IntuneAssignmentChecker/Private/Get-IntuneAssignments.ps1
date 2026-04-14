function Get-IntuneAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,

        [Parameter(Mandatory = $true)]
        [string]$EntityId,

        [Parameter(Mandatory = $false)]
        [string]$GroupId = $null,

        [Parameter(Mandatory = $false)]
        [string[]]$GroupIds = @()
    )

    # Unify GroupId and GroupIds into a single effective list
    $effectiveGroupIds = if ($GroupIds.Count -gt 0) { $GroupIds }
                         elseif ($GroupId) { @($GroupId) }
                         else { @() }

    # Determine the correct assignments URI based on EntityType
    $actualAssignmentsUri = $null
    # $isResolvedAppProtectionPolicy = $false # Flag if we resolved a generic App Protection Policy. Not strictly needed with current logic.

    if ($EntityType -eq "deviceAppManagement/managedAppPolicies") {
        # For generic App Protection Policies, determine the specific policy type first
        $policyDetailsUri = "$GraphEndpoint/beta/deviceAppManagement/managedAppPolicies/$EntityId"
        try {
            $policyDetailsResponse = Invoke-MgGraphRequest -Uri $policyDetailsUri -Method Get
            $policyODataType = $policyDetailsResponse.'@odata.type'
            $specificPolicyTypePath = switch ($policyODataType) {
                "#microsoft.graph.androidManagedAppProtection" { "androidManagedAppProtections" }
                "#microsoft.graph.iosManagedAppProtection" { "iosManagedAppProtections" }
                "#microsoft.graph.windowsManagedAppProtection" { "windowsManagedAppProtections" }
                default { $null }
            }
            if ($specificPolicyTypePath) {
                $actualAssignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/$specificPolicyTypePath('$EntityId')/assignments"
            }
            else {
                Write-Warning "Could not determine specific App Protection Policy type for $EntityId from OData type '$policyODataType'."
                return [System.Collections.ArrayList]::new() # Return empty ArrayList
            }
        }
        catch {
            Write-Warning "Error fetching details for App Protection Policy '$EntityId': $($_.Exception.Message)"
            return [System.Collections.ArrayList]::new() # Return empty ArrayList
        }
    }
    elseif ($EntityType -eq "mobileAppConfigurations") {
        $actualAssignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileAppConfigurations('$EntityId')/assignments"
    }
    elseif ($EntityType -like "deviceAppManagement/*ManagedAppProtections") {
        # Already specific App Protection Policy type
        # Example: deviceAppManagement/iosManagedAppProtections
        $actualAssignmentsUri = "$GraphEndpoint/beta/$EntityType('$EntityId')/assignments" # EntityType already includes deviceAppManagement
    }
    elseif ($EntityType -like "virtualEndpoint/*") {
        # Windows 365 Cloud PC policies use forward slash format instead of OData parentheses
        # Example: virtualEndpoint/provisioningPolicies or virtualEndpoint/userSettings
        $actualAssignmentsUri = "$GraphEndpoint/beta/deviceManagement/$EntityType/$EntityId/assignments"
    }
    else {
        # General device management entities
        $actualAssignmentsUri = "$GraphEndpoint/beta/deviceManagement/$EntityType('$EntityId')/assignments"
    }

    if (-not $actualAssignmentsUri) {
        # This case should ideally be covered by the logic above, but as a fallback:
        Write-Warning "Could not determine a valid assignments URI for EntityType '$EntityType' and EntityId '$EntityId'."
        return [System.Collections.ArrayList]::new() # Return empty ArrayList
    }

    $assignmentsToReturn = [System.Collections.ArrayList]::new()
    try {
        $allAssignmentsForEntity = [System.Collections.ArrayList]::new()
        $currentAssignmentsPageUri = $actualAssignmentsUri
        do {
            $pagedAssignmentResponse = Invoke-MgGraphRequest -Uri $currentAssignmentsPageUri -Method Get
            if ($pagedAssignmentResponse -and $null -ne $pagedAssignmentResponse.value) {
                $allAssignmentsForEntity.AddRange($pagedAssignmentResponse.value)
            }
            $currentAssignmentsPageUri = $pagedAssignmentResponse.'@odata.nextLink'
        } while (![string]::IsNullOrEmpty($currentAssignmentsPageUri))

        # Ensure $allAssignmentsForEntity is not null before trying to iterate
        $assignmentList = if ($allAssignmentsForEntity) { $allAssignmentsForEntity } else { @() }

        foreach ($assignment in $assignmentList) {
            $currentAssignmentReason = $null
            $currentTargetGroupId = $null # Initialize to null

            if ($assignment.target -and $assignment.target.'@odata.type') {
                $odataType = $assignment.target.'@odata.type'

                if ($odataType -eq '#microsoft.graph.groupAssignmentTarget') {
                    $currentTargetGroupId = $assignment.target.groupId
                    if ($effectiveGroupIds.Count -gt 0) {
                        # Specific group check requested
                        if ($effectiveGroupIds -contains $currentTargetGroupId) {
                            $currentAssignmentReason = "Direct Assignment"
                        }
                    }
                    else {
                        # No specific group, list all group assignments
                        $currentAssignmentReason = "Group Assignment"
                    }
                }
                elseif ($odataType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    $currentTargetGroupId = $assignment.target.groupId
                    if ($effectiveGroupIds.Count -gt 0) {
                        # Specific group check requested
                        if ($effectiveGroupIds -contains $currentTargetGroupId) {
                            $currentAssignmentReason = "Direct Exclusion"
                        }
                    }
                    else {
                        # No specific group, list all group exclusions
                        $currentAssignmentReason = "Group Exclusion"
                    }
                }
                elseif ($effectiveGroupIds.Count -eq 0) {
                    # Only consider non-group assignments if NOT querying for a specific group
                    $currentAssignmentReason = switch ($odataType) {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                        default { $null }
                    }
                }
            }
            else {
                Write-Warning "Assignment item for EntityId '$EntityId' (URI: $actualAssignmentsUri) is missing 'target' or 'target.@odata.type' property. Assignment data: $($assignment | ConvertTo-Json -Depth 3)"
            }

            if ($currentAssignmentReason) {
                $null = $assignmentsToReturn.Add([PSCustomObject]@{
                        Reason  = $currentAssignmentReason
                        GroupId = $currentTargetGroupId
                        Apps    = $null # 'Apps' property is not directly available from general assignments endpoint
                    })
            }
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403 -or $errorMessage -match "403|Forbidden|Authorization_RequestDenied") {
            Write-Warning "Permission denied (403) for '$actualAssignmentsUri'. Ensure admin consent has been granted for the required Graph API permissions: DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All"
        }
        else {
            Write-Warning "Error fetching assignments from '$actualAssignmentsUri': $errorMessage"
        }
    }

    return $assignmentsToReturn
}
