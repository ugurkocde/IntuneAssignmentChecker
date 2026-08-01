function Get-IntuneAssignments {
    [CmdletBinding()]
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
        $policyDetailsUri = "$script:GraphEndpoint/beta/deviceAppManagement/managedAppPolicies/$EntityId"
        try {
            $policyDetailsResponse = Invoke-IACGraphRequest -Uri $policyDetailsUri -Method Get
            $actualAssignmentsUri = Get-AppProtectionAssignmentUri -Policy $policyDetailsResponse
            if (-not $actualAssignmentsUri) {
                Write-Warning "Could not determine specific App Protection Policy type for $EntityId from OData type '$($policyDetailsResponse.'@odata.type')'."
                return [System.Collections.ArrayList]::new() # Return empty ArrayList
            }
        }
        catch {
            Write-Warning "Error fetching details for App Protection Policy '$EntityId': $($_.Exception.Message)"
            return [System.Collections.ArrayList]::new() # Return empty ArrayList
        }
    }
    elseif ($EntityType -eq "mobileAppConfigurations") {
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/deviceAppManagement/mobileAppConfigurations('$EntityId')/assignments"
    }
    elseif ($EntityType -like "deviceAppManagement/*ManagedAppProtections") {
        # Already specific App Protection Policy type
        # Example: deviceAppManagement/iosManagedAppProtections
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/$EntityType('$EntityId')/assignments" # EntityType already includes deviceAppManagement
    }
    elseif ($EntityType -like "virtualEndpoint/*") {
        # Windows 365 Cloud PC policies use forward slash format instead of OData parentheses
        # Example: virtualEndpoint/provisioningPolicies or virtualEndpoint/userSettings
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/$EntityType/$EntityId/assignments"
    }
    elseif ($EntityType -eq "groupPolicyConfigurations") {
        # Imported Administrative Templates use the documented resource-path form.
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/groupPolicyConfigurations/$EntityId/assignments"
    }
    elseif ($EntityType -in @('windowsFeatureUpdateProfiles', 'windowsQualityUpdateProfiles', 'windowsDriverUpdateProfiles', 'windowsQualityUpdatePolicies')) {
        # Windows Update workloads expose assignments on the documented resource path.
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/$EntityType/$EntityId/assignments"
    }
    else {
        # General device management entities
        $actualAssignmentsUri = "$script:GraphEndpoint/beta/deviceManagement/$EntityType('$EntityId')/assignments"
    }

    if (-not $actualAssignmentsUri) {
        # This case should ideally be covered by the logic above, but as a fallback:
        Write-Warning "Could not determine a valid assignments URI for EntityType '$EntityType' and EntityId '$EntityId'."
        return [System.Collections.ArrayList]::new() # Return empty ArrayList
    }

    $assignmentsToReturn = [System.Collections.ArrayList]::new()
    try {
        $allAssignmentsForEntity = @((Invoke-IACGraphRequest -Uri $actualAssignmentsUri -Method Get).value)

        # Ensure $allAssignmentsForEntity is not null before trying to iterate
        $assignmentList = if ($allAssignmentsForEntity) { $allAssignmentsForEntity } else { @() }

        foreach ($assignment in $assignmentList) {
            if (-not $assignment.target -or -not $assignment.target.'@odata.type') {
                Write-Warning "Assignment item for EntityId '$EntityId' (URI: $actualAssignmentsUri) is missing 'target' or 'target.@odata.type' property. Assignment data: $($assignment | ConvertTo-Json -Depth 3)"
                continue
            }
            $normalizedAssignment = ConvertTo-IACNormalizedAssignment -Assignment $assignment -GroupIds $effectiveGroupIds
            if ($normalizedAssignment) { $null = $assignmentsToReturn.Add($normalizedAssignment) }
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
