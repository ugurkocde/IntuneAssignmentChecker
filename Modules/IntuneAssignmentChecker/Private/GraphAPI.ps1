# Private/GraphAPI.ps1
# Graph API interaction functions for Intune Assignment Checker
# These functions handle environment setup and API calls

function Set-Environment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    if ($EnvironmentName) {
        switch ($EnvironmentName) {
            'Global' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGov' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            'USGovDoD' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            default {
                Write-Host "Invalid environment name. Using interactive selection." -ForegroundColor Yellow
                # Fall through to interactive selection
            }
        }
    }

    # Interactive selection if no valid environment name was provided
    do {
        Write-Host "Select Intune Tenant Environment:" -ForegroundColor Cyan
        Write-Host "  [1] Global" -ForegroundColor White
        Write-Host "  [2] USGov" -ForegroundColor White
        Write-Host "  [3] USGovDoD" -ForegroundColor White
        Write-Host ""
        Write-Host "  [0] Exit" -ForegroundColor White
        Write-Host ""
        Write-Host "Select an option: " -ForegroundColor Yellow -NoNewline

        $selection = Read-Host

        switch ($selection) {
            '1' {
                $script:GraphEndpoint = "https://graph.microsoft.com"
                $script:GraphEnvironment = "Global"
                Write-Host "Environment set to Global" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '2' {
                $script:GraphEndpoint = "https://graph.microsoft.us"
                $script:GraphEnvironment = "USGov"
                Write-Host "Environment set to USGov" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '3' {
                $script:GraphEndpoint = "https://dod-graph.microsoft.us"
                $script:GraphEnvironment = "USGovDoD"
                Write-Host "Environment set to USGovDoD" -ForegroundColor Green
                return $script:GraphEnvironment
            }
            '0' {
                Write-Host "Thank you for using IntuneAssignmentChecker! 👋" -ForegroundColor Green
                Write-Host "If you found this tool helpful, please consider:" -ForegroundColor Cyan
                Write-Host "- Starring the repository: https://github.com/ugurkocde/IntuneAssignmentChecker" -ForegroundColor White
                Write-Host "- Supporting the project: https://github.com/sponsors/ugurkocde" -ForegroundColor White
                Write-Host ""
                exit
            }
            default {
                Write-Host "Invalid choice, please select 1,2,3, or 0" -ForegroundColor Red
            }
        }
    } while ($selection -ne '0')
}

function Get-IntuneAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,

        [Parameter(Mandatory = $true)]
        [string]$EntityId,

        [Parameter(Mandatory = $false)]
        [string]$GroupId = $null
    )

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
                    if ($GroupId) {
                        # Specific group check requested
                        if ($currentTargetGroupId -eq $GroupId) {
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
                    if ($GroupId) {
                        # Specific group check requested
                        if ($currentTargetGroupId -eq $GroupId) {
                            $currentAssignmentReason = "Direct Exclusion"
                        }
                    }
                    else {
                        # No specific group, list all group exclusions
                        $currentAssignmentReason = "Group Exclusion"
                    }
                }
                elseif (-not $GroupId) {
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
                $null = $assignmentsToReturn.Add(@{
                        Reason  = $currentAssignmentReason
                        GroupId = $currentTargetGroupId
                        Apps    = $null # 'Apps' property is not directly available from general assignments endpoint
                    })
            }
        }
    }
    catch {
        Write-Warning "Error fetching assignments from '$actualAssignmentsUri': $($_.Exception.Message)"
    }

    return $assignmentsToReturn
}

function Get-IntuneEntities {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,

        [Parameter(Mandatory = $false)]
        [string]$Filter = "",

        [Parameter(Mandatory = $false)]
        [string]$Select = "",

        [Parameter(Mandatory = $false)]
        [string]$Expand = ""
    )

    # Handle special cases for app management and specific deviceManagement endpoints
    if ($EntityType -like "deviceAppManagement/*" -or $EntityType -eq "deviceManagement/templates" -or $EntityType -eq "deviceManagement/intents") {
        $baseUri = "$GraphEndpoint/beta"
        $actualEntityType = $EntityType
    }
    else {
        $baseUri = "$GraphEndpoint/beta/deviceManagement"
        $actualEntityType = "$EntityType"
    }

    $currentUri = "$baseUri/$actualEntityType"
    if ($Filter) { $currentUri += "?`$filter=$Filter" }
    if ($Select) { $currentUri += $(if ($Filter) { "&" }else { "?" }) + "`$select=$Select" }
    if ($Expand) { $currentUri += $(if ($Filter -or $Select) { "&" }else { "?" }) + "`$expand=$Expand" }

    $entities = [System.Collections.ArrayList]::new() # Initialize as ArrayList

    do {
        try {
            $response = Invoke-MgGraphRequest -Uri $currentUri -Method Get -ErrorAction Stop
            if ($null -ne $response -and $null -ne $response.value) {
                if ($response.value -is [array]) {
                    $entities.AddRange($response.value)
                }
                else {
                    $entities.Add($response.value)
                }
            }
            $currentUri = $response.'@odata.nextLink'
        }
        catch {
            Write-Warning "Error fetching entities for $EntityType from $currentUri : $($_.Exception.Message)"
            $currentUri = $null # Stop pagination on error
        }
    } while ($currentUri)

    return $entities
}
