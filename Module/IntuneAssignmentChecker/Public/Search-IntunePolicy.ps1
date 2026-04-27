function Search-IntunePolicy {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$PolicySearchTerm,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

    Write-Host "Policy Search / Reverse Lookup selected" -ForegroundColor Green

    if ($PolicySearchTerm) {
        $searchTerm = $PolicySearchTerm
    }
    else {
        Write-Host "Enter policy name or partial name to search for: " -ForegroundColor Cyan
        $searchTerm = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "No search term provided. Please try again." -ForegroundColor Red
        return
    }

    Write-Host "Searching for policies matching '$searchTerm'..." -ForegroundColor Yellow

    $allSearchResults = [System.Collections.ArrayList]::new()
    $groupNameCache = @{}
    $totalCategories = 18
    $currentCategory = 0

    # Helper function to resolve assignment targets for a matched policy
    function Resolve-SearchAssignments {
        param (
            [object[]]$Assignments,
            [string]$CategoryLabel,
            [string]$PolicyName,
            [string]$PolicyId,
            [System.Collections.ArrayList]$Results,
            [hashtable]$GroupCache
        )

        if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
            [void]$Results.Add([PSCustomObject]@{
                Category       = $CategoryLabel
                PolicyName     = $PolicyName
                PolicyId       = $PolicyId
                AssignmentType = "None"
                TargetName     = "No assignments"
                TargetGroupId  = ""
                FilterName     = ""
                FilterType     = ""
            })
            return
        }

        foreach ($assignment in $Assignments) {
            $assignmentType = "Include"
            $targetName = ""
            $targetGroupId = ""

            if ($assignment.Reason -eq "Group Assignment") {
                $targetGroupId = $assignment.GroupId
                if ($GroupCache.ContainsKey($targetGroupId)) {
                    $targetName = $GroupCache[$targetGroupId]
                }
                else {
                    $groupInfo = Get-GroupInfo -GroupId $targetGroupId
                    $targetName = if ($groupInfo.Success) { $groupInfo.DisplayName } else { "Unknown Group" }
                    $GroupCache[$targetGroupId] = $targetName
                }
            }
            elseif ($assignment.Reason -eq "Group Exclusion") {
                $assignmentType = "Exclude"
                $targetGroupId = $assignment.GroupId
                if ($GroupCache.ContainsKey($targetGroupId)) {
                    $targetName = $GroupCache[$targetGroupId]
                }
                else {
                    $groupInfo = Get-GroupInfo -GroupId $targetGroupId
                    $targetName = if ($groupInfo.Success) { $groupInfo.DisplayName } else { "Unknown Group" }
                    $GroupCache[$targetGroupId] = $targetName
                }
            }
            elseif ($assignment.Reason -eq "All Users") {
                $targetName = "All Users"
            }
            elseif ($assignment.Reason -eq "All Devices") {
                $targetName = "All Devices"
            }
            else {
                continue
            }

            $filterName = ''
            $filterType = ''
            if ($assignment.FilterId -and $assignment.FilterType -and $assignment.FilterType -ne 'none') {
                if ($script:AssignmentFilterLookup -and $script:AssignmentFilterLookup.ContainsKey($assignment.FilterId)) {
                    $filterName = $script:AssignmentFilterLookup[$assignment.FilterId].Name
                }
                else {
                    $filterName = "Unknown Filter ($($assignment.FilterId))"
                }
                $filterType = switch ($assignment.FilterType) {
                    'include' { 'Include' }
                    'exclude' { 'Exclude' }
                    default   { $assignment.FilterType }
                }
            }

            [void]$Results.Add([PSCustomObject]@{
                Category       = $CategoryLabel
                PolicyName     = $PolicyName
                PolicyId       = $PolicyId
                AssignmentType = $assignmentType
                TargetName     = $targetName
                TargetGroupId  = $targetGroupId
                FilterName     = $filterName
                FilterType     = $filterType
            })
        }
    }

    # --- 1. Device Configurations ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Device Configurations..." -ForegroundColor Yellow
    $searchDeviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
    $matchedDeviceConfigs = $searchDeviceConfigs | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedDeviceConfigs) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Device Configuration" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 2. Settings Catalog ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Settings Catalog Policies..." -ForegroundColor Yellow
    $searchSettingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
    # Exclude endpoint security policies (they will be handled separately)
    $searchSettingsCatalogFiltered = $searchSettingsCatalog | Where-Object {
        -not ($_.templateReference -and $_.templateReference.templateFamily -and $_.templateReference.templateFamily -like 'endpointSecurity*')
    }
    $matchedSettingsCatalog = $searchSettingsCatalogFiltered | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedSettingsCatalog) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Settings Catalog" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 3. Compliance Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Compliance Policies..." -ForegroundColor Yellow
    $searchCompliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    $matchedCompliancePolicies = $searchCompliancePolicies | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedCompliancePolicies) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Compliance Policy" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 4. App Protection Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching App Protection Policies..." -ForegroundColor Yellow
    $searchAppProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
    $matchedAppProtectionPolicies = $searchAppProtectionPolicies | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedAppProtectionPolicies) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $policyType = $policy.'@odata.type'
        $assignmentsUri = switch ($policyType) {
            "#microsoft.graph.androidManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments" }
            "#microsoft.graph.iosManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments" }
            "#microsoft.graph.windowsManagedAppProtection" { "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments" }
            default { $null }
        }

        if ($assignmentsUri) {
            try {
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                $appProtAssignments = @()
                foreach ($assignment in $assignmentResponse.value) {
                    $assignmentReason = $null
                    $groupId = $null
                    switch ($assignment.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' { $assignmentReason = "All Users" }
                        '#microsoft.graph.allDevicesAssignmentTarget' { $assignmentReason = "All Devices" }
                        '#microsoft.graph.groupAssignmentTarget' {
                            $assignmentReason = "Group Assignment"
                            $groupId = $assignment.target.groupId
                        }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' {
                            $assignmentReason = "Group Exclusion"
                            $groupId = $assignment.target.groupId
                        }
                    }
                    if ($assignmentReason) {
                        $appProtAssignments += [PSCustomObject]@{ Reason = $assignmentReason; GroupId = $groupId }
                    }
                }
                Resolve-SearchAssignments -Assignments $appProtAssignments -CategoryLabel "App Protection Policy" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
            }
            catch {
                Write-Host "Error fetching assignments for policy $($policyName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            # Unknown app protection type - add as no assignments
            [void]$allSearchResults.Add([PSCustomObject]@{
                Category       = "App Protection Policy"
                PolicyName     = $policyName
                PolicyId       = $policy.id
                AssignmentType = "None"
                TargetName     = "No assignments"
                TargetGroupId  = ""
            })
        }
    }

    # --- 5. App Configuration Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching App Configuration Policies..." -ForegroundColor Yellow
    $searchAppConfigPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/mobileAppConfigurations"
    $matchedAppConfigPolicies = $searchAppConfigPolicies | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedAppConfigPolicies) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "mobileAppConfigurations" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "App Configuration Policy" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 6. Applications ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Applications..." -ForegroundColor Yellow
    $searchAppUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
    $searchAppResponse = Invoke-MgGraphRequest -Uri $searchAppUri -Method Get
    $searchAllApps = $searchAppResponse.value
    while ($searchAppResponse.'@odata.nextLink') {
        $searchAppResponse = Invoke-MgGraphRequest -Uri $searchAppResponse.'@odata.nextLink' -Method Get
        $searchAllApps += $searchAppResponse.value
    }
    $matchedApps = $searchAllApps | Where-Object {
        -not ($_.isFeatured -or $_.isBuiltIn) -and
        ($_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*")
    }
    foreach ($app in $matchedApps) {
        $appName = if (-not [string]::IsNullOrWhiteSpace($app.displayName)) { $app.displayName } else { $app.name }
        $appId = $app.id
        try {
            $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
            $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

            if ($null -eq $assignmentResponse.value -or $assignmentResponse.value.Count -eq 0) {
                [void]$allSearchResults.Add([PSCustomObject]@{
                    Category       = "Application"
                    PolicyName     = $appName
                    PolicyId       = $appId
                    AssignmentType = "None"
                    TargetName     = "No assignments"
                    TargetGroupId  = ""
                })
            }
            else {
                foreach ($assignment in $assignmentResponse.value) {
                    $assignmentType = "Include"
                    $targetName = ""
                    $targetGroupId = ""
                    $intentLabel = if ($assignment.intent) { " ($($assignment.intent))" } else { "" }

                    switch ($assignment.target.'@odata.type') {
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                            $targetName = "All Users$intentLabel"
                        }
                        '#microsoft.graph.allDevicesAssignmentTarget' {
                            $targetName = "All Devices$intentLabel"
                        }
                        '#microsoft.graph.groupAssignmentTarget' {
                            $targetGroupId = $assignment.target.groupId
                            if ($groupNameCache.ContainsKey($targetGroupId)) {
                                $targetName = $groupNameCache[$targetGroupId]
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $targetGroupId
                                $targetName = if ($groupInfo.Success) { $groupInfo.DisplayName } else { "Unknown Group" }
                                $groupNameCache[$targetGroupId] = $targetName
                            }
                            $targetName = "$targetName$intentLabel"
                        }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' {
                            $assignmentType = "Exclude"
                            $targetGroupId = $assignment.target.groupId
                            if ($groupNameCache.ContainsKey($targetGroupId)) {
                                $targetName = $groupNameCache[$targetGroupId]
                            }
                            else {
                                $groupInfo = Get-GroupInfo -GroupId $targetGroupId
                                $targetName = if ($groupInfo.Success) { $groupInfo.DisplayName } else { "Unknown Group" }
                                $groupNameCache[$targetGroupId] = $targetName
                            }
                        }
                        default { continue }
                    }

                    [void]$allSearchResults.Add([PSCustomObject]@{
                        Category       = "Application"
                        PolicyName     = $appName
                        PolicyId       = $appId
                        AssignmentType = $assignmentType
                        TargetName     = $targetName
                        TargetGroupId  = $targetGroupId
                    })
                }
            }
        }
        catch {
            Write-Host "Error fetching assignments for app $($appName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # --- 7. Platform Scripts ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Platform Scripts..." -ForegroundColor Yellow
    $searchPlatformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
    $matchedPlatformScripts = $searchPlatformScripts | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedPlatformScripts) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Platform Script" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 8. Proactive Remediation Scripts ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Proactive Remediation Scripts..." -ForegroundColor Yellow
    $searchHealthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
    $matchedHealthScripts = $searchHealthScripts | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedHealthScripts) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Proactive Remediation Script" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 9-14. Endpoint Security (fetch configurationPolicies and intents once, filter for all 6 subtypes) ---
    $searchConfigPolicies = Get-IntuneEntities -EntityType "configurationPolicies"
    $searchAllIntents = Get-IntuneEntities -EntityType "deviceManagement/intents"
    Add-IntentTemplateFamilyInfo -IntentPolicies $searchAllIntents

    $endpointSecurityFamilies = @(
        @{ Family = "endpointSecurityAntivirus";                      Label = "Endpoint Security - Antivirus" }
        @{ Family = "endpointSecurityDiskEncryption";                 Label = "Endpoint Security - Disk Encryption" }
        @{ Family = "endpointSecurityFirewall";                       Label = "Endpoint Security - Firewall" }
        @{ Family = "endpointSecurityEndpointDetectionAndResponse";   Label = "Endpoint Security - EDR" }
        @{ Family = "endpointSecurityAttackSurfaceReduction";         Label = "Endpoint Security - ASR" }
        @{ Family = "endpointSecurityAccountProtection";              Label = "Endpoint Security - Account Protection" }
    )

    $searchProcessedESIds = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($esFamily in $endpointSecurityFamilies) {
        $currentCategory++
        Write-Host "[$currentCategory/$totalCategories] Searching $($esFamily.Label)..." -ForegroundColor Yellow

        # Check configurationPolicies
        $matchingConfigES = $searchConfigPolicies | Where-Object {
            $_.templateReference -and $_.templateReference.templateFamily -eq $esFamily.Family -and
            ($_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*")
        }
        foreach ($policy in $matchingConfigES) {
            if ($searchProcessedESIds.Add($policy.id)) {
                $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
                $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                Resolve-SearchAssignments -Assignments $assignments -CategoryLabel $esFamily.Label -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
            }
        }

        # Check intents (legacy)
        $matchingIntentsES = $searchAllIntents | Where-Object {
            $_.templateReference -and $_.templateReference.templateFamily -eq $esFamily.Family -and
            ($_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*")
        }
        foreach ($policy in $matchingIntentsES) {
            if ($searchProcessedESIds.Add($policy.id)) {
                $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
                try {
                    $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                    $intentAssignments = foreach ($assignment in $assignmentsResponse.value) {
                        [PSCustomObject]@{
                            Reason  = switch ($assignment.target.'@odata.type') {
                                '#microsoft.graph.allLicensedUsersAssignmentTarget' { "All Users" }
                                '#microsoft.graph.allDevicesAssignmentTarget' { "All Devices" }
                                '#microsoft.graph.groupAssignmentTarget' { "Group Assignment" }
                                '#microsoft.graph.exclusionGroupAssignmentTarget' { "Group Exclusion" }
                                default { "Unknown" }
                            }
                            GroupId = if ($assignment.target.'@odata.type' -match "groupAssignmentTarget") { $assignment.target.groupId } else { $null }
                        }
                    }
                    Resolve-SearchAssignments -Assignments $intentAssignments -CategoryLabel $esFamily.Label -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
                }
                catch {
                    Write-Host "Error fetching assignments for intent policy $($policyName): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }

    # --- 15. Autopilot Deployment Profiles ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Autopilot Deployment Profiles..." -ForegroundColor Yellow
    $searchAutopilotProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    $matchedAutopilotProfiles = $searchAutopilotProfiles | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
    foreach ($policy in $matchedAutopilotProfiles) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Autopilot Deployment Profile" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 16. Enrollment Status Page ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Enrollment Status Page Profiles..." -ForegroundColor Yellow
    $searchEnrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $searchESPProfiles = $searchEnrollmentConfigs | Where-Object {
        $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' -and
        ($_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*")
    }
    foreach ($policy in $searchESPProfiles) {
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $policy.id
        Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Enrollment Status Page" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
    }

    # --- 17. Cloud PC Provisioning Policies ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Cloud PC Provisioning Policies..." -ForegroundColor Yellow
    try {
        $searchCloudPCProvisioning = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
        $matchedCloudPCProvisioning = $searchCloudPCProvisioning | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
        foreach ($policy in $matchedCloudPCProvisioning) {
            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
            Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Cloud PC Provisioning Policy" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
        }
    }
    catch {
        Write-Warning "Unable to fetch Cloud PC Provisioning Policies: $($_.Exception.Message)"
    }

    # --- 18. Cloud PC User Settings ---
    $currentCategory++
    Write-Host "[$currentCategory/$totalCategories] Searching Cloud PC User Settings..." -ForegroundColor Yellow
    try {
        $searchCloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
        $matchedCloudPCUserSettings = $searchCloudPCUserSettings | Where-Object { $_.displayName -like "*$searchTerm*" -or $_.name -like "*$searchTerm*" }
        foreach ($policy in $matchedCloudPCUserSettings) {
            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
            $assignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $policy.id
            Resolve-SearchAssignments -Assignments $assignments -CategoryLabel "Cloud PC User Setting" -PolicyName $policyName -PolicyId $policy.id -Results $allSearchResults -GroupCache $groupNameCache
        }
    }
    catch {
        Write-Warning "Unable to fetch Cloud PC User Settings: $($_.Exception.Message)"
    }

    # --- Display Results ---
    $uniquePolicies = $allSearchResults | Select-Object -Property PolicyId -Unique
    $totalMatches = $uniquePolicies.Count

    if ($totalMatches -eq 0) {
        Write-Host "`nNo policies found matching '$searchTerm'." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan
        Write-Host "  POLICY SEARCH RESULTS" -ForegroundColor Cyan
        Write-Host "  Search term: '$searchTerm'" -ForegroundColor White
        Write-Host "  Found $totalMatches matching $(if ($totalMatches -eq 1) { 'policy' } else { 'policies' })" -ForegroundColor White
        Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan

        $groupedResults = $allSearchResults | Group-Object -Property PolicyId

        foreach ($policyGroup in $groupedResults) {
            $first = $policyGroup.Group[0]
            $policyName = $first.PolicyName
            if (-not $policyName) { $policyName = "Unnamed Policy" }

            Write-Host "`n===== $policyName =====" -ForegroundColor White
            Write-Host "Category: $($first.Category) | Policy ID: $($first.PolicyId)" -ForegroundColor Gray

            $separator = Get-Separator
            Write-Host $separator -ForegroundColor Gray
            Write-Host "Assignment Targets:" -ForegroundColor Yellow

            foreach ($result in $policyGroup.Group) {
                $filterDisplay = ''
                if ($result.FilterName) {
                    $filterDisplay = " (Filter: $($result.FilterName) [$($result.FilterType)])"
                }
                if ($result.AssignmentType -eq "None") {
                    Write-Host "  No assignments" -ForegroundColor DarkGray
                }
                elseif ($result.AssignmentType -eq "Exclude") {
                    $target = if ($result.TargetGroupId) { "Group: $($result.TargetName) (ID: $($result.TargetGroupId))" } else { $result.TargetName }
                    Write-Host "  [EXCLUDE] $target$filterDisplay" -ForegroundColor Red
                }
                else {
                    $target = if ($result.TargetGroupId) { "Group: $($result.TargetName) (ID: $($result.TargetGroupId))" } else { $result.TargetName }
                    Write-Host "  [INCLUDE] $target$filterDisplay" -ForegroundColor Green
                }
            }
            Write-Host $separator -ForegroundColor Gray
        }

        # Summary
        $totalTargets = ($allSearchResults | Where-Object { $_.AssignmentType -ne "None" }).Count
        Write-Host "`n=== Search Summary ===" -ForegroundColor Cyan
        Write-Host "  Found $totalMatches $(if ($totalMatches -eq 1) { 'policy' } else { 'policies' }) matching '$searchTerm'" -ForegroundColor White
        Write-Host "  Total assignment targets: $totalTargets" -ForegroundColor White
    }

    # --- Export ---
    $exportData = [System.Collections.ArrayList]::new()
    $null = $exportData.Add([PSCustomObject]@{
        Category         = "Search Info"
        Item             = "Search term: $searchTerm"
        ScopeTags        = ""
        AssignmentReason = "Found $totalMatches policies"
        FilterName       = ""
        FilterType       = ""
    })

    foreach ($result in $allSearchResults) {
        $filterLabel = if ($result.FilterName) { " (Filter: $($result.FilterName) [$($result.FilterType)])" } else { "" }
        $null = $exportData.Add([PSCustomObject]@{
            Category         = $result.Category
            Item             = "$($result.PolicyName) (ID: $($result.PolicyId))"
            ScopeTags        = ""
            AssignmentReason = "[$($result.AssignmentType)] $($result.TargetName)$(if ($result.TargetGroupId) { " (ID: $($result.TargetGroupId))" })$filterLabel"
            FilterName       = $result.FilterName
            FilterType       = $result.FilterType
        })
    }

    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntunePolicySearch.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}
