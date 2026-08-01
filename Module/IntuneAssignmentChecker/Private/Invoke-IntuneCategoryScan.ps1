function Invoke-IntuneCategoryScan {
    [CmdletBinding()]
    # PSReviewUnusedParameter cannot trace usage inside the nested helper functions below
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ProcessEntity')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'EntityPreFilter')]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Categories,

        # Per-cmdlet plugin. Receives one context object per entity:
        # {Category, Entity, Assignments (normalized), RawAssignments, Buckets}.
        # Invoked also for zero-assignment entities.
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProcessEntity,

        [Parameter(Mandatory = $false)]
        [string[]]$AssignmentGroupIds = @(),

        # Invoked as: & $EntityPreFilter $entity $category. Entities that do not pass
        # never trigger an assignment fetch.
        [Parameter(Mandatory = $false)]
        [scriptblock]$EntityPreFilter,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress,

        [Parameter(Mandatory = $false)]
        [string]$ProgressVerb = 'Fetching',

        # Caller-owned cache keyed by EntityType string; lets multi-target loops fetch
        # each entity set once per run.
        [Parameter(Mandatory = $false)]
        [hashtable]$EntityCache
    )

    if ($null -eq $EntityCache) { $EntityCache = @{} }

    $buckets = @{}
    foreach ($category in $Categories) {
        foreach ($bucketKey in $category.BucketKeys) {
            if (-not $buckets.ContainsKey($bucketKey)) {
                $buckets[$bucketKey] = [System.Collections.Generic.List[object]]::new()
            }
        }
    }

    $scanErrors = [System.Collections.Generic.List[object]]::new()

    function Get-CachedEntitySet {
        param([string]$EntityType)
        if (-not $EntityCache.ContainsKey($EntityType)) {
            $EntityCache[$EntityType] = @(Get-IntuneEntities -EntityType $EntityType)
        }
        return , @($EntityCache[$EntityType])
    }

    function Get-PagedGraphValue {
        param([string]$Uri)
        $items = [System.Collections.Generic.List[object]]::new()
        $currentUri = $Uri
        do {
            $response = Invoke-MgGraphRequest -Uri $currentUri -Method Get
            if ($response -and $null -ne $response.value) {
                $items.AddRange(@($response.value))
            }
            $currentUri = $response.'@odata.nextLink'
        } while (![string]::IsNullOrEmpty($currentUri))
        return , $items
    }

    # Normalizes raw Graph assignment objects to the standard record shape, reproducing
    # Get-IntuneAssignments' label duality: with AssignmentGroupIds only Direct Assignment /
    # Direct Exclusion for matching groups (All Users/All Devices suppressed); without them
    # Group Assignment / Group Exclusion plus All Users / All Devices.
    function ConvertTo-NormalizedAssignment {
        param([object[]]$RawAssignments)
        $normalized = [System.Collections.Generic.List[object]]::new()
        foreach ($assignment in $RawAssignments) {
            $reason = $null
            $targetGroupId = $null
            $odataType = if ($assignment.target) { $assignment.target.'@odata.type' } else { $null }

            if ($odataType -eq '#microsoft.graph.groupAssignmentTarget') {
                $targetGroupId = $assignment.target.groupId
                if ($AssignmentGroupIds.Count -gt 0) {
                    if ($AssignmentGroupIds -contains $targetGroupId) { $reason = 'Direct Assignment' }
                }
                else {
                    $reason = 'Group Assignment'
                }
            }
            elseif ($odataType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $targetGroupId = $assignment.target.groupId
                if ($AssignmentGroupIds.Count -gt 0) {
                    if ($AssignmentGroupIds -contains $targetGroupId) { $reason = 'Direct Exclusion' }
                }
                else {
                    $reason = 'Group Exclusion'
                }
            }
            elseif ($AssignmentGroupIds.Count -eq 0) {
                $reason = switch ($odataType) {
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All Users' }
                    '#microsoft.graph.allDevicesAssignmentTarget' { 'All Devices' }
                    default { $null }
                }
            }

            if ($reason) {
                $filterId = $null
                $filterType = $null
                if ($assignment.target) {
                    $rawFilterId = $assignment.target.deviceAndAppManagementAssignmentFilterId
                    $rawFilterType = $assignment.target.deviceAndAppManagementAssignmentFilterType
                    if ($rawFilterType -and $rawFilterType -ne 'none' -and $rawFilterId -and $rawFilterId -ne '00000000-0000-0000-0000-000000000000') {
                        $filterId = $rawFilterId
                        $filterType = $rawFilterType
                    }
                }

                $normalized.Add([PSCustomObject]@{
                        Reason     = $reason
                        GroupId    = $targetGroupId
                        FilterId   = $filterId
                        FilterType = $filterType
                    })
            }
        }
        return , $normalized
    }

    function Test-CategoryEntityPreFilter {
        param($Entity, $Category)
        if ($null -eq $EntityPreFilter) { return $true }
        return [bool](& $EntityPreFilter $Entity $Category)
    }

    function Invoke-ProcessEntityCallback {
        param($Category, $Entity, $Assignments, $RawAssignments)
        $context = [PSCustomObject]@{
            Category       = $Category
            Entity         = $Entity
            Assignments    = $Assignments
            RawAssignments = $RawAssignments
            Buckets        = $buckets
        }
        & $ProcessEntity $context
    }

    $fetchableCategories = @($Categories | Where-Object { -not $_.BucketOnly })
    $totalCategories = $fetchableCategories.Count
    $currentCategory = 0

    foreach ($category in $fetchableCategories) {
        $currentCategory++
        if ($ShowProgress) {
            Write-Host "[$currentCategory/$totalCategories] $ProgressVerb $($category.DisplayName)..." -ForegroundColor Yellow
        }

        try {
            switch ($category.Kind) {
                'Entity' {
                    $entities = Get-CachedEntitySet -EntityType $category.EntityType
                    if ($category.EntityFilter) {
                        $entities = @($entities | Where-Object $category.EntityFilter)
                    }
                    foreach ($entity in $entities) {
                        if (-not (Test-CategoryEntityPreFilter -Entity $entity -Category $category)) { continue }
                        $assignments = @(Get-IntuneAssignments -EntityType $category.AssignmentEntityType -EntityId $entity.id -GroupIds $AssignmentGroupIds)
                        Invoke-ProcessEntityCallback -Category $category -Entity $entity -Assignments $assignments -RawAssignments $null
                    }
                }
                'EndpointSecurity' {
                    # Two-phase lookup is retained intentionally: some assigned intents (e.g. a macOS
                    # FileVault intent) have no configurationPolicies counterpart because the MC955748
                    # migration was Windows-only.
                    $processedIds = [System.Collections.Generic.HashSet[string]]::new()

                    # Phase 1: Settings Catalog style ES policies from configurationPolicies
                    $configPolicies = Get-CachedEntitySet -EntityType $category.EntityType
                    $matchingConfigPolicies = @($configPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $category.TemplateFamily })
                    foreach ($policy in $matchingConfigPolicies) {
                        if (-not $processedIds.Add([string]$policy.id)) { continue }
                        if (-not (Test-CategoryEntityPreFilter -Entity $policy -Category $category)) { continue }
                        $assignments = @(Get-IntuneAssignments -EntityType $category.AssignmentEntityType -EntityId $policy.id -GroupIds $AssignmentGroupIds)
                        Invoke-ProcessEntityCallback -Category $category -Entity $policy -Assignments $assignments -RawAssignments $null
                    }

                    # Phase 2: legacy template style ES policies from deviceManagement/intents
                    $intents = Get-CachedEntitySet -EntityType 'deviceManagement/intents'
                    Add-IntentTemplateFamilyInfo -IntentPolicies $intents
                    $matchingIntents = @($intents | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $category.TemplateFamily })
                    foreach ($policy in $matchingIntents) {
                        if (-not $processedIds.Add([string]$policy.id)) { continue }
                        if (-not (Test-CategoryEntityPreFilter -Entity $policy -Category $category)) { continue }
                        $rawAssignments = Get-PagedGraphValue -Uri "$script:GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments"
                        $assignments = ConvertTo-NormalizedAssignment -RawAssignments $rawAssignments
                        Invoke-ProcessEntityCallback -Category $category -Entity $policy -Assignments $assignments -RawAssignments $rawAssignments
                    }
                }
                'AppProtection' {
                    $policies = Get-CachedEntitySet -EntityType $category.EntityType
                    if ($category.EntityFilter) {
                        $policies = @($policies | Where-Object $category.EntityFilter)
                    }
                    foreach ($policy in $policies) {
                        if (-not (Test-CategoryEntityPreFilter -Entity $policy -Category $category)) { continue }
                        $assignmentsUri = Get-AppProtectionAssignmentUri -Policy $policy
                        $rawAssignments = if ($assignmentsUri) {
                            Get-PagedGraphValue -Uri $assignmentsUri
                        }
                        else {
                            [System.Collections.Generic.List[object]]::new()
                        }
                        $assignments = ConvertTo-NormalizedAssignment -RawAssignments $rawAssignments
                        Invoke-ProcessEntityCallback -Category $category -Entity $policy -Assignments $assignments -RawAssignments $rawAssignments
                    }
                }
                'MobileApps' {
                    if (-not $EntityCache.ContainsKey($category.EntityType)) {
                        # roleScopeTagIds is not reliably returned by the collection endpoint
                        # unless it is requested explicitly.
                        $EntityCache[$category.EntityType] = Get-PagedGraphValue -Uri "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$select=id,displayName,roleScopeTagIds"
                    }
                    $allApps = @($EntityCache[$category.EntityType])
                    if ($category.EntityFilter) {
                        $allApps = @($allApps | Where-Object $category.EntityFilter)
                    }
                    foreach ($app in $allApps) {
                        if (-not (Test-CategoryEntityPreFilter -Entity $app -Category $category)) { continue }
                        $rawAssignments = Get-PagedGraphValue -Uri "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps('$($app.id)')/assignments"
                        $assignments = ConvertTo-NormalizedAssignment -RawAssignments $rawAssignments
                        Invoke-ProcessEntityCallback -Category $category -Entity $app -Assignments $assignments -RawAssignments $rawAssignments
                    }
                }
                default {
                    throw "Unknown category kind '$($category.Kind)' for category '$($category.Id)'."
                }
            }
        }
        catch {
            if ($category.OptionalFeature) {
                # Optional features (e.g. Windows 365) fail quietly when the tenant is not licensed
                Write-Verbose "Skipping optional category '$($category.DisplayName)': $($_.Exception.Message)"
                continue
            }
            $scanErrors.Add([PSCustomObject]@{
                    CategoryId  = $category.Id
                    DisplayName = $category.DisplayName
                    Message     = $_.Exception.Message
                    ErrorRecord = $_
                })
            Write-Host "Error processing category '$($category.DisplayName)': $($_.Exception.Message)" -ForegroundColor Red
            Write-Error -Message "Category '$($category.Id)' failed: $($_.Exception.Message)"
            continue
        }
    }

    return [PSCustomObject]@{
        Buckets       = $buckets
        Errors        = $scanErrors
        CategoryCount = $totalCategories
    }
}
