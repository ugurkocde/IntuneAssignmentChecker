function Get-IntuneAssignmentAccess {
    <#
    .SYNOPSIS
    Explains which Intune RBAC role assignments can manage assignment records.

    .DESCRIPTION
    Correlates role assignment members, resource scopes, and scope tags with live
    or snapshotted policies. Results expose the granting role assignment and flag
    orphaned or unexpectedly broad administrative boundaries.

    .PARAMETER SnapshotPath
    Optional assignment snapshot used for policy and scope-tag inventory.

    .PARAMETER PolicyId
    Optional policy IDs to limit the analysis.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentAccess')]
    param(
        [Parameter()]
        [string]$SnapshotPath,

        [Parameter()]
        [string[]]$PolicyId = @(),

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'Json'
    )

    if (-not $script:GraphEndpoint) { throw 'Connect first with Connect-IntuneAssignmentChecker.' }
    $coverageStatus = 'Complete'
    $coverageMessages = @()
    $coverageBlocking = $false
    $records = if ($SnapshotPath) {
        $snapshot = Read-IACAssignmentSnapshot -Path $SnapshotPath
        if (Test-IACCoverageHasBlockingFailure -Coverage $snapshot.Coverage) {
            $coverageStatus = 'Partial'
            $coverageBlocking = $true
            $coverageMessages = @($snapshot.Coverage.Errors | ForEach-Object { "$($_.CategoryId): $($_.Message)" })
        }
        elseif (-not $snapshot.Coverage.Complete) {
            $coverageStatus = 'CompleteWithOptionalSkips'
            $coverageMessages = @($snapshot.Coverage.Categories | Where-Object Status -EQ Skipped | ForEach-Object { "$($_.CategoryId): optional workload skipped" })
        }
        @($snapshot.Records)
    }
    else {
        $categories = @(Get-IntuneCategoryDefinition -Audience Effective)
        $scan = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{} -BuildRecords
        if (@($scan.Errors).Count -gt 0) {
            $coverageStatus = 'Failed'
            $coverageBlocking = $true
            $coverageMessages = @($scan.Errors | ForEach-Object { "$($_.CategoryId): $($_.Message)" })
        }
        elseif (@($scan.Skipped).Count -gt 0) {
            $coverageStatus = 'CompleteWithOptionalSkips'
            $coverageMessages = @($scan.Skipped | ForEach-Object { "$($_.CategoryId): $($_.Message)" })
        }
        @($scan.Records)
    }
    if ($PolicyId.Count -gt 0) { $records = @($records | Where-Object PolicyId -In $PolicyId) }
    $policies = @($records | Where-Object PolicyId | Group-Object PolicyId | ForEach-Object { $_.Group[0] })

    $uri = '/deviceManagement/roleAssignments?$select=id,displayName,members,resourceScopes,roleScopeTagIds&$top=100'
    $roleAssignments = @((Invoke-IACGraphRequest -Uri $uri -Method GET).value)
    $roleDefinitions = @((Invoke-IACGraphRequest -Uri '/deviceManagement/roleDefinitions?$select=id,displayName,isBuiltIn&$expand=roleAssignments($select=id)&$top=100' -Method GET).value)
    $results = foreach ($roleAssignment in $roleAssignments) {
        $roleDefinition = $roleDefinitions | Where-Object {
            @($_.roleAssignments.id) -contains $roleAssignment.id
        } | Select-Object -First 1
        $members = @($roleAssignment.members | ForEach-Object { "$_" } | Where-Object { $_ })
        $resourceScopes = @($roleAssignment.resourceScopes | ForEach-Object { "$_" } | Where-Object { $_ })
        $scopeTags = @($roleAssignment.roleScopeTagIds | ForEach-Object { "$_" } | Where-Object { $_ })
        $isBroad = $resourceScopes.Count -eq 0 -and ($scopeTags.Count -eq 0 -or $scopeTags -contains '0')
        $matchingPolicyInventory = @($policies | Where-Object {
                $policyTags = @($_.ScopeTagIds | ForEach-Object { "$_" })
                $scopeTags.Count -eq 0 -or $scopeTags -contains '0' -or
                @($policyTags | Where-Object { $_ -in $scopeTags }).Count -gt 0
            })
        $matchingPolicies = if ($isBroad) { @($null) } else { @($matchingPolicyInventory) }
        if ($matchingPolicies.Count -eq 0) { $matchingPolicies = @($null) }
        foreach ($policy in $matchingPolicies) {
            $result = [PSCustomObject][ordered]@{
                SchemaName         = 'IntuneAssignmentChecker.AssignmentAccess'
                SchemaVersion      = 1
                TenantId           = $script:CurrentTenantId
                RoleAssignmentId   = $roleAssignment.id
                RoleAssignmentName = $roleAssignment.displayName
                RoleDefinitionId   = $roleDefinition.id
                RoleDefinitionName = $roleDefinition.displayName
                RoleDefinitionStatus = if ($roleDefinition) { 'Resolved' } else { 'Unavailable' }
                Members            = $members
                ResourceScopes     = $resourceScopes
                RoleScopeTagIds    = $scopeTags
                PolicyId           = $policy.PolicyId
                PolicyName         = $policy.PolicyName
                CategoryId         = $policy.CategoryId
                PolicyScopeTagIds  = @($policy.ScopeTagIds)
                MatchingPolicyCount = $matchingPolicyInventory.Count
                CoverageStatus     = $coverageStatus
                CoverageErrors     = @($coverageMessages)
                BoundaryStatus     = if ($members.Count -eq 0) { 'Orphaned' } elseif ($isBroad) { 'Broad' } elseif ($policy) { 'InScope' } elseif ($coverageBlocking) { 'CoverageIncomplete' } else { 'NoMatchingPolicy' }
                Explanation        = if ($members.Count -eq 0) {
                    'The role assignment has no members.'
                }
                elseif ($isBroad) { 'The role assignment has no resource-scope restriction and applies to all scope tags.' }
                elseif ($policy) { 'The policy and role assignment share an Intune scope tag.' }
                elseif ($coverageBlocking) { 'Policy coverage is incomplete, so the administrative boundary could not be fully evaluated.' }
                else { 'No supplied policy shares this role assignment scope.' }
            }
            $result.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentAccess')
            $result
        }
    }
    $results = @($results)
    if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject $results -Path $OutputPath -Format $OutputFormat }
    $results | Write-Output
}
