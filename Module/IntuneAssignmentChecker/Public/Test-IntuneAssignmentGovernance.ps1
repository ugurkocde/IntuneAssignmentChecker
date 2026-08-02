function Test-IntuneAssignmentGovernance {
    <#
    .SYNOPSIS
    Evaluates Intune assignment records against configurable governance rules.

    .DESCRIPTION
    Scans the connected tenant, a saved snapshot, or pipeline assignment records.
    Findings include severity, stable rule and finding IDs, evidence, remediation,
    and optional waiver state. The cmdlet never changes Intune assignments.

    .PARAMETER SnapshotPath
    Saved assignment snapshot to evaluate offline.

    .PARAMETER InputObject
    Assignment records supplied through the pipeline.

    .PARAMETER RulePath
    Optional JSON rule configuration replacing the built-in rule pack.

    .PARAMETER WaiverPath
    Optional JSON waiver document with RuleId, optional PolicyId/TargetId,
    owner, justification, and ExpiresAtUtc fields.

    .PARAMETER SkipGroupResolution
    Does not query target group membership. Offline snapshots automatically skip it.

    .PARAMETER FailOnSeverity
    Throws when an unsuppressed finding at or above this severity exists.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Tenant')]
    [OutputType('IntuneAssignmentChecker.GovernanceFinding')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Snapshot')]
        [string]$SnapshotPath,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Records')]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter()]
        [string]$RulePath,

        [Parameter()]
        [string]$WaiverPath,

        [Parameter()]
        [switch]$IncludeSuppressed,

        [Parameter()]
        [switch]$SkipGroupResolution,

        [Parameter()]
        [string[]]$CriticalCategory = @('CompliancePolicies', 'Applications', 'ESAntivirus', 'ESEndpointDetection'),

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'Json',

        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
        [string]$FailOnSeverity = 'None',

        [Parameter()]
        [switch]$SetExitCode
    )

    begin { $pipelineRecords = [System.Collections.Generic.List[object]]::new() }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Records') {
            foreach ($record in @($InputObject)) { if ($null -ne $record) { [void]$pipelineRecords.Add($record) } }
        }
    }
    end {
        $coverage = $null
        $resolveGroups = $false
        switch ($PSCmdlet.ParameterSetName) {
            'Snapshot' {
                $snapshot = Read-IACAssignmentSnapshot -Path $SnapshotPath
                $records = @($snapshot.Records)
                $coverage = $snapshot.Coverage
            }
            'Records' { $records = @($pipelineRecords) }
            default {
                if (-not $script:GraphEndpoint) { throw 'Connect first with Connect-IntuneAssignmentChecker or supply -SnapshotPath/-InputObject.' }
                if ($null -eq $script:AssignmentFilterLookup) { $script:AssignmentFilterLookup = Get-AssignmentFilterLookup }
                $categories = @(Get-IntuneCategoryDefinition -Audience Effective)
                $scan = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{} -BuildRecords
                $records = @($scan.Records)
                $coverage = [PSCustomObject]@{
                    Complete   = @($scan.Errors).Count -eq 0
                    Categories = @($categories | ForEach-Object {
                            $category = $_
                            [PSCustomObject]@{
                                CategoryId = $category.Id
                                Status = if (@($scan.Errors | Where-Object CategoryId -EQ $category.Id).Count -gt 0) { 'Failed' } else { 'Captured' }
                            }
                        })
                    Errors     = @($scan.Errors)
                }
                $resolveGroups = -not $SkipGroupResolution
            }
        }

        $rules = @(Get-IACGovernanceRule -RulePath $RulePath)
        $ruleById = @{}
        foreach ($rule in $rules) { if ($rule.enabled) { $ruleById["$($rule.id)"] = $rule } }
        $waivers = @()
        if ($WaiverPath) {
            $waiverDocument = Get-Content -LiteralPath $WaiverPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 -ErrorAction Stop
            $waivers = if ($waiverDocument.Waivers) { @($waiverDocument.Waivers) } else { @($waiverDocument) }
            foreach ($waiverEntry in $waivers) {
                foreach ($requiredWaiverField in @('RuleId', 'Owner', 'Justification', 'ExpiresAtUtc')) {
                    if ([string]::IsNullOrWhiteSpace("$($waiverEntry.$requiredWaiverField)")) {
                        throw "Governance waivers require $requiredWaiverField."
                    }
                }
            }
        }
        $findings = [System.Collections.Generic.List[object]]::new()
        $addFinding = {
            param($RuleId, $Record, $Message, $Remediation, $Evidence)
            if (-not $ruleById.ContainsKey($RuleId)) { return }
            $waiver = Find-IACGovernanceWaiver -Waiver $waivers -RuleId $RuleId -PolicyId "$($Record.PolicyId)" -TargetId "$($Record.TargetId)"
            $finding = New-IACGovernanceFinding -Rule $ruleById[$RuleId] -Record $Record -Message $Message -Remediation $Remediation -Evidence $Evidence -Waiver $waiver
            if (-not $finding.Suppressed -or $IncludeSuppressed) { [void]$findings.Add($finding) }
        }

        foreach ($record in $records) {
            if ($record.TargetType -eq 'AllUsers' -and $record.AssignmentMode -eq 'Include') {
                & $addFinding 'IAC001' $record "'$($record.PolicyName)' targets All Users." 'Replace broad targeting with approved groups or document a time-bound waiver.' @{ TargetType = 'AllUsers'; Intent = $record.Intent }
            }
            if ($record.TargetType -eq 'AllDevices' -and $record.AssignmentMode -eq 'Include') {
                & $addFinding 'IAC002' $record "'$($record.PolicyName)' targets All Devices." 'Replace broad targeting with approved device groups or document a time-bound waiver.' @{ TargetType = 'AllDevices'; Intent = $record.Intent }
            }
            if ($record.TargetType -eq 'Group' -and [string]::IsNullOrWhiteSpace("$($record.TargetName)")) {
                & $addFinding 'IAC004' $record "Target group '$($record.TargetId)' could not be resolved." 'Restore the target group or remove the stale assignment.' @{ Resolution = 'Unresolved' }
            }
            if ($record.FilterId -and $record.EffectiveState -eq 'Unknown') {
                & $addFinding 'IAC006' $record "Assignment filter '$($record.FilterId)' produced an unknown effective result." 'Validate the filter rule, supported properties, platform, and device inventory values.' @{ FilterId = $record.FilterId; FilterRule = $record.FilterRule; FilterPlatform = $record.FilterPlatform }
            }
            if ($record.AssignmentMode -eq 'None' -and $record.CategoryId -in $CriticalCategory) {
                & $addFinding 'IAC008' $record "Critical item '$($record.PolicyName)' has no assignments." 'Assign the item to an approved target or remove it from the critical category list.' @{ CriticalCategory = $record.CategoryId }
            }
        }

        foreach ($policyGroup in @($records | Where-Object { $_.PolicyId } | Group-Object PolicyId)) {
            $policyRecords = @($policyGroup.Group)
            $sample = $policyRecords[0]
            if ($sample.CategoryId -eq 'Applications' -and $policyRecords.Intent -contains 'required' -and
                @($policyRecords | Where-Object AssignmentMode -EQ 'Exclude').Count -eq 0) {
                & $addFinding 'IAC003' $sample "Required application '$($sample.PolicyName)' has no exclusion assignment." 'Add an appropriate exclusion group and document the rollback population.' @{ Intents = @($policyRecords.Intent | Sort-Object -Unique) }
            }
            foreach ($targetGroup in @($policyRecords | Where-Object TargetId | Group-Object TargetId)) {
                $modes = @($targetGroup.Group.AssignmentMode | Sort-Object -Unique)
                if ($modes -contains 'Include' -and $modes -contains 'Exclude') {
                    & $addFinding 'IAC005' $targetGroup.Group[0] "'$($sample.PolicyName)' both includes and excludes target '$($targetGroup.Name)'." 'Remove the contradictory assignment and validate effective targeting before deployment.' @{ Modes = $modes }
                }
            }
        }

        if ($coverage -and (Test-IACCoverageHasBlockingFailure -Coverage $coverage)) {
            $coverageRecord = if ($snapshot) {
                [PSCustomObject]@{ TenantId = $snapshot.Tenant.Id; TenantName = $snapshot.Tenant.Name }
            }
            else { [PSCustomObject]@{ TenantId = $script:CurrentTenantId; TenantName = $script:CurrentTenantName } }
            & $addFinding 'IAC007' $coverageRecord 'The evaluated snapshot has incomplete scan coverage.' 'Resolve failed or skipped workload scans and capture a complete snapshot.' @{ Categories = $coverage.Categories; Errors = $coverage.Errors }
        }

        if ($resolveGroups -and $ruleById.ContainsKey('IAC004')) {
            foreach ($groupRecord in @($records | Where-Object { $_.TargetType -eq 'Group' -and $_.TargetId } | Sort-Object TargetId -Unique)) {
                try {
                    $groupId = [uri]::EscapeDataString("$($groupRecord.TargetId)")
                    $members = Invoke-IACGraphRequest -Uri "/groups/$groupId/members?`$select=id&`$top=1" -Method GET -FirstPageOnly -ErrorAction Stop
                    if (@($members.value).Count -eq 0) {
                        & $addFinding 'IAC004' $groupRecord "Target group '$($groupRecord.TargetName)' is empty." 'Populate the target group or remove the ineffective assignment.' @{ Resolution = 'Empty'; MemberCountSample = 0 }
                    }
                }
                catch {
                    & $addFinding 'IAC004' $groupRecord "Target group '$($groupRecord.TargetId)' could not be checked: $($_.Exception.Message)" 'Verify GroupMember.Read.All and confirm that the target group still exists.' @{ Resolution = 'CheckFailed' }
                }
            }
        }

        $orderedFindings = @($findings | Sort-Object @{ Expression = { -(Get-IACSeverityRank $_.Severity) } }, RuleId, PolicyName, TargetName)
        if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject $orderedFindings -Path $OutputPath -Format $OutputFormat }
        $orderedFindings | Write-Output

        $threshold = Get-IACSeverityRank -Severity $FailOnSeverity
        $hasBlocking = $threshold -gt 0 -and @($orderedFindings | Where-Object {
                -not $_.Suppressed -and (Get-IACSeverityRank -Severity $_.Severity) -ge $threshold
            }).Count -gt 0
        if ($SetExitCode) { $global:LASTEXITCODE = if ($hasBlocking) { 2 } else { 0 } }
        if ($hasBlocking) { throw "Governance findings met or exceeded the configured $FailOnSeverity threshold." }
    }
}
