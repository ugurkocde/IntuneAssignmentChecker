function Get-IntuneAssignmentDrift {
    <#
    .SYNOPSIS
    Captures or loads current assignment state and compares it with an approved baseline.

    .DESCRIPTION
    Combines snapshot capture and comparison, classifies the risk of every change,
    and can correlate changes with Intune audit events. Results can be emitted as
    JSON, JSON Lines, or CSV and optionally posted to a webhook. No Intune settings
    or assignments are modified.

    .PARAMETER BaselinePath
    Approved reference snapshot.

    .PARAMETER CurrentSnapshotPath
    Existing current snapshot. When omitted, the connected tenant is captured.

    .PARAMETER ApproveBaseline
    Copies the validated current snapshot to BaselinePath instead of comparing it.

    .PARAMETER IncludeAuditAttribution
    Queries beta Intune audit events and correlates actor and operation metadata.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType('IntuneAssignmentChecker.AssignmentDriftEvent')]
    param(
        [Parameter(Mandatory)]
        [string]$BaselinePath,

        [Parameter()]
        [string]$CurrentSnapshotPath,

        [Parameter()]
        [switch]$ApproveBaseline,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$AllowIncompleteCoverage,

        [Parameter()]
        [switch]$AllowCoverageMismatch,

        [Parameter()]
        [switch]$IncludeAuditAttribution,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'JsonLines',

        [Parameter()]
        [uri]$WebhookUri,

        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
        [string]$FailOnRisk = 'None',

        [Parameter()]
        [switch]$SetExitCode
    )

    $temporarySnapshot = $null
    try {
        if (-not $CurrentSnapshotPath) {
            if (-not $script:GraphEndpoint) { throw 'Connect first with Connect-IntuneAssignmentChecker or supply -CurrentSnapshotPath.' }
            $temporarySnapshot = Join-Path ([IO.Path]::GetTempPath()) "iac-current-$([guid]::NewGuid().ToString('N')).json"
            $null = Export-IntuneAssignmentSnapshot -Path $temporarySnapshot -Force -PassThru
            $CurrentSnapshotPath = $temporarySnapshot
        }
        $current = Read-IACAssignmentSnapshot -Path $CurrentSnapshotPath

        if ($ApproveBaseline) {
            $resolvedBaseline = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BaselinePath)
            if ((Test-Path -LiteralPath $resolvedBaseline) -and -not $Force) {
                throw "Baseline '$resolvedBaseline' already exists; use -Force to replace it."
            }
            $parent = Split-Path -Parent $resolvedBaseline
            if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Copy-Item -LiteralPath $CurrentSnapshotPath -Destination $resolvedBaseline -Force
            $approval = [PSCustomObject][ordered]@{
                SchemaName    = 'IntuneAssignmentChecker.BaselineApproval'
                SchemaVersion = 1
                BaselinePath  = $resolvedBaseline
                TenantId      = $current.Tenant.Id
                CapturedAtUtc = $current.CapturedAtUtc
                ApprovedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
                RecordCount   = @($current.Records).Count
                Complete      = -not (Test-IACCoverageHasBlockingFailure -Coverage $current.Coverage)
            }
            $approval.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.BaselineApproval')
            return $approval
        }

        $reference = Read-IACAssignmentSnapshot -Path $BaselinePath
        $compareParameters = @{
            ReferencePath = $BaselinePath
            DifferencePath = $CurrentSnapshotPath
            AllowIncompleteCoverage = $AllowIncompleteCoverage
            AllowCoverageMismatch = $AllowCoverageMismatch
        }
        $changes = @(Compare-IntuneAssignmentSnapshot @compareParameters)
        $auditEvents = @()
        if ($IncludeAuditAttribution) {
            if (-not $script:GraphEndpoint) { throw 'Audit attribution requires an active Microsoft Graph connection.' }
            $from = [datetimeoffset]::Parse("$($reference.CapturedAtUtc)").UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $to = [datetimeoffset]::Parse("$($current.CapturedAtUtc)").UtcDateTime.AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $auditUri = "/deviceManagement/auditEvents?`$filter=activityDateTime ge $from and activityDateTime le $to&`$orderby=activityDateTime desc&`$select=id,displayName,activityDateTime,actor,resources,activityOperationType,componentName&`$top=100"
            $auditEvents = @((Invoke-IACGraphRequest -Uri $auditUri -Method GET).value)
        }

        $events = foreach ($change in $changes) {
            $state = if ($change.After) { $change.After } else { $change.Before }
            $audit = $auditEvents | Where-Object {
                $candidateAuditEvent = $_
                @($candidateAuditEvent.resources | Where-Object {
                        $_.resourceId -eq $change.PolicyId -or $_.resourceId -eq $change.AssignmentId -or
                        ($state.PolicyName -and $_.displayName -eq $state.PolicyName)
                    }).Count -gt 0
            } | Sort-Object activityDateTime -Descending | Select-Object -First 1
            $risk = if ($change.ChangeType -eq 'Added' -and $change.After.TargetType -in @('AllUsers', 'AllDevices') -and $change.After.Intent -eq 'required') { 'Critical' }
            elseif ($change.ChangeType -eq 'Added' -and $change.After.TargetType -in @('AllUsers', 'AllDevices')) { 'High' }
            elseif ($change.ChangeType -eq 'Removed') { 'High' }
            elseif ($change.ChangedFields -contains 'AssignmentMode' -or $change.ChangedFields -contains 'TargetType') { 'High' }
            elseif ($change.ChangedFields -contains 'FilterRule' -or $change.ChangedFields -contains 'FilterId') { 'Medium' }
            else { 'Low' }
            $actor = if ($audit.actor) {
                if ($audit.actor.userPrincipalName) { $audit.actor.userPrincipalName }
                elseif ($audit.actor.applicationDisplayName) { $audit.actor.applicationDisplayName }
                elseif ($audit.actor.applicationId) { $audit.actor.applicationId }
                else { $audit.actor.type }
            }
            $driftEvent = [PSCustomObject][ordered]@{
                SchemaName       = 'IntuneAssignmentChecker.AssignmentDriftEvent'
                SchemaVersion    = 1
                TenantId         = $current.Tenant.Id
                TenantName       = $current.Tenant.Name
                BaselineCaptured = $reference.CapturedAtUtc
                CurrentCaptured  = $current.CapturedAtUtc
                ChangeType       = $change.ChangeType
                Risk             = $risk
                IdentityKey      = $change.IdentityKey
                CategoryId       = $change.CategoryId
                PolicyId         = $change.PolicyId
                PolicyName       = $state.PolicyName
                AssignmentId     = $change.AssignmentId
                ChangedFields    = @($change.ChangedFields)
                Before           = $change.Before
                After            = $change.After
                AuditEventId     = $audit.id
                AuditOperation   = if ($audit.displayName) { $audit.displayName } else { $audit.activityOperationType }
                AuditActor       = $actor
                AuditActivityUtc = $audit.activityDateTime
                Attribution      = if ($audit) { 'Correlated' } elseif ($IncludeAuditAttribution) { 'NotFound' } else { 'NotRequested' }
            }
            $driftEvent.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentDriftEvent')
            $driftEvent
        }

        $events = @($events)
        if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject $events -Path $OutputPath -Format $OutputFormat }
        if ($WebhookUri) {
            if (-not $WebhookUri.IsAbsoluteUri -or $WebhookUri.Scheme -cne 'https') {
                throw '-WebhookUri must be an absolute HTTPS URI.'
            }
            $payload = [PSCustomObject]@{
                schemaName = 'IntuneAssignmentChecker.AssignmentDriftBatch'
                schemaVersion = 1
                tenantId = $current.Tenant.Id
                generatedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
                events = $events
            } | ConvertTo-Json -Depth 30
            if ($PSCmdlet.ShouldProcess($WebhookUri.AbsoluteUri, 'Post assignment drift batch')) {
                $null = Invoke-RestMethod -Uri $WebhookUri -Method Post -ContentType 'application/json' -Body $payload -MaximumRedirection 0 -ErrorAction Stop
            }
        }
        $events | Write-Output

        $threshold = Get-IACSeverityRank -Severity $FailOnRisk
        $hasBlocking = $threshold -gt 0 -and @($events | Where-Object {
                (Get-IACSeverityRank -Severity $_.Risk) -ge $threshold
            }).Count -gt 0
        if ($SetExitCode) { $global:LASTEXITCODE = if ($hasBlocking) { 2 } else { 0 } }
        if ($hasBlocking) { throw "Assignment drift met or exceeded the configured $FailOnRisk risk threshold." }
    }
    finally {
        if ($temporarySnapshot -and (Test-Path -LiteralPath $temporarySnapshot)) {
            Remove-Item -LiteralPath $temporarySnapshot -Force -ErrorAction SilentlyContinue
        }
    }
}
