function Invoke-IntuneAssignmentScan {
    <#
    .SYNOPSIS
    Runs the shared Intune assignment provider registry with resumable checkpoints.

    .DESCRIPTION
    Produces one structured scan-run object containing canonical assignment records,
    coverage, errors, skips, and performance diagnostics. A checkpoint is written
    after every category, allowing an interrupted scan to resume without repeating
    completed workloads. The command is read-only.

    .PARAMETER Category
    Optional category IDs from the Effective provider registry. The default is every
    registered assignment category.

    .PARAMETER ScanBudgetSeconds
    Maximum wall-clock budget. The budget is checked between categories so a Graph
    request that is already in progress is allowed to finish safely.

    .PARAMETER CheckpointPath
    JSON checkpoint path. The file contains completed records and coverage metadata,
    but no credentials or access tokens.

    .PARAMETER Resume
    Resumes the exact category selection stored in CheckpointPath.

    .PARAMETER KeepCheckpoint
    Retains a completed checkpoint. Incomplete checkpoints are always retained.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentScanRun')]
    param(
        [Parameter()]
        [string[]]$Category = @(),

        [Parameter()]
        [ValidateRange(0, 86400)]
        [int]$ScanBudgetSeconds = 0,

        [Parameter()]
        [string]$CheckpointPath,

        [Parameter()]
        [switch]$Resume,

        [Parameter()]
        [switch]$KeepCheckpoint,

        [Parameter()]
        [switch]$ShowProgress
    )

    if (-not $script:GraphEndpoint) {
        throw 'Connect first with Connect-IntuneAssignmentChecker.'
    }
    if ($Resume -and -not $CheckpointPath) {
        throw '-Resume requires -CheckpointPath.'
    }

    $registry = @(Get-IntuneCategoryDefinition -Audience Effective)
    $knownIds = @($registry.Id)
    $selectedIds = if ($Category.Count -gt 0) { @($Category | Select-Object -Unique) } else { @($knownIds) }
    $unknown = @($selectedIds | Where-Object { $_ -notin $knownIds })
    if ($unknown.Count -gt 0) {
        throw "Unknown scan category: $($unknown -join ', '). Use Get-IntuneAssignmentOperation for command discovery."
    }

    $runId = [guid]::NewGuid().ToString('D')
    $startedAt = [datetimeoffset]::UtcNow
    $completedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $records = [System.Collections.Generic.List[object]]::new()
    $coverage = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    $resolvedCheckpoint = $null

    if ($CheckpointPath) {
        if ([IO.Path]::GetExtension($CheckpointPath) -ine '.json') { throw 'CheckpointPath must be a .json file.' }
        $resolvedCheckpoint = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CheckpointPath)
        if ($Resume) {
            if (-not (Test-Path -LiteralPath $resolvedCheckpoint -PathType Leaf)) {
                throw "Checkpoint '$resolvedCheckpoint' does not exist."
            }
            $checkpoint = Get-Content -LiteralPath $resolvedCheckpoint -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 50 -ErrorAction Stop
            if ($checkpoint.SchemaName -ne 'IntuneAssignmentChecker.AssignmentScanCheckpoint' -or [int]$checkpoint.SchemaVersion -ne 1) {
                throw "Checkpoint '$resolvedCheckpoint' does not use the supported assignment scan checkpoint schema."
            }
            if (@(Compare-Object -ReferenceObject @($checkpoint.SelectedCategories) -DifferenceObject @($selectedIds)).Count -gt 0 -and $PSBoundParameters.ContainsKey('Category')) {
                throw 'The requested categories do not match the checkpoint category selection.'
            }
            $selectedIds = @($checkpoint.SelectedCategories)
            $runId = "$($checkpoint.RunId)"
            $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
            $startedAt = [datetimeoffset]::Parse("$($checkpoint.StartedAtUtc)", [Globalization.CultureInfo]::InvariantCulture, $styles)
            foreach ($id in @($checkpoint.CompletedCategories)) { [void]$completedIds.Add("$id") }
            foreach ($record in @($checkpoint.Records)) { [void]$records.Add((ConvertTo-IntuneAssignmentRecord -InputObject $record)) }
            foreach ($item in @($checkpoint.Coverage)) { [void]$coverage.Add($item) }
            foreach ($item in @($checkpoint.Errors)) { [void]$errors.Add($item) }
            foreach ($item in @($checkpoint.Skipped)) { [void]$skipped.Add($item) }
        }
        elseif (Test-Path -LiteralPath $resolvedCheckpoint) {
            throw "Checkpoint '$resolvedCheckpoint' already exists; use -Resume or choose another path."
        }
    }

    $saveCheckpoint = {
        if (-not $resolvedCheckpoint) { return }
        $parent = Split-Path -Parent $resolvedCheckpoint
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $document = [PSCustomObject][ordered]@{
            SchemaName          = 'IntuneAssignmentChecker.AssignmentScanCheckpoint'
            SchemaVersion       = 1
            RunId               = $runId
            StartedAtUtc        = $startedAt.ToUniversalTime().ToString('o')
            UpdatedAtUtc        = [datetimeoffset]::UtcNow.ToString('o')
            TenantId            = $script:CurrentTenantId
            SelectedCategories  = @($selectedIds)
            CompletedCategories = @($selectedIds | Where-Object { $completedIds.Contains($_) })
            Records             = @($records)
            Coverage            = @($coverage)
            Errors              = @($errors)
            Skipped             = @($skipped)
        }
        $temporaryPath = "$resolvedCheckpoint.tmp"
        [IO.File]::WriteAllText($temporaryPath, ($document | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $resolvedCheckpoint -Force
    }

    $entityCache = @{}
    $budgetExceeded = $false
    $categories = @($registry | Where-Object { $_.Id -in $selectedIds })
    foreach ($categoryDefinition in $categories) {
        if ($completedIds.Contains($categoryDefinition.Id)) { continue }
        $elapsed = [datetimeoffset]::UtcNow - $startedAt
        if ($ScanBudgetSeconds -gt 0 -and $elapsed.TotalSeconds -ge $ScanBudgetSeconds) {
            $budgetExceeded = $true
            break
        }

        # A resumed failed category replaces its previous failure/coverage entry.
        for ($index = $coverage.Count - 1; $index -ge 0; $index--) {
            if ($coverage[$index].CategoryId -eq $categoryDefinition.Id) { $coverage.RemoveAt($index) }
        }
        for ($index = $errors.Count - 1; $index -ge 0; $index--) {
            if ($errors[$index].CategoryId -eq $categoryDefinition.Id) { $errors.RemoveAt($index) }
        }

        $categoryStarted = [datetimeoffset]::UtcNow
        $scan = Invoke-IntuneCategoryScan -Categories @($categoryDefinition) -ProcessEntity {} `
            -EntityCache $entityCache -BuildRecords -ShowProgress:$ShowProgress -ProgressVerb 'Scanning'
        foreach ($record in @($scan.Records)) { [void]$records.Add($record) }
        foreach ($item in @($scan.Errors)) {
            [void]$errors.Add([PSCustomObject][ordered]@{
                    CategoryId  = "$($item.CategoryId)"
                    DisplayName = "$($item.DisplayName)"
                    Message     = "$($item.Message)"
                })
        }
        foreach ($item in @($scan.Skipped)) {
            [void]$skipped.Add([PSCustomObject][ordered]@{
                    CategoryId  = "$($item.CategoryId)"
                    DisplayName = "$($item.DisplayName)"
                    Message     = "$($item.Message)"
                })
        }
        $status = if (@($scan.Errors).Count -gt 0) { 'Failed' } elseif (@($scan.Skipped).Count -gt 0) { 'Skipped' } else { 'Captured' }
        [void]$coverage.Add([PSCustomObject][ordered]@{
                CategoryId    = $categoryDefinition.Id
                DisplayName   = $categoryDefinition.DisplayName
                Status        = $status
                RecordCount   = @($scan.Records).Count
                DurationMs    = [math]::Round(([datetimeoffset]::UtcNow - $categoryStarted).TotalMilliseconds)
            })
        if (@($scan.Errors).Count -eq 0) { [void]$completedIds.Add($categoryDefinition.Id) }
        & $saveCheckpoint
    }

    $completedAt = [datetimeoffset]::UtcNow
    $remaining = @($selectedIds | Where-Object { -not $completedIds.Contains($_) })
    $isComplete = -not $budgetExceeded -and $remaining.Count -eq 0 -and $errors.Count -eq 0
    $result = [PSCustomObject][ordered]@{
        SchemaName      = 'IntuneAssignmentChecker.AssignmentScanRun'
        SchemaVersion   = 1
        RunId           = $runId
        TenantId        = $script:CurrentTenantId
        TenantName      = $script:CurrentTenantName
        StartedAtUtc    = $startedAt.ToUniversalTime().ToString('o')
        CompletedAtUtc  = $completedAt.ToUniversalTime().ToString('o')
        DurationMs      = [math]::Round(($completedAt - $startedAt).TotalMilliseconds)
        Complete        = $isComplete
        BudgetExceeded  = $budgetExceeded
        Selected        = @($selectedIds)
        Completed       = @($selectedIds | Where-Object { $completedIds.Contains($_) })
        Remaining       = $remaining
        Coverage        = @($coverage)
        Records         = @($records)
        Errors          = @($errors)
        Skipped         = @($skipped)
        Diagnostics     = [PSCustomObject][ordered]@{
            ProviderCount         = $selectedIds.Count
            CompletedProviderCount = $completedIds.Count
            RecordCount           = $records.Count
            ErrorCount            = $errors.Count
            SkippedCount          = $skipped.Count
            EntityCacheEntryCount = $entityCache.Count
            CheckpointPath        = $resolvedCheckpoint
            GraphApiVersion       = 'beta'
        }
    }
    $result.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentScanRun')

    if ($resolvedCheckpoint -and ($KeepCheckpoint -or -not $isComplete)) { & $saveCheckpoint }
    elseif ($resolvedCheckpoint -and (Test-Path -LiteralPath $resolvedCheckpoint)) {
        Remove-Item -LiteralPath $resolvedCheckpoint -Force
    }
    $result
}
