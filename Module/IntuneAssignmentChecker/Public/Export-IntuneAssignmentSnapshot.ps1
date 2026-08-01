function Export-IntuneAssignmentSnapshot {
    <#
    .SYNOPSIS
    Captures Intune assignment state in a deterministic, schema-versioned JSON file.

    .DESCRIPTION
    With no pipeline input, scans the connected tenant through the shared category
    engine. Canonical assignment records are sorted by stable identity and projected
    through a fixed allowlist so credentials, tokens, and arbitrary extra properties
    cannot enter the snapshot.

    .PARAMETER Path
    Destination .json file.

    .PARAMETER InputObject
    Optional canonical assignment records to snapshot instead of scanning the tenant.

    .PARAMETER CoverageCategory
    Optional category IDs describing the coverage of supplied InputObject records.

    .PARAMETER CoverageComplete
    Declares supplied InputObject coverage complete. Supplied records default to
    incomplete because the cmdlet cannot infer whether an upstream scan failed.

    .PARAMETER CoverageError
    Optional objects with CategoryId and Message describing upstream scan failures.

    .PARAMETER CapturedAtUtc
    Capture timestamp. Defaults to the current UTC time; it can be fixed for
    reproducible builds and tests.

    .PARAMETER Force
    Overwrites an existing snapshot file.

    .PARAMETER PassThru
    Returns the in-memory snapshot document after writing it.

    .EXAMPLE
    Export-IntuneAssignmentSnapshot -Path './snapshots/intune.json'

    .EXAMPLE
    Get-IntuneAllPolicies -PassThru | Export-IntuneAssignmentSnapshot -Path './snapshot.json' -CoverageComplete
    #>
    [CmdletBinding(DefaultParameterSetName = 'Tenant')]
    [OutputType('IntuneAssignmentChecker.AssignmentSnapshot')]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Records')]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(ParameterSetName = 'Records')]
        [string[]]$CoverageCategory = @(),

        [Parameter(ParameterSetName = 'Records')]
        [switch]$CoverageComplete,

        [Parameter(ParameterSetName = 'Records')]
        [object[]]$CoverageError = @(),

        [Parameter()]
        [datetimeoffset]$CapturedAtUtc = [datetimeoffset]::UtcNow,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $inputRecords = [System.Collections.Generic.List[object]]::new()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Records') {
            foreach ($record in @($InputObject)) {
                if ($null -ne $record) { [void]$inputRecords.Add($record) }
            }
        }
    }

    end {
        if ([System.IO.Path]::GetExtension($Path) -ine '.json') {
            throw 'Path must be a .json file.'
        }
        $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
        if ((Test-Path -LiteralPath $resolvedPath) -and -not $Force) {
            throw "Assignment snapshot '$resolvedPath' already exists; use -Force to overwrite it."
        }
        $parentPath = Split-Path -Parent $resolvedPath
        if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
            New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
        }

        $coverageErrors = @()
        if ($PSCmdlet.ParameterSetName -eq 'Tenant') {
            if ([string]::IsNullOrWhiteSpace($script:GraphEndpoint)) {
                throw 'Connect first with Connect-IntuneAssignmentChecker.'
            }
            if ($null -eq $script:AssignmentFilterLookup) {
                $script:AssignmentFilterLookup = Get-AssignmentFilterLookup
            }
            $categories = @(Get-IntuneCategoryDefinition -Audience Effective)
            $scan = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity {} -EntityCache @{} `
                -ShowProgress -ProgressVerb 'Capturing' -BuildRecords
            $records = @($scan.Records | Where-Object { $null -ne $_ })
            $coverageErrors = @($scan.Errors | Where-Object { $null -ne $_ } | ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace("$($_.CategoryId)") -or [string]::IsNullOrWhiteSpace("$($_.Message)")) {
                        throw 'The category scanner returned an error without CategoryId or Message.'
                    }
                    [PSCustomObject][ordered]@{
                        CategoryId = $_.CategoryId
                        Message    = $_.Message
                    }
                })
            $coverageSkipped = @($scan.Skipped | Where-Object { $null -ne $_ } | ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace("$($_.CategoryId)") -or [string]::IsNullOrWhiteSpace("$($_.Message)")) {
                        throw 'The category scanner returned a skipped category without CategoryId or Message.'
                    }
                    [PSCustomObject][ordered]@{
                        CategoryId = $_.CategoryId
                        Message    = $_.Message
                    }
                })
            $declaredCategoryIds = foreach ($category in $categories) {
                if ($null -eq $category -or [string]::IsNullOrWhiteSpace("$($category.Id)")) {
                    throw 'The category scanner returned a category definition without Id.'
                }
                "$($category.Id)"
            }
            $declaredCategoryIds = @($declaredCategoryIds)
            $uniqueDeclaredCategoryIds = @(Get-IACOrdinalSortedUniqueString -InputObject $declaredCategoryIds)
            if ($declaredCategoryIds.Count -ne $uniqueDeclaredCategoryIds.Count) {
                throw 'The category scanner returned duplicate category definitions.'
            }
            $recordCategoryIds = @(Get-IACOrdinalSortedUniqueString -InputObject @(
                    $records.CategoryId | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
                ))
            $missingCoverage = @($recordCategoryIds | Where-Object { $_ -cnotin $uniqueDeclaredCategoryIds })
            if ($missingCoverage.Count -gt 0) {
                throw "The category scanner returned records outside declared coverage: $($missingCoverage -join ', ')."
            }
            $errorsOutsideCoverage = @($coverageErrors | Where-Object { $_.CategoryId -cnotin $uniqueDeclaredCategoryIds } |
                    ForEach-Object { $_.CategoryId })
            if ($errorsOutsideCoverage.Count -gt 0) {
                throw "The category scanner returned errors outside declared coverage: $($errorsOutsideCoverage -join ', ')."
            }
            $skipsOutsideCoverage = @($coverageSkipped | Where-Object { $_.CategoryId -cnotin $uniqueDeclaredCategoryIds } |
                    ForEach-Object { $_.CategoryId })
            if ($skipsOutsideCoverage.Count -gt 0) {
                throw "The category scanner returned skipped categories outside declared coverage: $($skipsOutsideCoverage -join ', ')."
            }
            $coverageCategories = foreach ($category in $categories) {
                $categoryError = $coverageErrors | Where-Object CategoryId -CEQ $category.Id | Select-Object -First 1
                $categorySkipped = $coverageSkipped | Where-Object CategoryId -CEQ $category.Id | Select-Object -First 1
                [PSCustomObject][ordered]@{
                    CategoryId  = $category.Id
                    DisplayName = $category.DisplayName
                    Status      = if ($categoryError) { 'Failed' } elseif ($categorySkipped) { 'Skipped' } else { 'Captured' }
                    RecordCount = @($records | Where-Object CategoryId -CEQ $category.Id).Count
                }
            }
            $coverageErrors = @($coverageErrors) + @($coverageSkipped)
            $coverageMode = 'TenantScan'
            $resolvedCoverageComplete = @($coverageErrors).Count -eq 0
        }
        else {
            $records = @($inputRecords)
            $recordCategoryIds = @(Get-IACOrdinalSortedUniqueString -InputObject @(
                    $records.CategoryId | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
                ))
            $declaredCategoryIds = if ($CoverageCategory.Count -gt 0) {
                @(Get-IACOrdinalSortedUniqueString -InputObject @(
                        $CoverageCategory | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    ))
            }
            else {
                $recordCategoryIds
            }
            $coverageErrors = foreach ($coverageErrorItem in @($CoverageError)) {
                $hasCategoryId = if ($coverageErrorItem -is [System.Collections.IDictionary]) {
                    $coverageErrorItem.Contains('CategoryId')
                }
                else { $null -ne $coverageErrorItem.PSObject.Properties['CategoryId'] }
                $hasMessage = if ($coverageErrorItem -is [System.Collections.IDictionary]) {
                    $coverageErrorItem.Contains('Message')
                }
                else { $null -ne $coverageErrorItem.PSObject.Properties['Message'] }
                if (-not $hasCategoryId -or -not $hasMessage) {
                    throw 'Every CoverageError must contain CategoryId and Message.'
                }
                $errorCategoryId = "$($coverageErrorItem.CategoryId)"
                $errorMessage = "$($coverageErrorItem.Message)"
                if ([string]::IsNullOrWhiteSpace($errorCategoryId) -or [string]::IsNullOrWhiteSpace($errorMessage)) {
                    throw 'Every CoverageError requires non-empty CategoryId and Message.'
                }
                [PSCustomObject][ordered]@{
                    CategoryId = $errorCategoryId
                    Message = $errorMessage
                }
            }
            $categoryIds = @(Get-IACOrdinalSortedUniqueString -InputObject @(
                    $declaredCategoryIds
                    $coverageErrors.CategoryId
                ))
            $missingCoverage = @($recordCategoryIds | Where-Object { $_ -cnotin $categoryIds })
            if ($missingCoverage.Count -gt 0) {
                throw "CoverageCategory does not include record categories: $($missingCoverage -join ', ')."
            }
            $coverageCategories = foreach ($categoryId in $categoryIds) {
                $categoryError = $coverageErrors | Where-Object CategoryId -CEQ $categoryId | Select-Object -First 1
                [PSCustomObject][ordered]@{
                    CategoryId  = "$categoryId"
                    DisplayName = $null
                    Status      = if ($categoryError) { 'Failed' } elseif ($CoverageComplete) { 'Provided' } else { 'Unknown' }
                    RecordCount = @($records | Where-Object CategoryId -CEQ $categoryId).Count
                }
            }
            $coverageMode = 'ProvidedRecords'
            $resolvedCoverageComplete = [bool]$CoverageComplete -and @($coverageErrors).Count -eq 0
        }

        $snapshot = New-IACAssignmentSnapshot -Records $records -CapturedAtUtc $CapturedAtUtc `
            -CoverageCategories @($coverageCategories) -CoverageErrors @($coverageErrors) `
            -CoverageComplete $resolvedCoverageComplete -CoverageMode $coverageMode
        $snapshot.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentSnapshot')
        Write-IACAssignmentSnapshot -Snapshot $snapshot -Path $resolvedPath
        Write-Verbose "Assignment snapshot written to '$resolvedPath'."

        if ($PassThru) { return $snapshot }
    }
}
