function Get-IntuneEffectiveAssignment {
    <#
    .SYNOPSIS
    Explains effective Intune assignment targeting for a user, a managed device, or both.

    .DESCRIPTION
    Combines All Users, All Devices, transitive user/device group membership,
    group exclusions, and assignment-filter evaluation. Results are Included,
    Excluded, NotTargeted, or Unknown with a machine-readable ReasonChain.

    This command explains assignment targeting only. It does not prove delivery,
    platform applicability, installation, execution, compliance, or device check-in.

    .PARAMETER UserPrincipalName
    Optional user principal name. Supply a user, a managed device, or both.

    .PARAMETER DeviceName
    Optional Intune managed-device name or managed-device ID.

    .PARAMETER PassThru
    Returns IntuneAssignmentChecker.AssignmentRecord objects with EffectiveState
    and ReasonChain fields.

    .PARAMETER ExportToCSV
    Exports effective results, including a compact JSON reason chain, to CSV.

    .PARAMETER ExportPath
    CSV destination. The path must end in .csv. Supplying it enables export.

    .EXAMPLE
    Get-IntuneEffectiveAssignment -UserPrincipalName 'user@contoso.com'

    .EXAMPLE
    Get-IntuneEffectiveAssignment -UserPrincipalName 'user@contoso.com' -DeviceName 'WIN-01' -PassThru

    .EXAMPLE
    Get-IntuneEffectiveAssignment -DeviceName 'WIN-01' -ExportPath './effective.csv'
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentRecord')]
    param(
        [Parameter()]
        [string]$UserPrincipalName,

        [Parameter()]
        [string]$DeviceName,

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -and [string]::IsNullOrWhiteSpace($DeviceName)) {
        Write-Error 'Supply -UserPrincipalName, -DeviceName, or both.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($script:GraphEndpoint)) {
        Write-Error 'Connect first with Connect-IntuneAssignmentChecker.'
        return
    }
    if (-not [string]::IsNullOrWhiteSpace($ExportPath) -and [System.IO.Path]::GetExtension($ExportPath) -ine '.csv') {
        Write-Error 'ExportPath must be a .csv file.'
        return
    }

    $userInfo = $null
    $managedDevice = $null
    $directoryDevice = $null
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $userInfo = Get-UserInfo -UserPrincipalName $UserPrincipalName.Trim()
        if (-not $userInfo.Success) {
            Write-Error "User '$UserPrincipalName' was not found."
            return
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
        $managedDeviceResult = Get-IACManagedDevice -Identity $DeviceName.Trim()
        if (-not $managedDeviceResult.Success) {
            Write-Error $managedDeviceResult.Reason
            return
        }
        $managedDevice = $managedDeviceResult.Device
        if (-not [string]::IsNullOrWhiteSpace("$($managedDevice.azureADDeviceId)")) {
            $directoryResult = Get-IACDirectoryDevice -AzureADDeviceId "$($managedDevice.azureADDeviceId)"
            if ($directoryResult.Success) { $directoryDevice = $directoryResult.Device }
            else { Write-Warning $directoryResult.Reason }
        }
        else {
            Write-Warning 'The managed device has no azureADDeviceId; device group targeting will remain Unknown.'
        }
    }

    if ($null -eq $script:AssignmentFilterLookup) {
        $script:AssignmentFilterLookup = Get-AssignmentFilterLookup
    }

    $membershipSources = @{}
    $userMembershipKnown = $true
    $deviceMembershipKnown = $true
    if ($userInfo) {
        try {
            foreach ($group in @(Get-GroupMemberships -ObjectId $userInfo.Id -ObjectType User)) {
                if (-not $group.id) { continue }
                $key = "$($group.id)"
                if (-not $membershipSources.ContainsKey($key)) {
                    $membershipSources[$key] = [PSCustomObject]@{ Name = $group.displayName; Sources = [System.Collections.Generic.List[string]]::new() }
                }
                if (-not $membershipSources[$key].Sources.Contains('User')) { [void]$membershipSources[$key].Sources.Add('User') }
            }
        }
        catch {
            $userMembershipKnown = $false
            Write-Warning "User transitive group membership is incomplete: $($_.Exception.Message)"
        }
    }
    if ($managedDevice) {
        if ($directoryDevice) {
            try {
                foreach ($group in @(Get-GroupMemberships -ObjectId $directoryDevice.id -ObjectType Device)) {
                    if (-not $group.id) { continue }
                    $key = "$($group.id)"
                    if (-not $membershipSources.ContainsKey($key)) {
                        $membershipSources[$key] = [PSCustomObject]@{ Name = $group.displayName; Sources = [System.Collections.Generic.List[string]]::new() }
                    }
                    if (-not $membershipSources[$key].Sources.Contains('Device')) { [void]$membershipSources[$key].Sources.Add('Device') }
                }
            }
            catch {
                $deviceMembershipKnown = $false
                Write-Warning "Device transitive group membership is incomplete: $($_.Exception.Message)"
            }
        }
        else { $deviceMembershipKnown = $false }
    }

    $subjectType = if ($userInfo -and $managedDevice) { 'UserDevice' } elseif ($userInfo) { 'User' } else { 'Device' }
    $subjectId = if ($userInfo -and $managedDevice) { "$($userInfo.Id)|$($managedDevice.id)" }
        elseif ($userInfo) { "$($userInfo.Id)" } else { "$($managedDevice.id)" }
    $subjectName = if ($userInfo -and $managedDevice) { "$($userInfo.UserPrincipalName) on $($managedDevice.deviceName)" }
        elseif ($userInfo) { "$($userInfo.UserPrincipalName)" } else { "$($managedDevice.deviceName)" }

    $effectiveRecords = [System.Collections.Generic.List[object]]::new()
    $categories = Get-IntuneCategoryDefinition -Audience Effective
    $entityCache = @{}
    $processEntity = {
        param($context)

        $assignmentSets = if ($context.Category.Id -eq 'Applications' -and $context.Assignments.Count -gt 0) {
            @($context.Assignments | Group-Object { if ([string]::IsNullOrWhiteSpace("$($_.Intent)")) { 'none' } else { "$($_.Intent)".ToLowerInvariant() } } |
                    ForEach-Object { [PSCustomObject]@{ Intent = $_.Name; Assignments = @($_.Group) } })
        }
        else {
            @([PSCustomObject]@{ Intent = $null; Assignments = @($context.Assignments) })
        }

        foreach ($assignmentSet in $assignmentSets) {
            $effectiveCategory = $context.Category.PSObject.Copy()
            if ($context.Category.Id -eq 'Applications') {
                $effectiveCategory.ExportCategory = switch ($assignmentSet.Intent) {
                    'required' { 'Required App' }
                    'available' { 'Available App' }
                    'uninstall' { 'Uninstall App' }
                    default { 'Application' }
                }
            }
            $record = Resolve-IACEffectiveAssignment -Category $effectiveCategory -Entity $context.Entity `
                -Assignments $assignmentSet.Assignments -MembershipSources $membershipSources `
                -HasUser:($null -ne $userInfo) -HasDevice:($null -ne $managedDevice) `
                -UserMembershipKnown $userMembershipKnown -DeviceMembershipKnown $deviceMembershipKnown `
                -ManagedDevice $managedDevice -SubjectType $subjectType -SubjectId $subjectId -SubjectName $subjectName
            [void]$effectiveRecords.Add($record)
        }
    }

    $scan = Invoke-IntuneCategoryScan -Categories $categories -ProcessEntity $processEntity `
        -EntityCache $entityCache -ShowProgress -ProgressVerb 'Evaluating'
    if ($scan.Errors.Count -gt 0) {
        foreach ($scanError in $scan.Errors) {
            $failedCategory = $categories | Where-Object Id -eq $scanError.CategoryId | Select-Object -First 1
            $categoryName = if ($failedCategory.ExportCategory) { $failedCategory.ExportCategory }
                elseif ($scanError.DisplayName) { $scanError.DisplayName }
                else { $scanError.CategoryId }
            $failureReason = [PSCustomObject][ordered]@{
                Sequence          = 1
                Code              = 'Scan.CategoryFailed'
                FilterCode        = $null
                Outcome           = 'Unknown'
                AssignmentId      = $null
                AssignmentMode    = 'Unknown'
                TargetType        = 'Unknown'
                TargetId          = $null
                MembershipSources = @()
                TargetResult      = 'Unknown'
                FilterId          = $null
                FilterMode        = $null
                FilterResult      = 'Unknown'
                Message           = "$($scanError.Message)"
            }
            $failureRecord = New-IACAssignmentRecord `
                -CategoryId "$($scanError.CategoryId)" -Category "$categoryName" `
                -PolicyId '' -PolicyName '[Category scan failed]' `
                -Platform $(if ($failedCategory.Platform) { $failedCategory.Platform } else { 'Unknown' }) `
                -AssignmentMode Unknown -TargetType Unknown -EffectiveState Unknown `
                -ReasonChain @($failureReason) -SubjectType $subjectType -SubjectId $subjectId -SubjectName $subjectName `
                -AssignmentReason "$($scanError.Message)" -Source 'Get-IntuneEffectiveAssignment'
            [void]$effectiveRecords.Add($failureRecord)
            Write-Warning "Category '$($scanError.CategoryId)' failed: $($scanError.Message)"
        }
    }

    if (-not $PassThru) {
        if ($effectiveRecords.Count -gt 0) {
            $table = $effectiveRecords |
                Select-Object PolicyName, Category, EffectiveState, AssignmentMode, TargetType, TargetName |
                Format-Table -AutoSize |
                Out-String
            Write-Host $table
        }
        foreach ($state in @('Included', 'Excluded', 'Unknown', 'NotTargeted')) {
            $count = @($effectiveRecords | Where-Object EffectiveState -eq $state).Count
            Write-Host "$state`: $count"
        }
        Write-Host 'Targeting analysis is not proof of delivery, applicability, installation, execution, compliance, or device check-in.' -ForegroundColor Yellow
    }
    else {
        Write-Verbose 'Targeting analysis is not proof of delivery, applicability, installation, execution, compliance, or device check-in.'
    }

    if ($ExportToCSV -or -not [string]::IsNullOrWhiteSpace($ExportPath)) {
        $csvPath = if ([string]::IsNullOrWhiteSpace($ExportPath)) {
            Join-Path (Get-Location) 'IntuneEffectiveAssignments.csv'
        }
        else { $ExportPath }
        $parentPath = Split-Path -Parent $csvPath
        if ($parentPath -and -not (Test-Path $parentPath)) { New-Item -ItemType Directory -Path $parentPath -Force | Out-Null }

        $csvRows = foreach ($record in $effectiveRecords) {
            [PSCustomObject][ordered]@{
                SubjectType   = ConvertTo-IACCsvSafeValue $record.SubjectType
                SubjectId     = ConvertTo-IACCsvSafeValue $record.SubjectId
                SubjectName   = ConvertTo-IACCsvSafeValue $record.SubjectName
                CategoryId    = ConvertTo-IACCsvSafeValue $record.CategoryId
                Category      = ConvertTo-IACCsvSafeValue $record.Category
                PolicyName    = ConvertTo-IACCsvSafeValue $record.PolicyName
                PolicyId      = ConvertTo-IACCsvSafeValue $record.PolicyId
                Platform      = ConvertTo-IACCsvSafeValue $record.Platform
                Intent        = ConvertTo-IACCsvSafeValue $record.Intent
                EffectiveState = $record.EffectiveState
                AssignmentMode = $record.AssignmentMode
                TargetType    = $record.TargetType
                TargetId      = ConvertTo-IACCsvSafeValue $record.TargetId
                TargetName    = ConvertTo-IACCsvSafeValue $record.TargetName
                FilterId      = ConvertTo-IACCsvSafeValue $record.FilterId
                FilterName    = ConvertTo-IACCsvSafeValue $record.FilterName
                FilterMode    = $record.FilterMode
                AssignmentReason = ConvertTo-IACCsvSafeValue $record.AssignmentReason
                DecisionCode  = if ($record.ReasonChain.Count -gt 0) { $record.ReasonChain[-1].Code } else { $null }
                ReasonChain   = ConvertTo-IACCsvSafeValue (ConvertTo-Json -InputObject @($record.ReasonChain) -Depth 6 -Compress -AsArray)
            }
        }
        $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        if ($PassThru) { Write-Verbose "Results exported to $csvPath" }
        else { Write-Host "Results exported to $csvPath" -ForegroundColor Green }
    }

    if ($PassThru) { $effectiveRecords }
}
