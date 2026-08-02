function Test-IntuneAssignmentChange {
    <#
    .SYNOPSIS
    Simulates a proposed assignment change without writing to Microsoft Graph.

    .DESCRIPTION
    Applies an add, remove, target replacement, filter change, or intent change to
    records from a snapshot or the pipeline. The result contains before and after
    states, risk, affected known subjects, and an explicit simulation reason chain.

    .PARAMETER ChangeType
    Assignment mutation to model locally.

    .PARAMETER PolicyId
    Policy or application whose assignment should be simulated.

    .PARAMETER AssignmentId
    Existing assignment for remove/change operations.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Snapshot')]
    [OutputType('IntuneAssignmentChecker.AssignmentChangeSimulation')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Snapshot')]
        [string]$SnapshotPath,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Records')]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidateSet('AddAssignment', 'RemoveAssignment', 'ReplaceTarget', 'ChangeFilter', 'ChangeIntent')]
        [string]$ChangeType,

        [Parameter(Mandatory)]
        [string]$PolicyId,

        [Parameter()]
        [string]$AssignmentId,

        [Parameter()]
        [ValidateSet('Include', 'Exclude')]
        [string]$AssignmentMode = 'Include',

        [Parameter()]
        [ValidateSet('AllUsers', 'AllDevices', 'Group')]
        [string]$TargetType = 'Group',

        [Parameter()]
        [string]$TargetId,

        [Parameter()]
        [string]$TargetName,

        [Parameter()]
        [string]$FilterId,

        [Parameter()]
        [ValidateSet('include', 'exclude', 'none')]
        [string]$FilterMode = 'none',

        [Parameter()]
        [string]$Intent,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'Json'
    )

    begin { $pipelineRecords = [System.Collections.Generic.List[object]]::new() }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Records') {
            foreach ($record in @($InputObject)) { if ($null -ne $record) { [void]$pipelineRecords.Add($record) } }
        }
    }
    end {
        $records = if ($PSCmdlet.ParameterSetName -eq 'Snapshot') {
            @((Read-IACAssignmentSnapshot -Path $SnapshotPath).Records)
        }
        else { @($pipelineRecords) }
        $policyRecords = @($records | Where-Object PolicyId -EQ $PolicyId)
        if ($policyRecords.Count -eq 0) { throw "Policy '$PolicyId' was not found in the supplied assignment state." }

        $requiresExisting = $ChangeType -ne 'AddAssignment'
        $existing = if ($AssignmentId) {
            $policyRecords | Where-Object AssignmentId -EQ $AssignmentId | Select-Object -First 1
        }
        elseif ($requiresExisting -and $policyRecords.Count -eq 1) { $policyRecords[0] }
        if ($requiresExisting -and -not $existing) {
            throw 'Specify -AssignmentId when the proposed change operates on an existing assignment.'
        }
        if ($ChangeType -in @('AddAssignment', 'ReplaceTarget') -and $TargetType -eq 'Group' -and [string]::IsNullOrWhiteSpace($TargetId)) {
            throw "-$ChangeType with a Group target requires -TargetId."
        }

        $before = if ($existing) { $existing.PSObject.Copy() } else { $null }
        $after = switch ($ChangeType) {
            'RemoveAssignment' { $null }
            'AddAssignment' {
                $copy = $policyRecords[0].PSObject.Copy()
                $identity = "$PolicyId|$AssignmentMode|$TargetType|$TargetId|$FilterId|$Intent"
                $hash = (Get-IACSha256Hex -InputText $identity).Substring(0, 20)
                $copy.AssignmentId = "simulation:$hash"
                $copy.AssignmentMode = $AssignmentMode
                $copy.TargetType = $TargetType
                $copy.TargetId = if ($TargetType -eq 'Group') { $TargetId } else { $null }
                $copy.TargetName = if ($TargetName) { $TargetName } else { $TargetType }
                if ($PSBoundParameters.ContainsKey('Intent')) { $copy.Intent = $Intent }
                if ($PSBoundParameters.ContainsKey('FilterId')) { $copy.FilterId = $FilterId; $copy.FilterMode = $FilterMode }
                $copy
            }
            'ReplaceTarget' {
                $copy = $existing.PSObject.Copy()
                $copy.AssignmentMode = $AssignmentMode
                $copy.TargetType = $TargetType
                $copy.TargetId = if ($TargetType -eq 'Group') { $TargetId } else { $null }
                $copy.TargetName = if ($TargetName) { $TargetName } else { $TargetType }
                $copy
            }
            'ChangeFilter' {
                $copy = $existing.PSObject.Copy()
                $copy.FilterId = $FilterId
                $copy.FilterMode = $FilterMode
                $copy
            }
            'ChangeIntent' {
                if (-not $PSBoundParameters.ContainsKey('Intent')) { throw 'ChangeIntent requires -Intent.' }
                $copy = $existing.PSObject.Copy()
                $copy.Intent = $Intent
                $copy
            }
        }

        if ($after) {
            $reason = [PSCustomObject][ordered]@{
                Sequence       = @($after.ReasonChain).Count
                Code           = "Simulation.$ChangeType"
                Outcome        = 'Proposed'
                AssignmentId   = $after.AssignmentId
                AssignmentMode = $after.AssignmentMode
                TargetType     = $after.TargetType
                TargetId       = $after.TargetId
                FilterId       = $after.FilterId
                FilterMode     = $after.FilterMode
                Message        = 'Local simulation only; no Microsoft Graph write was performed.'
            }
            $after.ReasonChain = @($after.ReasonChain) + @($reason)
            if ($after.PSObject.Properties['Source']) { $after.Source = 'Simulation' }
            else { $after | Add-Member -NotePropertyName Source -NotePropertyValue 'Simulation' }
        }

        $affectedSubjects = @($records | Where-Object {
                $_.PolicyId -eq $PolicyId -and -not [string]::IsNullOrWhiteSpace("$($_.SubjectId)")
            } | Select-Object SubjectType, SubjectId, SubjectName, EffectiveState -Unique)
        $risk = if (($after -and $after.TargetType -in @('AllUsers', 'AllDevices')) -and ($after.Intent -eq 'required')) { 'Critical' }
        elseif ($after -and $after.TargetType -in @('AllUsers', 'AllDevices')) { 'High' }
        elseif ($ChangeType -eq 'RemoveAssignment') { 'High' }
        else { 'Medium' }
        $simulation = [PSCustomObject][ordered]@{
            SchemaName      = 'IntuneAssignmentChecker.AssignmentChangeSimulation'
            SchemaVersion   = 1
            SimulationId    = [guid]::NewGuid().ToString()
            SimulatedAtUtc  = [datetimeoffset]::UtcNow.ToString('o')
            ReadOnly        = $true
            ChangeType      = $ChangeType
            Risk            = $risk
            PolicyId        = $PolicyId
            PolicyName      = $policyRecords[0].PolicyName
            AssignmentId    = if ($after) { $after.AssignmentId } else { $before.AssignmentId }
            Before          = $before
            After           = $after
            AffectedSubjects = $affectedSubjects
            AffectedCount   = $affectedSubjects.Count
            CoverageNote    = if ($affectedSubjects.Count -eq 0) {
                'No subject-scoped effective records were supplied; affected users and devices cannot be enumerated.'
            }
            else { 'Affected subjects are limited to the supplied effective-assignment records.' }
        }
        $simulation.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentChangeSimulation')
        if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject @($simulation) -Path $OutputPath -Format $OutputFormat }
        $simulation
    }
}
