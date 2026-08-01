function Resolve-IACEffectiveAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Category,
        [Parameter(Mandatory)]$Entity,
        [AllowEmptyCollection()][object[]]$Assignments = @(),
        [Parameter(Mandatory)][hashtable]$MembershipSources,
        [switch]$HasUser,
        [switch]$HasDevice,
        [bool]$UserMembershipKnown = $true,
        [bool]$DeviceMembershipKnown = $true,
        [AllowNull()]$ManagedDevice,
        [Parameter(Mandatory)][string]$SubjectType,
        [AllowEmptyString()][string]$SubjectId,
        [Parameter(Mandatory)][string]$SubjectName
    )

    $reasonChain = [System.Collections.Generic.List[object]]::new()
    $candidates = [System.Collections.Generic.List[object]]::new()
    $sequence = 0

    foreach ($assignment in @($Assignments)) {
        $sequence++
        $targetResult = 'Unknown'
        $membershipSourceNames = @()
        $targetDimensions = [System.Collections.Generic.List[string]]::new()
        $targetCode = 'Target.Unsupported'
        $targetMessage = "Unsupported assignment target type '$($assignment.TargetType)'."

        switch ($assignment.TargetType) {
            'AllUsers' {
                $targetResult = if ($HasUser) { 'Match' } else { 'NotMatch' }
                if ($HasUser) { [void]$targetDimensions.Add('User') }
                $targetCode = 'Target.AllUsers'
                $targetMessage = if ($HasUser) { 'A user subject is present.' } else { 'No user subject was supplied.' }
            }
            'AllDevices' {
                $targetResult = if ($HasDevice) { 'Match' } else { 'NotMatch' }
                if ($HasDevice) { [void]$targetDimensions.Add('Device') }
                $targetCode = 'Target.AllDevices'
                $targetMessage = if ($HasDevice) { 'A managed-device subject is present.' } else { 'No device subject was supplied.' }
            }
            'Group' {
                if ($assignment.TargetId -and $MembershipSources.ContainsKey("$($assignment.TargetId)")) {
                    $targetResult = 'Match'
                    $membershipSourceNames = @($MembershipSources["$($assignment.TargetId)"].Sources)
                    foreach ($source in $membershipSourceNames) {
                        if ($source -in @('User', 'Device') -and -not $targetDimensions.Contains($source)) {
                            [void]$targetDimensions.Add($source)
                        }
                    }
                    $targetCode = 'Target.TransitiveGroupMembership'
                    $targetMessage = "The subject is a transitive member through: $($membershipSourceNames -join ', ')."
                }
                elseif (($HasUser -and -not $UserMembershipKnown) -or ($HasDevice -and -not $DeviceMembershipKnown)) {
                    $targetResult = 'Unknown'
                    if ($HasUser -and -not $UserMembershipKnown) { [void]$targetDimensions.Add('User') }
                    if ($HasDevice -and -not $DeviceMembershipKnown) { [void]$targetDimensions.Add('Device') }
                    $targetCode = 'Target.GroupMembershipUnknown'
                    $targetMessage = 'At least one supplied subject has an incomplete transitive group-membership result.'
                }
                else {
                    $targetResult = 'NotMatch'
                    $targetCode = 'Target.GroupNotMember'
                    $targetMessage = 'Neither supplied subject is a transitive member of the target group.'
                }
            }
        }

        $filterResult = 'NotEvaluated'
        $filterCode = 'Filter.NotEvaluated'
        $filterReason = 'The target did not match, so its assignment filter was not evaluated.'
        if ($targetResult -eq 'Match') {
            $filterId = "$($assignment.FilterId)"
            $filterMode = "$($assignment.FilterType)"
            $hasFilterId = -not [string]::IsNullOrWhiteSpace($filterId) -and
                $filterId -ne '00000000-0000-0000-0000-000000000000'
            if (-not $hasFilterId -or $filterMode -ieq 'none') {
                $filterResult = 'Match'
                $filterCode = 'Filter.None'
                $filterReason = 'No assignment filter is applied.'
            }
            elseif ([string]::IsNullOrWhiteSpace($filterMode) -or $filterMode -notin @('include', 'exclude')) {
                $filterResult = 'Unknown'
                $filterCode = 'Filter.UnsupportedMode'
                $filterReason = "Unsupported assignment filter mode '$filterMode'."
            }
            elseif ($null -eq $ManagedDevice) {
                $filterResult = 'Unknown'
                $filterCode = 'Filter.NoDevice'
                $filterReason = 'A managed device is required to evaluate this assignment filter.'
            }
            elseif (-not $script:AssignmentFilterLookup -or -not $script:AssignmentFilterLookup.ContainsKey($filterId)) {
                $filterResult = 'Unknown'
                $filterCode = 'Filter.NotInCache'
                $filterReason = "Assignment filter '$filterId' is not present in the tenant filter cache."
            }
            else {
                $filterEvaluation = Test-IACAssignmentFilter `
                    -Filter $script:AssignmentFilterLookup[$filterId] `
                    -Device $ManagedDevice -FilterMode $filterMode
                $filterResult = $filterEvaluation.Result
                $filterCode = "Filter.Evaluated.$filterResult"
                $filterReason = $filterEvaluation.Reason
            }
        }
        elseif ($targetResult -eq 'Unknown') {
            $filterResult = 'Unknown'
            $filterCode = 'Filter.TargetUnknown'
            $filterReason = 'Filter evaluation is blocked because target membership is unknown.'
        }

        $candidateOutcome = if ($targetResult -eq 'Unknown' -or $filterResult -eq 'Unknown') { 'Unknown' }
            elseif ($targetResult -ne 'Match' -or $filterResult -ne 'Match') { 'Inactive' }
            elseif ($assignment.AssignmentMode -eq 'Exclude') { 'Excluded' }
            elseif ($assignment.AssignmentMode -eq 'Include') { 'Included' }
            else { 'Unknown' }

        [void]$reasonChain.Add([PSCustomObject][ordered]@{
                Sequence          = $sequence
                Code              = $targetCode
                FilterCode        = $filterCode
                Outcome           = $candidateOutcome
                AssignmentId      = $assignment.AssignmentId
                AssignmentMode    = $assignment.AssignmentMode
                TargetType        = $assignment.TargetType
                TargetId          = $assignment.TargetId
                MembershipSources = @($membershipSourceNames)
                TargetResult      = $targetResult
                FilterId          = $assignment.FilterId
                FilterMode        = $assignment.FilterType
                FilterResult      = $filterResult
                Message           = "$targetMessage $filterReason"
            })
        [void]$candidates.Add([PSCustomObject]@{
                Assignment = $assignment
                Outcome = $candidateOutcome
                Dimensions = @($targetDimensions)
            })
    }

    $activeExclusions = @($candidates | Where-Object Outcome -eq Excluded)
    $unknownExclusions = @($candidates | Where-Object { $_.Outcome -eq 'Unknown' -and $_.Assignment.AssignmentMode -eq 'Exclude' })
    $activeInclusions = @($candidates | Where-Object Outcome -eq Included)
    $unknownInclusions = @($candidates | Where-Object { $_.Outcome -eq 'Unknown' -and $_.Assignment.AssignmentMode -eq 'Include' })
    $unknownOther = @($candidates | Where-Object {
            $_.Outcome -eq 'Unknown' -and $_.Assignment.AssignmentMode -notin @('Include', 'Exclude')
        })

    $compatibleExclusion = $null
    if ($activeInclusions.Count -gt 0 -and $activeExclusions.Count -gt 0) {
        foreach ($exclusion in $activeExclusions) {
            foreach ($inclusion in $activeInclusions) {
                if (@($exclusion.Dimensions | Where-Object { $_ -in $inclusion.Dimensions }).Count -gt 0) {
                    $compatibleExclusion = $exclusion
                    break
                }
            }
            if ($compatibleExclusion) { break }
        }
    }

    if ($activeInclusions.Count -gt 0) {
        if ($compatibleExclusion) {
            $effectiveState = 'Excluded'; $representative = $compatibleExclusion.Assignment
            $decisionCode = 'Decision.Excluded'
            $decisionMessage = 'A matching exclusion in the same user/device targeting dimension takes precedence over an inclusion.'
        }
        elseif ($activeExclusions.Count -gt 0) {
            $effectiveState = 'Unknown'; $representative = $activeExclusions[0].Assignment
            $decisionCode = 'Decision.CrossDimensionUnknown'
            $decisionMessage = 'Inclusion and exclusion match different user/device targeting dimensions; Intune behavior cannot be inferred safely.'
        }
        elseif ($unknownExclusions.Count -gt 0) {
            $effectiveState = 'Unknown'; $representative = $unknownExclusions[0].Assignment
            $decisionCode = 'Decision.UnresolvedExclusion'
            $decisionMessage = 'A possible exclusion prevents a definitive inclusion result.'
        }
        elseif ($unknownOther.Count -gt 0) {
            $effectiveState = 'Unknown'; $representative = $unknownOther[0].Assignment
            $decisionCode = 'Decision.UnknownAssignmentMode'
            $decisionMessage = 'An assignment uses an unsupported include/exclude mode.'
        }
        else {
            $effectiveState = 'Included'; $representative = $activeInclusions[0].Assignment
            $decisionCode = 'Decision.Included'
            $decisionMessage = 'At least one inclusion is active and no exclusion can override it.'
        }
    }
    elseif ($unknownInclusions.Count -gt 0) {
        $effectiveState = 'Unknown'; $representative = $unknownInclusions[0].Assignment
        $decisionCode = 'Decision.UnresolvedInclusion'
        $decisionMessage = 'A possible inclusion could not be evaluated definitively.'
    }
    elseif ($unknownOther.Count -gt 0) {
        $effectiveState = 'Unknown'; $representative = $unknownOther[0].Assignment
        $decisionCode = 'Decision.UnknownAssignmentMode'
        $decisionMessage = 'An assignment uses an unsupported include/exclude mode.'
    }
    else {
        $effectiveState = 'NotTargeted'
        $representative = if ($Assignments.Count -eq 0) {
            Get-IACNoAssignmentPlaceholder
        }
        else {
            Get-IACNoAssignmentPlaceholder -Reason 'No Matching Assignment'
        }
        $decisionCode = 'Decision.NotTargeted'
        $decisionMessage = if ($Assignments.Count -eq 0) { 'The policy has no assignments.' } else { 'No inclusion targets either supplied subject.' }
    }

    $sequence++
    [void]$reasonChain.Add([PSCustomObject][ordered]@{
            Sequence          = $sequence
            Code              = $decisionCode
            FilterCode        = $null
            Outcome           = $effectiveState
            AssignmentId      = $representative.AssignmentId
            AssignmentMode    = $representative.AssignmentMode
            TargetType        = $representative.TargetType
            TargetId          = $representative.TargetId
            MembershipSources = @()
            TargetResult      = $null
            FilterId          = $representative.FilterId
            FilterMode        = $representative.FilterType
            FilterResult      = $null
            Message           = $decisionMessage
        })

    $record = ConvertTo-IACAssignmentRecord -Category $Category -Entity $Entity -Assignment $representative `
        -SubjectType $SubjectType -SubjectId $SubjectId -SubjectName $SubjectName -Source 'Get-IntuneEffectiveAssignment'
    if ($representative.TargetType -eq 'Group' -and $representative.TargetId -and $MembershipSources.ContainsKey("$($representative.TargetId)")) {
        $record.TargetName = $MembershipSources["$($representative.TargetId)"].Name
    }
    $record.EffectiveState = $effectiveState
    $record.ReasonChain = @($reasonChain)
    return $record
}
