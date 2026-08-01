function Select-IACAssignmentRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Records,
        [Parameter(Mandatory)]
        [hashtable]$Buckets,
        [AllowEmptyCollection()]
        [string[]]$TargetTypes,
        [AllowEmptyCollection()]
        [string[]]$GroupIds,
        [string]$SubjectType,
        [string]$SubjectId,
        [string]$SubjectName,
        [Parameter(Mandatory)]
        [string]$Source
    )

    $visiblePolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($bucket in $Buckets.Values) {
        foreach ($entity in @($bucket)) {
            $entityPolicyId = if ($entity.id) { $entity.id } else { $entity.PolicyId }
            if ($entityPolicyId) { $null = $visiblePolicyIds.Add("$entityPolicyId") }
        }
    }

    $restrictGroupIds = $PSBoundParameters.ContainsKey('GroupIds')
    foreach ($record in $Records) {
        if (-not $visiblePolicyIds.Contains("$($record.PolicyId)")) { continue }
        if ($TargetTypes -and $record.TargetType -notin $TargetTypes) { continue }
        if ($record.TargetType -eq 'Group' -and $restrictGroupIds -and $record.TargetId -notin $GroupIds) { continue }

        $copy = [PSCustomObject][ordered]@{}
        foreach ($property in $record.PSObject.Properties) {
            $copy | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $copy.SubjectType = $SubjectType
        $copy.SubjectId = $SubjectId
        $copy.SubjectName = $SubjectName
        $copy.Source = $Source
        if ($copy.TargetType -eq 'Group' -and $copy.TargetId -and -not $copy.TargetName) {
            $copy.TargetName = (Get-GroupInfo -GroupId $copy.TargetId).DisplayName
        }
        $copy.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentRecord')
        $copy
    }
}
