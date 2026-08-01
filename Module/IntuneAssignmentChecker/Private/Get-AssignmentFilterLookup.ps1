function Get-AssignmentFilterLookup {
    [CmdletBinding()]
    param()
    $lookup = @{}
    try {
        $uri = "$script:GraphEndpoint/beta/deviceManagement/assignmentFilters?`$select=id,displayName,platform,rule,assignmentFilterManagementType"
        foreach ($filter in @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)) {
            $lookup["$($filter.id)"] = [PSCustomObject]@{
                Id                             = $filter.id
                Name                           = $filter.displayName
                Platform                       = $filter.platform
                Rule                           = $filter.rule
                AssignmentFilterManagementType = $filter.assignmentFilterManagementType
            }
        }
    }
    catch {
        Write-Warning "Could not fetch assignment filters: $($_.Exception.Message)"
    }
    return $lookup
}
