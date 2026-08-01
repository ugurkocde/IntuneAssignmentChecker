function Get-AssignmentFilterLookup {
    [CmdletBinding()]
    param()
    $lookup = @{}
    try {
        $uri = "$script:GraphEndpoint/beta/deviceManagement/assignmentFilters?`$select=id,displayName,platform"
        foreach ($filter in @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)) {
            $lookup["$($filter.id)"] = [PSCustomObject]@{
                Name     = $filter.displayName
                Platform = $filter.platform
            }
        }
    }
    catch {
        Write-Warning "Could not fetch assignment filters: $($_.Exception.Message)"
    }
    return $lookup
}
