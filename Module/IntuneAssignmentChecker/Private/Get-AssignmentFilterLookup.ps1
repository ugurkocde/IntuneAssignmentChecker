function Get-AssignmentFilterLookup {
    $lookup = @{}
    try {
        $uri = "$script:GraphEndpoint/beta/deviceManagement/assignmentFilters?`$select=id,displayName,platform"
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            foreach ($filter in $response.value) {
                $lookup["$($filter.id)"] = [PSCustomObject]@{
                    Name     = $filter.displayName
                    Platform = $filter.platform
                }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Warning "Could not fetch assignment filters: $($_.Exception.Message)"
    }
    return $lookup
}
