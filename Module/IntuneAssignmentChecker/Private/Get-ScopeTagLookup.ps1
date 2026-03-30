function Get-ScopeTagLookup {
    $lookup = @{ "0" = "Default" }
    try {
        $uri = "$script:GraphEndpoint/beta/deviceManagement/roleScopeTags?`$select=id,displayName"
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            foreach ($tag in $response.value) {
                $lookup["$($tag.id)"] = $tag.displayName
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Warning "Could not fetch scope tags: $($_.Exception.Message)"
    }
    return $lookup
}
