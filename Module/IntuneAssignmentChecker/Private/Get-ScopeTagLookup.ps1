function Get-ScopeTagLookup {
    [CmdletBinding()]
    param()
    $lookup = @{ "0" = "Default" }
    try {
        $uri = "$script:GraphEndpoint/beta/deviceManagement/roleScopeTags?`$select=id,displayName"
        foreach ($tag in @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)) {
            $lookup["$($tag.id)"] = $tag.displayName
        }
    }
    catch {
        Write-Warning "Could not fetch scope tags: $($_.Exception.Message)"
    }
    return $lookup
}
