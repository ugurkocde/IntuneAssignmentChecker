function Get-ScopeTagNames {
    param (
        [object[]]$ScopeTagIds,
        [hashtable]$ScopeTagLookup
    )
    if (-not $ScopeTagIds -or $ScopeTagIds.Count -eq 0) { return "Default" }
    $names = foreach ($id in $ScopeTagIds) {
        $key = "$id"
        if ($ScopeTagLookup.ContainsKey($key)) { $ScopeTagLookup[$key] }
        else { "Tag:$key" }
    }
    return ($names -join ", ")
}
