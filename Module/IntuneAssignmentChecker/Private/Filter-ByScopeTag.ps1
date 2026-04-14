function Filter-ByScopeTag {
    param (
        [object[]]$Items,
        [string]$FilterTag,
        [hashtable]$ScopeTagLookup
    )
    if ([string]::IsNullOrWhiteSpace($FilterTag)) { return $Items }
    return @($Items | Where-Object {
        $names = Get-ScopeTagNames -ScopeTagIds $_.roleScopeTagIds -ScopeTagLookup $ScopeTagLookup
        ($names -split ', ') -contains $FilterTag
    })
}
