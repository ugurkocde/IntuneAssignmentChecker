function Add-IntentTemplateFamilyInfo {
    param (
        [Parameter(Mandatory = $false)]
        $IntentPolicies
    )

    if (-not $IntentPolicies) { return }

    $lookup = Get-IntentTemplateFamilyLookup

    foreach ($intent in $IntentPolicies) {
        if ($intent.templateId -and $lookup.ContainsKey($intent.templateId)) {
            if (-not $intent.templateReference) {
                $intent | Add-Member -NotePropertyName 'templateReference' -NotePropertyValue @{
                    templateFamily = $lookup[$intent.templateId]
                }
            }
        }
    }
}
