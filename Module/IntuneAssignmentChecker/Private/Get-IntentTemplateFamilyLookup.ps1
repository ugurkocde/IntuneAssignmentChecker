function Get-IntentTemplateFamilyLookup {
    if ($null -ne $script:TemplateIdToFamilyCache) {
        return $script:TemplateIdToFamilyCache
    }

    $script:TemplateIdToFamilyCache = @{}
    try {
        $templates = Get-IntuneEntities -EntityType "deviceManagement/templates"
        foreach ($template in $templates) {
            $subtype = $template.templateSubtype
            if ($subtype -and $script:IntentTemplateSubtypeToFamily.ContainsKey($subtype)) {
                $script:TemplateIdToFamilyCache[$template.id] = $script:IntentTemplateSubtypeToFamily[$subtype]
            }
        }
    }
    catch {
        Write-Warning "Unable to fetch deviceManagement/templates for intent enrichment: $($_.Exception.Message)"
    }

    return $script:TemplateIdToFamilyCache
}
