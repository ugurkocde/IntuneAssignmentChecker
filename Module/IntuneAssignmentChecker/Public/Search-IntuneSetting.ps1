function Search-IntuneSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Keyword to search for in setting definitions")]
        [string]$Keyword,

        [Parameter(HelpMessage = "Show all matching definitions, including those not configured in any policy")]
        [switch]$ShowAll,

        [Parameter()]
        [switch]$ExportToCSV,

        [Parameter()]
        [string]$ExportPath
    )

    # Requires active Graph connection
    if (-not $script:GraphEndpoint) {
        Write-Host "Not connected. Run Connect-IntuneAssignmentChecker first." -ForegroundColor Red
        return
    }

    if ([string]::IsNullOrWhiteSpace($Keyword)) {
        Write-Host "Enter a setting keyword to search for (e.g., BitLocker, encryption, password): " -ForegroundColor Cyan
        $Keyword = Read-Host
    }

    if ([string]::IsNullOrWhiteSpace($Keyword)) {
        Write-Host "No keyword provided. Please try again." -ForegroundColor Red
        return
    }

    # ── Expand common abbreviations ────────────────────────────────────
    $abbreviations = @{
        'psso'     = 'platform sso'
        'mdatp'    = 'defender for endpoint'
        'wdac'     = 'application control'
        'asr'      = 'attack surface reduction'
        'edr'      = 'endpoint detection'
        'av'       = 'antivirus'
        'laps'     = 'local administrator password'
        'whfb'     = 'windows hello for business'
        'wufb'     = 'windows update for business'
        'esp'      = 'enrollment status page'
        'mfa'      = 'multi-factor authentication'
    }

    $expandedKeyword = $null
    if ($abbreviations.ContainsKey($Keyword.ToLower())) {
        $expandedKeyword = $abbreviations[$Keyword.ToLower()]
        Write-Host "Expanding '$Keyword' to '$expandedKeyword'" -ForegroundColor DarkGray
    }

    # ── Load setting definitions ─────────────────────────────────────────
    $dataPath = Join-Path $PSScriptRoot ".." "Data" "SettingDefinitions.json"
    if (-not (Test-Path $dataPath)) {
        Write-Host "Setting definitions file not found at: $dataPath" -ForegroundColor Red
        Write-Host "Run Update-IntuneSettingDefinition first to download the catalog." -ForegroundColor Yellow
        return
    }

    $rawJson = Get-Content -Path $dataPath -Raw -Encoding UTF8
    $definitions = $rawJson | ConvertFrom-Json

    if ($null -eq $definitions -or $definitions.Count -eq 0) {
        Write-Host "Setting definitions file is empty." -ForegroundColor Red
        Write-Host "Run Update-IntuneSettingDefinition first to download the catalog." -ForegroundColor Yellow
        return
    }

    # ── Search definitions by keyword ────────────────────────────────────
    # Build list of search terms: original keyword + expanded abbreviation (if any)
    $searchTerms = @($Keyword.ToLower())
    if ($expandedKeyword) { $searchTerms += $expandedKeyword.ToLower() }

    $matchedDefinitions = [System.Collections.ArrayList]::new()

    foreach ($def in $definitions) {
        $match = $false

        foreach ($term in $searchTerms) {
            if ($match) { break }
            $termNormalized = ($term -replace '[_\-\.\s]', '')

            # Check displayName (exact substring)
            if ($def.displayName -and $def.displayName.ToLower().Contains($term)) {
                $match = $true
            }

            # Check id (exact substring)
            if (-not $match -and $def.id -and $def.id.ToLower().Contains($term)) {
                $match = $true
            }

            # Check id with normalized form (spaces/separators removed)
            if (-not $match -and $def.id) {
                $idNormalized = ($def.id.ToLower() -replace '[_\-\.\s]', '')
                if ($idNormalized.Contains($termNormalized)) {
                    $match = $true
                }
            }

            # Check displayName with normalized form
            if (-not $match -and $def.displayName) {
                $nameNormalized = ($def.displayName.ToLower() -replace '[_\-\.\s]', '')
                if ($nameNormalized.Contains($termNormalized)) {
                    $match = $true
                }
            }

            # Check keywords array
            if (-not $match -and $def.keywords) {
                foreach ($kw in $def.keywords) {
                    if ($kw -and $kw.ToLower().Contains($term)) {
                        $match = $true
                        break
                    }
                }
            }
        }

        if ($match) {
            $null = $matchedDefinitions.Add($def)
        }
    }

    if ($matchedDefinitions.Count -eq 0) {
        Write-Host "`nNo setting definitions found matching '$Keyword'." -ForegroundColor Yellow
        return
    }

    # Build a lookup set of matched definition IDs for fast checking
    $matchedIdSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($def in $matchedDefinitions) {
        $null = $matchedIdSet.Add($def.id)
    }

    # ── Header ───────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan
    Write-Host "  SETTING SEARCH RESULTS" -ForegroundColor Cyan
    Write-Host "  Search term: '$Keyword'" -ForegroundColor White
    Write-Host "  Found $($matchedDefinitions.Count) matching setting $(if ($matchedDefinitions.Count -eq 1) { 'definition' } else { 'definitions' })" -ForegroundColor White
    Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan

    # ── Fetch all configuration policies (Settings Catalog + Endpoint Security) ──
    Write-Host "`nFetching configuration policies..." -ForegroundColor Yellow

    $allPolicies = [System.Collections.ArrayList]::new()
    $policyUri = "$($script:GraphEndpoint)/beta/deviceManagement/configurationPolicies?`$select=id,name,description,templateReference"
    do {
        try {
            $policyResponse = Invoke-MgGraphRequest -Uri $policyUri -Method Get
            if ($policyResponse.value) {
                foreach ($p in $policyResponse.value) {
                    $null = $allPolicies.Add($p)
                }
            }
            $policyUri = $policyResponse.'@odata.nextLink'
        }
        catch {
            Write-Host "Error fetching policies: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } while (![string]::IsNullOrEmpty($policyUri))

    Write-Host "Found $($allPolicies.Count) configuration policies. Scanning settings..." -ForegroundColor Gray

    # ── Scan each policy for matching settings ───────────────────────────
    # Structure: definitionId -> list of { PolicyName, PolicyId, ConfiguredValue }
    $settingResults = @{}

    $totalPolicies = $allPolicies.Count
    $currentPolicy = 0

    foreach ($policy in $allPolicies) {
        $currentPolicy++
        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.name)) { $policy.name } else { "Unnamed Policy" }
        $lineWidth = try { $Host.UI.RawUI.WindowSize.Width - 1 } catch { 120 }
        $progressText = "[$currentPolicy/$totalPolicies] Scanning: $policyName"
        if ($progressText.Length -gt $lineWidth) { $progressText = $progressText.Substring(0, $lineWidth - 3) + "..." }
        Write-Host "`r$($progressText.PadRight($lineWidth))" -NoNewline

        $settingsUri = "$($script:GraphEndpoint)/beta/deviceManagement/configurationPolicies('$($policy.id)')/settings"
        try {
            $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method Get
            if ($settingsResponse.value) {
                foreach ($setting in $settingsResponse.value) {
                    $instance = $setting.settingInstance
                    if ($null -eq $instance) { continue }

                    $defId = $instance.settingDefinitionId
                    if ([string]::IsNullOrEmpty($defId)) { continue }

                    if ($matchedIdSet.Contains($defId)) {
                        $configuredValue = Get-SettingValue -SettingInstance $instance

                        if (-not $settingResults.ContainsKey($defId)) {
                            $settingResults[$defId] = [System.Collections.ArrayList]::new()
                        }
                        $null = $settingResults[$defId].Add([PSCustomObject]@{
                            PolicyName      = $policyName
                            PolicyId        = $policy.id
                            ConfiguredValue = $configuredValue
                        })
                    }
                }
            }
        }
        catch {
            # Skip policies where settings cannot be fetched
        }
    }

    Write-Host "`r$((' ' * 120))" -NoNewline
    Write-Host "`rPolicy scan complete." -ForegroundColor Green

    # ── Display results per definition ───────────────────────────────────
    $exportData = [System.Collections.ArrayList]::new()
    $separator = Get-Separator

    $configuredCount = 0
    $skippedCount = 0

    foreach ($def in $matchedDefinitions) {
        $defId = $def.id
        $defName = if ($def.displayName) { $def.displayName } else { $defId }
        $defDesc = if ($def.description) { $def.description } else { "(no description)" }
        $hasConfigured = $settingResults.ContainsKey($defId) -and $settingResults[$defId].Count -gt 0

        # By default, only show definitions that are configured in at least one policy
        if (-not $hasConfigured -and -not $ShowAll) {
            $skippedCount++
            continue
        }

        Write-Host ""
        Write-Host "===== $defName =====" -ForegroundColor White
        Write-Host "Definition ID: $defId" -ForegroundColor Gray
        Write-Host "Description: $defDesc" -ForegroundColor Gray

        if ($hasConfigured) {
            $configuredCount++
            $policies = $settingResults[$defId]

            Write-Host ""
            Write-Host "Policies configuring this setting:" -ForegroundColor Yellow
            Write-Host ("  {0,-80} {1}" -f "Policy Name", "Configured Value") -ForegroundColor Cyan
            Write-Host "  $separator" -ForegroundColor Gray

            foreach ($entry in $policies) {
                $displayName = if ($entry.PolicyName.Length -gt 78) {
                    $entry.PolicyName.Substring(0, 75) + "..."
                } else {
                    $entry.PolicyName
                }
                Write-Host ("  {0,-80} {1}" -f $displayName, $entry.ConfiguredValue) -ForegroundColor White

                $null = $exportData.Add([PSCustomObject]@{
                    SettingName        = $defName
                    SettingDefinitionId = $defId
                    PolicyName         = $entry.PolicyName
                    PolicyId           = $entry.PolicyId
                    ConfiguredValue    = $entry.ConfiguredValue
                })
            }
            Write-Host "  $separator" -ForegroundColor Gray
        }
        else {
            # Only shown when -ShowAll is used
            Write-Host ""
            Write-Host "Policies configuring this setting:" -ForegroundColor Yellow
            Write-Host "  (no policies configure this setting)" -ForegroundColor DarkGray
        }
    }

    if ($skippedCount -gt 0) {
        Write-Host ""
        Write-Host "($skippedCount matching definitions not configured in any policy -- use -ShowAll to see them)" -ForegroundColor DarkGray
    }

    # ── Summary ──────────────────────────────────────────────────────────
    $policiesWithSettings = ($settingResults.Keys | Measure-Object).Count
    Write-Host ""
    Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan
    Write-Host "  Summary: $($matchedDefinitions.Count) definitions matched, $policiesWithSettings configured in policies" -ForegroundColor Cyan
    Write-Host (Get-Separator -Character "=") -ForegroundColor Cyan

    # ── Export ───────────────────────────────────────────────────────────
    Export-ResultsIfRequested -ExportData $exportData -DefaultFileName "IntuneSettingSearch.csv" -ForceExport:$ExportToCSV -CustomExportPath $ExportPath
}

# ── Helper: extract configured value from a setting instance ─────────
function Get-SettingValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SettingInstance
    )

    $type = $SettingInstance.'@odata.type'

    switch -Wildcard ($type) {
        '*choiceSettingInstance' {
            $rawValue = $SettingInstance.choiceSettingValue.value
            if ($rawValue) {
                # Extract last segment for readability (e.g., "..._1" -> "1")
                $segments = $rawValue -split '_'
                $shortValue = $segments[-1]
                return "$shortValue ($rawValue)"
            }
            return "(no value)"
        }
        '*simpleSettingInstance' {
            $val = $SettingInstance.simpleSettingValue.value
            if ($null -ne $val) { return [string]$val }
            return "(no value)"
        }
        '*simpleSettingCollectionInstance' {
            $values = $SettingInstance.simpleSettingCollectionValue
            if ($values -and $values.Count -gt 0) {
                return "Collection ($($values.Count) items)"
            }
            return "Collection (empty)"
        }
        '*groupSettingCollectionInstance' {
            $children = $SettingInstance.groupSettingCollectionValue
            if ($children -and $children.Count -gt 0) {
                return "Group Collection ($($children.Count) items)"
            }
            return "Group Collection (empty)"
        }
        '*groupSettingInstance' {
            return "Group Setting"
        }
        default {
            return "(unknown type: $type)"
        }
    }
}
