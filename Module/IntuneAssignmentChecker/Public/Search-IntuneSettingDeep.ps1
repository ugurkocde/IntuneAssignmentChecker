function Search-IntuneSettingDeep {
    <#
    .SYNOPSIS
    Searches the values and names configured in Intune policies.

    .DESCRIPTION
    Performs a read-only search of Settings Catalog and Endpoint Security policies, device
    configuration profiles (including custom OMA-URI settings and decoded macOS/iOS XML or
    plist payloads), Administrative Templates, and device compliance policies.

    Unlike Search-IntuneSetting, which starts from the setting definition catalog, this
    command inspects what is configured in each policy. Settings Catalog choice IDs are
    resolved to their Microsoft Graph display labels.

    Values identified as secret are never matched and are shown as [REDACTED]. A setting
    whose name looks sensitive, such as one containing 'password', hides its text value;
    true/false values, and numbers and choices in Microsoft-defined settings, stay visible.
    Policy families or policies that cannot be read are reported, because a search with
    scan errors cannot prove that a setting is absent.

    .PARAMETER Keyword
    Text to find in setting names, friendly names, and configured values. Matching is
    case-insensitive and also ignores spaces and punctuation.

    .PARAMETER ExportPath
    Optional CSV path. Scan errors are written beside it with an .errors.csv extension.

    .PARAMETER IncludeCompliance
    Includes device compliance policies. Enabled by default; use -IncludeCompliance:$false
    to exclude them.

    .PARAMETER IncludePolicyMetadata
    Also returns matches in policy metadata such as IDs, timestamps, and OData types.

    .PARAMETER PassThru
    Returns the result objects to the pipeline.

    .EXAMPLE
    Search-IntuneSettingDeep -Keyword 'Audit Group Membership'

    .EXAMPLE
    Search-IntuneSettingDeep -Keyword MicrosoftEntraSSO -ExportPath ./deep-search.csv

    .EXAMPLE
    $rows = Search-IntuneSettingDeep -Keyword Telemetry -IncludeCompliance:$false -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Text to find in configured setting names and values")]
        [ValidateNotNullOrEmpty()]
        [string]$Keyword,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [switch]$IncludeCompliance,

        [Parameter()]
        [switch]$IncludePolicyMetadata,

        [Parameter()]
        [switch]$PassThru
    )

    if ([string]::IsNullOrWhiteSpace($Keyword)) {
        throw 'Keyword cannot be blank.'
    }
    if ([string]::IsNullOrWhiteSpace($script:GraphEndpoint)) {
        throw 'Not connected. Run Connect-IntuneAssignmentChecker first.'
    }

    $scanCompliance = if ($PSBoundParameters.ContainsKey('IncludeCompliance')) { [bool]$IncludeCompliance } else { $true }
    $graphBase = $script:GraphEndpoint.TrimEnd('/')
    $definitions = Get-IACSettingDefinitionLookup
    Write-Host "Loaded $($definitions.Count) friendly setting names." -ForegroundColor DarkGray

    $state = New-IACDeepSearchState
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($family in @(Get-IACDeepSearchFamily -IncludeCompliance $scanCompliance)) {
        Write-Host "Scanning $($family.Name)..." -ForegroundColor Cyan
        try {
            $policies = @((Invoke-IACGraphRequest -Uri "$graphBase/beta/$($family.List)" -Method GET).value |
                    Where-Object { $null -ne $_ })
        }
        catch {
            $state.ScanErrors.Add([PSCustomObject]@{ Family = $family.Name; Policy = '(listing)'; Error = $_.Exception.Message })
            Write-Warning "Could not list $($family.Name): $($_.Exception.Message)"
            continue
        }
        Write-Host "  Retrieved $($policies.Count) policies." -ForegroundColor DarkGray

        foreach ($policy in $policies) {
            $policyId = [string](Get-IACDeepProperty -InputObject $policy -Name 'id')
            if ([string]::IsNullOrWhiteSpace($policyId)) { continue }
            $policyName = [string](Get-IACDeepProperty -InputObject $policy -Name 'name')
            if (-not $policyName) { $policyName = [string](Get-IACDeepProperty -InputObject $policy -Name 'displayName') }
            if (-not $policyName) { $policyName = $policyId }

            $detailPath = $family.Detail.Replace('{id}', [uri]::EscapeDataString($policyId))
            $scope = @{ Keyword = $Keyword; Family = $family; PolicyName = $policyName; PolicyId = $policyId }
            try {
                $detail = Invoke-IACGraphRequest -Uri "$graphBase/beta/$detailPath" -Method GET
                $state.PoliciesScanned++
                $policyMatches = switch ($family.Kind) {
                    'SettingsCatalog' {
                        Find-IACCatalogSettingMatch @scope -Settings @($detail.value) -Definitions $definitions -State $state
                    }
                    'AdministrativeTemplate' {
                        Find-IACAdministrativeTemplateMatch @scope -DefinitionValues @($detail.value)
                    }
                    default {
                        Find-IACPolicyObjectMatch @scope -Policy $detail -IncludePolicyMetadata ([bool]$IncludePolicyMetadata) -State $state
                    }
                }
                foreach ($match in @($policyMatches)) {
                    if ($null -ne $match) { $results.Add($match) }
                }
            }
            catch {
                $state.ScanErrors.Add([PSCustomObject]@{ Family = $family.Name; Policy = $policyName; Error = $_.Exception.Message })
                Write-Warning "Could not scan '$policyName' ($($family.Name)): $($_.Exception.Message)"
            }
        }
    }

    Write-Host "Scanned $($state.PoliciesScanned) policies and decoded $($state.DecodedPayloads) XML payloads. Found $($results.Count) matching settings." -ForegroundColor Cyan
    Write-Host "Choice labels: $($state.ChoiceResolved) resolved; $($state.ChoiceFallback) raw fallbacks; $($state.ChoiceRequests) metadata requests." -ForegroundColor DarkGray

    if ($state.ChoiceWarnings.Count -gt 0) {
        Write-Warning "$($state.ChoiceWarnings.Count) choice label lookup(s) failed; raw values were preserved."
        $state.ChoiceWarnings | Format-Table DefinitionId, Error -Wrap | Out-Host
    }
    if ($state.ScanErrors.Count -gt 0) {
        Write-Warning "$($state.ScanErrors.Count) policy or list request(s) failed. Negative results are NOT conclusive."
        $state.ScanErrors | Format-Table Family, Policy, Error -Wrap | Out-Host
    }
    elseif ($state.PoliciesScanned -eq 0) {
        Write-Warning 'No policies were found in the scanned policy families.'
    }

    if ($results.Count -eq 0) {
        Write-Host 'No matching settings found.' -ForegroundColor Yellow
    }
    else {
        $results | Format-Table PolicyName, SettingName, MatchedValue, PolicyType -AutoSize -Wrap | Out-Host
    }

    if ($ExportPath) {
        try {
            if ($results.Count -gt 0) {
                Export-IACDeepSearchCsv -InputObject $results.ToArray() -Path $ExportPath
                Write-Host "Exported $($results.Count) rows to $ExportPath" -ForegroundColor Green
            }
            else {
                Write-Warning 'No matches to export; CSV file not created.'
            }
            if ($state.ScanErrors.Count -gt 0) {
                $errorsPath = [System.IO.Path]::ChangeExtension($ExportPath, '.errors.csv')
                Export-IACDeepSearchCsv -InputObject $state.ScanErrors.ToArray() -Path $errorsPath
                Write-Warning "Scan errors exported to $errorsPath"
            }
        }
        catch {
            Write-Error "Could not export deep search results: $($_.Exception.Message)"
        }
    }

    if ($PassThru) { $results.ToArray() }
}
