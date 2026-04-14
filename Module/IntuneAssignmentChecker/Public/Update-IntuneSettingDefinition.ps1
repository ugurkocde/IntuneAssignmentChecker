function Update-IntuneSettingDefinition {
    [CmdletBinding()]
    param()

    # Requires active Graph connection
    if (-not $script:GraphEndpoint) {
        Write-Host "Not connected. Run Connect-IntuneAssignmentChecker first." -ForegroundColor Red
        return
    }

    $dataPath = Join-Path $PSScriptRoot ".." "Data" "SettingDefinitions.json"

    Write-Host "Fetching setting definitions from Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "This may take a few minutes (there are thousands of definitions)." -ForegroundColor Gray

    $allDefinitions = [System.Collections.ArrayList]::new()
    $uri = "$($script:GraphEndpoint)/beta/deviceManagement/configurationSettings?`$select=id,displayName,description,keywords,baseUri,offsetUri,categoryId"

    $page = 0
    do {
        $page++
        Write-Host "`rFetching page $page..." -NoNewline
        try {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            if ($response.value) {
                foreach ($def in $response.value) {
                    $null = $allDefinitions.Add([PSCustomObject]@{
                        id          = $def.id
                        displayName = $def.displayName
                        description = $def.description
                        keywords    = $def.keywords
                        baseUri     = $def.baseUri
                        offsetUri   = $def.offsetUri
                    })
                }
            }
            $uri = $response.'@odata.nextLink'
        }
        catch {
            Write-Host "`nError fetching definitions: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } while (![string]::IsNullOrEmpty($uri))

    Write-Host "`rFetched $($allDefinitions.Count) setting definitions." -ForegroundColor Green

    # Write JSON
    $allDefinitions | ConvertTo-Json -Depth 5 -Compress | Set-Content -Path $dataPath -Encoding UTF8
    Write-Host "Saved to: $dataPath" -ForegroundColor Green
    Write-Host "You can now use Search-IntuneSetting to search these definitions." -ForegroundColor Cyan
}
