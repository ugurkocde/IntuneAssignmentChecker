function Update-IntuneSettingDefinition {
    [CmdletBinding()]
    param()

    # Requires active Graph connection
    if (-not $script:GraphEndpoint) {
        Write-Host "Not connected. Run Connect-IntuneAssignmentChecker first." -ForegroundColor Red
        return
    }

    # Write to a user-writable location (module Data folder is read-only for PSGallery installs)
    $dataDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'IntuneAssignmentChecker'
    if (-not (Test-Path $dataDir)) {
        $null = New-Item -Path $dataDir -ItemType Directory -Force
    }
    $dataPath = Join-Path $dataDir 'SettingDefinitions.json'

    Write-Host "Fetching setting definitions from Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "This may take a few minutes (there are thousands of definitions)." -ForegroundColor Gray

    $allDefinitions = [System.Collections.ArrayList]::new()
    $uri = "$($script:GraphEndpoint)/beta/deviceManagement/configurationSettings?`$select=id,displayName,description,keywords,baseUri,offsetUri,categoryId"

    Write-Host "`rFetching paged definitions..." -NoNewline
    try {
        foreach ($def in @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)) {
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
    catch {
        Write-Host "`nError fetching definitions: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "`rFetched $($allDefinitions.Count) setting definitions." -ForegroundColor Green

    # Write JSON
    $allDefinitions | ConvertTo-Json -Depth 5 -Compress | Set-Content -Path $dataPath -Encoding UTF8
    Write-Host "Saved to: $dataPath" -ForegroundColor Green
    Write-Host "You can now use Search-IntuneSetting to search these definitions." -ForegroundColor Cyan
}
