function Export-IACStructuredOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Json', 'JsonLines', 'Csv')][string]$Format
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $parent = Split-Path -Parent $resolvedPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    switch ($Format) {
        'Json' {
            $content = ConvertTo-Json -InputObject @($InputObject) -Depth 30
            [System.IO.File]::WriteAllText($resolvedPath, "$($content.TrimEnd())`n", [System.Text.UTF8Encoding]::new($false))
        }
        'JsonLines' {
            $lines = foreach ($item in @($InputObject)) { ConvertTo-Json -InputObject $item -Depth 30 -Compress }
            $content = if (@($lines).Count -gt 0) { (@($lines) -join "`n") + "`n" } else { '' }
            [System.IO.File]::WriteAllText($resolvedPath, $content, [System.Text.UTF8Encoding]::new($false))
        }
        'Csv' {
            @($InputObject) | ForEach-Object {
                $row = [ordered]@{}
                foreach ($property in $_.PSObject.Properties) {
                    $csvValue = if ($null -eq $property.Value -or $property.Value -is [string] -or
                        $property.Value -is [ValueType]) { $property.Value }
                    else { ConvertTo-Json -InputObject $property.Value -Depth 20 -Compress }
                    $row[$property.Name] = ConvertTo-IACCsvSafeValue -Value $csvValue
                }
                [PSCustomObject]$row
            } | Export-Csv -LiteralPath $resolvedPath -NoTypeInformation -Encoding utf8
        }
    }
    return $resolvedPath
}

function Get-IACSeverityRank {
    [CmdletBinding()]
    param([AllowNull()][string]$Severity)

    switch ($Severity) {
        'Critical' { 4 }
        'High' { 3 }
        'Medium' { 2 }
        'Low' { 1 }
        default { 0 }
    }
}
