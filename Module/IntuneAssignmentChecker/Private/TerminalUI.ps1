function Test-IACVirtualTerminal {
    [CmdletBinding()]
    param()

    if ($env:NO_COLOR) { return $false }
    try { return [bool]$Host.UI.SupportsVirtualTerminal }
    catch { return $false }
}

function Write-IACTuiText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [ValidateSet('Default', 'Accent', 'Selected', 'Muted', 'Success', 'Warning', 'Error')]
        [string]$Style = 'Default',
        [switch]$NoNewline
    )

    $colors = @{
        Default  = "`e[0m"
        Accent   = "`e[1;36m"
        Selected = "`e[30;46m"
        Muted    = "`e[90m"
        Success  = "`e[32m"
        Warning  = "`e[33m"
        Error    = "`e[31m"
    }
    if (Test-IACVirtualTerminal) {
        Write-Host "$($colors[$Style])$Text`e[0m" -NoNewline:$NoNewline
    }
    else {
        $consoleColor = switch ($Style) {
            'Accent' { 'Cyan' }
            'Selected' { 'Black' }
            'Muted' { 'DarkGray' }
            'Success' { 'Green' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            default { 'Gray' }
        }
        if ($Style -eq 'Selected') {
            Write-Host $Text -ForegroundColor Black -BackgroundColor Cyan -NoNewline:$NoNewline
        }
        else {
            Write-Host $Text -ForegroundColor $consoleColor -NoNewline:$NoNewline
        }
    }
}

function Read-IACTuiParameterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Parameter,
        [Parameter(Mandatory)][string]$CommandName
    )

    $required = if ($Parameter.Mandatory) { 'required' } else { 'optional; Enter skips' }
    $choices = if (@($Parameter.ValidateSet).Count -gt 0) {
        " Choices: $(@($Parameter.ValidateSet) -join ', ')."
    }
    else { '' }
    Write-IACTuiText -Text "`n-$($Parameter.Name)" -Style Accent
    Write-IACTuiText -Text "  $($Parameter.TypeName); $required.$choices" -Style Muted
    if ($Parameter.HelpMessage) { Write-IACTuiText -Text "  $($Parameter.HelpMessage)" -Style Muted }

    if ($Parameter.IsSwitch) {
        $answer = Read-Host '  Enable? (y/N)'
        return [PSCustomObject]@{ Supplied = $answer -match '^(?i:y|yes)$'; Value = $true }
    }
    if ($Parameter.TypeName -eq 'SecureString') {
        $answer = Read-Host '  Supply this secret? (y/N)'
        if ($answer -notmatch '^(?i:y|yes)$') {
            if ($Parameter.Mandatory) { throw "-$($Parameter.Name) is required for $CommandName." }
            return [PSCustomObject]@{ Supplied = $false; Value = $null }
        }
        return [PSCustomObject]@{ Supplied = $true; Value = (Read-Host '  Secret' -AsSecureString) }
    }
    if ($Parameter.TypeName -eq 'PSCredential') {
        $answer = Read-Host '  Supply a credential? (y/N)'
        if ($answer -notmatch '^(?i:y|yes)$') {
            if ($Parameter.Mandatory) { throw "-$($Parameter.Name) is required for $CommandName." }
            return [PSCustomObject]@{ Supplied = $false; Value = $null }
        }
        return [PSCustomObject]@{ Supplied = $true; Value = (Get-Credential -Message "$CommandName -$($Parameter.Name)") }
    }

    while ($true) {
        $value = Read-Host '  Value'
        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($Parameter.Mandatory) {
                Write-IACTuiText -Text "  A value is required." -Style Warning
                continue
            }
            return [PSCustomObject]@{ Supplied = $false; Value = $null }
        }
        if ($Parameter.IsArray) {
            if ($value.StartsWith('@') -and (Test-Path -LiteralPath $value.Substring(1) -PathType Leaf)) {
                try {
                    $items = @(Get-Content -LiteralPath $value.Substring(1) -Raw -ErrorAction Stop |
                            ConvertFrom-Json -Depth 30 -ErrorAction Stop)
                }
                catch {
                    Write-IACTuiText -Text "  Could not read JSON input: $($_.Exception.Message)" -Style Warning
                    continue
                }
            }
            else { $items = @($value -split ',' | ForEach-Object Trim | Where-Object { $_ }) }
            $invalidItems = if (@($Parameter.ValidateSet).Count -gt 0) {
                @($items | Where-Object { $_ -notin $Parameter.ValidateSet })
            }
            else { @() }
            if ($invalidItems.Count -gt 0) {
                Write-IACTuiText -Text "  Invalid value(s): $($invalidItems -join ', '). Choose from: $(@($Parameter.ValidateSet) -join ', ')." -Style Warning
                continue
            }
            try {
                $targetType = [System.Management.Automation.PSTypeName]::new("$($Parameter.Type)").Type
                $convertedItems = if ($targetType) {
                    [System.Management.Automation.LanguagePrimitives]::ConvertTo($items, $targetType)
                }
                else { $items }
                return [PSCustomObject]@{ Supplied = $true; Value = $convertedItems }
            }
            catch {
                Write-IACTuiText -Text "  Could not convert the value: $($_.Exception.Message)" -Style Warning
                continue
            }
        }
        if (@($Parameter.ValidateSet).Count -gt 0 -and $value -notin $Parameter.ValidateSet) {
            Write-IACTuiText -Text "  Choose one of: $(@($Parameter.ValidateSet) -join ', ')." -Style Warning
            continue
        }
        try {
            $targetType = [System.Management.Automation.PSTypeName]::new("$($Parameter.Type)").Type
            $convertedValue = if ($targetType) {
                [System.Management.Automation.LanguagePrimitives]::ConvertTo($value, $targetType)
            }
            else { $value }
            return [PSCustomObject]@{ Supplied = $true; Value = $convertedValue }
        }
        catch {
            Write-IACTuiText -Text "  Could not convert the value: $($_.Exception.Message)" -Style Warning
        }
    }
}

function Read-IACTuiOperationParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Operation)

    $sets = @($Operation.ParameterSets)
    $parameterSet = $sets | Where-Object IsDefault | Select-Object -First 1
    if (-not $parameterSet) { $parameterSet = $sets | Select-Object -First 1 }
    if ($sets.Count -gt 1) {
        Write-IACTuiText -Text "`nParameter sets" -Style Accent
        for ($index = 0; $index -lt $sets.Count; $index++) {
            $suffix = if ($sets[$index].IsDefault) { ' (default)' } else { '' }
            Write-Host "  $($index + 1). $($sets[$index].Name)$suffix"
        }
        $selection = Read-Host "Select [1-$($sets.Count)] or Enter for default"
        if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $sets.Count) {
            $parameterSet = $sets[[int]$selection - 1]
        }
    }

    $values = @{}
    foreach ($parameter in @($parameterSet.Parameters)) {
        $result = Read-IACTuiParameterValue -Parameter $parameter -CommandName $Operation.Name
        if ($result.Supplied) { $values[$parameter.Name] = $result.Value }
    }
    return $values
}

function Show-IACTuiOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Operation)

    try {
        Clear-Host
        Write-IACTuiText -Text $Operation.Name -Style Accent
        Write-IACTuiText -Text $Operation.Synopsis -Style Muted
        $parameters = Read-IACTuiOperationParameters -Operation $Operation
        Write-IACTuiText -Text "`nRunning $($Operation.Name)...`n" -Style Success
        & $Operation.Name @parameters | Out-Host
    }
    catch {
        Write-IACTuiText -Text "`n$($_.Exception.Message)" -Style Error
    }
    Write-IACTuiText -Text "`nPress any key to return to the operation list." -Style Muted -NoNewline
    $null = [Console]::ReadKey($true)
}

function Show-IACTuiScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Operations,
        [Parameter(Mandatory)][int]$SelectedIndex,
        [AllowEmptyString()][string]$Filter = ''
    )

    Clear-Host
    Write-IACTuiText -Text 'INTUNE ASSIGNMENT CHECKER 5.0' -Style Accent
    $tenant = if ($script:CurrentTenantName) { $script:CurrentTenantName } elseif ($script:CurrentTenantId) { $script:CurrentTenantId } else { 'Not connected' }
    Write-IACTuiText -Text "Tenant: $tenant  |  Filter: $(if ($Filter) { $Filter } else { '(none)' })" -Style Muted
    Write-Host ''

    $height = try { [Console]::WindowHeight } catch { 30 }
    $pageSize = [math]::Max(8, $height - 12)
    $pageStart = [math]::Floor($SelectedIndex / $pageSize) * $pageSize
    $pageEnd = [math]::Min($Operations.Count - 1, $pageStart + $pageSize - 1)
    for ($index = $pageStart; $index -le $pageEnd; $index++) {
        $operation = $Operations[$index]
        $line = ' {0,-18} {1}' -f "[$($operation.Category)]", $operation.Name
        if ($index -eq $SelectedIndex) { Write-IACTuiText -Text "> $line" -Style Selected }
        else { Write-Host "  $line" }
    }

    if ($Operations.Count -gt 0) {
        $selected = $Operations[$SelectedIndex]
        Write-Host ''
        Write-IACTuiText -Text $selected.Synopsis -Style Muted
        Write-IACTuiText -Text "Capabilities: $(@($selected.Capabilities) -join ', ')" -Style Muted
    }
    Write-Host ''
    Write-IACTuiText -Text '↑/↓ J/K navigate  PgUp/PgDn jump  Enter run  / filter  C/T switch tenant  ? help  Q quit' -Style Accent
}
