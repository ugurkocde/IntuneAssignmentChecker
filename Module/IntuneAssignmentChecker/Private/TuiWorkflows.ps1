function New-IACTuiState {
    [CmdletBinding()]
    param(
        [ValidateSet('Overview', 'Assignments', 'Governance', 'Simulator', 'Drift', 'Health', 'Access', 'Filters', 'Fleet', 'Reports', 'Settings')]
        [string]$InitialView = 'Overview'
    )

    $registry = @(Get-IACTuiFeatureRegistry)
    $rows = @{}
    $notices = @{}
    foreach ($feature in $registry) { $rows[$feature.Id] = @(); $notices[$feature.Id] = @() }
    $navigationIndex = [array]::IndexOf(@($registry.Id), $InitialView)
    if ($navigationIndex -lt 0) { $navigationIndex = 0 }

    [PSCustomObject][ordered]@{
        Registry         = $registry
        ActiveViewId     = $InitialView
        NavigationIndex  = $navigationIndex
        NavigationOffset = 0
        LastNavigationWidth = 25
        Focus             = 'Navigation'
        SelectedIndex     = 0
        RowOffset         = 0
        Filter            = ''
        Rows              = $rows
        RawResults        = @{}
        Notices           = $notices
        Metrics           = [ordered]@{
            Coverage = $null
            Critical = $null
            Drift    = $null
            Health   = $null
        }
        StatusMessage     = 'Ready. Connect a tenant or open a workspace.'
        StatusStyle       = 'Muted'
        Busy              = $false
        ExitRequested     = $false
        HitTargets        = [Collections.Generic.List[object]]::new()
        Terminal          = $null
        Settings          = [ordered]@{
            BaselinePath    = ''
            OutputDirectory = (Get-Location).Path
            SnapshotPath    = ''
            ScopeTagFilter  = ''
        }
    }
}

function Set-IACTuiStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('Muted', 'Blue', 'Success', 'Warning', 'Error')][string]$Style = 'Muted'
    )

    $State.StatusMessage = $Message
    $State.StatusStyle = $Style
}

function Set-IACTuiActiveView {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$ViewId
    )

    $index = [array]::IndexOf(@($State.Registry.Id), $ViewId)
    if ($index -lt 0) { return }
    $State.ActiveViewId = $ViewId
    $State.NavigationIndex = $index
    $State.SelectedIndex = 0
    $State.RowOffset = 0
    $State.Filter = ''
}

function Get-IACTuiObjectProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string[]]$Name
    )

    if ($null -eq $InputObject) { return $null }
    foreach ($candidate in $Name) {
        $property = $InputObject.PSObject.Properties[$candidate]
        if ($property -and $null -ne $property.Value -and "$($property.Value)" -ne '') { return $property.Value }
    }
    return $null
}

function ConvertTo-IACTuiRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
        [int]$Ordinal = 0
    )

    process {
        if ($InputObject -is [System.Management.Automation.InformationRecord]) { return }
        if ($InputObject -is [System.Management.Automation.WarningRecord]) {
            return [PSCustomObject][ordered]@{
                Title       = 'Warning'
                Status      = 'Warning'
                Summary     = "$InputObject"
                DetailLines = @("$InputObject")
                Raw         = $InputObject
            }
        }
        $title = Get-IACTuiObjectProperty -InputObject $InputObject -Name @(
            'PolicyName', 'DisplayName', 'displayName', 'Name', 'name', 'Title', 'RuleId',
            'Check', 'TenantName', 'UserPrincipalName', 'DeviceName', 'FilterName', 'Id', 'id'
        )
        if (-not $title) { $title = "Result $($Ordinal + 1)" }
        $status = Get-IACTuiObjectProperty -InputObject $InputObject -Name @(
            'Severity', 'Risk', 'Status', 'Result', 'EffectiveState', 'ChangeType', 'AssignmentMode', 'Type'
        )
        if (-not $status) { $status = 'Available' }
        $summary = Get-IACTuiObjectProperty -InputObject $InputObject -Name @(
            'Message', 'Summary', 'Detail', 'Description', 'AssignmentReason', 'Reason', 'Remediation'
        )

        $detail = [Collections.Generic.List[string]]::new()
        foreach ($property in @($InputObject.PSObject.Properties)) {
            if ($detail.Count -ge 12) { break }
            if ($property.Name -match '^PS' -or $null -eq $property.Value) { continue }
            if ($property.Value -is [Collections.IDictionary] -or
                ($property.Value -is [Collections.IEnumerable] -and $property.Value -isnot [string])) { continue }
            $value = "$($property.Value)" -replace '[\r\n\t]+', ' '
            if ($value.Length -gt 180) { $value = $value.Substring(0, 179) + '…' }
            [void]$detail.Add("$($property.Name): $value")
        }
        if ($detail.Count -eq 0 -and $summary) { [void]$detail.Add("$summary") }
        [PSCustomObject][ordered]@{
            Title       = "$title"
            Status      = "$status"
            Summary     = "$summary"
            DetailLines = @($detail)
            Raw         = $InputObject
        }
    }
}

function ConvertTo-IACTuiRows {
    [CmdletBinding()]
    param([AllowNull()][object[]]$InputObject)

    $rows = [Collections.Generic.List[object]]::new()
    $ordinal = 0
    foreach ($item in @($InputObject)) {
        if ($null -eq $item -or $item -is [System.Management.Automation.InformationRecord]) { continue }
        $row = ConvertTo-IACTuiRow -InputObject $item -Ordinal $ordinal
        if ($row) { [void]$rows.Add($row); $ordinal++ }
    }
    return @($rows)
}

function Get-IACTuiViewRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [string]$ViewId = $State.ActiveViewId
    )

    $rows = @($State.Rows[$ViewId])
    if ([string]::IsNullOrWhiteSpace($State.Filter)) { return $rows }
    return @($rows | Where-Object {
            $_.Title -like "*$($State.Filter)*" -or $_.Status -like "*$($State.Filter)*" -or
            $_.Summary -like "*$($State.Filter)*" -or (@($_.DetailLines) -join ' ') -like "*$($State.Filter)*"
        })
}

function Set-IACTuiResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$ViewId,
        [AllowNull()][object[]]$Result,
        [Parameter(Mandatory)][string]$SuccessMessage
    )

    $State.RawResults[$ViewId] = @($Result)
    $State.Rows[$ViewId] = @(ConvertTo-IACTuiRows -InputObject @($Result))
    $State.SelectedIndex = 0
    $State.RowOffset = 0
    $State.Filter = ''
    Set-IACTuiStatus -State $State -Message $SuccessMessage -Style Success
}

function Test-IACTuiConnected {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    if ($script:GraphEndpoint) { return $true }
    Set-IACTuiActiveView -State $State -ViewId Settings
    Set-IACTuiStatus -State $State -Message 'Connect a tenant before loading live data.' -Style Warning
    return $false
}

function Show-IACTuiModalFrame {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Lines,
        [string[]]$Choices = @(),
        [int]$SelectedChoice = -1,
        [AllowEmptyString()][string]$InputText = '',
        [switch]$ShowInput
    )

    $width = [math]::Max(1, [math]::Min(1000, $(try { [Console]::WindowWidth } catch { 120 })))
    $height = [math]::Max(1, [math]::Min(500, $(try { [Console]::WindowHeight } catch { 36 })))
    $buffer = New-IACTuiBuffer -Width $width -Height $height
    Write-IACTuiBufferFill -Buffer $buffer -X 0 -Y 0 -Width $width -Height $height -Style Canvas
    if ($width -lt 20 -or $height -lt 8) {
        Write-IACTuiBufferText -Buffer $buffer -X 0 -Y 0 -Text $Title -Style Accent -MaxWidth $width
        if ($height -gt 2) { Write-IACTuiBufferText -Buffer $buffer -X 0 -Y 2 -Text $Lines[0] -Style Muted -MaxWidth $width }
        if ($ShowInput -and $height -gt 4) { Write-IACTuiBufferText -Buffer $buffer -X 0 -Y 4 -Text $InputText -Style Text -MaxWidth $width }
        $ansi = [bool]($State.Terminal -and $State.Terminal.ColorEnabled)
        $frame = ConvertTo-IACTuiBufferText -Buffer $buffer -Ansi:$ansi
        if ($State.Terminal -and $State.Terminal.VirtualTerminal) { [Console]::Write("`e[H$frame") } else { Clear-Host; [Console]::Write($frame) }
        return
    }
    $boxWidth = [math]::Min($width - 4, [math]::Max(54, [math]::Floor($width * 0.62)))
    $contentRows = $Lines.Count + $Choices.Count + $(if ($ShowInput) { 3 } else { 1 })
    $boxHeight = [math]::Min($height - 4, [math]::Max(10, $contentRows + 6))
    $boxX = [math]::Floor(($width - $boxWidth) / 2)
    $boxY = [math]::Floor(($height - $boxHeight) / 2)
    Write-IACTuiBox -Buffer $buffer -X $boxX -Y $boxY -Width $boxWidth -Height $boxHeight -Style PanelRaised -BorderStyle Accent
    Write-IACTuiBufferText -Buffer $buffer -X ($boxX + 3) -Y ($boxY + 1) -Text $Title -Style Accent -MaxWidth ($boxWidth - 6)
    $row = $boxY + 3
    foreach ($line in $Lines) {
        Write-IACTuiBufferText -Buffer $buffer -X ($boxX + 3) -Y $row -Text $line -Style Muted -MaxWidth ($boxWidth - 6)
        $row++
    }
    if ($ShowInput) {
        $row++
        Write-IACTuiBufferFill -Buffer $buffer -X ($boxX + 3) -Y $row -Width ($boxWidth - 6) -Height 1 -Style Panel
        $displayInput = ConvertTo-IACTuiDisplayText -Value "$InputText▌" -Width ($boxWidth - 8)
        Write-IACTuiBufferText -Buffer $buffer -X ($boxX + 4) -Y $row -Text $displayInput -Style Text
        $row += 2
    }
    foreach ($choice in $Choices) {
        $choiceIndex = [array]::IndexOf($Choices, $choice)
        $choiceStyle = if ($choiceIndex -eq $SelectedChoice) { 'AccentStrong' } else { 'Selected' }
        $label = "  $choice  "
        Write-IACTuiBufferText -Buffer $buffer -X ($boxX + 3) -Y $row -Text $label -Style $choiceStyle
        Add-IACTuiHitTarget -State $State -X ($boxX + 3) -Y $row -Width $label.Length -Height 1 -Action ModalChoice -Value $choiceIndex
        $row++
    }
    Write-IACTuiBufferText -Buffer $buffer -X ($boxX + 3) -Y ($boxY + $boxHeight - 2) -Text 'Enter confirm  Esc cancel' -Style Muted -MaxWidth ($boxWidth - 6)
    $ansi = [bool]($State.Terminal -and $State.Terminal.ColorEnabled)
    $frame = ConvertTo-IACTuiBufferText -Buffer $buffer -Ansi:$ansi
    if ($State.Terminal -and $State.Terminal.VirtualTerminal) { [Console]::Write("`e[H$frame") } else { Clear-Host; [Console]::Write($frame) }
}

function Read-IACTuiTextInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt,
        [AllowEmptyString()][string]$DefaultValue = '',
        [switch]$Required
    )

    $value = "$DefaultValue"
    while ($true) {
        $State.HitTargets.Clear()
        $guidance = if ($Required) { @($Prompt, 'A value is required.') } else { @($Prompt, 'Leave blank to skip.') }
        Show-IACTuiModalFrame -State $State -Title $Title -Lines $guidance -InputText $value -ShowInput -Choices @('Confirm', 'Cancel') -SelectedChoice 0
        $inputEvent = Read-IACTuiInput
        if (Test-IACTuiControlCEvent -InputEvent $inputEvent) { $State.ExitRequested = $true; return $null }
        if ($inputEvent.Kind -eq 'Mouse') {
            if ($inputEvent.Action -eq 'Wheel') { continue }
            if ($inputEvent.Button -eq 'Left' -and $inputEvent.Action -eq 'Down') {
                $target = Get-IACTuiHitTarget -State $State -X $inputEvent.X -Y $inputEvent.Y
                if ($target -and $target.Action -eq 'ModalChoice') {
                    if ([int]$target.Value -eq 1) { return $null }
                    if (-not $Required -or -not [string]::IsNullOrWhiteSpace($value)) { return $value }
                }
            }
            continue
        }
        switch ($inputEvent.Key) {
            'Escape' { return $null }
            'Enter' {
                if (-not $Required -or -not [string]::IsNullOrWhiteSpace($value)) { return $value }
            }
            'Backspace' { if ($value.Length -gt 0) { $value = $value.Substring(0, $value.Length - 1) } }
            default {
                if ($inputEvent.Character.Length -eq 1 -and -not [char]::IsControl($inputEvent.Character[0])) { $value += $inputEvent.Character }
            }
        }
    }
}

function Read-IACTuiChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][ValidateCount(1, 20)][string[]]$Choice,
        [int]$DefaultIndex = 0
    )

    $selected = [math]::Max(0, [math]::Min($DefaultIndex, $Choice.Count - 1))
    while ($true) {
        $State.HitTargets.Clear()
        Show-IACTuiModalFrame -State $State -Title $Title -Lines @($Prompt) -Choices $Choice -SelectedChoice $selected
        $inputEvent = Read-IACTuiInput
        if (Test-IACTuiControlCEvent -InputEvent $inputEvent) { $State.ExitRequested = $true; return $null }
        if ($inputEvent.Kind -eq 'Mouse') {
            if ($inputEvent.Action -eq 'Wheel') {
                $selected = [math]::Max(0, [math]::Min($Choice.Count - 1, $selected - $inputEvent.WheelDelta))
                continue
            }
            if ($inputEvent.Button -eq 'Left' -and $inputEvent.Action -eq 'Down') {
                $target = Get-IACTuiHitTarget -State $State -X $inputEvent.X -Y $inputEvent.Y
                if ($target -and $target.Action -eq 'ModalChoice') { return $Choice[[int]$target.Value] }
            }
            continue
        }
        switch ($inputEvent.Key) {
            'Escape' { return $null }
            'Enter' { return $Choice[$selected] }
            'UpArrow' { $selected = [math]::Max(0, $selected - 1) }
            'DownArrow' { $selected = [math]::Min($Choice.Count - 1, $selected + 1) }
            default {
                if ($inputEvent.Character -in @('k', 'K')) { $selected = [math]::Max(0, $selected - 1) }
                elseif ($inputEvent.Character -in @('j', 'J')) { $selected = [math]::Min($Choice.Count - 1, $selected + 1) }
            }
        }
    }
}

function Read-IACTuiSecretInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt
    )

    $secret = [Security.SecureString]::new()
    while ($true) {
        $State.HitTargets.Clear()
        Show-IACTuiModalFrame -State $State -Title $Title -Lines @($Prompt, 'The value is kept as a SecureString and is never displayed.') `
            -InputText ('•' * $secret.Length) -ShowInput -Choices @('Confirm', 'Cancel') -SelectedChoice 0
        $inputEvent = Read-IACTuiInput
        if (Test-IACTuiControlCEvent -InputEvent $inputEvent) { $State.ExitRequested = $true; $secret.Dispose(); return $null }
        if ($inputEvent.Kind -eq 'Mouse') {
            if ($inputEvent.Button -eq 'Left' -and $inputEvent.Action -eq 'Down') {
                $target = Get-IACTuiHitTarget -State $State -X $inputEvent.X -Y $inputEvent.Y
                if ($target -and $target.Action -eq 'ModalChoice') {
                    if ([int]$target.Value -eq 1) { $secret.Dispose(); return $null }
                    if ($secret.Length -gt 0) { $secret.MakeReadOnly(); return $secret }
                }
            }
            continue
        }
        if ($inputEvent.Kind -ne 'Key') { continue }
        switch ($inputEvent.Key) {
            'Escape' { $secret.Dispose(); return $null }
            'Enter' { if ($secret.Length -gt 0) { $secret.MakeReadOnly(); return $secret } }
            'Backspace' { if ($secret.Length -gt 0) { $secret.RemoveAt($secret.Length - 1) } }
            default {
                if ($inputEvent.Character.Length -eq 1 -and -not [char]::IsControl($inputEvent.Character[0])) {
                    $secret.AppendChar($inputEvent.Character[0])
                }
            }
        }
    }
}

function Read-IACTuiConfirmation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt
    )

    (Read-IACTuiChoice -State $State -Title $Title -Prompt $Prompt -Choice @('Continue', 'Cancel') -DefaultIndex 1) -eq 'Continue'
}

function Read-IACTuiMultiChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][ValidateCount(1, 16)][string[]]$Choice,
        [string[]]$DefaultChoice = @(),
        [scriptblock]$InputProvider,
        [switch]$SuppressRender
    )

    $selected = [Collections.Generic.HashSet[int]]::new()
    foreach ($defaultValue in $DefaultChoice) {
        $index = [array]::IndexOf($Choice, $defaultValue)
        if ($index -ge 0) { $null = $selected.Add($index) }
    }
    $cursor = 0
    :multiChoiceLoop while ($true) {
        $displayChoices = @(
            for ($index = 0; $index -lt $Choice.Count; $index++) {
                "[$(if ($selected.Contains($index)) { 'x' } else { ' ' })] $($Choice[$index])"
            }
            'Apply selection'
            'Cancel'
        )
        if (-not $SuppressRender) {
            $State.HitTargets.Clear()
            Show-IACTuiModalFrame -State $State -Title $Title -Lines @($Prompt, 'Select one or more profiles. Space or click toggles a profile.') `
                -Choices $displayChoices -SelectedChoice $cursor
        }
        $inputEvent = if ($InputProvider) { & $InputProvider } else { Read-IACTuiInput }
        if (Test-IACTuiControlCEvent -InputEvent $inputEvent) { $State.ExitRequested = $true; return $null }
        $chosenIndex = -1
        if ($inputEvent.Kind -eq 'Mouse') {
            if ($inputEvent.Action -eq 'Wheel') {
                $cursor = [math]::Max(0, [math]::Min($displayChoices.Count - 1, $cursor - $inputEvent.WheelDelta))
                continue
            }
            if ($inputEvent.Button -eq 'Left' -and $inputEvent.Action -eq 'Down') {
                $target = Get-IACTuiHitTarget -State $State -X $inputEvent.X -Y $inputEvent.Y
                if ($target -and $target.Action -eq 'ModalChoice') { $chosenIndex = [int]$target.Value }
            }
            if ($chosenIndex -lt 0) { continue }
        }
        elseif ($inputEvent.Kind -eq 'Key') {
            switch ($inputEvent.Key) {
                'Escape' { return $null }
                'UpArrow' { $cursor = [math]::Max(0, $cursor - 1); continue multiChoiceLoop }
                'DownArrow' { $cursor = [math]::Min($displayChoices.Count - 1, $cursor + 1); continue multiChoiceLoop }
                'Spacebar' { $chosenIndex = $cursor }
                'Enter' { $chosenIndex = $cursor }
                default {
                    if ($inputEvent.Character -in @('k', 'K')) { $cursor = [math]::Max(0, $cursor - 1); continue multiChoiceLoop }
                    if ($inputEvent.Character -in @('j', 'J')) { $cursor = [math]::Min($displayChoices.Count - 1, $cursor + 1); continue multiChoiceLoop }
                    continue multiChoiceLoop
                }
            }
        }
        else { continue }

        if ($chosenIndex -eq $Choice.Count + 1) { return $null }
        if ($chosenIndex -eq $Choice.Count) {
            if ($selected.Count -eq 0) {
                Set-IACTuiStatus -State $State -Message 'Select at least one capability profile.' -Style Warning
                continue
            }
            return @($selected | Sort-Object | ForEach-Object { $Choice[$_] })
        }

        if ($Choice[$chosenIndex] -eq 'Full') {
            $selected.Clear()
            $null = $selected.Add($chosenIndex)
        }
        else {
            $fullIndex = [array]::IndexOf($Choice, 'Full')
            if ($fullIndex -ge 0) { $null = $selected.Remove($fullIndex) }
            if (-not $selected.Remove($chosenIndex)) { $null = $selected.Add($chosenIndex) }
        }
        $cursor = $chosenIndex
    }
}

function Invoke-IACTuiCapturedOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$ViewId,
        [Parameter(Mandatory)][scriptblock]$Operation,
        [Parameter(Mandatory)][string]$SuccessMessage,
        [switch]$SuppressRender
    )

    $State.Busy = $true
    if (-not $SuppressRender) { Show-IACTuiFrame -State $State }
    $restoreControlCMode = $false
    $originalControlCMode = $false
    try {
        try {
            $originalControlCMode = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $false
            $restoreControlCMode = $true
        }
        catch { }
        $result = @(& $Operation *>&1)
        $operationErrors = @($result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $operationWarnings = @($result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $objects = @($result | Where-Object {
                $_ -isnot [System.Management.Automation.ErrorRecord] -and
                $_ -isnot [System.Management.Automation.WarningRecord] -and
                $_ -isnot [System.Management.Automation.InformationRecord] -and
                $_ -isnot [System.Management.Automation.VerboseRecord] -and
                $_ -isnot [System.Management.Automation.DebugRecord]
            })
        $State.Notices[$ViewId] = @(
            $operationErrors | ForEach-Object { [PSCustomObject]@{ Status = 'Error'; Message = $_.Exception.Message } }
            $operationWarnings | ForEach-Object { [PSCustomObject]@{ Status = 'Warning'; Message = "$($_.Message)" } }
        )
        if ($objects.Count -gt 0) {
            Set-IACTuiResult -State $State -ViewId $ViewId -Result $objects -SuccessMessage $SuccessMessage
            if ($operationErrors.Count -gt 0) {
                Set-IACTuiStatus -State $State -Message "Loaded $($objects.Count) results with $($operationErrors.Count) partial error(s)." -Style Warning
            }
            elseif ($operationWarnings.Count -gt 0) {
                Set-IACTuiStatus -State $State -Message "Loaded $($objects.Count) results with $($operationWarnings.Count) warning(s)." -Style Warning
            }
            return $objects
        }
        if ($operationErrors.Count -gt 0) {
            $errorRows = @($operationErrors | ForEach-Object {
                    [PSCustomObject][ordered]@{ Title = 'Operation failed'; Status = 'Error'; Message = $_.Exception.Message }
                })
            Set-IACTuiResult -State $State -ViewId $ViewId -Result $errorRows -SuccessMessage $operationErrors[0].Exception.Message
            Set-IACTuiStatus -State $State -Message $operationErrors[0].Exception.Message -Style Error
            return @()
        }
        if ($operationWarnings.Count -gt 0) {
            $warningSummary = [PSCustomObject][ordered]@{
                Title = "Completed with $($operationWarnings.Count) warning(s)"
                Status = 'Warning'
                Message = "$($operationWarnings[0].Message)"
            }
            Set-IACTuiResult -State $State -ViewId $ViewId -Result @($warningSummary) -SuccessMessage $warningSummary.Title
            Set-IACTuiStatus -State $State -Message $warningSummary.Title -Style Warning
            return @()
        }
        if ($objects.Count -eq 0) {
            $activityMessages = @($result | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } |
                    ForEach-Object { "$($_.MessageData)" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $objects = @($activityMessages | ForEach-Object {
                    $status = Get-IACTuiInformationStatus -Message $_
                    [PSCustomObject][ordered]@{
                        Title   = (ConvertTo-IACTuiDisplayText -Value $_ -Width 80)
                        Status  = $status
                        Message = $_
                    }
                })
        }
        Set-IACTuiResult -State $State -ViewId $ViewId -Result $objects -SuccessMessage $SuccessMessage
        $State.RawResults[$ViewId] = @()
        $informationErrors = @($objects | Where-Object Status -EQ Error)
        if ($informationErrors.Count -gt 0) {
            $State.Notices[$ViewId] = @($informationErrors | ForEach-Object {
                    [PSCustomObject]@{ Status = 'Error'; Message = $_.Message }
                })
            Set-IACTuiStatus -State $State -Message $informationErrors[0].Message -Style Error
            return @()
        }
        $informationWarnings = @($objects | Where-Object Status -EQ Warning)
        if ($informationWarnings.Count -gt 0) {
            $State.Notices[$ViewId] = @($informationWarnings | ForEach-Object {
                    [PSCustomObject]@{ Status = 'Warning'; Message = $_.Message }
                })
            Set-IACTuiStatus -State $State -Message $informationWarnings[0].Message -Style Warning
            return @()
        }
        return @()
    }
    catch {
        $errorRow = [PSCustomObject][ordered]@{
            Title = 'Operation failed'
            Status = 'Error'
            Message = $_.Exception.Message
        }
        Set-IACTuiResult -State $State -ViewId $ViewId -Result @($errorRow) -SuccessMessage $_.Exception.Message
        $State.Notices[$ViewId] = @([PSCustomObject]@{ Status = 'Error'; Message = $_.Exception.Message })
        Set-IACTuiStatus -State $State -Message $_.Exception.Message -Style Error
        return @()
    }
    finally {
        if ($restoreControlCMode) {
            try { [Console]::TreatControlCAsInput = $originalControlCMode }
            catch { }
        }
        $State.Busy = $false
    }
}

function Get-IACTuiInformationStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    $normalized = $Message.Trim()
    if ($normalized -match '(?i)^(not connected\.|invalid |user not found:|device not found:|multiple (devices|groups) (match|found)|the group lookup .+ invalid|error (fetching|checking)|setting definitions file (not found|is empty)|please provide at least two groups|both .+ required|no (user or device|group|keyword|valid upns?|device name|upn) provided|no (group|device) found)') {
        return 'Error'
    }
    if ($normalized -match '(?i)(nothing to simulate|already a member)') { return 'Warning' }
    return 'Complete'
}

function Export-IACTuiScanRunSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Force
    )

    $coverageErrors = @($Run.Errors) + @($Run.Skipped)
    $snapshotParameters = @{
        Path             = $Path
        InputObject      = @($Run.Records)
        CoverageCategory = @($Run.Selected)
        CoverageComplete = [bool]$Run.Complete
        CoverageError    = @($coverageErrors)
        Force            = $Force
        PassThru         = $true
    }
    Export-IntuneAssignmentSnapshot @snapshotParameters
}

function Invoke-IACTuiAssignmentAction {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$ActionId)

    if (-not (Test-IACTuiConnected -State $State)) { return }
    $scopeTag = $State.Settings.ScopeTagFilter
    switch ($ActionId) {
        'SearchAssignments' {
            $term = Read-IACTuiTextInput -State $State -Title 'Search policies' -Prompt 'Policy or application name' -Required
            if ($null -ne $term) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Policy search complete.' -Operation { Search-IntunePolicy -PolicySearchTerm $term -PassThru } | Out-Null }
        }
        'FindUserAssignments' {
            $users = Read-IACTuiTextInput -State $State -Title 'Find a user' -Prompt 'User principal name (separate several with commas)' -Required
            if ($null -ne $users) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'User assignments loaded.' -Operation { Get-IntuneUserAssignment -UserPrincipalNames $users -ScopeTagFilter $scopeTag -PassThru } | Out-Null }
        }
        'FindDeviceAssignments' {
            $devices = Read-IACTuiTextInput -State $State -Title 'Find a device' -Prompt 'Device name or object ID (separate several with commas)' -Required
            if ($null -ne $devices) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Device assignments loaded.' -Operation { Get-IntuneDeviceAssignment -DeviceNames $devices -ScopeTagFilter $scopeTag -PassThru } | Out-Null }
        }
        'FindGroupAssignments' {
            $groups = Read-IACTuiTextInput -State $State -Title 'Find a group' -Prompt 'Group name or object ID (separate several with commas)' -Required
            if ($null -ne $groups) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Group assignments loaded.' -Operation { Get-IntuneGroupAssignment -GroupNames $groups -IncludeNestedGroups -ScopeTagFilter $scopeTag -PassThru } | Out-Null }
        }
        'ExplainEffectiveAssignment' {
            $user = Read-IACTuiTextInput -State $State -Title 'Explain effective state' -Prompt 'User principal name (optional)'
            if ($null -eq $user) { return }
            $device = Read-IACTuiTextInput -State $State -Title 'Explain effective state' -Prompt 'Device name or object ID (optional)'
            if ($null -eq $device) { return }
            if (-not $user -and -not $device) { Set-IACTuiStatus -State $State -Message 'Enter a user, a device, or both.' -Style Warning; return }
            $explanationMode = 'Effective targeting trace'
            if ($user -and $device) {
                $explanationMode = Read-IACTuiChoice -State $State -Title 'Explain effective state' -Prompt 'Choose the result view.' -Choice @('Effective targeting trace', 'Combined user/device inventory')
                if (-not $explanationMode) { return }
            }
            if ($explanationMode -eq 'Combined user/device inventory') {
                Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Combined assignment inventory loaded.' -Operation {
                    Get-IntuneUserDeviceAssignment -UserPrincipalName $user -DeviceName $device -ScopeTagFilter $scopeTag -PassThru
                } | Out-Null
            }
            else {
                Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Effective assignment calculated.' -Operation {
                    Get-IntuneEffectiveAssignment -UserPrincipalName $user -DeviceName $device -PassThru
                } | Out-Null
            }
        }
        'BrowseAssignmentInventory' {
            $mode = Read-IACTuiChoice -State $State -Title 'Browse assignment inventory' -Prompt 'Choose the assignment view.' -Choice @(
                'All policies', 'All Users targeting', 'All Devices targeting', 'Unassigned policies', 'Empty target groups'
            )
            if (-not $mode) { return }
            $operation = switch ($mode) {
                'All policies' { { Get-IntuneAllPolicies -ScopeTagFilter $scopeTag -PassThru } }
                'All Users targeting' { { Get-IntuneAllUsersAssignment -ScopeTagFilter $scopeTag -PassThru } }
                'All Devices targeting' { { Get-IntuneAllDevicesAssignment -ScopeTagFilter $scopeTag -PassThru } }
                'Unassigned policies' { { Get-IntuneUnassignedPolicy -ScopeTagFilter $scopeTag -PassThru } }
                'Empty target groups' { { Get-IntuneEmptyGroup -PassThru } }
            }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage "$mode loaded." -Operation $operation | Out-Null
        }
        'CompareGroupTargeting' {
            $groups = Read-IACTuiTextInput -State $State -Title 'Compare groups' -Prompt 'Two or more group names, separated with commas' -Required
            if ($null -ne $groups) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Group comparison complete.' -Operation { Compare-IntuneGroupAssignment -CompareGroupNames $groups -IncludeNestedGroups -PassThru } | Out-Null }
        }
        'SearchConfiguredSettings' {
            $keyword = Read-IACTuiTextInput -State $State -Title 'Search configured settings' -Prompt 'Setting name or keyword' -Required
            if ($null -ne $keyword) { Invoke-IACTuiCapturedOperation -State $State -ViewId Assignments -SuccessMessage 'Settings search complete.' -Operation { Search-IntuneSetting -Keyword $keyword -PassThru } | Out-Null }
        }
    }
}

function Invoke-IACTuiSimulatorAction {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$ActionId)

    switch ($ActionId) {
        'SimulateAssignmentChange' {
            $snapshot = Read-IACTuiTextInput -State $State -Title 'Propose assignment change' -Prompt 'Saved snapshot path' -DefaultValue $State.Settings.SnapshotPath -Required
            if ($null -eq $snapshot) { return }
            $change = Read-IACTuiChoice -State $State -Title 'Propose assignment change' -Prompt 'What should change?' -Choice @('Add assignment', 'Remove assignment', 'Replace target', 'Change filter', 'Change intent')
            if (-not $change) { return }
            $policy = Read-IACTuiTextInput -State $State -Title 'Propose assignment change' -Prompt 'Policy ID' -Required
            if ($null -eq $policy) { return }
            $changeType = @{
                'Add assignment' = 'AddAssignment'; 'Remove assignment' = 'RemoveAssignment'; 'Replace target' = 'ReplaceTarget'
                'Change filter' = 'ChangeFilter'; 'Change intent' = 'ChangeIntent'
            }[$change]
            $parameters = @{ SnapshotPath = $snapshot; ChangeType = $changeType; PolicyId = $policy }
            if ($changeType -ne 'AddAssignment') {
                $assignment = Read-IACTuiTextInput -State $State -Title 'Propose assignment change' -Prompt 'Existing assignment ID' -Required
                if ($null -eq $assignment) { return }; $parameters.AssignmentId = $assignment
            }
            if ($changeType -in @('AddAssignment', 'ReplaceTarget')) {
                $targetType = Read-IACTuiChoice -State $State -Title 'Target' -Prompt 'Choose the target type.' -Choice @('Group', 'All Users', 'All Devices')
                if (-not $targetType) { return }
                $parameters.TargetType = $targetType -replace ' ', ''
                if ($targetType -eq 'Group') {
                    $targetId = Read-IACTuiTextInput -State $State -Title 'Target' -Prompt 'Group object ID' -Required
                    if ($null -eq $targetId) { return }; $parameters.TargetId = $targetId
                }
            }
            if ($changeType -eq 'ChangeIntent') {
                $intent = Read-IACTuiTextInput -State $State -Title 'Application intent' -Prompt 'New intent (for example required or available)' -Required
                if ($null -eq $intent) { return }; $parameters.Intent = $intent
            }
            if ($changeType -eq 'ChangeFilter') {
                $filterId = Read-IACTuiTextInput -State $State -Title 'Assignment filter' -Prompt 'Filter ID (blank removes the filter)'
                if ($null -eq $filterId) { return }; $parameters.FilterId = $filterId
                $filterMode = Read-IACTuiChoice -State $State -Title 'Assignment filter' -Prompt 'How should the filter apply?' -Choice @('include', 'exclude', 'none')
                if (-not $filterMode) { return }; $parameters.FilterMode = $filterMode
            }
            $State.Settings.SnapshotPath = $snapshot
            Invoke-IACTuiCapturedOperation -State $State -ViewId Simulator -SuccessMessage 'Blast-radius simulation complete. No changes were written.' -Operation { Test-IntuneAssignmentChange @parameters } | Out-Null
        }
        { $_ -in @('SimulateMembershipAdd', 'SimulateMembershipRemoval') } {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $entityType = Read-IACTuiChoice -State $State -Title 'Membership simulation' -Prompt 'Whose membership should be modeled?' -Choice @('User', 'Device')
            if (-not $entityType) { return }
            $entity = Read-IACTuiTextInput -State $State -Title 'Membership simulation' -Prompt $(if ($entityType -eq 'User') { 'User principal name' } else { 'Device name or object ID' }) -Required
            if ($null -eq $entity) { return }
            $group = Read-IACTuiTextInput -State $State -Title 'Membership simulation' -Prompt 'Target group name or object ID' -Required
            if ($null -eq $group) { return }
            $entityParameters = if ($entityType -eq 'User') { @{ UserPrincipalNames = $entity } } else { @{ DeviceNames = $entity } }
            if ($State.Settings.ScopeTagFilter) { $entityParameters.ScopeTagFilter = $State.Settings.ScopeTagFilter }
            if ($ActionId -eq 'SimulateMembershipAdd') {
                Invoke-IACTuiCapturedOperation -State $State -ViewId Simulator -SuccessMessage 'Membership-add simulation complete. No changes were written.' -Operation {
                    Test-IntuneGroupMembership @entityParameters -SimulateTargetGroup $group -PassThru
                } | Out-Null
            }
            else {
                Invoke-IACTuiCapturedOperation -State $State -ViewId Simulator -SuccessMessage 'Membership-removal simulation complete. No changes were written.' -Operation {
                    Test-IntuneGroupRemoval @entityParameters -SimulateRemoveTargetGroup $group -PassThru
                } | Out-Null
            }
        }
    }
}

function Invoke-IACTuiWorkflowAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$ActionId
    )

    switch ($State.ActiveViewId) {
        'Assignments' { Invoke-IACTuiAssignmentAction -State $State -ActionId $ActionId; return }
        'Simulator' { Invoke-IACTuiSimulatorAction -State $State -ActionId $ActionId; return }
    }

    switch ($ActionId) {
        'RefreshOverview' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $result = @(Invoke-IACTuiCapturedOperation -State $State -ViewId Overview -SuccessMessage 'Tenant posture refreshed.' -Operation { Test-IntuneAssignmentGovernance })
            if ($State.StatusStyle -eq 'Error' -or ($State.StatusStyle -eq 'Warning' -and $result.Count -eq 0)) {
                $State.Metrics.Critical = $null
                $State.Metrics.Coverage = $null
                return
            }
            $critical = @($result | Where-Object Severity -in @('Critical', 'High')).Count
            $coverageFinding = @($result | Where-Object RuleId -EQ 'IAG008').Count -gt 0
            $State.Metrics.Critical = $critical
            $State.Metrics.Coverage = if ($coverageFinding) { 'Partial' } else { 'Complete' }
        }
        'ResumeScan' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $checkpoint = Read-IACTuiTextInput -State $State -Title 'Resume assignment scan' -Prompt 'Checkpoint path (blank starts a new scan)' -DefaultValue $State.Settings.SnapshotPath
            if ($null -eq $checkpoint) { return }
            $budgetText = Read-IACTuiTextInput -State $State -Title 'Resume assignment scan' -Prompt 'Time budget in seconds (0 means no limit)' -DefaultValue '0' -Required
            if ($null -eq $budgetText) { return }
            $budget = 0
            if (-not [int]::TryParse($budgetText, [ref]$budget) -or $budget -lt 0) { Set-IACTuiStatus -State $State -Message 'Time budget must be zero or a positive whole number.' -Style Warning; return }
            $scanParameters = @{ ScanBudgetSeconds = $budget; ShowProgress = $true }
            if ($checkpoint) { $scanParameters.CheckpointPath = $checkpoint; $scanParameters.Resume = $true }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Overview -SuccessMessage 'Assignment scan complete.' -Operation { Invoke-IntuneAssignmentScan @scanParameters } | Out-Null
        }
        'RefreshGovernance' {
            $source = Read-IACTuiChoice -State $State -Title 'Run governance scan' -Prompt 'Choose the source to evaluate.' -Choice @('Connected tenant', 'Saved snapshot')
            if (-not $source) { return }
            $rulePath = Read-IACTuiTextInput -State $State -Title 'Governance rules' -Prompt 'Custom rule pack path (blank uses the built-in baseline)'
            if ($null -eq $rulePath) { return }
            $waiverPath = Read-IACTuiTextInput -State $State -Title 'Governance waivers' -Prompt 'Approved waiver file (optional)'
            if ($null -eq $waiverPath) { return }
            $visibility = Read-IACTuiChoice -State $State -Title 'Governance waivers' -Prompt 'Which findings should be visible?' -Choice @('Active findings only', 'Include approved waivers')
            if (-not $visibility) { return }
            $governanceParameters = @{}
            if ($rulePath) { $governanceParameters.RulePath = $rulePath }
            if ($waiverPath) { $governanceParameters.WaiverPath = $waiverPath }
            if ($visibility -eq 'Include approved waivers') { $governanceParameters.IncludeSuppressed = $true }
            if ($source -eq 'Connected tenant') {
                if (-not (Test-IACTuiConnected -State $State)) { return }
                Invoke-IACTuiCapturedOperation -State $State -ViewId Governance -SuccessMessage 'Governance scan complete.' -Operation { Test-IntuneAssignmentGovernance @governanceParameters } | Out-Null
            }
            else {
                $path = Read-IACTuiTextInput -State $State -Title 'Run governance scan' -Prompt 'Snapshot path' -DefaultValue $State.Settings.SnapshotPath -Required
                if ($null -eq $path) { return }
                $State.Settings.SnapshotPath = $path
                $governanceParameters.SnapshotPath = $path
                Invoke-IACTuiCapturedOperation -State $State -ViewId Governance -SuccessMessage 'Offline governance scan complete.' -Operation { Test-IntuneAssignmentGovernance @governanceParameters } | Out-Null
            }
        }
        'RefreshDrift' {
            $baseline = Read-IACTuiTextInput -State $State -Title 'Compare approved baseline' -Prompt 'Approved baseline path' -DefaultValue $State.Settings.BaselinePath -Required
            if ($null -eq $baseline) { return }
            $current = Read-IACTuiTextInput -State $State -Title 'Compare approved baseline' -Prompt 'Current snapshot path (blank captures the connected tenant)'
            if ($null -eq $current) { return }
            if (-not $current -and -not (Test-IACTuiConnected -State $State)) { return }
            $State.Settings.BaselinePath = $baseline
            $parameters = @{ BaselinePath = $baseline; IncludeAuditAttribution = $true }
            if ($current) { $parameters.CurrentSnapshotPath = $current }
            $result = @(Invoke-IACTuiCapturedOperation -State $State -ViewId Drift -SuccessMessage 'Drift comparison complete.' -Operation { Get-IntuneAssignmentDrift @parameters })
            $State.Metrics.Drift = if ($State.StatusStyle -eq 'Error' -or ($State.StatusStyle -eq 'Warning' -and $result.Count -eq 0)) { $null } else { $result.Count }
        }
        'ApproveBaseline' {
            $baseline = Read-IACTuiTextInput -State $State -Title 'Approve drift baseline' -Prompt 'Approved baseline destination' -DefaultValue $State.Settings.BaselinePath -Required
            if ($null -eq $baseline) { return }
            $current = Read-IACTuiTextInput -State $State -Title 'Approve drift baseline' -Prompt 'Reviewed snapshot path' -DefaultValue $State.Settings.SnapshotPath -Required
            if ($null -eq $current) { return }
            if (-not (Read-IACTuiConfirmation -State $State -Title 'Approve drift baseline' -Prompt 'Replace the approved baseline with this reviewed snapshot?')) { return }
            $State.Settings.BaselinePath = $baseline
            Invoke-IACTuiCapturedOperation -State $State -ViewId Drift -SuccessMessage 'Approved baseline updated.' -Operation {
                Get-IntuneAssignmentDrift -BaselinePath $baseline -CurrentSnapshotPath $current -ApproveBaseline -Force
            } | Out-Null
        }
        'CaptureSnapshot' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $path = Read-IACTuiTextInput -State $State -Title 'Capture snapshot' -Prompt 'Destination JSON path' -DefaultValue $State.Settings.SnapshotPath -Required
            if ($null -eq $path) { return }
            $force = $false
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                if (-not (Read-IACTuiConfirmation -State $State -Title 'Capture snapshot' -Prompt 'A snapshot already exists at this path. Replace it?')) { return }
                $force = $true
            }
            $State.Settings.SnapshotPath = $path
            Invoke-IACTuiCapturedOperation -State $State -ViewId Drift -SuccessMessage "Snapshot saved to $path." -Operation {
                $run = Invoke-IntuneAssignmentScan -ShowProgress
                Export-IACTuiScanRunSnapshot -Run $run -Path $path -Force:$force
            } | Out-Null
        }
        'CompareSnapshots' {
            $reference = Read-IACTuiTextInput -State $State -Title 'Compare snapshots' -Prompt 'Reference snapshot path' -DefaultValue $State.Settings.BaselinePath -Required
            if ($null -eq $reference) { return }
            $difference = Read-IACTuiTextInput -State $State -Title 'Compare snapshots' -Prompt 'Newer snapshot path' -DefaultValue $State.Settings.SnapshotPath -Required
            if ($null -eq $difference) { return }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Drift -SuccessMessage 'Snapshot comparison complete.' -Operation {
                Compare-IntuneAssignmentSnapshot -ReferencePath $reference -DifferencePath $difference
            } | Out-Null
        }
        'RefreshHealth' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $workload = Read-IACTuiChoice -State $State -Title 'Load delivery health' -Prompt 'Choose a workload.' -Choice @('All workloads', 'Device configuration', 'Compliance', 'Applications')
            if (-not $workload) { return }
            $staleText = Read-IACTuiTextInput -State $State -Title 'Load delivery health' -Prompt 'Mark reports stale after this many days' -DefaultValue '14' -Required
            if ($null -eq $staleText) { return }
            $staleDays = 0
            if (-not [int]::TryParse($staleText, [ref]$staleDays) -or $staleDays -lt 1 -or $staleDays -gt 3650) {
                Set-IACTuiStatus -State $State -Message 'Stale-report age must be between 1 and 3650 days.' -Style Warning
                return
            }
            $workloads = switch ($workload) { 'All workloads' { @('DeviceConfiguration', 'Compliance', 'Applications') }; 'Device configuration' { @('DeviceConfiguration') }; default { @($workload) } }
            $result = @(Invoke-IACTuiCapturedOperation -State $State -ViewId Health -SuccessMessage 'Delivery health loaded.' -Operation { Get-IntuneAssignmentHealth -Workload $workloads -StaleAfterDays $staleDays })
            $success = @($result | Where-Object Status -in @('SuccessfullyApplied', 'Installed', 'Success')).Count
            $State.Metrics.Health = if ($result.Count -gt 0) { '{0:P0}' -f ($success / $result.Count) } else { '—' }
        }
        'LoadFailures' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Health -SuccessMessage 'Assignment failures loaded.' -Operation { Get-IntuneFailedAssignment -PassThru } | Out-Null
        }
        'RefreshAccess' {
            $snapshot = Read-IACTuiTextInput -State $State -Title 'Analyze administrative access' -Prompt 'Snapshot path (blank uses the connected tenant)'
            if ($null -eq $snapshot) { return }
            if (-not $snapshot -and -not (Test-IACTuiConnected -State $State)) { return }
            $policy = Read-IACTuiTextInput -State $State -Title 'Analyze administrative access' -Prompt 'Policy ID to narrow results (optional)'
            if ($null -eq $policy) { return }
            $parameters = @{}; if ($snapshot) { $parameters.SnapshotPath = $snapshot }; if ($policy) { $parameters.PolicyId = @($policy) }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Access -SuccessMessage 'Administrative access analysis complete.' -Operation { Get-IntuneAssignmentAccess @parameters } | Out-Null
        }
        'RefreshFilters' {
            $snapshot = Read-IACTuiTextInput -State $State -Title 'Audit assignment filters' -Prompt 'Snapshot path (blank scans the connected tenant)'
            if ($null -eq $snapshot) { return }
            if (-not $snapshot -and -not (Test-IACTuiConnected -State $State)) { return }
            $parameters = @{}; if ($snapshot) { $parameters.SnapshotPath = $snapshot }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Filters -SuccessMessage 'Assignment-filter audit complete.' -Operation { Test-IntuneAssignmentFilterSet @parameters } | Out-Null
        }
        'EvaluateFilter' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $device = Read-IACTuiTextInput -State $State -Title 'Evaluate a filter' -Prompt 'Managed device name' -Required
            if ($null -eq $device) { return }
            $filter = Read-IACTuiTextInput -State $State -Title 'Evaluate a filter' -Prompt 'Assignment filter ID' -Required
            if ($null -eq $filter) { return }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Filters -SuccessMessage 'Device evaluation complete.' -Operation { Test-IntuneAssignmentFilter -DeviceName $device -FilterId $filter } | Out-Null
        }
        'RunFleetScan' {
            $configuration = Read-IACTuiTextInput -State $State -Title 'Scan tenant fleet' -Prompt 'Fleet configuration path' -Required
            if ($null -eq $configuration) { return }
            $output = Read-IACTuiTextInput -State $State -Title 'Scan tenant fleet' -Prompt 'Output directory' -DefaultValue $State.Settings.OutputDirectory -Required
            if ($null -eq $output) { return }
            $State.Settings.OutputDirectory = $output
            Invoke-IACTuiCapturedOperation -State $State -ViewId Fleet -SuccessMessage 'Fleet scan finished.' -Operation {
                Invoke-IntuneAssignmentFleetScan -ConfigurationPath $configuration -OutputDirectory $output
            } | Out-Null
        }
        'CreateHtmlReport' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            $path = Read-IACTuiTextInput -State $State -Title 'Create HTML report' -Prompt 'HTML file or destination directory (blank uses Documents)'
            if ($null -eq $path) { return }
            $companion = Read-IACTuiChoice -State $State -Title 'Create HTML report' -Prompt 'Create a CSV companion for data analysis?' -Choice @('HTML and CSV', 'HTML only')
            if (-not $companion) { return }
            $reportParameters = @{}
            if ($path) { $reportParameters.HTMLReportPath = $path }
            if ($companion -eq 'HTML only') { $reportParameters.NoCSVReport = $true }
            else {
                $csvPath = Read-IACTuiTextInput -State $State -Title 'Create HTML report' -Prompt 'Custom CSV path (blank follows the HTML file)'
                if ($null -eq $csvPath) { return }
                if ($csvPath) { $reportParameters.CSVReportPath = $csvPath }
            }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Reports -SuccessMessage 'HTML report created.' -Operation {
                New-IntuneHTMLReport @reportParameters
            } | Out-Null
        }
        'MigrateRecords' {
            $source = Read-IACTuiTextInput -State $State -Title 'Migrate assignment records' -Prompt 'Version 1 JSON file' -Required
            if ($null -eq $source) { return }
            $destination = Read-IACTuiTextInput -State $State -Title 'Migrate assignment records' -Prompt 'Version 2 JSON destination' -Required
            if ($null -eq $destination) { return }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Reports -SuccessMessage "Migrated records saved to $destination." -Operation {
                $records = Get-Content -LiteralPath $source -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
                $converted = @($records | ConvertTo-IntuneAssignmentRecord)
                $converted | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $destination -Encoding utf8NoBOM
                $converted
            } | Out-Null
        }
        'ExportWorkspaceData' {
            $availableViews = @($State.Registry | Where-Object { @($State.RawResults[$_.Id]).Count -gt 0 })
            if ($availableViews.Count -eq 0) { Set-IACTuiStatus -State $State -Message 'Load workspace results before exporting them.' -Style Warning; return }
            $viewTitle = Read-IACTuiChoice -State $State -Title 'Save current results' -Prompt 'Choose the loaded workspace to export.' -Choice @($availableViews.Title)
            if (-not $viewTitle) { return }
            $selectedView = $availableViews | Where-Object Title -EQ $viewTitle | Select-Object -First 1
            $format = Read-IACTuiChoice -State $State -Title 'Save current results' -Prompt 'Choose a portable output format.' -Choice @('JSON', 'JSON Lines', 'CSV')
            if (-not $format) { return }
            $path = Read-IACTuiTextInput -State $State -Title 'Save current results' -Prompt 'Destination file path' -Required
            if ($null -eq $path) { return }
            $structuredFormat = @{ 'JSON' = 'Json'; 'JSON Lines' = 'JsonLines'; 'CSV' = 'Csv' }[$format]
            if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                -not (Read-IACTuiConfirmation -State $State -Title 'Save current results' -Prompt 'A file already exists at this path. Replace it?')) { return }
            try {
                Export-IACStructuredOutput -InputObject @($State.RawResults[$selectedView.Id]) -Path $path -Format $structuredFormat
                Set-IACTuiStatus -State $State -Message "$viewTitle results saved to $path." -Style Success
            }
            catch { Set-IACTuiStatus -State $State -Message $_.Exception.Message -Style Error }
        }
        'ConnectTenant' {
            $environment = Read-IACTuiChoice -State $State -Title 'Connect tenant' -Prompt 'Choose the Microsoft cloud.' -Choice @('Global', 'USGov', 'USGovDoD')
            if (-not $environment) { return }
            $capabilityProfile = @(Read-IACTuiMultiChoice -State $State -Title 'Connect tenant' -Prompt 'Choose the least-privilege capabilities needed for this session.' -Choice @('Core', 'Applications', 'Devices', 'Scripts', 'CloudPC', 'ScopeTags', 'Audit', 'Full') -DefaultChoice @('Full') | Where-Object { $null -ne $_ })
            if ($capabilityProfile.Count -eq 0) { return }
            $authentication = Read-IACTuiChoice -State $State -Title 'Connect tenant' -Prompt 'Choose the authentication method.' -Choice @('Interactive sign-in', 'Certificate', 'Client secret', 'Access token')
            if (-not $authentication) { return }
            $tenant = Read-IACTuiTextInput -State $State -Title 'Connect tenant' -Prompt 'Tenant ID (blank lets sign-in choose)'
            if ($null -eq $tenant) { return }
            $parameters = @{ Environment = $environment; Capability = $capabilityProfile; PassThru = $true }
            if ($tenant) { $parameters.TenantId = $tenant }
            if ($authentication -in @('Interactive sign-in', 'Certificate', 'Client secret')) {
                $appId = Read-IACTuiTextInput -State $State -Title 'Connect tenant' -Prompt $(if ($authentication -eq 'Interactive sign-in') { 'Application ID (optional)' } else { 'Application ID' }) -Required:($authentication -ne 'Interactive sign-in')
                if ($null -eq $appId) { return }
                if ($appId) { $parameters.AppId = $appId }
            }
            switch ($authentication) {
                'Certificate' {
                    if (-not $tenant) { Set-IACTuiStatus -State $State -Message 'Certificate sign-in requires a tenant ID.' -Style Warning; return }
                    $thumbprint = Read-IACTuiTextInput -State $State -Title 'Connect tenant' -Prompt 'Certificate thumbprint' -Required
                    if ($null -eq $thumbprint) { return }; $parameters.CertificateThumbprint = $thumbprint
                }
                'Client secret' {
                    if (-not $tenant) { Set-IACTuiStatus -State $State -Message 'Client-secret sign-in requires a tenant ID.' -Style Warning; return }
                    $secret = Read-IACTuiSecretInput -State $State -Title 'Connect tenant' -Prompt 'Client secret'
                    if ($null -eq $secret) { return }
                    $parameters.ClientSecretCredential = [PSCredential]::new($parameters.AppId, $secret)
                }
                'Access token' {
                    $token = Read-IACTuiSecretInput -State $State -Title 'Connect tenant' -Prompt 'Pre-fetched Microsoft Graph access token'
                    if ($null -eq $token) { return }; $parameters.AccessToken = $token
                }
            }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Settings -SuccessMessage 'Tenant connected.' -Operation { Connect-IntuneAssignmentChecker @parameters } | Out-Null
        }
        'SwitchTenant' {
            if (-not (Read-IACTuiConfirmation -State $State -Title 'Switch tenant' -Prompt 'Clear tenant-scoped caches and start a new sign-in?')) { return }
            $environment = Read-IACTuiChoice -State $State -Title 'Switch tenant' -Prompt 'Choose the Microsoft cloud.' -Choice @('Global', 'USGov', 'USGovDoD')
            if (-not $environment) { return }
            $capabilityProfile = @(Read-IACTuiMultiChoice -State $State -Title 'Switch tenant' -Prompt 'Choose the capabilities needed in the next tenant.' -Choice @('Core', 'Applications', 'Devices', 'Scripts', 'CloudPC', 'ScopeTags', 'Audit', 'Full') -DefaultChoice @('Full') | Where-Object { $null -ne $_ })
            if ($capabilityProfile.Count -eq 0) { return }
            $authentication = Read-IACTuiChoice -State $State -Title 'Switch tenant' -Prompt 'Choose the authentication method.' -Choice @('Interactive sign-in', 'Certificate', 'Client secret', 'Access token')
            if (-not $authentication) { return }
            $tenant = Read-IACTuiTextInput -State $State -Title 'Switch tenant' -Prompt 'Tenant ID (blank lets sign-in choose)'
            if ($null -eq $tenant) { return }
            $parameters = @{ Environment = $environment; Capability = $capabilityProfile; PassThru = $true }
            if ($tenant) { $parameters.TenantId = $tenant }
            if ($authentication -in @('Interactive sign-in', 'Certificate', 'Client secret')) {
                $appId = Read-IACTuiTextInput -State $State -Title 'Switch tenant' -Prompt $(if ($authentication -eq 'Interactive sign-in') { 'Application ID (optional)' } else { 'Application ID' }) -Required:($authentication -ne 'Interactive sign-in')
                if ($null -eq $appId) { return }
                if ($appId) { $parameters.AppId = $appId }
            }
            switch ($authentication) {
                'Certificate' {
                    if (-not $tenant) { Set-IACTuiStatus -State $State -Message 'Certificate sign-in requires a tenant ID.' -Style Warning; return }
                    $thumbprint = Read-IACTuiTextInput -State $State -Title 'Switch tenant' -Prompt 'Certificate thumbprint' -Required
                    if ($null -eq $thumbprint) { return }; $parameters.CertificateThumbprint = $thumbprint
                }
                'Client secret' {
                    if (-not $tenant) { Set-IACTuiStatus -State $State -Message 'Client-secret sign-in requires a tenant ID.' -Style Warning; return }
                    $secret = Read-IACTuiSecretInput -State $State -Title 'Switch tenant' -Prompt 'Client secret'
                    if ($null -eq $secret) { return }
                    $parameters.ClientSecretCredential = [PSCredential]::new($parameters.AppId, $secret)
                }
                'Access token' {
                    $token = Read-IACTuiSecretInput -State $State -Title 'Switch tenant' -Prompt 'Pre-fetched Microsoft Graph access token'
                    if ($null -eq $token) { return }; $parameters.AccessToken = $token
                }
            }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Settings -SuccessMessage 'Tenant switched.' -Operation { Switch-IntuneAssignmentCheckerTenant @parameters } | Out-Null
        }
        'RunDiagnostics' {
            $parameters = if ($script:GraphEndpoint) { @{} } else { @{ SkipGraphProbe = $true } }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Settings -SuccessMessage 'Environment diagnostics complete.' -Operation { Test-IntuneAssignmentCheckerEnvironment @parameters } | Out-Null
        }
        'RefreshSettingDefinitions' {
            if (-not (Test-IACTuiConnected -State $State)) { return }
            if (-not (Read-IACTuiConfirmation -State $State -Title 'Refresh setting catalog' -Prompt 'Download the latest setting definitions to the local cache?')) { return }
            Invoke-IACTuiCapturedOperation -State $State -ViewId Settings -SuccessMessage 'Setting definitions refreshed.' -Operation { Update-IntuneSettingDefinition } | Out-Null
        }
        'ConfigureScopeFilter' {
            $scopeTag = Read-IACTuiTextInput -State $State -Title 'Assignment scope filter' -Prompt 'Scope-tag name (blank clears the filter)' -DefaultValue $State.Settings.ScopeTagFilter
            if ($null -eq $scopeTag) { return }
            $State.Settings.ScopeTagFilter = $scopeTag
            Set-IACTuiStatus -State $State -Message $(if ($scopeTag) { "Assignment searches will use scope tag '$scopeTag'." } else { 'Assignment scope filter cleared.' }) -Style Success
        }
        default { Set-IACTuiStatus -State $State -Message "This action is not available: $ActionId" -Style Warning }
    }
}

function Show-IACTuiHelp {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    $choice = Read-IACTuiChoice -State $State -Title 'Command center help' -Prompt 'Mouse: click workspaces, actions, and rows; use the wheel to scroll. Keyboard: Tab changes focus, arrows or J/K move, Enter opens a workspace, R runs its primary action, / filters, T opens Settings, Escape goes back, and Q or Ctrl+C exits.' -Choice @('Return')
    $null = $choice
}

function Invoke-IACTuiInputEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$InputEvent,
        [switch]$SkipActionInvoke
    )

    if ($InputEvent.Kind -eq 'Mouse') {
        if ($InputEvent.Action -eq 'Wheel') {
            if ($InputEvent.X -lt $State.LastNavigationWidth) {
                $State.NavigationIndex = [math]::Max(0, [math]::Min($State.Registry.Count - 1, $State.NavigationIndex - $InputEvent.WheelDelta))
                $State.Focus = 'Navigation'
            }
            else {
                $rows = @(Get-IACTuiViewRows -State $State)
                $State.SelectedIndex = [math]::Max(0, [math]::Min([math]::Max(0, $rows.Count - 1), $State.SelectedIndex - $InputEvent.WheelDelta))
                $State.Focus = 'Content'
            }
            return
        }
        if ($InputEvent.Button -ne 'Left' -or $InputEvent.Action -ne 'Down') { return }
        $target = Get-IACTuiHitTarget -State $State -X $InputEvent.X -Y $InputEvent.Y
        if (-not $target) { return }
        switch ($target.Action) {
            'Navigate' { Set-IACTuiActiveView -State $State -ViewId "$($target.Value)"; $State.Focus = 'Navigation' }
            'SelectRow' { $State.SelectedIndex = [int]$target.Value; $State.Focus = 'Content' }
            'InvokeAction' { if (-not $SkipActionInvoke) { Invoke-IACTuiWorkflowAction -State $State -ActionId "$($target.Value)" } }
        }
        return
    }

    if ($InputEvent.Kind -ne 'Key') { return }
    $rows = @(Get-IACTuiViewRows -State $State)
    switch ($InputEvent.Key) {
        'Tab' { $State.Focus = if ($State.Focus -eq 'Navigation') { 'Content' } else { 'Navigation' } }
        'UpArrow' {
            if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Max(0, $State.NavigationIndex - 1) }
            else { $State.SelectedIndex = [math]::Max(0, $State.SelectedIndex - 1) }
        }
        'DownArrow' {
            if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Min($State.Registry.Count - 1, $State.NavigationIndex + 1) }
            else { $State.SelectedIndex = [math]::Min([math]::Max(0, $rows.Count - 1), $State.SelectedIndex + 1) }
        }
        'PageUp' {
            if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Max(0, $State.NavigationIndex - 10) }
            else { $State.SelectedIndex = [math]::Max(0, $State.SelectedIndex - 10) }
        }
        'PageDown' {
            if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Min($State.Registry.Count - 1, $State.NavigationIndex + 10) }
            else { $State.SelectedIndex = [math]::Min([math]::Max(0, $rows.Count - 1), $State.SelectedIndex + 10) }
        }
        'Home' { if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = 0 } else { $State.SelectedIndex = 0 } }
        'End' { if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = $State.Registry.Count - 1 } else { $State.SelectedIndex = [math]::Max(0, $rows.Count - 1) } }
        'Enter' {
            if ($State.Focus -eq 'Navigation') { Set-IACTuiActiveView -State $State -ViewId $State.Registry[$State.NavigationIndex].Id; $State.Focus = 'Content' }
        }
        'Escape' {
            if ($State.Filter) { $State.Filter = ''; $State.SelectedIndex = 0; $State.RowOffset = 0 }
            elseif ($State.Focus -eq 'Content') { $State.Focus = 'Navigation' }
            else { Set-IACTuiStatus -State $State -Message 'Press Q to leave the command center.' -Style Muted }
        }
        default {
            $character = $InputEvent.Character
            if (Test-IACTuiControlCEvent -InputEvent $InputEvent) { $State.ExitRequested = $true; return }
            if ($character -in @('q', 'Q')) { $State.ExitRequested = $true; return }
            if ($character -in @('j', 'J')) {
                if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Min($State.Registry.Count - 1, $State.NavigationIndex + 1) }
                else { $State.SelectedIndex = [math]::Min([math]::Max(0, $rows.Count - 1), $State.SelectedIndex + 1) }
                return
            }
            if ($character -in @('k', 'K')) {
                if ($State.Focus -eq 'Navigation') { $State.NavigationIndex = [math]::Max(0, $State.NavigationIndex - 1) }
                else { $State.SelectedIndex = [math]::Max(0, $State.SelectedIndex - 1) }
                return
            }
            if ($character -in @('t', 'T') -and $State.ActiveViewId -ne 'Settings') { Set-IACTuiActiveView -State $State -ViewId Settings; return }
            if ($character -eq '?') { if (-not $SkipActionInvoke) { Show-IACTuiHelp -State $State }; return }
            if ($character -eq '/') {
                if (-not $SkipActionInvoke) {
                    $filter = Read-IACTuiTextInput -State $State -Title 'Filter results' -Prompt 'Match a title, status, or detail' -DefaultValue $State.Filter
                    if ($null -ne $filter) { $State.Filter = $filter; $State.SelectedIndex = 0; $State.RowOffset = 0 }
                }
                return
            }
            if ([string]::IsNullOrEmpty($character) -or [char]::IsControl($character[0])) { return }
            $feature = $State.Registry | Where-Object Id -EQ $State.ActiveViewId | Select-Object -First 1
            $action = if ($character -in @('r', 'R')) { @($feature.Actions | Where-Object Primary | Select-Object -First 1) }
            else { @($feature.Actions | Where-Object { $_.Key -ceq [char]::ToUpperInvariant([char]$character) } | Select-Object -First 1) }
            if ($action.Count -gt 0) {
                if (-not $SkipActionInvoke) { Invoke-IACTuiWorkflowAction -State $State -ActionId $action[0].Id }
                return
            }
        }
    }
}
