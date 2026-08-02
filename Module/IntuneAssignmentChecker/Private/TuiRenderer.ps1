function Get-IACTuiAnsiStyle {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Style)

    switch ($Style) {
        'Canvas'       { "`e[38;2;223;229;236m`e[48;2;10;13;18m" }
        'Panel'        { "`e[38;2;223;229;236m`e[48;2;14;19;26m" }
        'PanelRaised'  { "`e[38;2;223;229;236m`e[48;2;18;25;35m" }
        'Border'       { "`e[38;2;41;52;68m`e[48;2;14;19;26m" }
        'Text'         { "`e[38;2;223;229;236m`e[48;2;14;19;26m" }
        'Muted'        { "`e[38;2;126;139;155m`e[48;2;14;19;26m" }
        'Accent'       { "`e[38;2;244;184;96m`e[48;2;14;19;26m" }
        'AccentStrong' { "`e[1;38;2;33;21;4m`e[48;2;244;184;96m" }
        'Blue'         { "`e[38;2;116;182;239m`e[48;2;14;19;26m" }
        'Success'      { "`e[38;2;128;214;164m`e[48;2;14;19;26m" }
        'Error'        { "`e[38;2;255;119;130m`e[48;2;14;19;26m" }
        'Warning'      { "`e[38;2;244;184;96m`e[48;2;14;19;26m" }
        'Selected'     { "`e[1;38;2;223;229;236m`e[48;2;41;52;68m" }
        default        { "`e[38;2;223;229;236m`e[48;2;10;13;18m" }
    }
}

function New-IACTuiBuffer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 1000)][int]$Width,
        [Parameter(Mandatory)][ValidateRange(1, 500)][int]$Height
    )

    $characters = [char[,]]::new($Height, $Width)
    $styles = [string[,]]::new($Height, $Width)
    for ($y = 0; $y -lt $Height; $y++) {
        for ($x = 0; $x -lt $Width; $x++) {
            $characters[$y, $x] = ' '
            $styles[$y, $x] = 'Canvas'
        }
    }
    [PSCustomObject]@{
        Width      = $Width
        Height     = $Height
        Characters = $characters
        Styles     = $styles
    }
}

function Set-IACTuiBufferCell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][char]$Character,
        [Parameter(Mandatory)][string]$Style
    )

    if ($X -lt 0 -or $X -ge $Buffer.Width -or $Y -lt 0 -or $Y -ge $Buffer.Height) { return }
    $Buffer.Characters[$Y, $X] = $Character
    $Buffer.Styles[$Y, $X] = $Style
}

function Write-IACTuiBufferFill {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)][string]$Style,
        [char]$Character = ' '
    )

    $right = [math]::Min($Buffer.Width, $X + $Width)
    $bottom = [math]::Min($Buffer.Height, $Y + $Height)
    for ($row = [math]::Max(0, $Y); $row -lt $bottom; $row++) {
        for ($column = [math]::Max(0, $X); $column -lt $right; $column++) {
            $Buffer.Characters[$row, $column] = $Character
            $Buffer.Styles[$row, $column] = $Style
        }
    }
}

function ConvertTo-IACTuiDisplayText {
    [CmdletBinding()]
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)][ValidateRange(0, 10000)][int]$Width,
        [switch]$Pad
    )

    if ($Width -eq 0) { return '' }
    $text = if ($null -eq $Value) { '' } else { "$Value" -replace '[\r\n\t]', ' ' }
    if ($text.Length -gt $Width) {
        $text = if ($Width -eq 1) { '…' } else { $text.Substring(0, $Width - 1) + '…' }
    }
    if ($Pad) { return $text.PadRight($Width) }
    return $text
}

function Write-IACTuiBufferText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [AllowEmptyString()][string]$Text,
        [string]$Style = 'Text',
        [int]$MaxWidth = 0
    )

    if ($Y -lt 0 -or $Y -ge $Buffer.Height -or $X -ge $Buffer.Width) { return }
    $available = $Buffer.Width - [math]::Max(0, $X)
    if ($MaxWidth -gt 0) { $available = [math]::Min($available, $MaxWidth) }
    $display = ConvertTo-IACTuiDisplayText -Value $Text -Width ([math]::Max(0, $available))
    for ($index = 0; $index -lt $display.Length; $index++) {
        Set-IACTuiBufferCell -Buffer $Buffer -X ($X + $index) -Y $Y -Character $display[$index] -Style $Style
    }
}

function Write-IACTuiBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][ValidateRange(2, 10000)][int]$Width,
        [Parameter(Mandatory)][ValidateRange(2, 10000)][int]$Height,
        [string]$Style = 'Panel',
        [string]$BorderStyle = 'Border'
    )

    Write-IACTuiBufferFill -Buffer $Buffer -X $X -Y $Y -Width $Width -Height $Height -Style $Style
    for ($column = $X; $column -lt ($X + $Width); $column++) {
        Set-IACTuiBufferCell -Buffer $Buffer -X $column -Y $Y -Character '-' -Style $BorderStyle
        Set-IACTuiBufferCell -Buffer $Buffer -X $column -Y ($Y + $Height - 1) -Character '-' -Style $BorderStyle
    }
    for ($row = $Y; $row -lt ($Y + $Height); $row++) {
        Set-IACTuiBufferCell -Buffer $Buffer -X $X -Y $row -Character '|' -Style $BorderStyle
        Set-IACTuiBufferCell -Buffer $Buffer -X ($X + $Width - 1) -Y $row -Character '|' -Style $BorderStyle
    }
    foreach ($corner in @(
            [PSCustomObject]@{ X = $X; Y = $Y }
            [PSCustomObject]@{ X = $X + $Width - 1; Y = $Y }
            [PSCustomObject]@{ X = $X; Y = $Y + $Height - 1 }
            [PSCustomObject]@{ X = $X + $Width - 1; Y = $Y + $Height - 1 }
        )) {
        Set-IACTuiBufferCell -Buffer $Buffer -X $corner.X -Y $corner.Y -Character '+' -Style $BorderStyle
    }
}

function ConvertTo-IACTuiBufferText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [switch]$Ansi
    )

    $output = [Text.StringBuilder]::new()
    $activeStyle = ''
    for ($y = 0; $y -lt $Buffer.Height; $y++) {
        for ($x = 0; $x -lt $Buffer.Width; $x++) {
            $style = $Buffer.Styles[$y, $x]
            if ($Ansi -and $style -ne $activeStyle) {
                [void]$output.Append((Get-IACTuiAnsiStyle -Style $style))
                $activeStyle = $style
            }
            [void]$output.Append($Buffer.Characters[$y, $x])
        }
        if ($Ansi) { [void]$output.Append("`e[0m") }
        if ($y -lt ($Buffer.Height - 1)) { [void]$output.Append("`n") }
        $activeStyle = ''
    }
    $output.ToString()
}

function Get-IACTuiStatusStyle {
    [CmdletBinding()]
    param([AllowNull()]$Value)

    switch -Regex ("$Value") {
        'Critical|High|Failed|Failure|Error|Conflict' { 'Error'; break }
        'Passed|Success|Healthy|Available|Complete|Applied|Installed' { 'Success'; break }
        'Medium|Warning|Pending|Stale|Unknown|Incomplete|Skipped' { 'Warning'; break }
        default { 'Blue' }
    }
}

function Write-IACTuiButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)]$Action,
        [switch]$Primary
    )

    $label = " $($Action.Key)  $($Action.Label) "
    $style = if ($Primary) { 'AccentStrong' } else { 'Selected' }
    Write-IACTuiBufferText -Buffer $Buffer -X $X -Y $Y -Text $label -Style $style
    Add-IACTuiHitTarget -State $State -X $X -Y $Y -Width $label.Length -Height 1 -Action InvokeAction -Value $Action.Id
    return $label.Length
}

function Write-IACTuiHeader {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Buffer, [Parameter(Mandatory)]$State)

    Write-IACTuiBufferFill -Buffer $Buffer -X 0 -Y 0 -Width $Buffer.Width -Height 3 -Style Panel
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y 0 -Text 'INTUNE ASSIGNMENT CHECKER' -Style Accent -MaxWidth 30
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y 1 -Text 'Assignment governance command center' -Style Muted -MaxWidth 42

    $tenant = if ($script:CurrentTenantName) { $script:CurrentTenantName } elseif ($script:CurrentTenantId) { $script:CurrentTenantId } else { 'Not connected' }
    $connectionStyle = if ($tenant -eq 'Not connected') { 'Warning' } else { 'Success' }
    $connection = "● $tenant"
    $connectionX = [math]::Max(2, $Buffer.Width - $connection.Length - 3)
    Write-IACTuiBufferText -Buffer $Buffer -X $connectionX -Y 0 -Text $connection -Style $connectionStyle
    Add-IACTuiHitTarget -State $State -X $connectionX -Y 0 -Width $connection.Length -Height 2 -Action Navigate -Value Settings

    $capability = if (@($script:RequestedCapabilities).Count -gt 0) { @($script:RequestedCapabilities) -join ', ' } else { 'Not selected' }
    $scope = if ($State.Settings.ScopeTagFilter) { $State.Settings.ScopeTagFilter } else { 'All scope tags' }
    $capabilityText = "Profile: $capability · $scope"
    Write-IACTuiBufferText -Buffer $Buffer -X ([math]::Max(2, $Buffer.Width - $capabilityText.Length - 3)) -Y 1 -Text $capabilityText -Style Muted
}

function Write-IACTuiNavigation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][int]$Top,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)][int]$Width
    )

    Write-IACTuiBufferFill -Buffer $Buffer -X 0 -Y $Top -Width $Width -Height $Height -Style Panel
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y ($Top + 1) -Text 'WORKSPACES' -Style Muted -MaxWidth ($Width - 4)
    $availableRows = [math]::Max(1, $Height - 4)
    $features = @($State.Registry)
    if ($State.NavigationIndex -lt $State.NavigationOffset) { $State.NavigationOffset = $State.NavigationIndex }
    if ($State.NavigationIndex -ge ($State.NavigationOffset + $availableRows)) {
        $State.NavigationOffset = $State.NavigationIndex - $availableRows + 1
    }
    $State.NavigationOffset = [math]::Max(0, [math]::Min($State.NavigationOffset, [math]::Max(0, $features.Count - $availableRows)))

    for ($row = 0; $row -lt $availableRows; $row++) {
        $index = $State.NavigationOffset + $row
        if ($index -ge $features.Count) { break }
        $feature = $features[$index]
        $style = if ($feature.Id -eq $State.ActiveViewId) { 'AccentStrong' } elseif ($State.Focus -eq 'Navigation' -and $index -eq $State.NavigationIndex) { 'Selected' } else { 'Text' }
        $prefix = if ($feature.Id -eq $State.ActiveViewId) { '›' } else { ' ' }
        $text = ConvertTo-IACTuiDisplayText -Value "$prefix $($feature.Title)" -Width ($Width - 2) -Pad
        Write-IACTuiBufferText -Buffer $Buffer -X 1 -Y ($Top + 2 + $row) -Text $text -Style $style
        Add-IACTuiHitTarget -State $State -X 1 -Y ($Top + 2 + $row) -Width ($Width - 2) -Height 1 -Action Navigate -Value $feature.Id
    }
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y ($Top + $Height - 1) -Text '↑↓ move  Enter open' -Style Muted -MaxWidth ($Width - 4)
}

function Write-IACTuiMetricCard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][string]$Label,
        [AllowNull()]$Value,
        [AllowNull()][string]$Hint,
        [string]$Style = 'Blue'
    )

    Write-IACTuiBox -Buffer $Buffer -X $X -Y $Y -Width $Width -Height 5 -Style PanelRaised
    Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($Y + 1) -Text $Label.ToUpperInvariant() -Style Muted -MaxWidth ($Width - 4)
    Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($Y + 2) -Text $(if ($null -eq $Value -or "$Value" -eq '') { '—' } else { "$Value" }) -Style $Style -MaxWidth ($Width - 4)
    Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($Y + 3) -Text "$Hint" -Style Muted -MaxWidth ($Width - 4)
}

function Write-IACTuiOverview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height
    )

    $gap = 1
    $cardWidth = [math]::Max(14, [math]::Floor(($Width - (3 * $gap)) / 4))
    $cards = @(
        @{ Label = 'Coverage'; Value = $State.Metrics.Coverage; Hint = 'workloads scanned'; Style = 'Blue' }
        @{ Label = 'Critical findings'; Value = $State.Metrics.Critical; Hint = 'needs attention'; Style = 'Error' }
        @{ Label = 'Drift'; Value = $State.Metrics.Drift; Hint = 'since baseline'; Style = 'Warning' }
        @{ Label = 'Delivery health'; Value = $State.Metrics.Health; Hint = 'successful'; Style = 'Success' }
    )
    for ($index = 0; $index -lt $cards.Count; $index++) {
        $cardX = $X + ($index * ($cardWidth + $gap))
        $actualWidth = if ($index -eq ($cards.Count - 1)) { [math]::Max(2, $X + $Width - $cardX) } else { $cardWidth }
        $card = $cards[$index]
        Write-IACTuiMetricCard -Buffer $Buffer -X $cardX -Y $Y -Width $actualWidth `
            -Label $card.Label -Value $card.Value -Hint $card.Hint -Style $card.Style
    }

    $contentY = $Y + 6
    $contentHeight = [math]::Max(4, $Height - 6)
    Write-IACTuiBox -Buffer $Buffer -X $X -Y $contentY -Width $Width -Height $contentHeight -Style Panel
    $overviewHeading = if ($State.Filter) { "PRIORITY FINDINGS · FILTER: $($State.Filter)" } else { 'PRIORITY FINDINGS' }
    Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($contentY + 1) -Text $overviewHeading -Style Accent -MaxWidth ($Width - 4)
    $rows = @(Get-IACTuiViewRows -State $State -ViewId Overview)
    if ($rows.Count -eq 0) {
        Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($contentY + 3) -Text 'No posture data loaded yet.' -Style Text -MaxWidth ($Width - 4)
        Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($contentY + 4) -Text 'Choose Refresh posture to scan the connected tenant.' -Style Muted -MaxWidth ($Width - 4)
        return
    }
    Write-IACTuiRows -Buffer $Buffer -State $State -Rows $rows -X ($X + 1) -Y ($contentY + 2) -Width ($Width - 2) -Height ($contentHeight - 3)
}

function Write-IACTuiRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height
    )

    if ($Rows.Count -eq 0) {
        Write-IACTuiBufferText -Buffer $Buffer -X ($X + 1) -Y ($Y + 1) -Text 'No results loaded. Choose an action above to begin.' -Style Muted -MaxWidth ($Width - 2)
        return
    }
    $visibleCount = [math]::Max(1, $Height)
    if ($State.SelectedIndex -lt $State.RowOffset) { $State.RowOffset = $State.SelectedIndex }
    if ($State.SelectedIndex -ge ($State.RowOffset + $visibleCount)) { $State.RowOffset = $State.SelectedIndex - $visibleCount + 1 }
    $State.RowOffset = [math]::Max(0, [math]::Min($State.RowOffset, [math]::Max(0, $Rows.Count - $visibleCount)))
    $statusWidth = [math]::Min(14, [math]::Max(8, [math]::Floor($Width * 0.2)))
    for ($displayIndex = 0; $displayIndex -lt $visibleCount; $displayIndex++) {
        $index = $State.RowOffset + $displayIndex
        if ($index -ge $Rows.Count) { break }
        $row = $Rows[$index]
        $selected = $State.Focus -eq 'Content' -and $index -eq $State.SelectedIndex
        $style = if ($selected) { 'Selected' } else { 'Text' }
        $titleWidth = [math]::Max(10, $Width - $statusWidth - 4)
        $title = ConvertTo-IACTuiDisplayText -Value "  $($row.Title)" -Width $titleWidth -Pad
        $status = ConvertTo-IACTuiDisplayText -Value "$($row.Status)" -Width $statusWidth -Pad
        Write-IACTuiBufferText -Buffer $Buffer -X $X -Y ($Y + $displayIndex) -Text $title -Style $style
        Write-IACTuiBufferText -Buffer $Buffer -X ($X + $titleWidth + 1) -Y ($Y + $displayIndex) -Text $status -Style $(if ($selected) { 'Selected' } else { Get-IACTuiStatusStyle -Value $row.Status })
        Add-IACTuiHitTarget -State $State -X $X -Y ($Y + $displayIndex) -Width $Width -Height 1 -Action SelectRow -Value $index
    }
}

function Write-IACTuiWorkspace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Buffer,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height
    )

    $feature = $State.Registry | Where-Object Id -EQ $State.ActiveViewId | Select-Object -First 1
    Write-IACTuiBufferText -Buffer $Buffer -X $X -Y $Y -Text $feature.Title -Style Accent -MaxWidth $Width
    Write-IACTuiBufferText -Buffer $Buffer -X $X -Y ($Y + 1) -Text $feature.Summary -Style Muted -MaxWidth $Width
    $buttonX = $X
    $buttonY = $Y + 3
    $buttonRows = 1
    foreach ($action in @($feature.Actions)) {
        $buttonWidth = " $($action.Key)  $($action.Label) ".Length
        if (($buttonX + $buttonWidth) -gt ($X + $Width)) {
            $buttonRows++
            $buttonY++
            $buttonX = $X
        }
        $used = Write-IACTuiButton -Buffer $Buffer -State $State -X $buttonX -Y $buttonY -Action $action -Primary:$action.Primary
        $buttonX += $used + 1
    }

    $contentY = $Y + 4 + $buttonRows
    $contentHeight = [math]::Max(3, $Height - 4 - $buttonRows)
    if ($State.ActiveViewId -eq 'Overview') {
        Write-IACTuiOverview -Buffer $Buffer -State $State -X $X -Y $contentY -Width $Width -Height $contentHeight
        return
    }

    $rows = @(Get-IACTuiViewRows -State $State)
    $listWidth = if ($Width -ge 60) { [math]::Floor($Width * 0.55) } else { $Width }
    Write-IACTuiBox -Buffer $Buffer -X $X -Y $contentY -Width $listWidth -Height $contentHeight -Style Panel
    $noticeCount = @($State.Notices[$State.ActiveViewId]).Count
    $resultHeading = if ($State.Filter) { "RESULTS · FILTER: $($State.Filter)" } else { 'RESULTS' }
    if ($noticeCount -gt 0) { $resultHeading += " · $noticeCount NOTICE$(if ($noticeCount -ne 1) { 'S' })" }
    Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y ($contentY + 1) -Text $resultHeading -Style Muted -MaxWidth ($listWidth - 4)
    $rowStart = $contentY + 2
    $rowHeight = $contentHeight - 3
    if ($noticeCount -gt 0) {
        $firstNotice = @($State.Notices[$State.ActiveViewId])[0]
        Write-IACTuiBufferText -Buffer $Buffer -X ($X + 2) -Y $rowStart -Text "! $($firstNotice.Message)" `
            -Style $(if ($firstNotice.Status -eq 'Error') { 'Error' } else { 'Warning' }) -MaxWidth ($listWidth - 4)
        $rowStart++
        $rowHeight = [math]::Max(1, $rowHeight - 1)
    }
    Write-IACTuiRows -Buffer $Buffer -State $State -Rows $rows -X ($X + 1) -Y $rowStart -Width ($listWidth - 2) -Height $rowHeight

    if ($listWidth -lt $Width) {
        $detailX = $X + $listWidth + 1
        $detailWidth = $Width - $listWidth - 1
        Write-IACTuiBox -Buffer $Buffer -X $detailX -Y $contentY -Width $detailWidth -Height $contentHeight -Style PanelRaised
        Write-IACTuiBufferText -Buffer $Buffer -X ($detailX + 2) -Y ($contentY + 1) -Text 'DETAIL' -Style Muted -MaxWidth ($detailWidth - 4)
        if ($rows.Count -gt 0) {
            $selectedIndex = [math]::Max(0, [math]::Min($State.SelectedIndex, $rows.Count - 1))
            $selected = $rows[$selectedIndex]
            Write-IACTuiBufferText -Buffer $Buffer -X ($detailX + 2) -Y ($contentY + 3) -Text $selected.Title -Style Accent -MaxWidth ($detailWidth - 4)
            $detailRow = $contentY + 5
            foreach ($line in @($selected.DetailLines)) {
                if ($detailRow -ge ($contentY + $contentHeight - 1)) { break }
                Write-IACTuiBufferText -Buffer $Buffer -X ($detailX + 2) -Y $detailRow -Text "$line" -Style Text -MaxWidth ($detailWidth - 4)
                $detailRow++
            }
        }
        else {
            Write-IACTuiBufferText -Buffer $Buffer -X ($detailX + 2) -Y ($contentY + 3) -Text 'Select an action to load data.' -Style Muted -MaxWidth ($detailWidth - 4)
        }
    }
}

function Write-IACTuiFooter {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Buffer, [Parameter(Mandatory)]$State)

    $y = $Buffer.Height - 2
    Write-IACTuiBufferFill -Buffer $Buffer -X 0 -Y $y -Width $Buffer.Width -Height 2 -Style Panel
    $messageStyle = if ($State.Busy) { 'Warning' } else { $State.StatusStyle }
    $message = if ($State.Busy) { 'Working…' } elseif ($State.StatusMessage) { $State.StatusMessage } else { 'Ready' }
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y $y -Text $message -Style $messageStyle -MaxWidth ($Buffer.Width - 4)
    $help = 'Tab focus  ↑↓ navigate  Enter open  R run  / filter  Esc back  ? help  Q quit'
    Write-IACTuiBufferText -Buffer $Buffer -X 2 -Y ($y + 1) -Text $help -Style Muted -MaxWidth ($Buffer.Width - 4)
}

function Get-IACTuiFrame {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][ValidateRange(1, 10000)][int]$Width,
        [Parameter(Mandatory)][ValidateRange(1, 10000)][int]$Height,
        [switch]$Ansi
    )

    $Width = [math]::Min(1000, $Width)
    $Height = [math]::Min(500, $Height)
    $State.HitTargets.Clear()
    $buffer = New-IACTuiBuffer -Width $Width -Height $Height
    if ($Width -lt 4 -or $Height -lt 4) {
        return ConvertTo-IACTuiBufferText -Buffer $buffer -Ansi:$Ansi
    }
    if ($Width -lt 90 -or $Height -lt 26) {
        Write-IACTuiBox -Buffer $buffer -X 1 -Y 1 -Width ($Width - 2) -Height ($Height - 2) -Style Panel
        Write-IACTuiBufferText -Buffer $buffer -X 4 -Y 3 -Text 'INTUNE ASSIGNMENT CHECKER' -Style Accent -MaxWidth ($Width - 8)
        Write-IACTuiBufferText -Buffer $buffer -X 4 -Y 6 -Text 'Terminal is too small for the command center.' -Style Warning -MaxWidth ($Width - 8)
        Write-IACTuiBufferText -Buffer $buffer -X 4 -Y 8 -Text "Current: ${Width}x${Height}  Required: 90x26" -Style Muted -MaxWidth ($Width - 8)
        return ConvertTo-IACTuiBufferText -Buffer $buffer -Ansi:$Ansi
    }

    Write-IACTuiHeader -Buffer $buffer -State $State
    $footerHeight = 2
    $bodyTop = 3
    $bodyHeight = $Height - $bodyTop - $footerHeight
    $navigationWidth = [math]::Min(25, [math]::Max(22, [math]::Floor($Width * 0.2)))
    $State.LastNavigationWidth = $navigationWidth
    Write-IACTuiNavigation -Buffer $buffer -State $State -Top $bodyTop -Height $bodyHeight -Width $navigationWidth
    $workspaceX = $navigationWidth + 2
    Write-IACTuiWorkspace -Buffer $buffer -State $State -X $workspaceX -Y ($bodyTop + 1) -Width ($Width - $workspaceX - 2) -Height ($bodyHeight - 2)
    Write-IACTuiFooter -Buffer $buffer -State $State
    ConvertTo-IACTuiBufferText -Buffer $buffer -Ansi:$Ansi
}

function Show-IACTuiFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    $width = [math]::Max(1, $(try { [Console]::WindowWidth } catch { 120 }))
    $height = [math]::Max(1, $(try { [Console]::WindowHeight } catch { 36 }))
    $ansi = [bool]($State.Terminal -and $State.Terminal.ColorEnabled)
    $frame = Get-IACTuiFrame -State $State -Width $width -Height $height -Ansi:$ansi
    if ($State.Terminal -and $State.Terminal.VirtualTerminal) { [Console]::Write("`e[H$frame") }
    else {
        Clear-Host
        [Console]::Write($frame)
    }
}
