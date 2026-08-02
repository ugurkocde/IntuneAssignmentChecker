function Test-IACVirtualTerminal {
    [CmdletBinding()]
    param()

    try { return [bool]$Host.UI.SupportsVirtualTerminal }
    catch { return $false }
}

function Get-IACWindowsTuiInputMode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uint32]$Mode)

    # ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT,
    # with QUICK_EDIT disabled so conhost does not consume clicks for selection.
    $result = [uint32]($Mode -bor [uint32]0x0290)
    if (($result -band [uint32]0x0040) -ne 0) { $result = [uint32]($result -bxor [uint32]0x0040) }
    return $result
}

function Initialize-IACWindowsConsoleInterop {
    [CmdletBinding()]
    param()

    if (-not $IsWindows -or ('IntuneAssignmentChecker.NativeConsole' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace IntuneAssignmentChecker
{
    internal static class NativeConsole
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    }
}
'@ -ErrorAction Stop
}

function Enable-IACTuiTerminal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [switch]$DisableMouse
    )

    $virtualTerminal = Test-IACVirtualTerminal
    $terminalState = [PSCustomObject][ordered]@{
        VirtualTerminal      = $virtualTerminal
        ColorEnabled         = $virtualTerminal -and -not $env:NO_COLOR
        MouseEnabled         = $false
        WindowsInputHandle   = [IntPtr]::Zero
        WindowsOriginalMode  = [uint32]0
        WindowsModeChanged   = $false
        OriginalCursorVisible = $true
    }
    try { $terminalState.OriginalCursorVisible = [Console]::CursorVisible } catch { }

    if ($virtualTerminal -and $IsWindows -and -not $DisableMouse) {
        try {
            Initialize-IACWindowsConsoleInterop
            $handle = [IntuneAssignmentChecker.NativeConsole]::GetStdHandle(-10)
            $mode = [uint32]0
            if ($handle -ne [IntPtr]::Zero -and [IntuneAssignmentChecker.NativeConsole]::GetConsoleMode($handle, [ref]$mode)) {
                # ENABLE_VIRTUAL_TERMINAL_INPUT makes SGR mouse sequences available
                # through Console.ReadKey in Windows Terminal and modern conhost.
                $virtualInputMode = Get-IACWindowsTuiInputMode -Mode $mode
                if ([IntuneAssignmentChecker.NativeConsole]::SetConsoleMode($handle, $virtualInputMode)) {
                    $terminalState.WindowsInputHandle = $handle
                    $terminalState.WindowsOriginalMode = $mode
                    $terminalState.WindowsModeChanged = $true
                    $terminalState.MouseEnabled = $true
                }
            }
        }
        catch {
            $terminalState.MouseEnabled = $false
        }
    }
    elseif ($virtualTerminal -and -not $DisableMouse) {
        $terminalState.MouseEnabled = $true
    }

    $State.Terminal = $terminalState
    if ($virtualTerminal) {
        $sequence = "`e[?1049h`e[?25l`e[2J`e[H"
        if ($terminalState.MouseEnabled) {
            # Button events, drag events, and SGR coordinates. SGR avoids the
            # 223-column limitation of the original X10 mouse encoding.
            $sequence += "`e[?1000h`e[?1002h`e[?1006h"
        }
        [Console]::Write($sequence)
    }
    else {
        try { [Console]::CursorVisible = $false } catch { }
        Clear-Host
    }
    return $terminalState
}

function Disable-IACTuiTerminal {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    $terminalState = $State.Terminal
    if ($terminalState -and $terminalState.VirtualTerminal) {
        $sequence = "`e[0m"
        if ($terminalState.MouseEnabled) { $sequence += "`e[?1006l`e[?1002l`e[?1000l" }
        $sequence += "`e[?25h`e[?1049l"
        [Console]::Write($sequence)
    }
    else {
        try { [Console]::CursorVisible = if ($terminalState) { $terminalState.OriginalCursorVisible } else { $true } } catch { }
        Clear-Host
    }

    if ($terminalState -and $terminalState.WindowsModeChanged) {
        try {
            $null = [IntuneAssignmentChecker.NativeConsole]::SetConsoleMode(
                $terminalState.WindowsInputHandle,
                $terminalState.WindowsOriginalMode
            )
        }
        catch { }
    }
}

function New-IACTuiKeyEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [AllowEmptyString()][string]$Character = '',
        [System.ConsoleModifiers]$Modifiers = [System.ConsoleModifiers]0
    )

    [PSCustomObject][ordered]@{
        Kind      = 'Key'
        Key       = $Key
        Character = $Character
        Modifiers = $Modifiers
    }
}

function Test-IACTuiControlCEvent {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputEvent)

    return $InputEvent.Kind -eq 'Key' -and $InputEvent.Key -eq 'C' -and
        (($InputEvent.Modifiers -band [ConsoleModifiers]::Control) -ne 0)
}

function ConvertFrom-IACTuiInputSequence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sequence)

    if ([string]::IsNullOrEmpty($Sequence) -or $Sequence -eq "`e") {
        return New-IACTuiKeyEvent -Key Escape
    }

    $mouseMatch = [regex]::Match($Sequence, '^\x1b\[<(\d+);(\d+);(\d+)([Mm])$')
    if ($mouseMatch.Success) {
        $code = [int]$mouseMatch.Groups[1].Value
        $x = [int]$mouseMatch.Groups[2].Value - 1
        $y = [int]$mouseMatch.Groups[3].Value - 1
        $terminator = $mouseMatch.Groups[4].Value
        $button = 'Unknown'
        $action = if ($terminator -ceq 'm') { 'Up' } elseif (($code -band 32) -ne 0) { 'Move' } else { 'Down' }
        $wheelDelta = 0

        if (($code -band 64) -ne 0) {
            $button = 'Wheel'
            $action = 'Wheel'
            $wheelDelta = if (($code -band 1) -eq 0) { 1 } else { -1 }
        }
        else {
            $button = switch ($code -band 3) {
                0 { 'Left' }
                1 { 'Middle' }
                2 { 'Right' }
                3 { 'None' }
            }
        }

        return [PSCustomObject][ordered]@{
            Kind       = 'Mouse'
            Key        = $null
            Character  = ''
            X          = $x
            Y          = $y
            Button     = $button
            Action     = $action
            WheelDelta = $wheelDelta
            Shift      = ($code -band 4) -ne 0
            Alt        = ($code -band 8) -ne 0
            Control    = ($code -band 16) -ne 0
            Sequence   = $Sequence
        }
    }

    $knownSequence = @{
        "`e[A" = 'UpArrow'
        "`e[B" = 'DownArrow'
        "`e[C" = 'RightArrow'
        "`e[D" = 'LeftArrow'
        "`e[5~" = 'PageUp'
        "`e[6~" = 'PageDown'
        "`e[H" = 'Home'
        "`e[F" = 'End'
    }
    if ($knownSequence.ContainsKey($Sequence)) {
        return New-IACTuiKeyEvent -Key $knownSequence[$Sequence]
    }
    return [PSCustomObject][ordered]@{
        Kind      = 'Unknown'
        Key       = $null
        Character = ''
        Sequence  = $Sequence
    }
}

function Read-IACTuiInput {
    [CmdletBinding()]
    param()

    $restoreControlCMode = $false
    $originalControlCMode = $false
    try {
        try {
            $originalControlCMode = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $true
            $restoreControlCMode = $true
        }
        catch { }

        $key = [Console]::ReadKey($true)
        if ($key.Key -eq [ConsoleKey]::Escape) {
            $sequence = [Text.StringBuilder]::new()
            [void]$sequence.Append("`e")
            $deadline = [datetime]::UtcNow.AddMilliseconds(50)
            $idleDeadline = $deadline
            while ([datetime]::UtcNow -lt $deadline) {
                if ([Console]::KeyAvailable) {
                    $next = [Console]::ReadKey($true)
                    [void]$sequence.Append($next.KeyChar)
                    $idleDeadline = [datetime]::UtcNow.AddMilliseconds(6)
                    $current = $sequence.ToString()
                    if ($current -match '^\x1b\[<\d+;\d+;\d+[Mm]$' -or
                        $current -in @("`e[A", "`e[B", "`e[C", "`e[D", "`e[H", "`e[F", "`e[5~", "`e[6~")) {
                        break
                    }
                }
                elseif ($sequence.Length -gt 1 -and [datetime]::UtcNow -ge $idleDeadline) { break }
                else { Start-Sleep -Milliseconds 1 }
            }
            return ConvertFrom-IACTuiInputSequence -Sequence $sequence.ToString()
        }

        return New-IACTuiKeyEvent -Key "$($key.Key)" -Character "$($key.KeyChar)" -Modifiers $key.Modifiers
    }
    finally {
        if ($restoreControlCMode) {
            try { [Console]::TreatControlCAsInput = $originalControlCMode }
            catch { }
        }
    }
}

function Add-IACTuiHitTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][ValidateRange(0, 10000)][int]$X,
        [Parameter(Mandatory)][ValidateRange(0, 10000)][int]$Y,
        [Parameter(Mandatory)][ValidateRange(1, 10000)][int]$Width,
        [Parameter(Mandatory)][ValidateRange(1, 10000)][int]$Height,
        [Parameter(Mandatory)][string]$Action,
        [AllowNull()]$Value
    )

    [void]$State.HitTargets.Add([PSCustomObject][ordered]@{
        X      = $X
        Y      = $Y
        Width  = $Width
        Height = $Height
        Action = $Action
        Value  = $Value
    })
}

function Get-IACTuiHitTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y
    )

    for ($index = $State.HitTargets.Count - 1; $index -ge 0; $index--) {
        $target = $State.HitTargets[$index]
        if ($X -ge $target.X -and $X -lt ($target.X + $target.Width) -and
            $Y -ge $target.Y -and $Y -lt ($target.Y + $target.Height)) {
            return $target
        }
    }
    return $null
}
