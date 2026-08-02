function Start-IntuneAssignmentCheckerTui {
    <#
    .SYNOPSIS
    Opens the IntuneAssignmentChecker assignment-governance command center.

    .DESCRIPTION
    Starts a task-oriented terminal interface for assignment discovery,
    governance, change simulation, drift, delivery health, RBAC, filters,
    fleet scans, reports, and connection settings. The interface uses the same
    PowerShell implementation as direct module commands and does not require a
    converted executable.

    Mouse input is enabled in terminals that support SGR mouse reporting.
    Every mouse action has a keyboard equivalent. Use -DisableMouse when a
    terminal multiplexer or accessibility tool needs to retain mouse events.

    .PARAMETER InitialView
    Workspace shown when the command center opens.

    .PARAMETER DisableMouse
    Keeps terminal mouse reporting disabled while preserving keyboard control.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Overview', 'Assignments', 'Governance', 'Simulator', 'Drift', 'Health', 'Access', 'Filters', 'Fleet', 'Reports', 'Settings')]
        [string]$InitialView = 'Overview',

        [Parameter()]
        [switch]$DisableMouse
    )

    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
        throw 'The terminal UI requires an interactive terminal. Use the individual module commands for automation.'
    }

    $module = Get-Module IntuneAssignmentChecker | Select-Object -First 1
    $operationalExports = @($module.ExportedFunctions.Keys | Where-Object {
            $_ -notin @('Get-IntuneAssignmentOperation', 'Invoke-IntuneAssignmentChecker', 'Start-IntuneAssignmentCheckerTui')
        })
    $parity = Test-IACTuiFeatureParity -CommandName $operationalExports
    if (-not $parity.Complete) {
        throw "The terminal workflow registry is incomplete. Missing: $($parity.Missing -join ', '); unknown: $($parity.Unknown -join ', ')."
    }

    $state = New-IACTuiState -InitialView $InitialView
    $launchNotice = [Environment]::GetEnvironmentVariable('IAC_LAUNCH_NOTICE', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($launchNotice)) {
        [Environment]::SetEnvironmentVariable('IAC_LAUNCH_NOTICE', $null, 'Process')
    }
    try {
        $terminal = Enable-IACTuiTerminal -State $state -DisableMouse:$DisableMouse
        $statusMessages = @()
        $statusStyle = 'Muted'
        if ($DisableMouse) {
            $statusMessages += 'Mouse input disabled; all features remain available from the keyboard.'
        }
        elseif (-not $terminal.MouseEnabled) {
            $statusMessages += 'Mouse reporting is unavailable in this terminal; keyboard navigation is fully supported.'
            $statusStyle = 'Warning'
        }
        if (-not [string]::IsNullOrWhiteSpace($launchNotice)) {
            $statusMessages += $launchNotice
            $statusStyle = 'Warning'
        }
        if ($statusMessages.Count -gt 0) {
            Set-IACTuiStatus -State $state -Message ($statusMessages -join ' ') -Style $statusStyle
        }

        while (-not $state.ExitRequested) {
            Show-IACTuiFrame -State $state
            $inputEvent = Read-IACTuiInput
            Invoke-IACTuiInputEvent -State $state -InputEvent $inputEvent
        }
    }
    finally {
        Disable-IACTuiTerminal -State $state
    }
}
