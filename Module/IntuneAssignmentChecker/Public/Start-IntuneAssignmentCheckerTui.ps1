function Start-IntuneAssignmentCheckerTui {
    <#
    .SYNOPSIS
    Starts the keyboard-driven IntuneAssignmentChecker terminal interface.

    .DESCRIPTION
    Presents the same operational surface as the PowerShell module. Commands,
    parameter sets, mandatory inputs, switches, credentials, secure strings, and
    ValidateSet choices are discovered dynamically from the exported cmdlets.
    No separate application logic or converted executable is used.

    .PARAMETER InitialFilter
    Filters the initial operation list by name, category, synopsis, or capability.

    .PARAMETER Command
    Opens the parameter editor for one command directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$InitialFilter,

        [Parameter()]
        [string]$Command
    )

    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
        throw 'The terminal UI requires an interactive terminal. Use the individual module cmdlets for automation.'
    }

    $catalog = @(Get-IACOperationCatalog)
    if ($Command) {
        $operation = $catalog | Where-Object Name -EQ $Command | Select-Object -First 1
        if (-not $operation) { throw "Unknown IntuneAssignmentChecker operation '$Command'." }
        Show-IACTuiOperation -Operation $operation
        return
    }

    $filter = "$InitialFilter"
    $selectedIndex = 0
    while ($true) {
        $operations = if ([string]::IsNullOrWhiteSpace($filter)) { @($catalog) }
        else {
            @($catalog | Where-Object {
                    $_.Name -like "*$filter*" -or $_.Category -like "*$filter*" -or
                    $_.Synopsis -like "*$filter*" -or (@($_.Capabilities) -join ' ') -like "*$filter*"
                })
        }
        if ($operations.Count -eq 0) {
            $filter = ''
            $selectedIndex = 0
            continue
        }
        if ($selectedIndex -ge $operations.Count) { $selectedIndex = $operations.Count - 1 }

        Show-IACTuiScreen -Operations $operations -SelectedIndex $selectedIndex -Filter $filter
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'UpArrow' { if ($selectedIndex -gt 0) { $selectedIndex-- } }
            'DownArrow' { if ($selectedIndex -lt $operations.Count - 1) { $selectedIndex++ } }
            'PageUp' { $selectedIndex = [math]::Max(0, $selectedIndex - 10) }
            'PageDown' { $selectedIndex = [math]::Min($operations.Count - 1, $selectedIndex + 10) }
            'Home' { $selectedIndex = 0 }
            'End' { $selectedIndex = $operations.Count - 1 }
            'Enter' { Show-IACTuiOperation -Operation $operations[$selectedIndex] }
            'C' {
                Show-IACTuiOperation -Operation ($catalog | Where-Object Name -EQ 'Switch-IntuneAssignmentCheckerTenant' | Select-Object -First 1)
            }
            'T' {
                Show-IACTuiOperation -Operation ($catalog | Where-Object Name -EQ 'Switch-IntuneAssignmentCheckerTenant' | Select-Object -First 1)
            }
            'Q' { Clear-Host; return }
            'Escape' { Clear-Host; return }
            'Oem2' {
                Write-Host ''
                $filter = Read-Host 'Filter operations (blank clears)'
                $selectedIndex = 0
            }
            default {
                if ($key.KeyChar -eq '/') {
                    Write-Host ''
                    $filter = Read-Host 'Filter operations (blank clears)'
                    $selectedIndex = 0
                }
                elseif ($key.KeyChar -in @('j', 'J') -and $selectedIndex -lt $operations.Count - 1) { $selectedIndex++ }
                elseif ($key.KeyChar -in @('k', 'K') -and $selectedIndex -gt 0) { $selectedIndex-- }
                elseif ($key.KeyChar -eq '?') {
                    Clear-Host
                    Write-IACTuiText -Text 'Terminal UI help' -Style Accent
                    Write-Host @'

The TUI discovers its commands from the imported module. Select an operation,
choose a parameter set, and enter values. Optional values can be skipped with
Enter. Arrays accept comma-separated values or @path-to-json. Secure inputs are
never echoed. Press C to disconnect and connect to another tenant. Commands still return the same structured PowerShell objects and
use the same Microsoft Graph beta transport as direct cmdlet invocation.
'@
                    Write-IACTuiText -Text 'Press any key to return.' -Style Muted -NoNewline
                    $null = [Console]::ReadKey($true)
                }
            }
        }
    }
}
