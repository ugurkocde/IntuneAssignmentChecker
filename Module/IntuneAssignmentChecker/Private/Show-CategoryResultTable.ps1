function Show-CategoryResultTable {
    <#
    .SYNOPSIS
        Renders one category result section as a fixed-width table.
    .DESCRIPTION
        Generalizes the table renderer that lived inside Get-IntuneGroupAssignment
        (Format-PolicyTable). Prints a Cyan section header, a Yellow column header,
        one row per item with truncation, and reason-based row coloring:
        Inherited Exclusion = Magenta, Direct Exclusion = Red, Inherited = DarkYellow,
        everything else = White.
    .PARAMETER Title
        Section title shown in the header block.
    .PARAMETER Items
        Items to render. Each item is expected to expose id, roleScopeTagIds and
        (optionally) AssignmentReason.
    .PARAMETER GetName
        Resolves the display name for one item. Defaults to displayName, then name,
        then "Unnamed Profile".
    .PARAMETER EmptyMessage
        Message shown when the section has no items. Defaults to "No <Title> found."
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Items,

        [Parameter(Mandatory = $false)]
        [scriptblock]$GetName,

        [Parameter(Mandatory = $false)]
        [string]$EmptyMessage
    )

    if (-not $GetName) {
        $GetName = {
            param($item)
            if (-not [string]::IsNullOrWhiteSpace($item.displayName)) { $item.displayName }
            elseif (-not [string]::IsNullOrWhiteSpace($item.name)) { $item.name }
            else { "Unnamed Profile" }
        }
    }
    if (-not $EmptyMessage) { $EmptyMessage = "No $Title found." }

    $tableSeparator = Get-Separator

    # Create prominent section header
    $headerSeparator = "-" * ($Title.Length + 16)
    Write-Host "`n$headerSeparator" -ForegroundColor Cyan
    Write-Host "------- $Title -------" -ForegroundColor Cyan
    Write-Host "$headerSeparator" -ForegroundColor Cyan

    if ($null -eq $Items -or $Items.Count -eq 0) {
        Write-Host $EmptyMessage -ForegroundColor Gray
        Write-Host $tableSeparator -ForegroundColor Gray
        Write-Host ""
        return
    }

    # Create table header
    $headerFormat = "{0,-40} {1,-15} {2,-20} {3,-30} {4,-35}" -f "Policy Name", "Platform", "Scope Tags", "ID", "Assignment"

    Write-Host $headerFormat -ForegroundColor Yellow
    Write-Host $tableSeparator -ForegroundColor Gray

    # Display each item
    foreach ($item in $Items) {
        $name = & $GetName $item

        if ($name.Length -gt 37) { $name = $name.Substring(0, 34) + "..." }

        $platform = Get-PolicyPlatform -Policy $item
        if ($platform.Length -gt 12) { $platform = $platform.Substring(0, 9) + "..." }

        $scopeTags = Get-ScopeTagNames -ScopeTagIds $item.roleScopeTagIds -ScopeTagLookup $script:ScopeTagLookup
        if ($scopeTags.Length -gt 17) { $scopeTags = $scopeTags.Substring(0, 14) + "..." }

        $id = $item.id
        if ($id.Length -gt 27) { $id = $id.Substring(0, 24) + "..." }

        $assignment = if ($item.AssignmentReason) { $item.AssignmentReason } else { "N/A" }
        if ($assignment.Length -gt 32) { $assignment = $assignment.Substring(0, 29) + "..." }

        $rowFormat = "{0,-40} {1,-15} {2,-20} {3,-30} {4,-35}" -f $name, $platform, $scopeTags, $id, $assignment
        if ($assignment -match "Inherited Exclusion") {
            Write-Host $rowFormat -ForegroundColor Magenta
        }
        elseif ($assignment -match "Direct Exclusion") {
            Write-Host $rowFormat -ForegroundColor Red
        }
        elseif ($assignment -match "Inherited") {
            Write-Host $rowFormat -ForegroundColor DarkYellow
        }
        else {
            Write-Host $rowFormat -ForegroundColor White
        }
    }
    Write-Host $tableSeparator -ForegroundColor Gray
}
