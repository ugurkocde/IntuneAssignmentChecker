function Get-Separator {
    param (
        [string]$Character = "-",
        [int]$MinWidth = 80
    )
    $width = try { [Math]::Max($MinWidth, $Host.UI.RawUI.WindowSize.Width - 2) } catch { 120 }
    return $Character * [Math]::Min($width, 120)
}
