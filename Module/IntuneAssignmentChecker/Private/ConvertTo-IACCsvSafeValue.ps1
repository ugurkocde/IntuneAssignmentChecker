function ConvertTo-IACCsvSafeValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    $text = "$Value"
    if ($text -match '^[=+\-@\t\r]') { return "'$text" }
    return $text
}
