function Get-IACDirectoryDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AzureADDeviceId
    )

    try {
        $escapedId = $AzureADDeviceId -replace "'", "''"
        $encodedFilter = [uri]::EscapeDataString("deviceId eq '$escapedId'")
        $uri = "$script:GraphEndpoint/beta/devices?`$filter=$encodedFilter&`$select=id,displayName,deviceId"
        $devices = @((Invoke-IACGraphRequest -Uri $uri -Method Get).value)
        if ($devices.Count -eq 1 -and $devices[0].id) {
            return [PSCustomObject]@{ Success = $true; Device = $devices[0]; Reason = $null }
        }
        if ($devices.Count -gt 1) {
            return [PSCustomObject]@{ Success = $false; Device = $null; Reason = "Multiple Entra devices use deviceId '$AzureADDeviceId'." }
        }
        return [PSCustomObject]@{ Success = $false; Device = $null; Reason = "No Entra device maps to managedDevice.azureADDeviceId '$AzureADDeviceId'." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Device = $null; Reason = "Entra device lookup failed: $($_.Exception.Message)" }
    }
}
