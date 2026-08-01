function Get-IACManagedDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )

    # These are the beta managedDevice fields used by the documented Intune
    # assignment-filter property map. skuNumber is used instead of the coarse
    # skuFamily, and deviceOwnership is intentionally not a managedDevice field.
    $select = @(
        'id', 'deviceName', 'operatingSystem', 'osVersion', 'model', 'manufacturer',
        'managedDeviceOwnerType', 'enrollmentProfileName', 'skuNumber',
        'deviceCategoryDisplayName', 'azureADDeviceId', 'jailBroken',
        'processorArchitecture', 'joinType', 'deviceEnrollmentType', 'managementAgent'
    ) -join ','

    try {
        if ($Identity -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $device = Invoke-IACGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices/$Identity`?`$select=$select" -Method Get
            if ($device -and $device.id) {
                return [PSCustomObject]@{ Success = $true; Device = $device; MultipleFound = $false; Reason = $null }
            }
            return [PSCustomObject]@{ Success = $false; Device = $null; MultipleFound = $false; Reason = "Managed device '$Identity' was not found." }
        }

        $escapedName = $Identity -replace "'", "''"
        $encodedFilter = [uri]::EscapeDataString("deviceName eq '$escapedName'")
        $response = Invoke-IACGraphRequest -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices?`$filter=$encodedFilter&`$select=$select" -Method Get
        $devices = @($response.value)
        if ($devices.Count -eq 1) {
            return [PSCustomObject]@{ Success = $true; Device = $devices[0]; MultipleFound = $false; Reason = $null }
        }
        if ($devices.Count -gt 1) {
            return [PSCustomObject]@{ Success = $false; Device = $null; MultipleFound = $true; Reason = "Multiple managed devices are named '$Identity'; use the Intune managed-device ID." }
        }
        return [PSCustomObject]@{ Success = $false; Device = $null; MultipleFound = $false; Reason = "Managed device '$Identity' was not found." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Device = $null; MultipleFound = $false; Reason = "Managed-device lookup failed: $($_.Exception.Message)" }
    }
}
