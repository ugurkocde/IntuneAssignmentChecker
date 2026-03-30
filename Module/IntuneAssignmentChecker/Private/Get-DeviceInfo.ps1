function Get-DeviceInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    $selectProps = "id,displayName,operatingSystem,operatingSystemVersion,managementType,deviceOwnership,trustType,isCompliant,isManaged,approximateLastSignInDateTime,manufacturer,model,enrollmentProfileName"
    $escapedName = $DeviceName -replace "'", "''"
    $deviceUri = "$GraphEndpoint/beta/devices?`$filter=displayName eq '$escapedName'&`$select=$selectProps"
    try {
        $deviceResponse = Invoke-MgGraphRequest -Uri $deviceUri -Method Get
    }
    catch {
        return @{
            Id              = $null
            DisplayName     = $DeviceName
            OperatingSystem = $null
            Success         = $false
            MultipleFound   = $false
            AllDevices      = $null
        }
    }

    if ($deviceResponse.value.Count -gt 1) {
        return @{
            Id              = $null
            DisplayName     = $DeviceName
            OperatingSystem = $null
            Success         = $false
            MultipleFound   = $true
            AllDevices      = $deviceResponse.value
        }
    }

    if ($deviceResponse.value.Count -eq 1) {
        return @{
            Id              = $deviceResponse.value[0].id
            DisplayName     = $deviceResponse.value[0].displayName
            OperatingSystem = $deviceResponse.value[0].operatingSystem
            Success         = $true
            MultipleFound   = $false
            AllDevices      = $null
        }
    }

    return @{
        Id              = $null
        DisplayName     = $DeviceName
        OperatingSystem = $null
        Success         = $false
        MultipleFound   = $false
        AllDevices      = $null
    }
}
