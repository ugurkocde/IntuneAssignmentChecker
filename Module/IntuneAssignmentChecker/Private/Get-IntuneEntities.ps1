function Get-IntuneEntities {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,

        [Parameter(Mandatory = $false)]
        [string]$Filter = "",

        [Parameter(Mandatory = $false)]
        [string]$Select = "",

        [Parameter(Mandatory = $false)]
        [string]$Expand = ""
    )

    # Handle special cases for app management and specific deviceManagement endpoints
    if ($EntityType -like "deviceAppManagement/*" -or $EntityType -eq "deviceManagement/templates" -or $EntityType -eq "deviceManagement/intents") {
        $baseUri = "$GraphEndpoint/beta"
        $actualEntityType = $EntityType
    }
    else {
        $baseUri = "$GraphEndpoint/beta/deviceManagement"
        $actualEntityType = "$EntityType"
    }

    $currentUri = "$baseUri/$actualEntityType"
    if ($Filter) { $currentUri += "?`$filter=$Filter" }
    if ($Select) { $currentUri += $(if ($Filter) { "&" }else { "?" }) + "`$select=$Select" }
    if ($Expand) { $currentUri += $(if ($Filter -or $Select) { "&" }else { "?" }) + "`$expand=$Expand" }

    $entities = [System.Collections.ArrayList]::new() # Initialize as ArrayList

    do {
        try {
            $response = Invoke-MgGraphRequest -Uri $currentUri -Method Get -ErrorAction Stop
            if ($null -ne $response -and $null -ne $response.value) {
                if ($response.value -is [array]) {
                    $entities.AddRange($response.value)
                }
                else {
                    $entities.Add($response.value)
                }
            }
            $currentUri = $response.'@odata.nextLink'
        }
        catch {
            $errorMessage = $_.Exception.Message
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 403 -or $errorMessage -match "403|Forbidden|Authorization_RequestDenied") {
                Write-Warning "Permission denied (403) for '$EntityType'. Ensure admin consent has been granted for the required Graph API permissions. Run 'Connect-MgGraph -Scopes ...' with the necessary scopes or grant admin consent in Azure AD."
            }
            else {
                Write-Warning "Error fetching entities for $EntityType from $currentUri : $errorMessage"
            }
            $currentUri = $null # Stop pagination on error
        }
    } while ($currentUri)

    return $entities
}
