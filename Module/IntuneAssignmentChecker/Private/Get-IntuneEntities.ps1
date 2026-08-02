function Get-IntuneEntities {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntityType,

        [Parameter(Mandatory = $false)]
        [string]$Filter = "",

        [Parameter(Mandatory = $false)]
        [string]$Select = "",

        [Parameter(Mandatory = $false)]
        [string]$Expand = "",

        # Optional beta workloads are not available in every tenant. Callers can
        # suppress the expected warning without changing the empty-result contract.
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,

        # Preserve legacy empty-result behavior by default, while coverage-aware
        # callers can require a terminating error for an unavailable workload.
        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnError
    )

    # Handle special cases for app management and specific deviceManagement endpoints
    if ($EntityType -like "deviceAppManagement/*" -or $EntityType -eq "deviceManagement/templates" -or $EntityType -eq "deviceManagement/intents") {
        $baseUri = "$script:GraphEndpoint/beta"
        $actualEntityType = $EntityType
    }
    else {
        $baseUri = "$script:GraphEndpoint/beta/deviceManagement"
        $actualEntityType = "$EntityType"
    }

    $currentUri = "$baseUri/$actualEntityType"
    if ($Filter) { $currentUri += "?`$filter=$Filter" }
    if ($Select) { $currentUri += $(if ($Filter) { "&" }else { "?" }) + "`$select=$Select" }
    if ($Expand) { $currentUri += $(if ($Filter -or $Select) { "&" }else { "?" }) + "`$expand=$Expand" }

    $entities = [System.Collections.ArrayList]::new() # Initialize as ArrayList

    try {
        $pagedEntities = @((Invoke-IACGraphRequest -Uri $currentUri -Method Get -ErrorAction Stop).value)
        if ($pagedEntities.Count -gt 0) { $entities.AddRange([object[]]$pagedEntities) }
    }
    catch {
        if ($ThrowOnError) { throw }
        $errorMessage = $_.Exception.Message
        $statusCode = if ($_.Exception.Data.Contains('StatusCode')) { $_.Exception.Data['StatusCode'] } else { $null }
        if ($statusCode -eq 403 -or $errorMessage -match "403|Forbidden|Authorization_RequestDenied") {
            Write-Warning "Permission denied (403) for '$EntityType'. Ensure admin consent has been granted for the required Graph API permissions. Run 'Connect-MgGraph -Scopes ...' with the necessary scopes or grant admin consent in Azure AD."
        }
        elseif ($Quiet) {
            Write-Verbose "Skipping unavailable entity set '$EntityType': $errorMessage"
        }
        else {
            Write-Warning "Error fetching entities for ${EntityType}: $errorMessage"
        }
    }

    return $entities
}
