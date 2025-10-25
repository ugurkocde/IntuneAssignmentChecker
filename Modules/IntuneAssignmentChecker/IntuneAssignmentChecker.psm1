# IntuneAssignmentChecker.psm1
# Main module file for Intune Assignment Checker
# This module provides tools to analyze and audit Intune policy and app assignments

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

# Get the module root path
$script:ModuleRoot = $PSScriptRoot

# Define script-level variables that will be used across functions
$script:GraphEndpoint = $null
$script:EnvironmentName = $null

# Import Private functions
Write-Verbose "Importing Private functions..."
$privateFunctions = @(
    Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
)

foreach ($import in $privateFunctions) {
    try {
        Write-Verbose "  Importing $($import.FullName)"
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Import Public functions
Write-Verbose "Importing Public functions..."
$publicFunctions = @(
    Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
)

foreach ($import in $publicFunctions) {
    try {
        Write-Verbose "  Importing $($import.FullName)"
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export Public functions
Write-Verbose "Exporting Public functions..."
Export-ModuleMember -Function @(
    'Show-Menu'
    'Switch-Tenant'
    'Show-SaveFileDialog'
    'Export-PolicyData'
    'Export-ResultsIfRequested'
)

# Export module variables if needed
Write-Verbose "Module loaded successfully: IntuneAssignmentChecker v3.4.5"
