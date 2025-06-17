<#
.SYNOPSIS
    Fully automated creation of the "Intune Assignment Checker" App Registration in Entra ID (Azure AD),
    including:
    - Required Microsoft Graph Application Permissions
    - Self-signed certificate creation
    - Certificate upload as KeyCredential to the App (via workaround using Client Secret)
    - Full tenant-aware naming
    - Certificate export to local disk for later use

.DESCRIPTION
    This script fully automates the creation of an Azure AD App Registration for use with Microsoft Intune Graph API queries.
    It assigns the required Microsoft Graph permissions, generates a self-signed certificate, creates a temporary Client Secret 
    (as a workaround to allow certificate injection via Graph API), uploads the certificate as KeyCredential, removes the Client Secret, 
    and finally exports the certificate to disk for later use with client credentials authentication.
    The script uses Update-MgApplication for certificate injection to avoid common Graph SDK permission issues.

.EXAMPLE
    PS C:\> .\Create-IntuneAssignmentCheckerApp.ps1

.NOTES
    Author: Stefan Redlin
    Inspired by Ugur Koc's Intune Assignment Checker (@UgurKocDe), which motivated the automation of the App Registration process.
    Many thanks for sharing this great tool — big shoutout to the IT community!
#>

# STEP 1: Connect to Microsoft Graph and get tenant information
Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.Read.All" -NoWelcome

$tenant = Get-MgOrganization
$tenantName = $tenant.VerifiedDomains | Where-Object { $_.IsDefault } | Select-Object -ExpandProperty Name

if ($tenantName -like "*.onmicrosoft.com") {
    $shortTenantName = $tenantName -replace ".onmicrosoft.com",""
} else {
    $shortTenantName = $tenantName.Split('.')[0]
}

Write-Host "Tenant detected: $tenantName" -ForegroundColor Green
Write-Host "Short Tenant Name: $shortTenantName" -ForegroundColor Green

# STEP 2: Define required permissions
$graphAppId = "00000003-0000-0000-c000-000000000000"
$permissions = @(
    @{ id = "df021288-bdef-4463-88db-98f22de89214"; displayName = "User.Read.All" },
    @{ id = "5b567255-7703-4780-807c-7be8301ae99b"; displayName = "Group.Read.All" },
    @{ id = "7438b122-aefc-4978-80ed-43db9fcc7715"; displayName = "Device.Read.All" },
    @{ id = "7a6ee1e7-141e-4cec-ae74-d9db155731ff"; displayName = "DeviceManagementApps.Read.All" },
    @{ id = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"; displayName = "DeviceManagementConfiguration.Read.All" },
    @{ id = "2f51be20-0bb4-4fed-bf7b-db946066c75e"; displayName = "DeviceManagementManagedDevices.Read.All" },
    @{ id = "06a5fe6d-c49d-46a7-b082-56b1b14103c7"; displayName = "DeviceManagementServiceConfig.Read.All" }
)

$requiredResourceAccess = @(
    @{
        resourceAppId = $graphAppId
        resourceAccess = @(
            $permissions | ForEach-Object { @{ id = $_.id; type = "Role" } }
        )
    }
)

# STEP 3: Create App Registration and Service Principal
$appDisplayName = "Intune Assignment Checker [$shortTenantName]"
$app = New-MgApplication -DisplayName $appDisplayName -SignInAudience AzureADMyOrg -RequiredResourceAccess $requiredResourceAccess
Write-Host "App Registration created: AppId: $($app.AppId)" -ForegroundColor Green

$sp = New-MgServicePrincipal -AppId $app.AppId
Write-Host "Service Principal created: ObjectId: $($sp.Id)" -ForegroundColor Green

# STEP 4: Create Temporary Client Secret (workaround)
$passwordCred = @{ "displayName" = "TemporaryClientSecret"; "endDateTime" = (Get-Date).AddHours(1) }
$clientSecret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCred
Write-Host "Temporary Client Secret created. Will be removed after certificate upload." -ForegroundColor Green

# STEP 5: Generate and upload self-signed certificate
$certSubject = "CN=IntuneAssignmentChecker-$shortTenantName"
$cert = New-SelfSignedCertificate `
    -Subject $certSubject `
    -CertStoreLocation "cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeySpec Signature `
    -KeyExportPolicy Exportable

$exportFolder = "C:\temp\$shortTenantName"
$exportPath = "$exportFolder\IntuneAssignmentChecker-$shortTenantName.cer"
New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
Export-Certificate -Cert $cert -FilePath $exportPath | Out-Null
Write-Host "Certificate exported to: $exportPath" -ForegroundColor Green

$keyCreds = @(
    @{ "Type" = "AsymmetricX509Cert"; "Usage" = "Verify"; "Key" = $cert.RawData }
)
Update-MgApplication -ApplicationId $app.Id -KeyCredentials $keyCreds
Write-Host "Certificate uploaded successfully." -ForegroundColor Green

# STEP 6: Remove Temporary Client Secret
$passwords = (Get-MgApplication -ApplicationId $app.Id).PasswordCredentials
foreach ($pwd in $passwords) {
    if ($pwd.DisplayName -eq "TemporaryClientSecret") {
        Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $pwd.KeyId
        Write-Host "Temporary Client Secret removed." -ForegroundColor Green
    }
}

# STEP 7: Final Output & Disconnect
Write-Host "`n----------------------------" -ForegroundColor Green
Write-Host "DONE! Next steps to complete manually:" -ForegroundColor Green
Write-Host "- Navigate to the App Registration in the Azure Portal" -ForegroundColor Green
Write-Host "- Grant Admin Consent for the API permissions" -ForegroundColor Green
Write-Host "App Display Name: $appDisplayName" -ForegroundColor Green
Write-Host "AppId: $($app.AppId)" -ForegroundColor Green
Write-Host "Certificate exported to: $exportPath" -ForegroundColor Green
Write-Host "----------------------------"

Disconnect-MgGraph | Out-Null
