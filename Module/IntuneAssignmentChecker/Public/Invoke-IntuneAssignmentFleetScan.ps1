function Invoke-IntuneAssignmentFleetScan {
    <#
    .SYNOPSIS
    Runs an isolated assignment-governance scan across multiple tenants.

    .DESCRIPTION
    Reads tenant authentication and capability profiles from JSON, processes each
    tenant sequentially because Graph authentication is process-global, and continues
    after tenant-specific failures. Client secrets are read from named environment
    variables and are never accepted in the configuration file itself.

    .PARAMETER ConfigurationPath
    JSON file containing a tenants array. Each tenant requires TenantId and supports
    AppId, CertificateThumbprint, ClientSecretEnvironmentVariable, Environment,
    Capability, BaselinePath, RulePath, and WaiverPath.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.FleetTenantResult')]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigurationPath,

        [Parameter()]
        [string]$OutputDirectory,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Json', 'JsonLines', 'Csv')]
        [string]$OutputFormat = 'JsonLines'
    )

    $resolvedConfiguration = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigurationPath)
    $configuration = Get-Content -LiteralPath $resolvedConfiguration -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 30 -ErrorAction Stop
    if ([int]$configuration.schemaVersion -ne 1) { throw "Fleet configuration schema '$($configuration.schemaVersion)' is not supported." }
    if (@($configuration.tenants).Count -eq 0) { throw 'Fleet configuration contains no tenants.' }
    $duplicateTenant = @($configuration.tenants | Group-Object TenantId | Where-Object Count -gt 1)
    if ($duplicateTenant.Count -gt 0) { throw "Fleet configuration contains duplicate tenant IDs: $($duplicateTenant.Name -join ', ')." }

    $resolvedOutputDirectory = if ($OutputDirectory) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
        $path
    }
    $fleetResults = [System.Collections.Generic.List[object]]::new()
    foreach ($tenant in @($configuration.tenants)) {
        $started = [datetimeoffset]::UtcNow
        $tenantId = "$($tenant.TenantId)"
        $snapshotPath = $null
        $governancePath = $null
        try {
            if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'Every fleet tenant requires TenantId.' }
            if (-not $tenant.CertificateThumbprint -and -not $tenant.ClientSecretEnvironmentVariable) {
                throw 'Unattended fleet tenants require CertificateThumbprint or ClientSecretEnvironmentVariable.'
            }
            if ([string]::IsNullOrWhiteSpace("$($tenant.AppId)")) {
                throw 'Unattended fleet tenants require AppId.'
            }
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            $script:GraphEndpoint = $null
            $script:CurrentTenantId = $null
            $script:CurrentTenantName = $null
            $script:CurrentUserUPN = $null
            $script:AssignmentFilterLookup = $null
            $script:ScopeTagLookup = $null
            $script:GroupInfoCache = $null

            $connect = @{
                TenantId = $tenantId
                Environment = if ($tenant.Environment) { "$($tenant.Environment)" } else { 'Global' }
                Capability = if ($tenant.Capability) { @($tenant.Capability) } else { @('Full') }
                SkipPermissionPrompt = $true
                PassThru = $true
            }
            if ($tenant.AppId) { $connect.AppId = "$($tenant.AppId)" }
            if ($tenant.CertificateThumbprint) { $connect.CertificateThumbprint = "$($tenant.CertificateThumbprint)" }
            if ($tenant.ClientSecretEnvironmentVariable) {
                if (-not $tenant.AppId) { throw 'ClientSecretEnvironmentVariable requires AppId.' }
                $secret = [Environment]::GetEnvironmentVariable("$($tenant.ClientSecretEnvironmentVariable)")
                if ([string]::IsNullOrWhiteSpace($secret)) { throw "Environment variable '$($tenant.ClientSecretEnvironmentVariable)' is empty or unavailable." }
                $secureSecret = ConvertTo-SecureString $secret -AsPlainText -Force
                $connect.ClientSecretCredential = [PSCredential]::new("$($tenant.AppId)", $secureSecret)
                $secret = $null
            }
            $connection = Connect-IntuneAssignmentChecker @connect
            if (-not $connection -or -not $script:GraphEndpoint) { throw 'Microsoft Graph connection did not complete.' }
            if ($connection.TenantId -and $connection.TenantId -ne $tenantId) {
                throw "Connected tenant '$($connection.TenantId)' does not match configured tenant '$tenantId'."
            }

            if ($resolvedOutputDirectory) {
                $safeTenantId = $tenantId -replace '[^A-Za-z0-9._-]', '_'
                $snapshotPath = Join-Path $resolvedOutputDirectory "$safeTenantId.snapshot.json"
                $governancePath = Join-Path $resolvedOutputDirectory "$safeTenantId.governance.jsonl"
                $null = Export-IntuneAssignmentSnapshot -Path $snapshotPath -Force -PassThru
                $governanceArguments = @{ SnapshotPath = $snapshotPath; OutputPath = $governancePath; OutputFormat = 'JsonLines' }
            }
            else { $governanceArguments = @{} }
            if ($tenant.RulePath) { $governanceArguments.RulePath = "$($tenant.RulePath)" }
            elseif ($configuration.RulePath) { $governanceArguments.RulePath = "$($configuration.RulePath)" }
            if ($tenant.WaiverPath) { $governanceArguments.WaiverPath = "$($tenant.WaiverPath)" }
            elseif ($configuration.WaiverPath) { $governanceArguments.WaiverPath = "$($configuration.WaiverPath)" }
            $findings = @(Test-IntuneAssignmentGovernance @governanceArguments)
            $drift = @()
            if ($tenant.BaselinePath -and $snapshotPath -and (Test-Path -LiteralPath "$($tenant.BaselinePath)")) {
                $drift = @(Get-IntuneAssignmentDrift -BaselinePath "$($tenant.BaselinePath)" -CurrentSnapshotPath $snapshotPath)
            }
            $result = [PSCustomObject][ordered]@{
                SchemaName       = 'IntuneAssignmentChecker.FleetTenantResult'
                SchemaVersion    = 1
                TenantId         = $tenantId
                TenantName       = $connection.TenantName
                Status           = if (@($findings | Where-Object Severity -in @('Critical', 'High')).Count -gt 0) { 'CompletedWithFindings' } else { 'Completed' }
                StartedAtUtc     = $started.ToString('o')
                CompletedAtUtc   = [datetimeoffset]::UtcNow.ToString('o')
                Capabilities     = @($connection.Capabilities)
                FindingCount     = $findings.Count
                CriticalCount    = @($findings | Where-Object Severity -EQ 'Critical').Count
                HighCount        = @($findings | Where-Object Severity -EQ 'High').Count
                DriftCount       = $drift.Count
                SnapshotPath     = $snapshotPath
                GovernancePath   = $governancePath
                Findings         = @($findings)
                DriftEvents      = @($drift)
                GraphApiVersion  = 'beta'
                Error            = $null
            }
        }
        catch {
            $result = [PSCustomObject][ordered]@{
                SchemaName       = 'IntuneAssignmentChecker.FleetTenantResult'
                SchemaVersion    = 1
                TenantId         = $tenantId
                TenantName       = $null
                Status           = 'Failed'
                StartedAtUtc     = $started.ToString('o')
                CompletedAtUtc   = [datetimeoffset]::UtcNow.ToString('o')
                Capabilities     = @()
                FindingCount     = 0
                CriticalCount    = 0
                HighCount        = 0
                DriftCount       = 0
                SnapshotPath     = $snapshotPath
                GovernancePath   = $governancePath
                Findings         = @()
                DriftEvents      = @()
                GraphApiVersion  = 'beta'
                Error            = $_.Exception.Message
            }
            Write-Error -ErrorRecord $_ -ErrorAction Continue
        }
        $result.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.FleetTenantResult')
        [void]$fleetResults.Add($result)
    }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    $script:GraphEndpoint = $null
    $script:CurrentTenantId = $null
    $script:CurrentTenantName = $null
    $script:CurrentUserUPN = $null
    $script:TemplateIdToFamilyCache = $null
    $script:AssignmentFilterLookup = $null
    $script:ScopeTagLookup = $null
    $script:GroupInfoCache = $null
    if ($OutputPath) { $null = Export-IACStructuredOutput -InputObject @($fleetResults) -Path $OutputPath -Format $OutputFormat }
    $fleetResults | Write-Output
}
