$context = Get-MgContext
$environment = $context.Environment

$GraphEndpoint = switch ($environment) {
    "Global" { "https://graph.microsoft.com" }
    "USGov" { "https://graph.microsoft.us" }
    "USGovDoD" { "https://dod-graph.microsoft.us" }
}
# Function to get assignment information
function Get-AssignmentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]$Assignments
    )

    if ($null -eq $Assignments -or $Assignments.Count -eq 0) {
        return @{
            Type   = "None"
            Target = "Not Assigned"
        }
    }

    $types = @()
    $targets = @()

    foreach ($assignment in $Assignments) {
        $type = "None"
        $target = "Not Assigned"
        $groupId = $null

        # Handle Graph API format (with target object)
        if ($assignment.target) {
            switch ($assignment.target.'@odata.type') {
                '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                    $type = "All Users"
                    $target = "All Users"
                }
                '#microsoft.graph.allDevicesAssignmentTarget' {
                    $type = "All Devices"
                    $target = "All Devices"
                }
                '#microsoft.graph.groupAssignmentTarget' {
                    $type = "Group"
                    $groupId = $assignment.target.groupId
                }
                '#microsoft.graph.exclusionGroupAssignmentTarget' {
                    $type = "Exclude"
                    $groupId = $assignment.target.groupId
                }
            }
        }
        # Handle standard format (with Reason and GroupId)
        else {
            $type = switch ($assignment.Reason) {
                "All Users" { "All Users"; break }
                "All Devices" { "All Devices"; break }
                "Group Assignment" { "Group"; break }
                "Exclude" { "Exclude"; break }
                default { "None" }
            }
            $groupId = $assignment.GroupId
        }

        # Get group name if we have a group ID
        if ($groupId) {
            $groupInfo = Get-GroupInfo -GroupId $groupId
            $target = $groupInfo.DisplayName
        }

        $types += $type
        $targets += $target
    }

    # Determine the primary type (prioritize All Users/Devices over Group)
    $primaryType = if ($types -contains "All Users") {
        "All Users"
    }
    elseif ($types -contains "All Devices") {
        "All Devices"
    }
    elseif ($types -contains "Group") {
        "Group"
    }
    elseif ($types -contains "Exclude") {
        "Exclude"
    }
    else {
        "None"
    }

    return @{
        Type   = $primaryType
        Target = ($targets -join "; ")
    }
}

$script:IntentTemplateSubtypeToFamily = @{
    'antivirus'                = 'endpointSecurityAntivirus'
    'diskEncryption'           = 'endpointSecurityDiskEncryption'
    'firewall'                 = 'endpointSecurityFirewall'
    'endpointDetectionReponse' = 'endpointSecurityEndpointDetectionAndResponse'
    'attackSurfaceReduction'   = 'endpointSecurityAttackSurfaceReduction'
    'accountProtection'        = 'endpointSecurityAccountProtection'
}
$script:TemplateIdToFamilyCache = $null

function Get-IntentTemplateFamilyLookup {
    if ($null -ne $script:TemplateIdToFamilyCache) {
        return $script:TemplateIdToFamilyCache
    }

    $script:TemplateIdToFamilyCache = @{}
    try {
        $templates = Get-IntuneEntities -EntityType "deviceManagement/templates"
        foreach ($template in $templates) {
            $subtype = $template.templateSubtype
            if ($subtype -and $script:IntentTemplateSubtypeToFamily.ContainsKey($subtype)) {
                $script:TemplateIdToFamilyCache[$template.id] = $script:IntentTemplateSubtypeToFamily[$subtype]
            }
        }
    }
    catch {
        Write-Warning "Unable to fetch deviceManagement/templates for intent enrichment: $($_.Exception.Message)"
    }

    return $script:TemplateIdToFamilyCache
}

function Add-IntentTemplateFamilyInfo {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$IntentPolicies
    )

    $lookup = Get-IntentTemplateFamilyLookup

    foreach ($intent in $IntentPolicies) {
        if ($intent.templateId -and $lookup.ContainsKey($intent.templateId)) {
            if (-not $intent.templateReference) {
                $intent | Add-Member -NotePropertyName 'templateReference' -NotePropertyValue @{
                    templateFamily = $lookup[$intent.templateId]
                }
            }
        }
    }
}

function Export-HTMLReport {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # HTML template with placeholders for $tabHeaders, $tabContent, summary stats, and chart
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intune Assignment Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f5f7fa;
            --text-color: #000;
            --card-bg: #fff;
            --table-bg: #fff;
            --hover-bg: #f8f9fa;
            --border-color: #dee2e6;
        }

        [data-theme="dark"] {
            --bg-color: #1a1a1a;
            --text-color: #fff;
            --card-bg: #2d2d2d;
            --table-bg: #2d2d2d;
            --hover-bg: #3d3d3d;
            --border-color: #404040;
        }

        body {
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            background-color: var(--card-bg);
            transition: transform 0.2s, background-color 0.3s ease;
            border-color: var(--border-color);
        }
        .card:hover {
            transform: translateY(-2px);
        }
        .badge-all-users {
            background-color: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
        }
        .badge-all-devices {
            background-color: #17a2b8;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
        }
        .badge-group {
            background-color: #ffc107;
            color: black;
            padding: 5px 10px;
            border-radius: 15px;
        }
        .badge-none {
            background-color: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
        }
        .badge-exclude {
            background-color: #6c757d;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
        }
        .summary-card {
            background-color: #f8f9fa;
            border: none;
        }
        .table-container {
            margin-top: 20px;
            background: var(--table-bg);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: background-color 0.3s ease;
        }

        .table {
            color: var(--text-color) !important;
        }

        .table thead th {
            color: var(--text-color) !important;
        }

        .table tbody tr:hover {
            background-color: var(--hover-bg) !important;
        }

        .dataTables_info, .dataTables_length, .dataTables_filter label {
            color: var(--text-color) !important;
        }
        .nav-tabs {
            margin-bottom: 20px;
            border-bottom: 2px solid var(--border-color);
        }
        .nav-tabs .nav-link {
            border: none;
            color: #6c757d;
            padding: 10px 20px;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }
        .nav-tabs .nav-link.active {
            color: #0d6efd;
            border-bottom: 2px solid #0d6efd;
            font-weight: 500;
        }
        .tab-content {
            padding: 20px;
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 10px 10px;
            background-color: var(--card-bg);
        }
        .chart-container {
            margin: 10px 0;
            padding: 15px;
            background: var(--card-bg);
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            height: 300px;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .search-box {
            margin: 20px 0;
            padding: 15px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        .policy-table {
            width: 100% !important;
        }
        .policy-table thead th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .report-header {
            background: linear-gradient(135deg, #0d6efd 0%, #0099ff 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            animation: fadeIn 0.5s ease-in-out;
            position: relative;
        }

        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 20px;
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            transition: transform 0.3s ease;
        }

        .theme-toggle:hover {
            transform: scale(1.1);
        }

        @media print {
            body {
                background-color: white !important;
                color: black !important;
            }
            .card, .table-container, .tab-content {
                background-color: white !important;
                color: black !important;
                box-shadow: none !important;
            }
            .theme-toggle, .buttons-collection {
                display: none !important;
            }
            .table {
                color: black !important;
            }
            .table thead th {
                color: black !important;
                background-color: #f8f9fa !important;
            }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .search-box {
            margin: 20px 0;
            padding: 20px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        .search-box input {
            border: 2px solid #dee2e6;
            transition: border-color 0.3s ease;
        }
        .search-box input:focus {
            border-color: #0d6efd;
            box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
        }
        .report-header h1 {
            margin: 0;
            font-weight: 300;
        }
        .report-header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary-stat {
            text-align: center;
            padding: 20px;
        }
        .summary-stat h3 {
            font-size: 2rem;
            font-weight: 300;
            margin: 10px 0;
            color: #0d6efd;
        }
        .summary-stat p {
            color: #6c757d;
            margin: 0;
        }
        #assignmentTypeFilter {
            border: 2px solid #dee2e6;
            border-radius: 5px;
            padding: 8px;
            transition: all 0.3s ease;
            background-color: var(--card-bg);
            color: var(--text-color);
        }
        #assignmentTypeFilter:focus {
            border-color: #0d6efd;
            box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
            outline: none;
        }
        .form-label {
            color: var(--text-color);
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="report-header">
            <h1>Intune Assignment Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM dd, yyyy HH:mm")</p>
        </div>

        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card summary-card">
                    <div class="card-body">
                        <h5 class="card-title">Summary</h5>
                        <div class="row" id="summary-stats">
                            <!-- Summary stats will be inserted here -->
                        </div>
                    </div>
                </div>
                <!-- Policy overview chart placeholder -->
            </div>
        </div>

        <div class="search-box">
            <div class="row align-items-end">
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="groupSearch">Search by Group Name:</label>
                        <input type="text" class="form-control" id="groupSearch" placeholder="Enter group name...">
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="assignmentTypeFilter" class="form-label">Filter by Assignment Type:</label>
                        <select class="form-select" id="assignmentTypeFilter">
                            <option value="all">All Types</option>
                            <option value="All Users">All Users</option>
                            <option value="All Devices">All Devices</option>
                            <option value="Group">Group</option>
                            <option value="None">None</option>
                            <option value="Exclude">Exclude</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <ul class="nav nav-tabs" id="assignmentTabs" role="tablist">
            <!-- Tab headers will be inserted here -->
        </ul>

        <div class="tab-content" id="assignmentTabContent">
            <!-- Tab content will be inserted here -->
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.2.2/js/buttons.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.1.3/jszip.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.2.2/js/buttons.html5.min.js"></script>
    <script>
        jQuery(document).ready(function() {
            // Initialize DataTables
            var tables = jQuery('.policy-table').DataTable({
                dom: 'Blfrtip',
                buttons: [
                    'copyHtml5',
                    'excelHtml5',
                    'csvHtml5'
                ],
                pageLength: 10,
                lengthMenu: [[10, 25, 50, -1], [10, 25, 50, "All"]],
                ordering: false,
                columnDefs: [
                    {
                        targets: '_all',
                        orderable: false
                    }
                ]
            });

            // Assignment Type Filter
            jQuery('#assignmentTypeFilter').on('change', function() {
                const filterValue = jQuery(this).val();
                jQuery('.policy-table').each(function() {
                    const dataTable = jQuery(this).DataTable();
                    if (filterValue === 'all') {
                        dataTable.search('').columns().search('').draw();
                    } else {
                        dataTable.column(1).search(filterValue, false, false).draw();
                    }
                });
            });

            jQuery('#groupSearch').on('keyup', function() {
                const searchTerm = this.value.toLowerCase();
                jQuery('.policy-table').each(function() {
                    jQuery(this).DataTable().search(searchTerm).draw();
                });
            });

            // Show the first tab by default
            const firstTab = document.querySelector('.nav-tabs .nav-link');
            const firstPane = document.querySelector('.tab-pane');
            if (firstTab) firstTab.classList.add('active');
            if (firstPane) firstPane.classList.add('show', 'active');
        });
    </script>
</body>
</html>
"@

    # Initialize collections
    $policies = @{
        DeviceConfigs             = @()
        SettingsCatalog           = @()
        AdminTemplates            = @()
        CompliancePolicies        = @()
        AppProtectionPolicies     = @()
        AppConfigurationPolicies  = @()
        PlatformScripts           = @()
        HealthScripts             = @()
        RequiredApps              = @()
        AvailableApps             = @()
        UninstallApps             = @()
        DeploymentProfiles        = @()
        ESPProfiles              = @()
        AntivirusProfiles         = @()
        DiskEncryptionProfiles    = @()
        FirewallProfiles          = @()
        EndpointDetectionProfiles = @()
        AttackSurfaceProfiles     = @()
        AccountProtectionProfiles = @()
        CloudPCProvisioningPolicies = @()
        CloudPCUserSettings       = @()
    }

    # Fetch all policies
    Write-Host "Fetching Device Configurations..." -ForegroundColor Yellow
    $deviceConfigs = Get-IntuneEntities -EntityType "deviceConfigurations"
    foreach ($config in $deviceConfigs) {
        $assignments = Get-IntuneAssignments -EntityType "deviceConfigurations" -EntityId $config.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.DeviceConfigs += @{
            Name           = $config.displayName
            ID             = $config.id
            Type           = "Device Configuration"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    Write-Host "Fetching Settings Catalog Policies..." -ForegroundColor Yellow
    $settingsCatalog = Get-IntuneEntities -EntityType "configurationPolicies"
    foreach ($policy in $settingsCatalog) {
        # Exclude Endpoint Security policies from this generic Settings Catalog fetch
        if ($policy.templateReference -and $policy.templateReference.templateFamily -like "endpointSecurity*") {
            continue
        }
        $assignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.SettingsCatalog += @{
            Name           = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
            ID             = $policy.id
            Type           = "Settings Catalog"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    Write-Host "Fetching Administrative Templates..." -ForegroundColor Yellow
    $adminTemplates = Get-IntuneEntities -EntityType "groupPolicyConfigurations"
    foreach ($template in $adminTemplates) {
        $assignments = Get-IntuneAssignments -EntityType "groupPolicyConfigurations" -EntityId $template.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.AdminTemplates += @{
            Name           = $template.displayName
            ID             = $template.id
            Type           = "Administrative Template"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    Write-Host "Fetching Compliance Policies..." -ForegroundColor Yellow
    $compliancePolicies = Get-IntuneEntities -EntityType "deviceCompliancePolicies"
    foreach ($policy in $compliancePolicies) {
        $assignments = Get-IntuneAssignments -EntityType "deviceCompliancePolicies" -EntityId $policy.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.CompliancePolicies += @{
            Name           = $policy.displayName
            ID             = $policy.id
            Type           = "Compliance Policy"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    Write-Host "Fetching App Protection Policies..." -ForegroundColor Yellow
    $appProtectionPolicies = Get-IntuneEntities -EntityType "deviceAppManagement/managedAppPolicies"
    foreach ($policy in $appProtectionPolicies) {
        $policyType = $policy.'@odata.type'
        $assignmentsUri = switch ($policyType) {
            "#microsoft.graph.androidManagedAppProtection" {
                "$GraphEndpoint/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments"
            }
            "#microsoft.graph.iosManagedAppProtection" {
                "$GraphEndpoint/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments"
            }
            "#microsoft.graph.windowsManagedAppProtection" {
                "$GraphEndpoint/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments"
            }
            default { $null }
        }

        if ($assignmentsUri) {
            try {
                $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get
                # Pass the raw .value to Get-AssignmentInfo as it expects an array of assignment objects
                $assignmentInfo = Get-AssignmentInfo -Assignments $assignmentResponse.value 

                $policies.AppProtectionPolicies += @{
                    Name           = $policy.displayName
                    ID             = $policy.id
                    Type           = "App Protection Policy ($($policyType.Split('.')[-1].Replace('ManagedAppProtection','')))"
                    AssignmentType = $assignmentInfo.Type
                    AssignedTo     = $assignmentInfo.Target
                }
            }
            catch {
                Write-Host "Error fetching assignments for App Protection policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Get Platform Scripts
    Write-Host "Fetching Platform Scripts..." -ForegroundColor Yellow
    $platformScripts = Get-IntuneEntities -EntityType "deviceManagementScripts"
    foreach ($script in $platformScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceManagementScripts" -EntityId $script.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.PlatformScripts += @{
            Name           = $script.displayName
            ID             = $script.id
            Type           = "PowerShell Script"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    # Get Proactive Remediation Scripts
    Write-Host "Fetching Proactive Remediation Scripts..." -ForegroundColor Yellow
    $healthScripts = Get-IntuneEntities -EntityType "deviceHealthScripts"
    foreach ($script in $healthScripts) {
        $assignments = Get-IntuneAssignments -EntityType "deviceHealthScripts" -EntityId $script.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.HealthScripts += @{
            Name           = $script.displayName
            ID             = $script.id
            Type           = "Proactive Remediation Script"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    # Get Autopilot Deployment Profiles
    Write-Host "Fetching Autopilot Deployment Profiles..." -ForegroundColor Yellow
    $autoProfiles = Get-IntuneEntities -EntityType "windowsAutopilotDeploymentProfiles"
    foreach ($profile in $autoProfiles) {
        $assignments = Get-IntuneAssignments -EntityType "windowsAutopilotDeploymentProfiles" -EntityId $profile.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.DeploymentProfiles += @{
            Name           = $profile.displayName
            ID             = $profile.id
            Type           = "Autopilot Deployment Profile"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    # Get Enrollment Status Page Profiles
    Write-Host "Fetching Enrollment Status Page Profiles..." -ForegroundColor Yellow
    $enrollmentConfigs = Get-IntuneEntities -EntityType "deviceEnrollmentConfigurations"
    $espProfiles = $enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' }
    foreach ($esp in $espProfiles) {
        $assignments = Get-IntuneAssignments -EntityType "deviceEnrollmentConfigurations" -EntityId $esp.id
        $assignmentInfo = Get-AssignmentInfo -Assignments $assignments
        $policies.ESPProfiles += @{
            Name           = $esp.displayName
            ID             = $esp.id
            Type           = "Enrollment Status Page"
            AssignmentType = $assignmentInfo.Type
            AssignedTo     = $assignmentInfo.Target
        }
    }

    # Get Windows 365 Cloud PC Provisioning Policies
    Write-Host "Fetching Windows 365 Cloud PC Provisioning Policies..." -ForegroundColor Yellow
    try {
        $cloudPCProvisioningPolicies = Get-IntuneEntities -EntityType "virtualEndpoint/provisioningPolicies"
        foreach ($policy in $cloudPCProvisioningPolicies) {
            $rawAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/provisioningPolicies" -EntityId $policy.id
            $assignmentInfo = Get-AssignmentInfo -Assignments $rawAssignments
            $policies.CloudPCProvisioningPolicies += @{
                Name           = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
                ID             = $policy.id
                Type           = "Windows 365 Cloud PC Provisioning Policy"
                AssignmentType = $assignmentInfo.Type
                AssignedTo     = $assignmentInfo.Target
            }
        }
    }
    catch {
        Write-Warning "Unable to fetch Windows 365 Cloud PC Provisioning Policies: $($_.Exception.Message)"
    }

    # Get Windows 365 Cloud PC User Settings
    Write-Host "Fetching Windows 365 Cloud PC User Settings..." -ForegroundColor Yellow
    try {
        $cloudPCUserSettings = Get-IntuneEntities -EntityType "virtualEndpoint/userSettings"
        foreach ($setting in $cloudPCUserSettings) {
            $rawAssignments = Get-IntuneAssignments -EntityType "virtualEndpoint/userSettings" -EntityId $setting.id
            $assignmentInfo = Get-AssignmentInfo -Assignments $rawAssignments
            $policies.CloudPCUserSettings += @{
                Name           = if (-not [string]::IsNullOrWhiteSpace($setting.displayName)) { $setting.displayName } else { $setting.name }
                ID             = $setting.id
                Type           = "Windows 365 Cloud PC User Setting"
                AssignmentType = $assignmentInfo.Type
                AssignedTo     = $assignmentInfo.Target
            }
        }
    }
    catch {
        Write-Warning "Unable to fetch Windows 365 Cloud PC User Settings: $($_.Exception.Message)"
    }

    # Endpoint Security Policies Fetching
    $endpointSecurityCategories = @(
        @{ Name = "Antivirus"; Key = "AntivirusProfiles"; TemplateFamily = "endpointSecurityAntivirus"; UserFriendlyType = "Antivirus Profile" },
        @{ Name = "Disk Encryption"; Key = "DiskEncryptionProfiles"; TemplateFamily = "endpointSecurityDiskEncryption"; UserFriendlyType = "Disk Encryption Profile" },
        @{ Name = "Firewall"; Key = "FirewallProfiles"; TemplateFamily = "endpointSecurityFirewall"; UserFriendlyType = "Firewall Profile" },
        @{ Name = "Endpoint Detection and Response"; Key = "EndpointDetectionProfiles"; TemplateFamily = "endpointSecurityEndpointDetectionAndResponse"; UserFriendlyType = "EDR Profile" },
        @{ Name = "Attack Surface Reduction"; Key = "AttackSurfaceProfiles"; TemplateFamily = "endpointSecurityAttackSurfaceReduction"; UserFriendlyType = "ASR Profile" },
        @{ Name = "Account Protection"; Key = "AccountProtectionProfiles"; TemplateFamily = "endpointSecurityAccountProtection"; UserFriendlyType = "Account Protection Profile" }
    )

    foreach ($esCategory in $endpointSecurityCategories) {
        Write-Host "Fetching Endpoint Security - $($esCategory.Name) Policies..." -ForegroundColor Yellow
        $processedIds = [System.Collections.Generic.HashSet[string]]::new()

        # 1. Check configurationPolicies (Settings Catalog)
        $allConfigPolicies = Get-IntuneEntities -EntityType "configurationPolicies"
        $configPolicies = $allConfigPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
        if ($configPolicies) {
            foreach ($policy in $configPolicies) {
                if ($processedIds.Add($policy.id)) {
                    $rawAssignments = Get-IntuneAssignments -EntityType "configurationPolicies" -EntityId $policy.id
                    $assignmentInfo = Get-AssignmentInfo -Assignments $rawAssignments
                    $policies[$esCategory.Key] += @{
                        Name           = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
                        ID             = $policy.id
                        Type           = $esCategory.UserFriendlyType
                        AssignmentType = $assignmentInfo.Type
                        AssignedTo     = $assignmentInfo.Target
                    }
                }
            }
        }

        # 2. Check deviceManagement/intents (Templates)
        $allIntentPolicies = Get-IntuneEntities -EntityType "deviceManagement/intents"
        Add-IntentTemplateFamilyInfo -IntentPolicies $allIntentPolicies
        $intentPolicies = $allIntentPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateFamily -eq $esCategory.TemplateFamily }
        if ($intentPolicies) {
            foreach ($policy in $intentPolicies) {
                if ($processedIds.Add($policy.id)) {
                    try {
                        $assignmentsResponse = Invoke-MgGraphRequest -Uri "$GraphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments" -Method Get
                        $assignmentInfo = Get-AssignmentInfo -Assignments $assignmentsResponse.value # This expects an array
                        $policies[$esCategory.Key] += @{
                            Name           = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) { $policy.displayName } else { $policy.name }
                            ID             = $policy.id
                            Type           = $esCategory.UserFriendlyType
                            AssignmentType = $assignmentInfo.Type
                            AssignedTo     = $assignmentInfo.Target
                        }
                    } 
                    catch {
                        Write-Host "Error fetching assignments for $($esCategory.Name) intent $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                } 
            } 
        } 
    }

    # Get Apps
    Write-Host "Fetching Applications..." -ForegroundColor Yellow
    $appUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
    $appResponse = Invoke-MgGraphRequest -Uri $appUri -Method Get
    $allApps = $appResponse.value
    while ($appResponse.'@odata.nextLink') {
        $appResponse = Invoke-MgGraphRequest -Uri $appResponse.'@odata.nextLink' -Method Get
        $allApps += $appResponse.value
    }

    foreach ($app in $allApps) {
        # Skip built-in and Microsoft apps
        if ($app.isFeatured -or $app.isBuiltIn) {
            continue
        }

        $appId = $app.id
        $assignmentsUri = "$GraphEndpoint/beta/deviceAppManagement/mobileApps('$appId')/assignments"
        $assignmentResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method Get

        foreach ($assignment in $assignmentResponse.value) {
            # Get-AssignmentInfo expects an array of assignment objects.
            # Here, $assignment is a single assignment object from the loop.
            # We need to wrap it in an array for Get-AssignmentInfo.
            $currentAssignmentArray = @($assignment) # Ensure it's an array
            $assignmentInfo = Get-AssignmentInfo -Assignments $currentAssignmentArray
            
            $appInfo = @{
                Name           = $app.displayName
                ID             = $app.id
                Type           = "Application"
                AssignmentType = $assignmentInfo.Type 
                AssignedTo     = $assignmentInfo.Target 
            }

            switch ($assignment.intent) {
                "required" { $policies.RequiredApps += $appInfo }
                "available" { $policies.AvailableApps += $appInfo }
                "uninstall" { $policies.UninstallApps += $appInfo }
            }
        }
    }

    # Generate summary statistics
    $summaryStats = @{
        TotalPolicies = 0
        AllUsers      = 0
        AllDevices    = 0
        GroupAssigned = 0
        Unassigned    = 0
    }

    $categories = @(
        @{ Key = 'all'; Name = 'All Policies & Apps' }, 
        @{ Key = 'DeviceConfigs'; Name = 'Device Configurations' },
        @{ Key = 'SettingsCatalog'; Name = 'Settings Catalog' },
        @{ Key = 'AdminTemplates'; Name = 'Administrative Templates' },
        @{ Key = 'CompliancePolicies'; Name = 'Compliance Policies' },
        @{ Key = 'AppProtectionPolicies'; Name = 'App Protection Policies' },
        @{ Key = 'RequiredApps'; Name = 'Required Applications' },
        @{ Key = 'AvailableApps'; Name = 'Available Applications' },
        @{ Key = 'UninstallApps'; Name = 'Uninstall Applications' },
        @{ Key = 'PlatformScripts'; Name = 'Platform Scripts' },
        @{ Key = 'HealthScripts'; Name = 'Proactive Remediation Scripts' },
        @{ Key = 'DeploymentProfiles'; Name = 'Autopilot Deployment Profiles' },
        @{ Key = 'ESPProfiles'; Name = 'Enrollment Status Page Profiles' },
        @{ Key = 'CloudPCProvisioningPolicies'; Name = 'Windows 365 Cloud PC Provisioning Policies' },
        @{ Key = 'CloudPCUserSettings'; Name = 'Windows 365 Cloud PC User Settings' },
        @{ Key = 'AntivirusProfiles'; Name = 'Endpoint Security - Antivirus' },
        @{ Key = 'DiskEncryptionProfiles'; Name = 'Endpoint Security - Disk Encryption' },
        @{ Key = 'FirewallProfiles'; Name = 'Endpoint Security - Firewall' },
        @{ Key = 'EndpointDetectionProfiles'; Name = 'Endpoint Security - EDR' },
        @{ Key = 'AttackSurfaceProfiles'; Name = 'Endpoint Security - ASR' },
        @{ Key = 'AccountProtectionProfiles'; Name = 'Endpoint Security - Account Protection' }
    )

    # Recalculate summary stats for all defined categories in $policies
    foreach ($category in $categories | Where-Object { $_.Key -ne 'all' }) {
        if ($policies.ContainsKey($category.Key)) {
            $items = $policies[$category.Key]
            if ($null -ne $items) { 
                $summaryStats.TotalPolicies += $items.Count
                $summaryStats.AllUsers += ($items | Where-Object { $_.AssignmentType -eq "All Users" }).Count
                $summaryStats.AllDevices += ($items | Where-Object { $_.AssignmentType -eq "All Devices" }).Count
                $summaryStats.GroupAssigned += ($items | Where-Object { $_.AssignmentType -eq "Group" }).Count
                $summaryStats.Unassigned += ($items | Where-Object { $_.AssignmentType -eq "None" }).Count
            }
        }
    }
    
    # Build dynamic tab headers and tab content
    $tabHeaders = ""
    $tabContent = ""

    foreach ($category in $categories) {
        $isActive = ($category -eq $categories[0])
        $categoryId = $category.Key.ToLower()

        $tabHeaders += @"
<li class='nav-item' role='presentation'>
    <button class='nav-link$(if($isActive -and $category.Key -ne 'all'){ ' active' } else { '' })'
            id='$categoryId-tab'
            data-bs-toggle='tab'
            data-bs-target='#$categoryId'
            type='button'
            role='tab'
            aria-controls='$categoryId'
            aria-selected='$(if($isActive -and $category.Key -ne 'all'){ 'true' } else { 'false' })'>
        $($category.Name)
    </button>
</li>
"@

        if ($category.Key -eq 'all') {
            $allTableRows = foreach ($cat in $categories | Where-Object { $_.Key -ne 'all' }) {
                if ($policies.ContainsKey($cat.Key)) {
                    # Ensure category exists in policies
                    $categoryPolicies = $policies[$cat.Key]
                    if ($categoryPolicies) {
                        foreach ($p in $categoryPolicies) {
                            $badgeClass = switch ($p.AssignmentType) {
                                'All Users' { 'badge-all-users' }
                                'All Devices' { 'badge-all-devices' }
                                'Group' { 'badge-group' }
                                'Exclude' { 'badge-exclude' }
                                default { 'badge-none' }
                            }
                            "<tr>
                                <td>$($p.Name)</td>
                                <td><span class='badge $badgeClass'>$($p.AssignmentType)</span></td>
                                <td>$($p.AssignedTo)</td>
                            </tr>"
                        }
                    }
                }
            }
            $tabContent += @"
<div class='tab-pane fade$(if($isActive){ ' show active' } else { '' })'
     id='$categoryId'
     role='tabpanel'
     aria-labelledby='$categoryId-tab'>
    <div class='table-container'>
        <table class='table table-striped policy-table'>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Assignment Type</th>
                    <th>Assigned To</th>
                </tr>
            </thead>
            <tbody>
                $($allTableRows -join "`n")
            </tbody>
        </table>
    </div>
</div>
"@
        }
        else {
            $tableRows = "" # Initialize to empty string
            if ($policies.ContainsKey($category.Key)) {
                # Check if category exists
                $currentCategoryPolicies = $policies[$category.Key]
                if ($currentCategoryPolicies) {
                    # Check if there are policies for this category
                    $tableRows = foreach ($p in $currentCategoryPolicies) {
                        $badgeClass = switch ($p.AssignmentType) {
                            'All Users' { 'badge-all-users' }
                            'All Devices' { 'badge-all-devices' }
                            'Group' { 'badge-group' }
                            'Exclude' { 'badge-exclude' }
                            default { 'badge-none' }
                        }
                        "<tr>
                            <td>$($p.Name)</td>
                            <td><span class='badge $badgeClass'>$($p.AssignmentType)</span></td>
                            <td>$($p.AssignedTo)</td>
                        </tr>"
                    }
                }
            }
            $tabContent += @"
<div class='tab-pane fade$(if($isActive -and $category.Key -ne 'all'){ ' show active' } else { '' })'
     id='$categoryId'
     role='tabpanel'
     aria-labelledby='$categoryId-tab'>
    <div class='table-container'>
        <table class='table table-striped policy-table'>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Assignment Type</th>
                    <th>Assigned To</th>
                </tr>
            </thead>
            <tbody>
                $($tableRows -join "`n")
            </tbody>
        </table>
    </div>
</div>
"@
        }
    }

    # Summary cards
    $summaryCards = @"
<div class='col'>
    <div class='card text-center summary-card'>
        <div class='card-body'>
            <i class='fas fa-layer-group mb-3' style='font-size:2rem;color:#0d6efd;'></i>
            <h5 class='card-title'>Total Policies</h5>
            <h3 class='card-text'>$($summaryStats.TotalPolicies)</h3>
            <p class='text-muted small'>Total configured policies</p>
        </div>
    </div>
</div>
<div class='col'>
    <div class='card text-center summary-card'>
        <div class='card-body'>
            <i class='fas fa-users mb-3' style='font-size:2rem;color:#28a745;'></i>
            <h5 class='card-title'>All Users</h5>
            <h3 class='card-text'>$($summaryStats.AllUsers)</h3>
            <p class='text-muted small'>Assigned to all users</p>
        </div>
    </div>
</div>
<div class='col'>
    <div class='card text-center summary-card'>
        <div class='card-body'>
            <i class='fas fa-laptop mb-3' style='font-size:2rem;color:#17a2b8;'></i>
            <h5 class='card-title'>All Devices</h5>
            <h3 class='card-text'>$($summaryStats.AllDevices)</h3>
            <p class='text-muted small'>Assigned to all devices</p>
        </div>
    </div>
</div>
<div class='col'>
    <div class='card text-center summary-card'>
        <div class='card-body'>
            <i class='fas fa-object-group mb-3' style='font-size:2rem;color:#ffc107;'></i>
            <h5 class='card-title'>Group Assigned</h5>
            <h3 class='card-text'>$($summaryStats.GroupAssigned)</h3>
            <p class='text-muted small'>Assigned to specific groups</p>
        </div>
    </div>
</div>
<div class='col'>
    <div class='card text-center summary-card'>
        <div class='card-body'>
            <i class='fas fa-exclamation-triangle mb-3' style='font-size:2rem;color:#dc3545;'></i>
            <h5 class='card-title'>Unassigned</h5>
            <h3 class='card-text'>$($summaryStats.Unassigned)</h3>
            <p class='text-muted small'>Not assigned to any target</p>
        </div>
    </div>
</div>
"@

    # Insert chart container + Chart.js script
    $chartBlock = @"
<div class='row'>
    <div class='col-md-6'>
        <div class='chart-container'>
            <canvas id='policyDistributionChart'></canvas>
        </div>
    </div>
    <div class='col-md-6'>
        <div class='chart-container'>
            <canvas id='policyTypesChart'></canvas>
        </div>
    </div>
</div>
<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
<script>
    // Policy Distribution Pie Chart
    var ctx1 = document.getElementById('policyDistributionChart').getContext('2d');
    var policyDistributionChart = new Chart(ctx1, {
        type: 'pie',
        data: {
            labels: ['All Users', 'All Devices', 'Group Assigned', 'Unassigned'],
            datasets: [{
                data: [$($summaryStats.AllUsers), $($summaryStats.AllDevices), $($summaryStats.GroupAssigned), $($summaryStats.Unassigned)],
                backgroundColor: ['#28a745', '#17a2b8', '#ffc107', '#dc3545'],
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { font: { size: 10 } }
                },
                title: {
                    display: true,
                    text: 'Policy Assignment Distribution',
                    font: { size: 14 }
                }
            }
        }
    });

    // Policy Types Bar Chart
    var ctx2 = document.getElementById('policyTypesChart').getContext('2d');
    var policyTypesChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: ['Device Configs', 'Settings Catalog', 'Admin Templates', 'Compliance', 'App Protection', 'Autopilot Profiles', 'ESP Profiles', 'Windows 365 Provisioning', 'Windows 365 User Settings', 'Scripts', 'Antivirus', 'Disk Encryption', 'Firewall', 'EDR', 'ASR', 'Account Protection'],
            datasets: [{
                label: 'Number of Policies',
                data: [
                    $($policies.DeviceConfigs.Count),
                    $($policies.SettingsCatalog.Count),
                    $($policies.AdminTemplates.Count),
                    $($policies.CompliancePolicies.Count),
                    $($policies.AppProtectionPolicies.Count),
                    $($policies.DeploymentProfiles.Count),
                    $($policies.ESPProfiles.Count),
                    $($policies.CloudPCProvisioningPolicies.Count),
                    $($policies.CloudPCUserSettings.Count),
                    ($($policies.PlatformScripts.Count) + $($policies.HealthScripts.Count)),
                    $($policies.AntivirusProfiles.Count),
                    $($policies.DiskEncryptionProfiles.Count),
                    $($policies.FirewallProfiles.Count),
                    $($policies.EndpointDetectionProfiles.Count),
                    $($policies.AttackSurfaceProfiles.Count),
                    $($policies.AccountProtectionProfiles.Count)
                ],
                backgroundColor: [
                    '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#6f42c1', '#20c997',
                    '#17a2b8', '#fd7e14', '#858796', '#5a5c69', '#f8f9fc', '#dddfeb', '#d1d3e2', '#b4b6c2', '#6610f2'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Policy Types Distribution',
                    font: { size: 14 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { font: { size: 10 } }
                },
                x: {
                    ticks: { font: { size: 10 } }
                }
            }
        }
    });
</script>
"@

    # Final HTML
    $htmlContent = $htmlTemplate `
        -replace '<!-- Tab headers will be inserted here -->', $tabHeaders `
        -replace '<!-- Tab content will be inserted here -->', $tabContent `
        -replace '<!-- Summary stats will be inserted here -->', $summaryCards `
        -replace '<!-- Policy overview chart placeholder -->', $chartBlock

    # Output file
    $htmlContent | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "HTML report exported to: $FilePath" -ForegroundColor Green
}

