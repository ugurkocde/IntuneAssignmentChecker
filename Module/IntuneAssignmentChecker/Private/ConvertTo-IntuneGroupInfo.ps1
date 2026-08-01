function ConvertTo-IntuneGroupInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Group
    )

    process {
        $groupTypes = @($Group.groupTypes)
        $isMicrosoft365 = $groupTypes -contains 'Unified'
        $isDynamic = $groupTypes -contains 'DynamicMembership'
        $mailEnabled = $Group.mailEnabled -eq $true
        $securityEnabled = $Group.securityEnabled -eq $true

        # Microsoft Graph documents groupTypes, mailEnabled, and
        # securityEnabled as the canonical group-type discriminators.
        $groupType = if ($isMicrosoft365) {
            'Microsoft 365'
        }
        elseif ($mailEnabled -and $securityEnabled) {
            'Mail-enabled Security'
        }
        elseif ($securityEnabled) {
            'Security'
        }
        elseif ($mailEnabled) {
            'Distribution'
        }
        else {
            'Unknown'
        }

        [PSCustomObject]@{
            Id                = $Group.id
            DisplayName       = $Group.displayName
            GroupType         = $groupType
            MembershipType    = if ($isDynamic) { 'Dynamic' } else { 'Assigned' }
            IsMicrosoft365    = $isMicrosoft365
            Mail              = $Group.mail
            GroupTypes        = $groupTypes
            MailEnabled       = $mailEnabled
            SecurityEnabled   = $securityEnabled
            Success           = -not [string]::IsNullOrWhiteSpace([string]$Group.id)
        }
    }
}
