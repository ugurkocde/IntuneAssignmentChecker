#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker'

    function Invoke-MgGraphRequest {
        param([string]$Uri, [string]$Method, [object]$Body, [string]$ErrorAction)
        $null = $Uri
        $null = $Method
        $null = $Body
        $null = $ErrorAction
    }
    function Connect-IntuneAssignmentChecker { param() }
    function Get-MgContext { param([string]$ErrorAction) $null = $ErrorAction; [PSCustomObject]@{ TenantId = 'test' } }

    . (Join-Path $moduleRoot 'Private/Invoke-IACGraphRequest.ps1')
    . (Join-Path $moduleRoot 'Private/ConvertTo-IACCsvSafeValue.ps1')
    . (Join-Path $moduleRoot 'Private/DeepSettingSearch.ps1')
    . (Join-Path $moduleRoot 'Private/Show-Menu.ps1')
    . (Join-Path $moduleRoot 'Public/Search-IntuneSetting.ps1')
    . (Join-Path $moduleRoot 'Public/Search-IntuneSettingDeep.ps1')
    . (Join-Path $moduleRoot 'Public/Invoke-IntuneAssignmentChecker.ps1')

    $script:ApiBase = 'https://graph.test/beta/deviceManagement'
    $script:CatalogList = "$script:ApiBase/configurationPolicies"
    $script:ProfileList = "$script:ApiBase/deviceConfigurations"
    $script:TemplateList = "$script:ApiBase/groupPolicyConfigurations"
    $script:ComplianceList = "$script:ApiBase/deviceCompliancePolicies"
    $script:AuditDefinition = 'device_vendor_msft_policy_config_audit_accountmanagement_auditgroupmembership'
    $script:SettingsExpand = '?$expand=settingDefinitions'

    function ConvertTo-TestBase64 {
        param([string]$Text, [System.Text.Encoding]$Encoding = [System.Text.UTF8Encoding]::new($false))
        $preamble = $Encoding.GetPreamble()
        return [Convert]::ToBase64String([byte[]]($preamble + $Encoding.GetBytes($Text)))
    }

    function New-ChoiceSetting {
        param([string]$DefinitionId, [string]$Value, [object[]]$Children = @())
        return @{
            id              = '0'
            settingInstance = @{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $DefinitionId
                choiceSettingValue  = @{ value = $Value; children = $Children }
            }
        }
    }

    function New-SimpleSetting {
        param([string]$DefinitionId, [object]$Value, [string]$ValueType = 'deviceManagementConfigurationStringSettingValue')
        return @{
            id              = '0'
            settingInstance = @{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = $DefinitionId
                simpleSettingValue  = @{ '@odata.type' = "#microsoft.graph.$ValueType"; value = $Value }
            }
        }
    }

    function Set-CatalogPolicy {
        param([string]$Id = 'catalog-1', [string]$Name = 'Catalog Policy', [object[]]$Settings = @())
        $script:GraphRoutes[$script:CatalogList] = @{ value = @(@{ id = $Id; name = $Name }) }
        $script:GraphRoutes["$script:CatalogList/$Id/settings$script:SettingsExpand"] = @{ value = $Settings }
    }

    function Set-ProfilePolicy {
        param([string]$Id = 'profile-1', [string]$Name = 'Profile Policy', [hashtable]$Detail = @{})
        $Detail['id'] = $Id
        $Detail['displayName'] = $Name
        $script:GraphRoutes[$script:ProfileList] = @{ value = @(@{ id = $Id; displayName = $Name }) }
        $script:GraphRoutes["$script:ProfileList/$Id"] = $Detail
    }

    function New-GraphFailure {
        param([int]$Status)
        return [System.Net.Http.HttpRequestException]::new("HTTP $Status simulated failure")
    }
}

Describe 'Search-IntuneSettingDeep' {
    BeforeEach {
        $script:GraphEndpoint = 'https://graph.test'
        $script:GraphRoutes = @{}
        $script:GraphCalls = [System.Collections.Generic.List[string]]::new()

        Mock Write-Host {}
        Mock Out-Host {}
        Mock Start-Sleep {}
        Mock Get-IACSettingDefinitionLookup {
            $lookup = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
            $lookup[$script:AuditDefinition] = 'Audit Group Membership'
            return $lookup
        }
        Mock Invoke-MgGraphRequest {
            $script:GraphCalls.Add("$Method $Uri")
            if ($script:GraphRoutes.ContainsKey($Uri)) {
                $route = $script:GraphRoutes[$Uri]
                if ($route -is [scriptblock]) { return & $route }
                return $route
            }
            return @{ value = @() }
        }
    }

    Context 'Pagination' {
        It 'follows nextLink for policy lists and per-policy settings' {
            $script:GraphRoutes[$script:CatalogList] = @{
                value             = @(@{ id = 'p1'; name = 'First' })
                '@odata.nextLink' = "$script:CatalogList`?`$skiptoken=2"
            }
            $script:GraphRoutes["$script:CatalogList`?`$skiptoken=2"] = @{ value = @(@{ id = 'p2'; name = 'Second' }) }
            $script:GraphRoutes["$script:CatalogList/p1/settings$script:SettingsExpand"] = @{
                value             = @(New-SimpleSetting -DefinitionId 'needle_one' -Value 'a')
                '@odata.nextLink' = "$script:CatalogList/p1/settings?`$skiptoken=2"
            }
            $script:GraphRoutes["$script:CatalogList/p1/settings?`$skiptoken=2"] = @{
                value = @(New-SimpleSetting -DefinitionId 'needle_two' -Value 'b')
            }
            $script:GraphRoutes["$script:CatalogList/p2/settings$script:SettingsExpand"] = @{
                value = @(New-SimpleSetting -DefinitionId 'needle_three' -Value 'c')
            }

            $rows = @(Search-IntuneSettingDeep -Keyword needle -PassThru)

            @($rows.SettingDefinitionId | Sort-Object) | Should -Be @('needle_one', 'needle_three', 'needle_two')
            @($rows | Where-Object PolicyName -eq 'Second').Count | Should -Be 1
        }

        It 'reports a nextLink outside the active endpoint instead of following it' {
            $script:GraphRoutes[$script:CatalogList] = @{
                value             = @(@{ id = 'p1'; name = 'First' })
                '@odata.nextLink' = 'https://attacker.test/beta/deviceManagement/configurationPolicies'
            }

            $null = Search-IntuneSettingDeep -Keyword needle -PassThru -WarningVariable warnings -WarningAction SilentlyContinue

            $script:GraphCalls | Should -Not -Contain 'GET https://attacker.test/beta/deviceManagement/configurationPolicies'
            ($warnings -join ' ') | Should -Match 'NOT conclusive'
        }

        It 'issues only GET requests' {
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId $script:AuditDefinition -Value "${script:AuditDefinition}_1")

            $null = Search-IntuneSettingDeep -Keyword audit -PassThru -WarningAction SilentlyContinue

            $script:GraphCalls.Count | Should -BeGreaterThan 0
            @($script:GraphCalls | Where-Object { $_ -notmatch '^GET ' }) | Should -BeNullOrEmpty
        }
    }

    Context 'Friendly setting names' {
        It 'finds one row per instance by friendly name or normalized ID' {
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId $script:AuditDefinition -Value "${script:AuditDefinition}_1")
            $script:GraphRoutes["$script:ApiBase/configurationSettings/$script:AuditDefinition"] = @{
                options = @(@{ itemId = "${script:AuditDefinition}_1"; displayName = 'Success' })
            }

            foreach ($keyword in 'Audit Group Membership', 'auditgroupmembership') {
                $rows = @(Search-IntuneSettingDeep -Keyword $keyword -PassThru)
                $rows.Count | Should -Be 1
                $rows[0].SettingName | Should -BeExactly 'Audit Group Membership'
                $rows[0].MatchedValue | Should -BeExactly 'Success'
            }
        }

        It 'falls back to the raw ID when no friendly name is known' {
            Set-CatalogPolicy -Settings @(New-SimpleSetting -DefinitionId 'vendor_unknown_setting' -Value 'x')

            $rows = @(Search-IntuneSettingDeep -Keyword unknown_setting -PassThru)

            $rows[0].SettingName | Should -BeExactly 'vendor_unknown_setting'
        }

        It 'finds Settings Catalog children nested below a choice' {
            $child = (New-SimpleSetting -DefinitionId 'parent_child_needle' -Value 'nested').settingInstance
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'parent_setting' -Value 'parent_setting_1' -Children @($child))

            $rows = @(Search-IntuneSettingDeep -Keyword child_needle -PassThru -WarningAction SilentlyContinue)

            $rows.Count | Should -Be 1
            $rows[0].MatchedValue | Should -BeExactly 'nested'
        }

        It 'searches Administrative Template names from the expanded definition' {
            $script:GraphRoutes[$script:TemplateList] = @{ value = @(@{ id = 'gp1'; displayName = 'Edge Template' }) }
            $script:GraphRoutes["$script:TemplateList/gp1/definitionValues?`$expand=definition"] = @{
                value = @(@{
                        id = 'value-1'; enabled = $false
                        definition = @{ id = 'def-1'; displayName = 'Block third party cookies'; categoryPath = '\Edge\Privacy' }
                    })
            }

            $rows = @(Search-IntuneSettingDeep -Keyword 'third party cookies' -PassThru)

            $rows.Count | Should -Be 1
            $rows[0].SettingName | Should -BeExactly 'Block third party cookies'
            $rows[0].MatchedValue | Should -BeExactly 'Disabled'
        }

        It 'matches the configured state of an Administrative Template setting' {
            $script:GraphRoutes[$script:TemplateList] = @{ value = @(@{ id = 'gp1'; displayName = 'Edge Template' }) }
            $script:GraphRoutes["$script:TemplateList/gp1/definitionValues?`$expand=definition"] = @{
                value = @(
                    @{ id = 'value-1'; enabled = $false; definition = @{ id = 'def-1'; displayName = 'Block third party cookies'; categoryPath = '\Edge' } }
                    @{ id = 'value-2'; definition = @{ id = 'def-2'; displayName = 'State not returned'; categoryPath = '\Edge' } }
                )
            }

            $rows = @(Search-IntuneSettingDeep -Keyword Disabled -PassThru)

            $rows.Count | Should -Be 1
            $rows[0].SettingDefinitionId | Should -BeExactly 'def-1'
            @(Search-IntuneSettingDeep -Keyword Unknown -PassThru) | Should -BeNullOrEmpty
        }
    }

    Context 'Choice value resolution' {
        It 'uses option name when displayName is absent' {
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'needle_choice' -Value 'needle_choice_1')
            $script:GraphRoutes["$script:ApiBase/configurationSettings/needle_choice"] = @{
                options = @(@{ itemId = 'needle_choice_1'; name = 'Enabled by name' })
            }

            $row = @(Search-IntuneSettingDeep -Keyword needle_choice -PassThru)[0]

            $row.MatchedValue | Should -BeExactly 'Enabled by name'
            $row.RawValue | Should -BeExactly 'needle_choice_1'
        }

        It 'requests each definition once per search' {
            Set-CatalogPolicy -Settings @(
                New-ChoiceSetting -DefinitionId 'needle_choice' -Value 'needle_choice_1'
                New-ChoiceSetting -DefinitionId 'needle_choice' -Value 'needle_choice_0'
            )
            $script:GraphRoutes["$script:ApiBase/configurationSettings/needle_choice"] = @{
                options = @(
                    @{ itemId = 'needle_choice_1'; displayName = 'On' }
                    @{ itemId = 'needle_choice_0'; displayName = 'Off' }
                )
            }

            $rows = @(Search-IntuneSettingDeep -Keyword needle_choice -PassThru)

            @($rows.MatchedValue | Sort-Object) | Should -Be @('Off', 'On')
            @($script:GraphCalls | Where-Object { $_ -like '*configurationSettings/needle_choice' }).Count | Should -Be 1
        }

        It 'resolves every value in a choice collection' {
            $collection = @{
                id              = '0'
                settingInstance = @{
                    settingDefinitionId          = 'needle_collection'
                    choiceSettingCollectionValue = @(@{ value = 'needle_collection_a' }, @{ value = 'needle_collection_b' })
                }
            }
            Set-CatalogPolicy -Settings @($collection)
            $script:GraphRoutes["$script:ApiBase/configurationSettings/needle_collection"] = @{
                options = @(
                    @{ itemId = 'needle_collection_a'; displayName = 'Alpha' }
                    @{ itemId = 'needle_collection_b'; displayName = 'Beta' }
                )
            }

            $row = @(Search-IntuneSettingDeep -Keyword needle_collection -PassThru)[0]

            $row.MatchedValue | Should -BeExactly 'Alpha; Beta'
        }

        It 'keeps the raw choice ID and does not infer a label when metadata lookup fails' {
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'needle_choice' -Value 'needle_choice_1')
            $script:GraphRoutes["$script:ApiBase/configurationSettings/needle_choice"] = { throw (New-GraphFailure -Status 404) }

            $row = @(Search-IntuneSettingDeep -Keyword needle_choice -PassThru -WarningVariable warnings -WarningAction SilentlyContinue)[0]

            $row.MatchedValue | Should -BeExactly 'needle_choice_1'
            ($warnings -join ' ') | Should -Match 'choice label lookup'
        }

        It 'keeps the raw choice ID when the option is missing from metadata' {
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'needle_choice' -Value 'needle_choice_9')
            $script:GraphRoutes["$script:ApiBase/configurationSettings/needle_choice"] = @{
                options = @(@{ itemId = 'needle_choice_1'; displayName = 'On' })
            }

            $row = @(Search-IntuneSettingDeep -Keyword needle_choice -PassThru -WarningAction SilentlyContinue)[0]

            $row.MatchedValue | Should -BeExactly 'needle_choice_9'
        }

        Context 'Searching by label' {
            BeforeEach {
                $script:AuditSetting = New-ChoiceSetting -DefinitionId $script:AuditDefinition -Value "$($script:AuditDefinition)_1"
                $script:AuditSetting['settingDefinitions'] = @(@{
                        id      = $script:AuditDefinition
                        options = @(
                            @{ itemId = "$($script:AuditDefinition)_0"; displayName = 'No Auditing' }
                            @{ itemId = "$($script:AuditDefinition)_1"; displayName = 'Success' }
                        )
                    })
            }

            It 'matches the label of the selected option without extra Graph requests' {
                Set-CatalogPolicy -Settings @($script:AuditSetting)

                $rows = @(Search-IntuneSettingDeep -Keyword Success -PassThru)

                $rows.Count | Should -Be 1
                $rows[0].MatchedValue | Should -BeExactly 'Success'
                @($script:GraphCalls | Where-Object { $_ -like '*configurationSettings*' }).Count | Should -Be 0
            }

            It 'does not match labels of options the policy did not select' {
                Set-CatalogPolicy -Settings @($script:AuditSetting)

                @(Search-IntuneSettingDeep -Keyword 'No Auditing' -PassThru) | Should -BeNullOrEmpty
            }

            It 'falls back to a definition request when Graph returns no expanded definitions' {
                Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'vendor_choice' -Value 'vendor_choice_1')
                $script:GraphRoutes["$script:ApiBase/configurationSettings/vendor_choice"] = @{
                    options = @(@{ itemId = 'vendor_choice_1'; displayName = 'Block downloads' })
                }

                $rows = @(Search-IntuneSettingDeep -Keyword 'Block downloads' -PassThru)

                $rows.Count | Should -Be 1
                @($script:GraphCalls | Where-Object { $_ -like '*configurationSettings/vendor_choice' }).Count | Should -Be 1
            }

            It 'does not treat expanded definition metadata as configured settings' {
                $script:AuditSetting['settingDefinitions'][0]['referredSettingInformationList'] = @(@{ settingDefinitionId = 'needle_phantom' })
                Set-CatalogPolicy -Settings @($script:AuditSetting)

                @(Search-IntuneSettingDeep -Keyword needle_phantom -PassThru) | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Base64 XML and plist decoding' {
        It 'decodes a complete plist with an Apple DOCTYPE' {
            $plist = @'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>PayloadContent</key><array><dict><key>MicrosoftEntraSSO</key><true/></dict></array></dict></plist>
'@
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }

            $rows = @(Search-IntuneSettingDeep -Keyword MicrosoftEntraSSO -PassThru)

            $rows.Count | Should -Be 1
            $rows[0].SettingName | Should -BeExactly 'MicrosoftEntraSSO'
            $rows[0].MatchedValue | Should -BeExactly 'true'
            $rows[0].SettingPath | Should -BeExactly 'payload.PayloadContent[0].MicrosoftEntraSSO'
        }

        It 'decodes a plist fragment with several top-level elements' {
            $fragment = '<key>First</key><string>one</string><key>NeedleSetting</key><false/>'
            Set-ProfilePolicy -Detail @{ configurationXml = (ConvertTo-TestBase64 -Text $fragment) }

            $row = @(Search-IntuneSettingDeep -Keyword NeedleSetting -PassThru)[0]

            $row.MatchedValue | Should -BeExactly 'false'
        }

        It 'accepts whitespace before the XML declaration' {
            $xml = "`r`n  <?xml version=`"1.0`"?><plist><dict><key>NeedleSetting</key><string>value</string></dict></plist>"
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }

            @(Search-IntuneSettingDeep -Keyword NeedleSetting -PassThru).Count | Should -Be 1
        }

        It 'decodes UTF-16 payloads that carry a byte order mark' {
            $xml = '<plist><dict><key>NeedleSetting</key><string>value</string></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml -Encoding ([System.Text.UnicodeEncoding]::new($false, $true))) }

            @(Search-IntuneSettingDeep -Keyword NeedleSetting -PassThru).Count | Should -Be 1
        }

        It 'searches non-plist XML elements' {
            $xml = '<configuration><browser><homepage>https://intranet.contoso.test</homepage></browser></configuration>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }

            $row = @(Search-IntuneSettingDeep -Keyword intranet -PassThru)[0]

            $row.SettingPath | Should -BeExactly 'payload.configuration.browser.homepage'
        }

        It 'does not read ordinary XML as a plist because it contains a key element' {
            $xml = '<portal><key>region</key><homepage>https://intranet.contoso.test</homepage></portal>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }

            $row = @(Search-IntuneSettingDeep -Keyword homepage -PassThru)[0]

            $row.SettingPath | Should -BeExactly 'payload.portal.homepage'
            $row.MatchedValue | Should -BeExactly 'https://intranet.contoso.test'
        }

        It 'is not confused by elements named after .NET XML members' {
            $xml = '<config><InnerText>needle-value</InnerText><LocalName>other</LocalName></config>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }

            $row = @(Search-IntuneSettingDeep -Keyword needle-value -PassThru)[0]

            $row.SettingName | Should -BeExactly 'InnerText'
            $row.MatchedValue | Should -BeExactly 'needle-value'
        }

        It 'does not return the encoded payload through generic traversal' {
            $encoded = ConvertTo-TestBase64 -Text '<plist><dict><key>Other</key><string>x</string></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = $encoded }

            $rows = @(Search-IntuneSettingDeep -Keyword $encoded.Substring(0, 12) -PassThru)

            $rows | Should -BeNullOrEmpty
        }
    }

    Context 'XML entity safety' {
        It 'does not resolve an external entity' {
            $target = Join-Path $TestDrive 'external.txt'
            Set-Content -LiteralPath $target -Value 'EXTERNAL-MARKER'
            $targetUri = ([uri]$target).AbsoluteUri
            $xml = "<?xml version=`"1.0`"?><!DOCTYPE plist [<!ENTITY xxe SYSTEM `"$targetUri`">]><plist><dict><key>Leak</key><string>&xxe;</string></dict></plist>"
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }
            $export = Join-Path $TestDrive 'xxe.csv'

            $rows = @(Search-IntuneSettingDeep -Keyword Leak -PassThru -ExportPath $export -WarningAction SilentlyContinue)

            $rows | Should -BeNullOrEmpty
            Get-Content -LiteralPath ([IO.Path]::ChangeExtension($export, '.errors.csv')) -Raw |
                Should -Not -Match 'EXTERNAL-MARKER'
        }

        It 'does not load an external DTD or its entities' {
            $dtd = Join-Path $TestDrive 'external.dtd'
            Set-Content -LiteralPath $dtd -Value '<!ENTITY fromDtd "EXTERNAL-MARKER">'
            $dtdUri = ([uri]$dtd).AbsoluteUri
            $xml = "<!DOCTYPE plist SYSTEM `"$dtdUri`"><plist><dict><key>Leak</key><string>&fromDtd;</string></dict></plist>"

            { ConvertTo-IACSafeXmlDocument -Xml $xml } | Should -Throw '*malformed or uses a prohibited DTD*'
        }

        It 'rejects entity expansion attacks' {
            $xml = '<!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><lolz>&b;</lolz>'

            { ConvertTo-IACSafeXmlDocument -Xml $xml } | Should -Throw '*malformed or uses a prohibited DTD*'
        }

        It 'rejects a DOCTYPE placed after the prolog' {
            { ConvertTo-IACSafeXmlDocument -Xml '<a/><!DOCTYPE b [<!ENTITY c "d">]>' } | Should -Throw
        }
    }

    Context 'Sensitive values' {
        It 'neither matches nor returns a Settings Catalog secret value' {
            Set-CatalogPolicy -Settings @(
                New-SimpleSetting -DefinitionId 'vendor_wifi_profile_value' -Value 'CorrectHorse' -ValueType 'deviceManagementConfigurationSecretSettingValue'
            )

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
            $row = @(Search-IntuneSettingDeep -Keyword vendor_wifi -PassThru)[0]
            $row.MatchedValue | Should -BeExactly '[REDACTED]'
            $row.RawValue | Should -BeExactly '[REDACTED]'
        }

        It 'redacts children of a sensitive Settings Catalog parent' {
            $child = (New-SimpleSetting -DefinitionId 'vendor_child_value' -Value 'CorrectHorse').settingInstance
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'vendor_credential_group' -Value 'vendor_credential_group_1' -Children @($child))

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru -WarningAction SilentlyContinue) | Should -BeNullOrEmpty
            (@(Search-IntuneSettingDeep -Keyword vendor_child -PassThru -WarningAction SilentlyContinue)[0]).MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'shows number and choice values of Settings Catalog settings with sensitive names' {
            $lengthId = 'device_vendor_msft_policy_config_devicelock_minimumpasswordlength'
            $complexId = 'device_vendor_msft_policy_config_devicelock_alphanumericdevicepasswordrequired'
            Set-CatalogPolicy -Settings @(
                New-SimpleSetting -DefinitionId $lengthId -Value 14 -ValueType 'deviceManagementConfigurationIntegerSettingValue'
                New-ChoiceSetting -DefinitionId $complexId -Value "${complexId}_1"
            )
            $script:GraphRoutes["$script:ApiBase/configurationSettings/$complexId"] = @{
                options = @(@{ itemId = "${complexId}_1"; displayName = 'Alphanumeric required' })
            }

            $rows = @(Search-IntuneSettingDeep -Keyword password -PassThru)

            ($rows | Where-Object SettingDefinitionId -eq $lengthId).MatchedValue | Should -BeExactly '14'
            ($rows | Where-Object SettingDefinitionId -eq $complexId).MatchedValue | Should -BeExactly 'Alphanumeric required'
        }

        It 'hides a Settings Catalog text value when only the friendly name looks sensitive' {
            Mock Get-IACSettingDefinitionLookup {
                $lookup = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
                $lookup['vendor_logon_notification_text'] = 'Password sent in logon notification'
                return $lookup
            }
            Set-CatalogPolicy -Settings @(New-SimpleSetting -DefinitionId 'vendor_logon_notification_text' -Value 'CorrectHorse')

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
            (@(Search-IntuneSettingDeep -Keyword 'logon notification' -PassThru)[0]).MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'passes sensitivity from a parent friendly name to its children' {
            Mock Get-IACSettingDefinitionLookup {
                $lookup = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
                $lookup['vendor_service_group'] = 'Service credentials'
                return $lookup
            }
            $child = (New-SimpleSetting -DefinitionId 'vendor_service_child' -Value 'CorrectHorse').settingInstance
            Set-CatalogPolicy -Settings @(New-ChoiceSetting -DefinitionId 'vendor_service_group' -Value 'vendor_service_group_1' -Children @($child))

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru -WarningAction SilentlyContinue) | Should -BeNullOrEmpty
            (@(Search-IntuneSettingDeep -Keyword vendor_service_child -PassThru -WarningAction SilentlyContinue)[0]).MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'shows true/false and number policy properties with sensitive names but hides text' {
            Set-ProfilePolicy -Detail @{ passwordRequired = $true; passwordMinimumLength = 8; passwordRequiredType = 'alphanumeric' }

            $rows = @(Search-IntuneSettingDeep -Keyword password -PassThru)

            ($rows | Where-Object SettingName -eq 'passwordRequired').MatchedValue | Should -BeExactly 'True'
            ($rows | Where-Object SettingName -eq 'passwordMinimumLength').MatchedValue | Should -BeExactly '8'
            ($rows | Where-Object SettingName -eq 'passwordRequiredType').MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'hides a number but shows true/false in an OMA-URI setting with a sensitive label' {
            Set-ProfilePolicy -Detail @{
                omaSettings = @(
                    @{ '@odata.type' = '#microsoft.graph.omaSettingInteger'; displayName = 'Kiosk admin password'; omaUri = './Vendor/Kiosk/Pin'; value = 4321 }
                    @{ '@odata.type' = '#microsoft.graph.omaSettingBoolean'; displayName = 'Require password'; omaUri = './Vendor/Kiosk/Require'; value = $true }
                )
            }

            @(Search-IntuneSettingDeep -Keyword 4321 -PassThru) | Should -BeNullOrEmpty
            $rows = @(Search-IntuneSettingDeep -Keyword value -PassThru)
            ($rows | Where-Object SettingPath -eq 'settings.omaSettings[0].value').MatchedValue | Should -BeExactly '[REDACTED]'
            ($rows | Where-Object SettingPath -eq 'settings.omaSettings[1].value').MatchedValue | Should -BeExactly 'True'
        }

        It 'hides an encrypted OMA-URI value of any type' {
            Set-ProfilePolicy -Detail @{
                omaSettings = @(@{ '@odata.type' = '#microsoft.graph.omaSettingBoolean'; displayName = 'NeedleOma'; isEncrypted = $true; value = $true })
            }

            $row = @(Search-IntuneSettingDeep -Keyword value -PassThru) | Where-Object SettingName -eq 'value'
            $row.MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'shows true/false under a sensitive plist key but hides numbers and text' {
            $plist = '<plist><dict><key>PasswordManagerEnabled</key><true/><key>AdminPassword</key><integer>4321</integer><key>ServicePassword</key><string>CorrectHorse</string></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }

            @(Search-IntuneSettingDeep -Keyword 4321 -PassThru) | Should -BeNullOrEmpty
            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
            $rows = @(Search-IntuneSettingDeep -Keyword password -PassThru)
            ($rows | Where-Object SettingName -eq 'PasswordManagerEnabled').MatchedValue | Should -BeExactly 'true'
            ($rows | Where-Object SettingName -eq 'AdminPassword').MatchedValue | Should -BeExactly '[REDACTED]'
            ($rows | Where-Object SettingName -eq 'ServicePassword').MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'protects an encrypted OMA-URI value' -ForEach @(
            @{ Marker = @{ isEncrypted = $true } }
            @{ Marker = @{ secretReferenceValueId = 'reference-1' } }
            @{ Marker = @{ displayName = 'Service account password' } }
            @{ Marker = @{ omaUri = './Device/Vendor/MSFT/Example/Password' } }
        ) {
            $setting = @{ '@odata.type' = '#microsoft.graph.omaSettingString'; value = 'CorrectHorse' }
            foreach ($key in $Marker.Keys) { $setting[$key] = $Marker[$key] }
            if (-not $setting.ContainsKey('displayName')) { $setting['displayName'] = 'NeedleOma' }
            Set-ProfilePolicy -Detail @{ omaSettings = @($setting) }

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
            $valueRow = @(Search-IntuneSettingDeep -Keyword value -PassThru) | Where-Object SettingName -eq 'value'
            $valueRow.MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'does not expose OMA-URI binary values' {
            Set-ProfilePolicy -Detail @{
                omaSettings = @(@{
                        '@odata.type' = '#microsoft.graph.omaSettingBase64'
                        displayName   = 'Certificate blob'
                        fileName      = 'blob.bin'
                        value         = 'Q29ycmVjdEhvcnNl'
                    })
            }

            @(Search-IntuneSettingDeep -Keyword Q29ycmVjdEhvcnNl -PassThru) | Should -BeNullOrEmpty
        }

        It 'redacts values nested under a sensitive plist key' {
            $plist = '<plist><dict><key>Password</key><dict><key>value</key><string>CorrectHorse</string></dict></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
            $rows = @(Search-IntuneSettingDeep -Keyword Password -PassThru)
            $rows[0].MatchedValue | Should -BeExactly '[REDACTED]'
        }

        It 'redacts a plist value identified by a sibling label' {
            $plist = '<plist><dict><key>Name</key><string>ApiToken</string><key>Value</key><string>CorrectHorse</string></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
        }

        It 'withholds plist binary data' {
            $plist = '<plist><dict><key>NeedleBlob</key><data>Q29ycmVjdEhvcnNl</data></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }

            (@(Search-IntuneSettingDeep -Keyword NeedleBlob -PassThru)[0]).MatchedValue | Should -BeExactly '[binary data withheld]'
        }

        It 'redacts sensitive values in non-plist XML' {
            $xml = '<config><credentials><user>svc</user><secretValue>CorrectHorse</secretValue></credentials></config>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }

            @(Search-IntuneSettingDeep -Keyword CorrectHorse -PassThru) | Should -BeNullOrEmpty
        }

        It 'truncates long non-secret values' {
            Set-ProfilePolicy -Detail @{ customValue = 'needle' + ('x' * 500) }

            $row = @(Search-IntuneSettingDeep -Keyword needle -PassThru)[0]

            $row.MatchedValue.Length | Should -Be 163
            $row.RawValue.Length | Should -Be 163
        }

        It 'neutralizes spreadsheet formulas in CSV exports' {
            Set-CatalogPolicy -Name '=HYPERLINK("https://attacker.test")' -Settings @(New-SimpleSetting -DefinitionId 'needle_setting' -Value '+SUM(1,1)')
            $export = Join-Path $TestDrive 'formula.csv'

            $null = Search-IntuneSettingDeep -Keyword needle_setting -ExportPath $export

            $row = Import-Csv -LiteralPath $export
            $row.PolicyName | Should -BeLike "'=HYPERLINK*"
            $row.MatchedValue | Should -BeExactly "'+SUM(1,1)"
        }

        It 'exports the same columns for every policy family' {
            Set-CatalogPolicy -Settings @(New-SimpleSetting -DefinitionId 'needle_catalog' -Value 'a')
            Set-ProfilePolicy -Detail @{ needleField = 'b' }
            $export = Join-Path $TestDrive 'columns.csv'

            $results = @(Search-IntuneSettingDeep -Keyword needle -ExportPath $export -PassThru)

            # Export-Csv takes its header from the first row, so compare the rows before export.
            $catalogRow = $results | Where-Object PolicyType -like 'Settings Catalog*'
            $profileRow = $results | Where-Object PolicyType -like 'Device configuration*'
            @($profileRow.PSObject.Properties.Name) | Should -Be @($catalogRow.PSObject.Properties.Name)

            $rows = @(Import-Csv -LiteralPath $export)
            $rows.Count | Should -Be 2
            ($rows | Where-Object SettingDefinitionId -eq 'needle_catalog').RawValue | Should -BeExactly 'a'
            ($rows | Where-Object SettingName -eq 'needleField').RawValue | Should -BeExactly 'b'
        }
    }

    Context 'Nesting limit' {
        BeforeEach {
            $script:DeepExport = Join-Path $TestDrive 'deep.csv'
            Remove-Item -LiteralPath $script:DeepExport, ([IO.Path]::ChangeExtension($script:DeepExport, '.errors.csv')) -ErrorAction SilentlyContinue
        }

        It 'reports <Name> nested too deeply and keeps the matches above the limit' -ForEach @(
            @{ Name = 'a policy property'; Location = 'A policy property' }
            @{ Name = 'a plist payload'; Location = 'The decoded payload' }
            @{ Name = 'an XML payload'; Location = 'The decoded payload' }
            @{ Name = 'a Settings Catalog setting'; Location = 'A setting' }
        ) {
            switch ($Name) {
                'a policy property' {
                    $node = @{ needleDeep = 'x' }
                    foreach ($level in 1..45) { $node = @{ child = $node } }
                    Set-ProfilePolicy -Detail @{ needleTop = 'y'; nested = $node }
                }
                'a plist payload' {
                    $plist = '<plist><dict><key>needleTop</key><string>y</string><key>nest</key>' +
                        ('<dict><key>needleDeep</key>' * 45) + '<string>x</string>' + ('</dict>' * 45) + '</dict></plist>'
                    Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $plist) }
                }
                'an XML payload' {
                    $xml = '<config><needleTop>y</needleTop>' + ('<n>' * 45) + '<needleDeep>x</needleDeep>' + ('</n>' * 45) + '</config>'
                    Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }
                }
                'a Settings Catalog setting' {
                    $instance = (New-SimpleSetting -DefinitionId 'needleDeep' -Value 'x').settingInstance
                    foreach ($level in 1..20) {
                        $instance = (New-ChoiceSetting -DefinitionId "group_$level" -Value "group_${level}_1" -Children @($instance)).settingInstance
                    }
                    Set-CatalogPolicy -Settings @(@{ id = '0'; settingInstance = $instance }, (New-SimpleSetting -DefinitionId 'needleTop' -Value 'y'))
                }
            }

            $rows = @(Search-IntuneSettingDeep -Keyword needle -PassThru -ExportPath $script:DeepExport `
                    -WarningVariable warnings -WarningAction SilentlyContinue)

            @($rows | Where-Object { $_.SettingName -eq 'needleTop' -or $_.SettingDefinitionId -eq 'needleTop' }).Count | Should -Be 1
            ($warnings -join ' ') | Should -Match 'NOT conclusive'
            $errors = @(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($script:DeepExport, '.errors.csv')))
            $errors.Count | Should -Be 1
            $errors[0].Error | Should -BeExactly "$Location is nested more than 40 levels deep; deeper settings were not searched."
        }
    }

    Context 'Malformed payloads' {
        It 'reports invalid payload <Name> and continues with other policies' -ForEach @(
            @{ Name = 'Base64'; Payload = 'not-base64!!' }
            @{ Name = 'XML'; Payload = '<plist><dict><key>Broken</dict>' }
            @{ Name = 'binary'; Payload = [Convert]::ToBase64String([byte[]](0x30, 0x82, 0xFF, 0xFE, 0x00, 0xC3)) }
        ) {
            $script:GraphRoutes[$script:ProfileList] = @{
                value = @(@{ id = 'bad'; displayName = 'Bad' }, @{ id = 'good'; displayName = 'Good' })
            }
            $script:GraphRoutes["$script:ProfileList/bad"] = @{ id = 'bad'; displayName = 'Bad'; payload = $Payload }
            $script:GraphRoutes["$script:ProfileList/good"] = @{ id = 'good'; displayName = 'Good'; needleField = 'found' }

            $rows = @(Search-IntuneSettingDeep -Keyword needleField -PassThru -WarningVariable warnings -WarningAction SilentlyContinue)

            $rows.Count | Should -Be 1
            $rows[0].PolicyName | Should -BeExactly 'Good'
            ($warnings -join ' ') | Should -Match 'NOT conclusive'
        }

        It 'does not echo payload content in XML errors' {
            $xml = '<plist><dict><key>Password</key><string>&CorrectHorse;</string></dict></plist>'
            Set-ProfilePolicy -Detail @{ payload = (ConvertTo-TestBase64 -Text $xml) }
            $export = Join-Path $TestDrive 'malformed.csv'

            $null = Search-IntuneSettingDeep -Keyword anything -ExportPath $export -WarningAction SilentlyContinue

            $errorText = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($export, '.errors.csv')) -Raw
            $errorText | Should -Match 'malformed or uses a prohibited DTD'
            $errorText | Should -Not -Match 'CorrectHorse'
        }

        It 'rejects payloads over the size limit' {
            { ConvertFrom-IACConfigurationPayload -Encoded ('<a>' + ('x' * (2MB + 1)) + '</a>') } |
                Should -Throw '*2 MiB*'
            { ConvertFrom-IACConfigurationPayload -Encoded ([byte[]]::new(2MB + 1)) } |
                Should -Throw '*2 MiB*'
        }

        It 'tolerates malformed catalog records' {
            Set-CatalogPolicy -Settings @(
                @{ id = 'no-instance' }
                @{ id = 'empty'; settingInstance = @{} }
                @{ id = 'no-value'; settingInstance = @{ settingDefinitionId = 'needle_no_value' } }
                $null
            )

            $rows = @(Search-IntuneSettingDeep -Keyword needle_no_value -PassThru)

            $rows.Count | Should -Be 1
            $rows[0].MatchedValue | Should -BeExactly '[group or nested setting]'
        }

        It 'skips list entries without an ID' {
            $script:GraphRoutes[$script:CatalogList] = @{ value = @(@{ name = 'No ID' }, $null) }

            @(Search-IntuneSettingDeep -Keyword needle -PassThru -WarningAction SilentlyContinue) | Should -BeNullOrEmpty
            @($script:GraphCalls | Where-Object { $_ -like '*configurationPolicies/*' }) | Should -BeNullOrEmpty
        }
    }

    Context 'Empty results' {
        It 'returns nothing and creates no CSV when nothing matches' {
            Set-CatalogPolicy -Settings @(New-SimpleSetting -DefinitionId 'other_setting' -Value 'other')
            $export = Join-Path $TestDrive 'empty.csv'

            $rows = @(Search-IntuneSettingDeep -Keyword needle -PassThru -ExportPath $export -WarningAction SilentlyContinue)

            $rows | Should -BeNullOrEmpty
            Test-Path -LiteralPath $export | Should -BeFalse
            Should -Invoke Write-Host -ParameterFilter { $Object -eq 'No matching settings found.' }
        }

        It 'distinguishes an empty tenant from a failed scan' {
            $null = Search-IntuneSettingDeep -Keyword needle -PassThru -WarningVariable warnings -WarningAction SilentlyContinue

            ($warnings -join ' ') | Should -Match 'No policies were found'
            ($warnings -join ' ') | Should -Not -Match 'NOT conclusive'
        }

        It 'writes nothing to the pipeline without PassThru' {
            Set-CatalogPolicy -Settings @(New-SimpleSetting -DefinitionId 'needle_setting' -Value 'a')

            @(Search-IntuneSettingDeep -Keyword needle_setting) | Should -BeNullOrEmpty
        }

        It 'rejects a whitespace keyword' {
            { Search-IntuneSettingDeep -Keyword '   ' } | Should -Throw '*blank*'
        }
    }

    Context 'API failures' {
        It 'continues with other families when a list request is forbidden' {
            $script:GraphRoutes[$script:CatalogList] = { throw (New-GraphFailure -Status 403) }
            Set-ProfilePolicy -Detail @{ needleField = 'found' }

            $rows = @(Search-IntuneSettingDeep -Keyword needleField -PassThru -WarningVariable warnings -WarningAction SilentlyContinue)

            $rows.Count | Should -Be 1
            ($warnings -join ' ') | Should -Match 'Could not list Settings Catalog'
            ($warnings -join ' ') | Should -Match 'NOT conclusive'
        }

        It 'continues with other policies when one detail request fails' {
            $script:GraphRoutes[$script:ProfileList] = @{
                value = @(@{ id = 'bad'; displayName = 'Bad' }, @{ id = 'good'; displayName = 'Good' })
            }
            $script:GraphRoutes["$script:ProfileList/bad"] = { throw (New-GraphFailure -Status 400) }
            $script:GraphRoutes["$script:ProfileList/good"] = @{ id = 'good'; displayName = 'Good'; needleField = 'found' }
            $export = Join-Path $TestDrive 'failure.csv'

            $rows = @(Search-IntuneSettingDeep -Keyword needleField -PassThru -ExportPath $export -WarningAction SilentlyContinue)

            $rows.Count | Should -Be 1
            $errors = @(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($export, '.errors.csv')))
            $errors.Count | Should -Be 1
            $errors[0].Policy | Should -BeExactly 'Bad'
        }

        It 'retries a throttled request through the shared Graph transport' {
            $script:ThrottleCount = 0
            $script:GraphRoutes[$script:CatalogList] = {
                $script:ThrottleCount++
                if ($script:ThrottleCount -eq 1) { throw (New-GraphFailure -Status 429) }
                return @{ value = @() }
            }

            $null = Search-IntuneSettingDeep -Keyword needle -PassThru -WarningAction SilentlyContinue

            $script:ThrottleCount | Should -Be 2
            Should -Invoke Start-Sleep -Times 1 -Exactly
        }

        It 'throws when not connected' {
            $script:GraphEndpoint = $null

            { Search-IntuneSettingDeep -Keyword needle } | Should -Throw '*Connect-IntuneAssignmentChecker*'
        }
    }

    Context 'Policy family scope' {
        BeforeEach {
            $script:GraphRoutes[$script:ComplianceList] = @{ value = @(@{ id = 'c1'; displayName = 'Compliance' }) }
            $script:GraphRoutes["$script:ComplianceList/c1"] = @{ id = 'c1'; displayName = 'Compliance'; needleField = 'found' }
        }

        It 'includes compliance policies by default' {
            @(Search-IntuneSettingDeep -Keyword needleField -PassThru).Count | Should -Be 1
        }

        It 'excludes compliance policies on request' {
            @(Search-IntuneSettingDeep -Keyword needleField -IncludeCompliance:$false -PassThru -WarningVariable warnings -WarningAction SilentlyContinue) | Should -BeNullOrEmpty
            $script:GraphCalls | Should -Not -Contain "GET $script:ComplianceList"
            ($warnings -join ' ') | Should -Match 'No policies were found'
        }

        It 'hides policy metadata unless requested' {
            Set-ProfilePolicy -Id 'needle-id' -Detail @{ createdDateTime = 'needle-date'; roleScopeTagIds = @('needle-tag') }

            @(Search-IntuneSettingDeep -Keyword needle- -IncludeCompliance:$false -PassThru) | Should -BeNullOrEmpty
            @(Search-IntuneSettingDeep -Keyword needle- -IncludeCompliance:$false -IncludePolicyMetadata -PassThru).Count | Should -Be 3
        }
    }
}

Describe 'Get-IACSettingDefinitionLookup' {
    It 'uses the first readable file and warns about a corrupt one' {
        $corrupt = Join-Path $TestDrive 'corrupt.json'
        $valid = Join-Path $TestDrive 'valid.json'
        Set-Content -LiteralPath $corrupt -Value '{ not json'
        Set-Content -LiteralPath $valid -Value '[{"id":"setting_a","displayName":"Setting A"}]'

        $lookup = Get-IACSettingDefinitionLookup -CandidatePath @($corrupt, $valid) `
            -WarningVariable loadWarnings -WarningAction SilentlyContinue

        $lookup['SETTING_A'] | Should -BeExactly 'Setting A'
        ($loadWarnings -join ' ') | Should -Match 'could not be loaded'
    }

    It 'falls back to the next file when a readable file has no usable entries' {
        $empty = Join-Path $TestDrive 'empty.json'
        $valid = Join-Path $TestDrive 'bundled.json'
        Set-Content -LiteralPath $empty -Value '[]'
        Set-Content -LiteralPath $valid -Value '[{"id":"setting_b","displayName":"Setting B"}]'

        $lookup = Get-IACSettingDefinitionLookup -CandidatePath @($empty, $valid) `
            -WarningVariable loadWarnings -WarningAction SilentlyContinue

        $lookup['setting_b'] | Should -BeExactly 'Setting B'
        ($loadWarnings -join ' ') | Should -Match 'no usable entries'
    }

    It 'returns an empty lookup with a warning when no file exists' {
        $lookup = Get-IACSettingDefinitionLookup -CandidatePath @((Join-Path $TestDrive 'missing.json')) `
            -WarningVariable loadWarnings -WarningAction SilentlyContinue

        $lookup.Count | Should -Be 0
        ($loadWarnings -join ' ') | Should -Match 'No setting definitions'
    }
}

Describe 'Deep search menu integration' {
    BeforeEach {
        Mock Write-Host {}
        Mock Connect-IntuneAssignmentChecker {}
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'test' } }
        Mock Search-IntuneSettingDeep {}
        Mock Read-Host { '' }
    }

    It 'adds option 17 and keeps option 15' {
        Show-Menu

        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[17`] Deep Search*' } -Times 1 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[15`] Search for Specific Settings*' } -Times 1 -Exactly
    }

    It 'runs deep search in parameter mode without prompting' {
        Invoke-IntuneAssignmentChecker -SearchSettingDeep -SettingKeyword Telemetry -ExportPath ./deep.csv

        Should -Invoke Read-Host -Times 0 -Exactly
        Should -Invoke Search-IntuneSettingDeep -Times 1 -Exactly -ParameterFilter {
            $Keyword -eq 'Telemetry' -and $ExportPath -eq './deep.csv' -and -not $PesterBoundParameters.ContainsKey('IncludeCompliance')
        }
    }

    It 'forwards an explicit compliance exclusion' {
        Invoke-IntuneAssignmentChecker -SearchSettingDeep -SettingKeyword Telemetry -IncludeComplianceInDeepSearch:$false

        Should -Invoke Search-IntuneSettingDeep -Times 1 -Exactly -ParameterFilter {
            $PesterBoundParameters.ContainsKey('IncludeCompliance') -and -not $IncludeCompliance
        }
    }

    It 'cancels on a blank keyword' {
        Invoke-IntuneAssignmentChecker -SearchSettingDeep

        Should -Invoke Search-IntuneSettingDeep -Times 0 -Exactly
    }

    It 'still routes -SearchSetting to the original command' {
        Mock Search-IntuneSetting {}

        Invoke-IntuneAssignmentChecker -SearchSetting -SettingKeyword BitLocker

        Should -Invoke Search-IntuneSetting -Times 1 -Exactly
        Should -Invoke Search-IntuneSettingDeep -Times 0 -Exactly
    }
}
