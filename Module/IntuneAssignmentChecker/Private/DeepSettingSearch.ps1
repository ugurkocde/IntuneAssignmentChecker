# Read-only helpers for Search-IntuneSettingDeep.
#
# Graph responses and decoded profiles are untrusted tenant data. These helpers never
# resolve XML entities, never decode arbitrary Base64 properties, and never match or
# return a value that is identified as secret.

function Get-IACDeepProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [ValueType]) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$Name] }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-IACDeepEntry {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject)

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.Keys)) {
            [PSCustomObject]@{ Name = [string]$key; Value = $InputObject[$key] }
        }
        return
    }
    foreach ($property in @($InputObject.PSObject.Properties)) {
        [PSCustomObject]@{ Name = $property.Name; Value = $property.Value }
    }
}

function Test-IACSensitiveSettingName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return $Name -match '(?i)password|passwd|passphrase|pwd|psk|secret|token|credential|private.?key|client.?key|api.?key|recovery.?key|shared.?key|auth.?key|license.?key|product.?key|signing.?key|encryption.?key|certificate|pfx|pkcs|connection.?string'
}

function Test-IACSensitiveLabel {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Name,
        [AllowNull()][AllowEmptyString()][string]$Text
    )

    # Name/value style records carry the setting's identity in a sibling field.
    return $Name -in @('name', 'key', 'displayName', 'label', 'title', 'omaUri') -and
        (Test-IACSensitiveSettingName -Name $Text)
}

# Protection levels, weakest first. A sensitive-looking name hides only values that could
# hold a secret, so password lengths and on/off settings stay visible:
#   None   - shown.
#   Name   - Microsoft-defined setting with a sensitive name: text is hidden.
#   Custom - admin-defined record or payload with a sensitive name or label: everything
#            except true/false is hidden, because a PIN can be stored as a number.
#   Secret - secret type, encrypted, secret-referenced, or binary value: everything is hidden.
function Join-IACProtection {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Current,
        [Parameter(Mandatory = $true)][string]$Additional
    )

    $order = @('None', 'Name', 'Custom', 'Secret')
    if ($order.IndexOf($Additional) -gt $order.IndexOf($Current)) { return $Additional }
    return $Current
}

function Get-IACValueKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return 'Text' }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -eq [TypeCode]::Boolean) { return 'Boolean' }
    if ($typeCode -ge [TypeCode]::SByte -and $typeCode -le [TypeCode]::Decimal) { return 'Number' }
    return 'Text'
}

function Test-IACHiddenValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Protection,
        # Text, Number, Boolean, or Choice (a Settings Catalog option ID).
        [Parameter(Mandatory = $true)][string]$Kind
    )

    switch ($Protection) {
        'Secret' { return $true }
        'Custom' { return $Kind -ne 'Boolean' }
        'Name' { return $Kind -eq 'Text' }
    }
    return $false
}

function Get-IACValueProtection {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Node)

    $odataType = [string](Get-IACDeepProperty -InputObject $Node -Name '@odata.type')
    if ($odataType -match '(?i)(?:SecretSettingValue|omaSettingBase64|omaSettingStringXml)$') { return 'Secret' }
    if ((Get-IACDeepProperty -InputObject $Node -Name 'isEncrypted') -eq $true) { return 'Secret' }
    if (-not [string]::IsNullOrWhiteSpace([string](Get-IACDeepProperty -InputObject $Node -Name 'secretReferenceValueId'))) {
        return 'Secret'
    }
    foreach ($label in @('omaUri', 'displayName', 'name', 'key')) {
        $labelText = [string](Get-IACDeepProperty -InputObject $Node -Name $label)
        if (Test-IACSensitiveLabel -Name $label -Text $labelText) { return 'Custom' }
    }
    return 'None'
}

function Test-IACDeepKeywordMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Keyword
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    if ($Text.IndexOf($Keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }

    # Let 'Audit Group Membership' match auditgroupmembership and vice versa.
    $normalizedText = [regex]::Replace($Text, '[^a-zA-Z0-9]', '')
    $normalizedKeyword = [regex]::Replace($Keyword, '[^a-zA-Z0-9]', '')
    return $normalizedKeyword.Length -ge 3 -and
        $normalizedText.IndexOf($normalizedKeyword, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Format-IACDeepValue {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 160) { return $Value.Substring(0, 160) + '...' }
    return $Value
}

function ConvertFrom-IACConfigurationPayload {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Encoded)

    $maximumBytes = 2MB
    if ($null -eq $Encoded) { return $null }

    if ($Encoded -is [byte[]]) {
        $bytes = $Encoded
    }
    else {
        $value = ([string]$Encoded).Trim()
        if ($value.Length -eq 0) { return $null }
        if ($value.StartsWith('<')) {
            if ($value.Length -gt $maximumBytes) { throw 'Configuration payload exceeds the 2 MiB safety limit.' }
            return $value
        }
        if ($value.Length -gt ([math]::Ceiling($maximumBytes / 3) * 4)) {
            throw 'Configuration payload exceeds the 2 MiB safety limit.'
        }
        try { $bytes = [Convert]::FromBase64String($value) }
        catch { throw 'Configuration payload is not valid Base64 or XML.' }
    }

    if ($bytes.Length -gt $maximumBytes) { throw 'Configuration payload exceeds the 2 MiB safety limit.' }

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $reader = [System.IO.StreamReader]::new([System.IO.MemoryStream]::new($bytes), $encoding, $true)
    try { return $reader.ReadToEnd() }
    catch { throw 'Configuration payload is not text. It may be a signed or binary profile.' }
    finally { $reader.Dispose() }
}

function ConvertTo-IACSafeXmlDocument {
    [CmdletBinding()]
    [OutputType([System.Xml.XmlDocument])]
    param([Parameter(Mandatory = $true)][string]$Xml)

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 2MB + 64

    # macOS configurationXml can be a plist fragment with several top-level elements, so
    # parse under a private root. Only the declaration and a simple prolog DOCTYPE (the
    # standard Apple plist form) are removed. Any DOCTYPE with an internal subset stays in
    # place and is rejected by DtdProcessing.Prohibit.
    $normalized = $Xml.TrimStart([char]0xFEFF, [char]0x20, [char]0x09, [char]0x0D, [char]0x0A)
    $normalized = [regex]::Replace($normalized, '^<\?xml\s[^>]*\?>\s*', '')
    $normalized = [regex]::Replace($normalized, '^<!DOCTYPE\s[^\[\]<>]*>', '')

    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create(
            [System.IO.StringReader]::new("<iac-fragment>$normalized</iac-fragment>"),
            $settings
        )
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    }
    catch {
        # XmlException messages can quote payload content, so report only its location.
        $xmlError = $_.Exception.GetBaseException()
        if ($xmlError -is [System.Xml.XmlException]) {
            throw "XML is malformed or uses a prohibited DTD (line $($xmlError.LineNumber), position $($xmlError.LinePosition))."
        }
        throw 'XML could not be parsed.'
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}

# The XML helpers call get_* accessors because PowerShell's XML adapter lets a child
# element named, for example, InnerText shadow the .NET property of the same name.
function Get-IACXmlChildElement {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Xml.XmlNode]$Node)

    foreach ($child in $Node.get_ChildNodes()) {
        if ($child.get_NodeType() -eq [System.Xml.XmlNodeType]::Element) { $child }
    }
}

function Find-IACPlistMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Container,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$Sensitive = $false,
        [int]$Depth = 0
    )

    if ($Depth -gt 40) { return }
    $elements = @(Get-IACXmlChildElement -Node $Container)
    $isArray = $Container.get_LocalName() -eq 'array'

    $labelSensitive = $false
    for ($labelIndex = 0; $labelIndex -lt $elements.Count - 1; $labelIndex++) {
        if ($elements[$labelIndex].get_LocalName() -eq 'key' -and
            $elements[$labelIndex + 1].get_LocalName() -eq 'string' -and
            (Test-IACSensitiveLabel -Name $elements[$labelIndex].get_InnerText() -Text $elements[$labelIndex + 1].get_InnerText())) {
            $labelSensitive = $true
            break
        }
    }

    for ($index = 0; $index -lt $elements.Count; $index++) {
        $element = $elements[$index]
        if ($element.get_LocalName() -ne 'key') {
            if (@(Get-IACXmlChildElement -Node $element).Count -gt 0) {
                $childPath = if ($isArray) { "${Path}[$index]" } else { $Path }
                Find-IACPlistMatch -Container $element -Keyword $Keyword -Path $childPath `
                    -Sensitive $Sensitive -Depth ($Depth + 1)
            }
            continue
        }

        if ($index + 1 -ge $elements.Count) { continue }
        $valueNode = $elements[$index + 1]
        $valueKind = $valueNode.get_LocalName()
        if ($valueKind -eq 'key') { continue }
        $index++

        $settingName = $element.get_InnerText()
        $settingPath = "$Path.$settingName"
        $settingSensitive = $Sensitive -or (Test-IACSensitiveSettingName -Name $settingName) -or
            ($labelSensitive -and $settingName -eq 'value')
        $settingValue = switch ($valueKind) {
            'true' { 'true' }
            'false' { 'false' }
            'dict' { '[dictionary]' }
            'array' { '[array]' }
            'data' { '[binary data withheld]' }
            default { $valueNode.get_InnerText() }
        }

        # Payload keys are admin-defined, so a sensitive name hides everything except true/false.
        $plistKind = if ($valueKind -in @('true', 'false')) { 'Boolean' } else { 'Text' }
        $hidden = $settingSensitive -and (Test-IACHiddenValue -Protection 'Custom' -Kind $plistKind)
        $isScalar = $valueKind -notin @('dict', 'array', 'data')
        $nameMatches = Test-IACDeepKeywordMatch -Text $settingName -Keyword $Keyword
        $valueMatches = $isScalar -and -not $hidden -and
            (Test-IACDeepKeywordMatch -Text $settingValue -Keyword $Keyword)
        if ($nameMatches -or $valueMatches) {
            [PSCustomObject]@{
                SettingPath  = $settingPath
                SettingName  = $settingName
                MatchedValue = if ($hidden) { '[REDACTED]' } else { Format-IACDeepValue -Value $settingValue }
            }
        }

        if ($valueKind -in @('dict', 'array')) {
            Find-IACPlistMatch -Container $valueNode -Keyword $Keyword -Path $settingPath `
                -Sensitive $settingSensitive -Depth ($Depth + 1)
        }
    }
}

function Find-IACXmlElementMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Container,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$Sensitive = $false,
        [int]$Depth = 0
    )

    if ($Depth -gt 40) { return }
    $elements = @(Get-IACXmlChildElement -Node $Container)

    $labelSensitive = $false
    foreach ($element in $elements) {
        if (@(Get-IACXmlChildElement -Node $element).Count -eq 0 -and
            (Test-IACSensitiveLabel -Name $element.get_LocalName() -Text $element.get_InnerText())) {
            $labelSensitive = $true
            break
        }
    }

    foreach ($element in $elements) {
        $name = $element.get_LocalName()
        $elementPath = "$Path.$name"
        $isLabel = $name -in @('name', 'key', 'displayName', 'label', 'title', 'omaUri')
        $elementSensitive = $Sensitive -or (Test-IACSensitiveSettingName -Name $name) -or
            ($labelSensitive -and -not $isLabel)

        if (@(Get-IACXmlChildElement -Node $element).Count -gt 0) {
            Find-IACXmlElementMatch -Container $element -Keyword $Keyword -Path $elementPath `
                -Sensitive $elementSensitive -Depth ($Depth + 1)
            continue
        }

        $value = $element.get_InnerText()
        if ((Test-IACDeepKeywordMatch -Text $name -Keyword $Keyword) -or
            (-not $elementSensitive -and (Test-IACDeepKeywordMatch -Text $value -Keyword $Keyword))) {
            [PSCustomObject]@{
                SettingPath  = $elementPath
                SettingName  = $name
                MatchedValue = if ($elementSensitive) { '[REDACTED]' } else { Format-IACDeepValue -Value $value }
            }
        }
    }
}

function Find-IACXmlSettingMatch {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Xml,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [Parameter(Mandatory = $true)][string]$Property
    )

    if ([string]::IsNullOrWhiteSpace($Xml)) { return }
    $document = ConvertTo-IACSafeXmlDocument -Xml $Xml
    $root = $document.get_DocumentElement()
    if ($null -ne $document.SelectSingleNode('//key')) {
        Find-IACPlistMatch -Container $root -Keyword $Keyword -Path $Property
    }
    else {
        Find-IACXmlElementMatch -Container $root -Keyword $Keyword -Path $Property
    }
}

function Find-IACGraphValueMatch {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [ValidateSet('None', 'Name', 'Custom', 'Secret')][string]$Protection = 'None',
        [int]$Depth = 0
    )

    if ($null -eq $Node -or $Depth -gt 40) { return }

    if ($Node -is [string] -or $Node -is [ValueType]) {
        $text = [string]$Node
        $hidden = Test-IACHiddenValue -Protection $Protection -Kind (Get-IACValueKind -Value $Node)
        if ((Test-IACDeepKeywordMatch -Text $Name -Keyword $Keyword) -or
            (-not $hidden -and (Test-IACDeepKeywordMatch -Text $text -Keyword $Keyword))) {
            [PSCustomObject]@{
                SettingPath  = $Path
                SettingName  = $Name
                MatchedValue = if ($hidden) { '[REDACTED]' } else { Format-IACDeepValue -Value $text }
            }
        }
        return
    }

    if ($Node -isnot [System.Collections.IDictionary] -and $Node -is [System.Collections.IEnumerable]) {
        $index = 0
        foreach ($item in $Node) {
            Find-IACGraphValueMatch -Node $item -Path "${Path}[$index]" -Name $Name -Keyword $Keyword `
                -Protection $Protection -Depth ($Depth + 1)
            $index++
        }
        return
    }

    # Property names come from the Microsoft Graph schema. A record's 'value' can also be
    # protected by its type, encryption flags, or an admin-defined sibling label.
    $valueProtection = Get-IACValueProtection -Node $Node
    foreach ($entry in @(Get-IACDeepEntry -InputObject $Node)) {
        # Encoded profiles are searched only through the XML decoder.
        if ($entry.Name -in @('payload', 'configurationXml')) { continue }
        $entryProtection = $Protection
        if (Test-IACSensitiveSettingName -Name $entry.Name) {
            $entryProtection = Join-IACProtection -Current $entryProtection -Additional 'Name'
        }
        if ($entry.Name -eq 'value') {
            $entryProtection = Join-IACProtection -Current $entryProtection -Additional $valueProtection
        }
        Find-IACGraphValueMatch -Node $entry.Value -Path "$Path.$($entry.Name)" -Name $entry.Name `
            -Keyword $Keyword -Protection $entryProtection -Depth ($Depth + 1)
    }
}

function Find-IACCatalogInstance {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$Sensitive = $false,
        [int]$Depth = 0
    )

    if ($null -eq $Node -or $Depth -gt 40 -or $Node -is [string] -or $Node -is [ValueType]) { return }

    if ($Node -isnot [System.Collections.IDictionary] -and $Node -is [System.Collections.IEnumerable]) {
        $index = 0
        foreach ($item in $Node) {
            Find-IACCatalogInstance -Node $item -Path "${Path}[$index]" -Sensitive $Sensitive -Depth ($Depth + 1)
            $index++
        }
        return
    }

    $instanceSensitive = $Sensitive
    $definitionId = [string](Get-IACDeepProperty -InputObject $Node -Name 'settingDefinitionId')
    if (-not [string]::IsNullOrWhiteSpace($definitionId)) {
        $instanceSensitive = $Sensitive -or (Test-IACSensitiveSettingName -Name $definitionId)
        [PSCustomObject]@{
            Node         = $Node
            Path         = $Path
            DefinitionId = $definitionId
            Sensitive    = $instanceSensitive
        }
    }

    foreach ($entry in @(Get-IACDeepEntry -InputObject $Node)) {
        if ($entry.Name -in @('auditRuleInformation', 'settingInstanceTemplateReference', 'settingValueTemplateReference')) {
            continue
        }
        Find-IACCatalogInstance -Node $entry.Value -Path "$Path.$($entry.Name)" `
            -Sensitive $instanceSensitive -Depth ($Depth + 1)
    }
}

function Get-IACCatalogValue {
    [CmdletBinding()]
    param([AllowNull()][object]$Instance)

    $values = [System.Collections.Generic.List[string]]::new()
    $kinds = [System.Collections.Generic.HashSet[string]]::new()
    $isSecret = $false
    $isChoice = $null -ne (Get-IACDeepProperty -InputObject $Instance -Name 'choiceSettingValue') -or
        $null -ne (Get-IACDeepProperty -InputObject $Instance -Name 'choiceSettingCollectionValue')
    $valueObjects = @(
        Get-IACDeepProperty -InputObject $Instance -Name 'simpleSettingValue'
        Get-IACDeepProperty -InputObject $Instance -Name 'choiceSettingValue'
        Get-IACDeepProperty -InputObject $Instance -Name 'simpleSettingCollectionValue'
        Get-IACDeepProperty -InputObject $Instance -Name 'choiceSettingCollectionValue'
    )
    foreach ($valueObject in $valueObjects) {
        if ($null -eq $valueObject) { continue }
        if ([string](Get-IACDeepProperty -InputObject $valueObject -Name '@odata.type') -match '(?i)SecretSettingValue$') {
            $isSecret = $true
        }
        $value = Get-IACDeepProperty -InputObject $valueObject -Name 'value'
        if ($null -ne $value) {
            $values.Add([string]$value)
            $null = $kinds.Add((Get-IACValueKind -Value $value))
        }
    }

    # Choice values are option IDs from the setting definition, so they cannot hold a secret.
    $kind = if ($isChoice) { 'Choice' }
    elseif ($kinds.Count -eq 1 -and -not $kinds.Contains('Text')) { @($kinds)[0] }
    else { 'Text' }

    return [PSCustomObject]@{
        Values   = $values.ToArray()
        Kind     = $kind
        IsSecret = $isSecret
        IsChoice = $isChoice
    }
}

function Get-IACChoiceOptionMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DefinitionId,
        [Parameter(Mandatory = $true)][hashtable]$State
    )

    # Failures are cached too, so one bad definition cannot flood Microsoft Graph.
    if ($State.ChoiceCache.ContainsKey($DefinitionId)) { return $State.ChoiceCache[$DefinitionId] }

    $State.ChoiceRequests++
    $optionMap = $null
    try {
        $encodedId = [uri]::EscapeDataString($DefinitionId)
        $uri = "$($script:GraphEndpoint.TrimEnd('/'))/beta/deviceManagement/configurationSettings/$encodedId"
        $definition = Invoke-IACGraphRequest -Uri $uri -Method GET
        $optionMap = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($option in @(Get-IACDeepProperty -InputObject $definition -Name 'options')) {
            if ($null -eq $option) { continue }
            $itemId = [string](Get-IACDeepProperty -InputObject $option -Name 'itemId')
            $label = [string](Get-IACDeepProperty -InputObject $option -Name 'displayName')
            if ([string]::IsNullOrWhiteSpace($label)) {
                $label = [string](Get-IACDeepProperty -InputObject $option -Name 'name')
            }
            if (-not [string]::IsNullOrWhiteSpace($itemId) -and -not [string]::IsNullOrWhiteSpace($label)) {
                $optionMap[$itemId] = $label
            }
        }
        if ($optionMap.Count -eq 0) {
            $State.ChoiceWarnings.Add([PSCustomObject]@{
                    DefinitionId = $DefinitionId
                    Error        = 'Graph returned no usable options[].itemId/displayName records.'
                })
        }
    }
    catch {
        $optionMap = $null
        $State.ChoiceWarnings.Add([PSCustomObject]@{
                DefinitionId = $DefinitionId
                Error        = $_.Exception.Message
            })
    }

    $State.ChoiceCache[$DefinitionId] = $optionMap
    return $optionMap
}

function Resolve-IACSettingDisplayValue {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$Values,
        [Parameter(Mandatory = $true)][string]$DefinitionId,
        [bool]$IsChoice = $false,
        [bool]$Sensitive = $false,
        [Parameter(Mandatory = $true)][hashtable]$State
    )

    if ($Sensitive) {
        return [PSCustomObject]@{ DisplayValue = '[REDACTED]'; RawValue = '[REDACTED]' }
    }
    if ($null -eq $Values -or $Values.Count -eq 0) {
        return [PSCustomObject]@{ DisplayValue = '[group or nested setting]'; RawValue = '' }
    }

    # Labels come only from definition metadata. Numeric suffixes are definition-specific.
    $optionMap = if ($IsChoice) { Get-IACChoiceOptionMap -DefinitionId $DefinitionId -State $State } else { $null }
    $display = [System.Collections.Generic.List[string]]::new()
    foreach ($value in $Values) {
        if ($null -ne $optionMap -and $optionMap.ContainsKey($value)) {
            $display.Add($optionMap[$value])
            $State.ChoiceResolved++
            continue
        }
        if ($IsChoice) {
            $State.ChoiceFallback++
            if ($null -ne $optionMap -and $optionMap.Count -gt 0) {
                $State.ChoiceWarnings.Add([PSCustomObject]@{
                        DefinitionId = $DefinitionId
                        Error        = "No option metadata matched choice ID '$value'."
                    })
            }
        }
        $display.Add((Format-IACDeepValue -Value $value))
    }

    $rawValue = $Values -join '; '
    if (-not $IsChoice) { $rawValue = Format-IACDeepValue -Value $rawValue }
    return [PSCustomObject]@{ DisplayValue = ($display -join '; '); RawValue = $rawValue }
}

function Get-IACSettingDefinitionLookup {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, string]])]
    param([string[]]$CandidatePath)

    if (-not $CandidatePath) {
        # Same precedence as Search-IntuneSetting: refreshed user copy, then bundled data.
        $CandidatePath = @(
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'IntuneAssignmentChecker/SettingDefinitions.json')
            (Join-Path $PSScriptRoot '../Data/SettingDefinitions.json')
        )
    }

    $lookup = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $CandidatePath) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try {
            $catalog = @(Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 40)
            foreach ($definition in $catalog) {
                $id = [string](Get-IACDeepProperty -InputObject $definition -Name 'id')
                $displayName = [string](Get-IACDeepProperty -InputObject $definition -Name 'displayName')
                if ($id -and $displayName -and -not $lookup.ContainsKey($id)) { $lookup.Add($id, $displayName) }
            }
            return $lookup
        }
        catch {
            $lookup.Clear()
            Write-Warning "Setting definitions in '$path' could not be loaded: $($_.Exception.Message)"
        }
    }

    Write-Warning 'No setting definitions were loaded. Raw setting IDs will still be searched.'
    return $lookup
}

function Get-IACDeepSearchFamily {
    [CmdletBinding()]
    param([bool]$IncludeCompliance = $true)

    $families = @(
        @{
            Name   = 'Settings Catalog / Endpoint Security'
            Kind   = 'SettingsCatalog'
            List   = 'deviceManagement/configurationPolicies'
            Detail = 'deviceManagement/configurationPolicies/{id}/settings'
        }
        @{
            Name   = 'Device configuration / custom OMA-URI'
            Kind   = 'PolicyObject'
            List   = 'deviceManagement/deviceConfigurations'
            Detail = 'deviceManagement/deviceConfigurations/{id}'
        }
        @{
            Name   = 'Administrative Templates'
            Kind   = 'AdministrativeTemplate'
            List   = 'deviceManagement/groupPolicyConfigurations'
            Detail = 'deviceManagement/groupPolicyConfigurations/{id}/definitionValues?$expand=definition'
        }
    )
    if ($IncludeCompliance) {
        $families += @{
            Name   = 'Device compliance policies'
            Kind   = 'PolicyObject'
            List   = 'deviceManagement/deviceCompliancePolicies'
            Detail = 'deviceManagement/deviceCompliancePolicies/{id}'
        }
    }
    return $families
}

function New-IACDeepSearchState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        ChoiceCache     = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        ChoiceWarnings  = [System.Collections.Generic.List[object]]::new()
        ChoiceRequests  = 0
        ChoiceResolved  = 0
        ChoiceFallback  = 0
        ScanErrors      = [System.Collections.Generic.List[object]]::new()
        PoliciesScanned = 0
        DecodedPayloads = 0
    }
}

function New-IACDeepSearchResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Family,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$PolicyId,
        [AllowNull()][string]$SettingPath,
        [AllowNull()][string]$SettingName,
        [AllowNull()][string]$MatchedValue,
        [AllowNull()][string]$RawValue,
        [AllowNull()][string]$SettingDefinitionId
    )

    # Every row has the same columns because Export-Csv takes its header from the first row.
    return [PSCustomObject]@{
        PSTypeName          = 'IntuneAssignmentChecker.DeepSettingSearchResult'
        PolicyType          = $Family.Name
        PolicyName          = $PolicyName
        PolicyId            = $PolicyId
        SettingPath         = $SettingPath
        SettingName         = $SettingName
        MatchedValue        = $MatchedValue
        RawValue            = $RawValue
        SettingDefinitionId = $SettingDefinitionId
    }
}

function Find-IACCatalogSettingMatch {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Settings,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [AllowNull()][System.Collections.IDictionary]$Definitions,
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][hashtable]$Family,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$PolicyId
    )

    foreach ($instance in @(Find-IACCatalogInstance -Node $Settings -Path 'settings')) {
        $definitionId = $instance.DefinitionId
        $friendlyName = Get-IACDeepProperty -InputObject $Definitions -Name $definitionId
        if ([string]::IsNullOrWhiteSpace($friendlyName)) { $friendlyName = $definitionId }

        $configured = Get-IACCatalogValue -Instance $instance.Node
        $protection = if ($configured.IsSecret) { 'Secret' }
        elseif ($instance.Sensitive -or (Test-IACSensitiveSettingName -Name $friendlyName)) { 'Name' }
        else { 'None' }
        $hidden = Test-IACHiddenValue -Protection $protection -Kind $configured.Kind
        $isMatch = (Test-IACDeepKeywordMatch -Text $definitionId -Keyword $Keyword) -or
            (Test-IACDeepKeywordMatch -Text $friendlyName -Keyword $Keyword)
        if (-not $isMatch -and -not $hidden) {
            foreach ($value in $configured.Values) {
                if (Test-IACDeepKeywordMatch -Text $value -Keyword $Keyword) { $isMatch = $true; break }
            }
        }
        if (-not $isMatch) { continue }

        $resolved = Resolve-IACSettingDisplayValue -Values $configured.Values -DefinitionId $definitionId `
            -IsChoice $configured.IsChoice -Sensitive $hidden -State $State
        New-IACDeepSearchResult -Family $Family -PolicyName $PolicyName -PolicyId $PolicyId `
            -SettingPath $instance.Path -SettingName $friendlyName -MatchedValue $resolved.DisplayValue `
            -RawValue $resolved.RawValue -SettingDefinitionId $definitionId
    }
}

function Find-IACAdministrativeTemplateMatch {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$DefinitionValues,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [Parameter(Mandatory = $true)][hashtable]$Family,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$PolicyId
    )

    $index = -1
    foreach ($definitionValue in @($DefinitionValues)) {
        $index++
        $definition = Get-IACDeepProperty -InputObject $definitionValue -Name 'definition'
        $name = [string](Get-IACDeepProperty -InputObject $definition -Name 'displayName')
        $category = [string](Get-IACDeepProperty -InputObject $definition -Name 'categoryPath')
        if (-not (Test-IACDeepKeywordMatch -Text $name -Keyword $Keyword) -and
            -not (Test-IACDeepKeywordMatch -Text $category -Keyword $Keyword)) { continue }

        $enabled = Get-IACDeepProperty -InputObject $definitionValue -Name 'enabled'
        $state = if ($null -eq $enabled) { 'Unknown' } elseif ($enabled) { 'Enabled' } else { 'Disabled' }
        New-IACDeepSearchResult -Family $Family -PolicyName $PolicyName -PolicyId $PolicyId `
            -SettingPath "definitionValues[$index]" -SettingName $(if ($name) { $name } else { $category }) `
            -MatchedValue $state -RawValue $state `
            -SettingDefinitionId ([string](Get-IACDeepProperty -InputObject $definition -Name 'id'))
    }
}

function Find-IACPolicyObjectMatch {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Policy,
        [Parameter(Mandatory = $true)][string]$Keyword,
        [bool]$IncludePolicyMetadata = $false,
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][hashtable]$Family,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$PolicyId
    )

    # Decode only the documented profile fields, never arbitrary Base64 properties.
    foreach ($propertyName in @('configurationXml', 'payload')) {
        $encoded = Get-IACDeepProperty -InputObject $Policy -Name $propertyName
        if ($null -eq $encoded -or [string]::IsNullOrWhiteSpace([string]$encoded)) { continue }
        try {
            $xmlText = ConvertFrom-IACConfigurationPayload -Encoded $encoded
            $xmlMatches = @(Find-IACXmlSettingMatch -Xml $xmlText -Keyword $Keyword -Property $propertyName)
            $State.DecodedPayloads++
            foreach ($match in $xmlMatches) {
                New-IACDeepSearchResult -Family $Family -PolicyName $PolicyName -PolicyId $PolicyId `
                    -SettingPath $match.SettingPath -SettingName $match.SettingName `
                    -MatchedValue $match.MatchedValue -RawValue $match.MatchedValue
            }
        }
        catch {
            $State.ScanErrors.Add([PSCustomObject]@{
                    Family = $Family.Name
                    Policy = $PolicyName
                    Error  = "Could not decode $propertyName`: $($_.Exception.Message)"
                })
        }
    }

    $metadataPattern = '(?:^|\.)(?:id|createdDateTime|lastModifiedDateTime)$|\.roleScopeTagIds(?:\[\d+\])?$|@odata\.[A-Za-z]+$'
    foreach ($match in @(Find-IACGraphValueMatch -Node $Policy -Path 'settings' -Name 'settings' -Keyword $Keyword)) {
        if (-not $IncludePolicyMetadata -and $match.SettingPath -match $metadataPattern) { continue }
        New-IACDeepSearchResult -Family $Family -PolicyName $PolicyName -PolicyId $PolicyId `
            -SettingPath $match.SettingPath -SettingName $match.SettingName `
            -MatchedValue $match.MatchedValue -RawValue $match.MatchedValue
    }
}

function Export-IACDeepSearchCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $InputObject | ForEach-Object {
        $row = [ordered]@{}
        foreach ($property in $_.PSObject.Properties) {
            $row[$property.Name] = ConvertTo-IACCsvSafeValue -Value $property.Value
        }
        [PSCustomObject]$row
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
}
