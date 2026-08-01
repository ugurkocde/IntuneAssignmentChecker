function ConvertTo-IACTokenList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Rule
    )

    if ($Rule.Length -gt 8192) { throw 'Assignment filter rule exceeds the 8192-character safety limit.' }

    $tokens = [System.Collections.Generic.List[object]]::new()
    $index = 0
    while ($index -lt $Rule.Length) {
        if ($tokens.Count -ge 1024) { throw 'Assignment filter rule exceeds the 1024-token safety limit.' }
        $character = $Rule[$index]
        if ([char]::IsWhiteSpace($character)) {
            $index++
            continue
        }

        $punctuation = switch ($character) {
            '(' { 'LeftParen' }
            ')' { 'RightParen' }
            '[' { 'LeftBracket' }
            ']' { 'RightBracket' }
            ',' { 'Comma' }
            default { $null }
        }
        if ($punctuation) {
            $tokens.Add([PSCustomObject]@{ Kind = $punctuation; Value = "$character"; Position = $index })
            $index++
            continue
        }

        if ($character -eq '"' -or $character -eq "'") {
            $quote = $character
            $start = $index
            $index++
            $builder = [System.Text.StringBuilder]::new()
            $closed = $false
            while ($index -lt $Rule.Length) {
                $current = $Rule[$index]
                if ($current -eq $quote) {
                    # Accept doubled quotes as a literal quote as well as the common
                    # backslash/backtick escape form handled below.
                    if (($index + 1) -lt $Rule.Length -and $Rule[$index + 1] -eq $quote) {
                        [void]$builder.Append($quote)
                        $index += 2
                        continue
                    }
                    $closed = $true
                    $index++
                    break
                }
                if (($current -eq '\' -or $current -eq '`') -and ($index + 1) -lt $Rule.Length) {
                    $escaped = $Rule[$index + 1]
                    if ($escaped -eq $quote -or $escaped -eq '\' -or $escaped -eq '`') {
                        [void]$builder.Append($escaped)
                        $index += 2
                        continue
                    }
                }
                [void]$builder.Append($current)
                $index++
            }
            if (-not $closed) { throw "Unterminated string literal at position $start." }
            $tokens.Add([PSCustomObject]@{ Kind = 'String'; Value = $builder.ToString(); Position = $start })
            continue
        }

        if ("$character" -match '^[A-Za-z0-9_.$-]$') {
            $start = $index
            while ($index -lt $Rule.Length -and "$($Rule[$index])" -match '^[A-Za-z0-9_.$-]$') { $index++ }
            $tokens.Add([PSCustomObject]@{ Kind = 'Word'; Value = $Rule.Substring($start, $index - $start); Position = $start })
            continue
        }

        throw "Unsupported character '$character' at position $index."
    }

    $tokens.Add([PSCustomObject]@{ Kind = 'End'; Value = ''; Position = $Rule.Length })
    return , $tokens
}

function ConvertTo-IACFilterAst {
    [CmdletBinding()]
    # PSScriptAnalyzer cannot trace the Tokens reference through the nested
    # recursive-descent parser functions below.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Tokens')]
    param(
        [Parameter(Mandatory)]
        [object[]]$Tokens
    )

    $state = [PSCustomObject]@{ Position = 0; Depth = 0 }
    $comparisonOperators = @('eq', 'ne', 'gt', 'ge', 'lt', 'le', 'in', 'notin', 'contains', 'notcontains', 'startswith')

    function Get-IACParserToken {
        return $Tokens[$state.Position]
    }

    function Read-IACParserToken {
        param([string]$Kind)
        $token = Get-IACParserToken
        if ($token.Kind -ne $Kind) { throw "Expected $Kind at position $($token.Position), found $($token.Kind)." }
        $state.Position++
        return $token
    }

    function Get-IACNormalizedOperator {
        param([string]$Value)
        $normalized = $Value.TrimStart([char]'-').ToLowerInvariant()
        switch ($normalized) {
            'equals' { 'eq' }
            'notequals' { 'ne' }
            'greaterthan' { 'gt' }
            'greaterthanorequals' { 'ge' }
            'lessthan' { 'lt' }
            'lessthanorequals' { 'le' }
            default { $normalized }
        }
    }

    function Test-IACLogicalToken {
        param([string]$Name)
        $token = Get-IACParserToken
        return $token.Kind -eq 'Word' -and (Get-IACNormalizedOperator -Value $token.Value) -eq $Name
    }

    function Read-IACScalarLiteral {
        $token = Get-IACParserToken
        if ($token.Kind -eq 'String') {
            $state.Position++
            return [PSCustomObject]@{ ValueType = 'String'; Value = $token.Value }
        }
        if ($token.Kind -eq 'Word') {
            $state.Position++
            if ($token.Value -ieq 'null' -or $token.Value -ieq '$null') {
                return [PSCustomObject]@{ ValueType = 'Null'; Value = $null }
            }
            return [PSCustomObject]@{ ValueType = 'Bare'; Value = $token.Value }
        }
        throw "Expected a scalar value at position $($token.Position)."
    }

    function Read-IACLiteral {
        if ((Get-IACParserToken).Kind -ne 'LeftBracket') { return Read-IACScalarLiteral }

        [void](Read-IACParserToken -Kind 'LeftBracket')
        $values = [System.Collections.Generic.List[object]]::new()
        if ((Get-IACParserToken).Kind -ne 'RightBracket') {
            $values.Add((Read-IACScalarLiteral))
            while ((Get-IACParserToken).Kind -eq 'Comma') {
                [void](Read-IACParserToken -Kind 'Comma')
                $values.Add((Read-IACScalarLiteral))
            }
        }
        [void](Read-IACParserToken -Kind 'RightBracket')
        return [PSCustomObject]@{ ValueType = 'Array'; Value = @($values) }
    }

    function Read-IACComparison {
        $property = Read-IACParserToken -Kind 'Word'
        if ($property.Value -notmatch '^(?i:device|app)\.[A-Za-z][A-Za-z0-9_]*$') {
            throw "Invalid assignment-filter property '$($property.Value)' at position $($property.Position)."
        }
        $operatorToken = Read-IACParserToken -Kind 'Word'
        $operator = Get-IACNormalizedOperator -Value $operatorToken.Value
        if ($comparisonOperators -notcontains $operator) {
            throw "Unsupported assignment-filter operator '$($operatorToken.Value)' at position $($operatorToken.Position)."
        }
        $literal = Read-IACLiteral
        return [PSCustomObject]@{
            NodeType = 'Comparison'
            Property = $property.Value
            Operator = $operator
            Literal  = $literal
        }
    }

    function Read-IACPrimary {
        if ((Get-IACParserToken).Kind -eq 'LeftParen') {
            $state.Depth++
            if ($state.Depth -gt 64) { throw 'Assignment filter nesting exceeds the 64-level safety limit.' }
            [void](Read-IACParserToken -Kind 'LeftParen')
            $expression = Read-IACOrExpression
            [void](Read-IACParserToken -Kind 'RightParen')
            $state.Depth--
            return $expression
        }
        return Read-IACComparison
    }

    function Read-IACAndExpression {
        $left = Read-IACPrimary
        while (Test-IACLogicalToken -Name 'and') {
            $state.Position++
            $left = [PSCustomObject]@{ NodeType = 'And'; Left = $left; Right = (Read-IACPrimary) }
        }
        return $left
    }

    function Read-IACOrExpression {
        $left = Read-IACAndExpression
        while (Test-IACLogicalToken -Name 'or') {
            $state.Position++
            $left = [PSCustomObject]@{ NodeType = 'Or'; Left = $left; Right = (Read-IACAndExpression) }
        }
        return $left
    }

    $ast = Read-IACOrExpression
    $remaining = Get-IACParserToken
    if ($remaining.Kind -ne 'End') { throw "Unexpected token '$($remaining.Value)' at position $($remaining.Position)." }
    return $ast
}

function Get-IACObjectProperty {
    param($InputObject, [string[]]$Names)

    foreach ($name in $Names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in $InputObject.Keys) {
                if ("$key" -ieq $name) {
                    return [PSCustomObject]@{ Found = $true; Name = "$key"; Value = $InputObject[$key] }
                }
            }
        }
        elseif ($null -ne $InputObject) {
            $property = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
            if ($property) { return [PSCustomObject]@{ Found = $true; Name = $property.Name; Value = $property.Value } }
        }
    }
    return [PSCustomObject]@{ Found = $false; Name = $null; Value = $null }
}

function Get-IACDeviceFilterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)][string]$Property
    )

    # Intune filter property -> beta managedDevice/Entra device field mapping.
    # Only these documented properties are eligible for local evaluation.
    $propertyMap = @{
        cpuarchitecture        = @{ Sources = @('processorArchitecture', 'cpuArchitecture'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin') }
        devicecategory         = @{ Sources = @('deviceCategoryDisplayName', 'deviceCategory'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        devicemanagementtype   = @{ Sources = @('deviceManagementType', 'deviceEnrollmentType'); Transform = 'ManagementType'; ValueType = 'String'; Operators = @('eq', 'ne') }
        devicename             = @{ Sources = @('deviceName', 'displayName'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        deviceownership        = @{ Sources = @('managedDeviceOwnerType', 'deviceOwnership'); Transform = 'Ownership'; ValueType = 'String'; Operators = @('eq', 'ne') }
        devicetrusttype        = @{ Sources = @('joinType', 'trustType'); Transform = 'TrustType'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin') }
        enrollmentprofilename = @{ Sources = @('enrollmentProfileName'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        isrooted               = @{ Sources = @('isRooted', 'jailBroken'); Transform = 'Rooted'; ValueType = 'String'; Operators = @('eq', 'ne') }
        manufacturer           = @{ Sources = @('manufacturer'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        model                  = @{ Sources = @('model'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        operatingsystemversion = @{ Sources = @('operatingSystemVersion', 'osVersion'); Transform = 'Identity'; ValueType = 'Version'; Operators = @('eq', 'ne', 'gt', 'ge', 'lt', 'le') }
        osversion              = @{ Sources = @('osVersion', 'operatingSystemVersion'); Transform = 'Identity'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
        operatingsystemsku     = @{ Sources = @('operatingSystemSKU', 'skuNumber'); Transform = 'Sku'; ValueType = 'String'; Operators = @('eq', 'ne', 'in', 'notin', 'startswith', 'contains', 'notcontains') }
    }

    if ($Property -notmatch '^(?i:device)\.(?<name>[A-Za-z][A-Za-z0-9_]*)$') {
        return [PSCustomObject]@{ Known = $false; Reason = "Only documented managed-device properties are supported; '$Property' is not one." }
    }
    $propertyName = $Matches.name.ToLowerInvariant()
    if (-not $propertyMap.ContainsKey($propertyName)) {
        return [PSCustomObject]@{ Known = $false; Reason = "Unsupported managed-device filter property '$Property'." }
    }

    $definition = $propertyMap[$propertyName]
    $source = Get-IACObjectProperty -InputObject $Device -Names $definition.Sources
    if (-not $source.Found) {
        return [PSCustomObject]@{ Known = $false; Reason = "Device response does not contain a source field for '$Property'." }
    }
    if ($null -eq $source.Value) {
        return [PSCustomObject]@{ Known = $true; Value = $null; ValueType = $definition.ValueType; Operators = $definition.Operators; SourceProperty = $source.Name }
    }

    $rawValue = "$($source.Value)"
    $transformed = switch ($definition.Transform) {
        'Ownership' {
            switch -Regex ($rawValue) {
                '^(?i:company|corporate)$' { 'Corporate'; break }
                '^(?i:personal)$' { 'Personal'; break }
                '^(?i:unknown)$' { 'Unknown'; break }
                default { $null }
            }
        }
        'TrustType' {
            switch -Regex ($rawValue) {
                '^(?i:azuread|azureadjoined)$' { 'Azure AD joined'; break }
                '^(?i:workplace|azureadregistered)$' { 'Azure AD registered'; break }
                '^(?i:serverad|hybridazureadjoined)$' { 'Hybrid Azure AD joined'; break }
                '^(?i:unknown)$' { 'Unknown'; break }
                default { $null }
            }
        }
        'Rooted' {
            if ($source.Value -is [bool]) { if ($source.Value) { 'True' } else { 'False' } }
            elseif ($rawValue -match '^(?i:true|false|unknown)$') { $rawValue }
            else { $null }
        }
        'ManagementType' {
            $managementTypes = @{
                androidenterprisededicateddevice       = $null # shared mode cannot be inferred safely
                androidenterprisefullymanaged          = 'Corporate-owned fully managed'
                androidenterprisecorporateworkprofile  = 'Corporate-owned with work profile'
                androidaospuserlessdeviceenrollment    = 'AOSP userless devices'
                androidaospuserowneddeviceenrollment   = 'AOSP user-associated devices'
            }
            if ($managementTypes.ContainsKey($rawValue.ToLowerInvariant())) { $managementTypes[$rawValue.ToLowerInvariant()] }
            elseif ($rawValue -in $managementTypes.Values) { $rawValue }
            else { $null }
        }
        'Sku' {
            $skuByNumber = @{
                '4' = 'Enterprise'; '10' = 'Core'; '27' = 'EnterpriseN'; '48' = 'Professional'; '49' = 'BusinessN'
                '72' = 'EnterpriseEval'; '84' = 'EnterpriseNEval'; '98' = 'CoreN'; '99' = 'CoreCountrySpecific'
                '100' = 'CoreSingleLanguage'; '101' = 'Core'; '111' = 'Core'; '119' = 'PPIPro'; '121' = 'Education'
                '122' = 'EducationN'; '123' = 'IoTUAP'; '125' = 'EnterpriseS'; '126' = 'EnterpriseSN'
                '129' = 'EnterpriseSEval'; '131' = 'IoTUAPCommercial'; '136' = 'Holographic'
                '138' = 'ProfessionalSingleLanguage'; '161' = 'ProfessionalWorkstation'; '162' = 'ProfessionalN'
                '164' = 'ProfessionalEducation'; '165' = 'ProfessionalEducationN'; '171' = 'EnterpriseG'
                '172' = 'EnterpriseGN'; '175' = 'ServerRdsh'; '188' = 'IoTEnterprise'; '202' = 'CloudEditionN'
                '203' = 'CloudEdition'
            }
            $supportedSkus = @($skuByNumber.Values | Select-Object -Unique)
            if ($source.Name -ieq 'skuNumber') { $skuByNumber[$rawValue] }
            else { $supportedSkus | Where-Object { $_ -ieq $rawValue } | Select-Object -First 1 }
        }
        default { $source.Value }
    }

    if ($null -eq $transformed) {
        return [PSCustomObject]@{ Known = $false; Reason = "Device field '$($source.Name)' value '$rawValue' cannot be mapped safely to '$Property'." }
    }
    return [PSCustomObject]@{
        Known          = $true
        Value          = $transformed
        ValueType      = $definition.ValueType
        Operators      = $definition.Operators
        SourceProperty = $source.Name
    }
}

function Compare-IACVersionValue {
    param([AllowNull()]$Left, [AllowNull()]$Right)
    $pattern = '^\d+(?:\.\d+){0,15}$'
    if ($null -eq $Left -or $null -eq $Right -or "$Left" -notmatch $pattern -or "$Right" -notmatch $pattern) {
        return [PSCustomObject]@{ Known = $false; Comparison = 0 }
    }
    $leftParts = @("$Left" -split '\.' | ForEach-Object { [System.Numerics.BigInteger]::Parse($_) })
    $rightParts = @("$Right" -split '\.' | ForEach-Object { [System.Numerics.BigInteger]::Parse($_) })
    if ($leftParts.Count -ne $rightParts.Count) {
        return [PSCustomObject]@{ Known = $false; Comparison = 0 }
    }
    $length = $leftParts.Count
    for ($index = 0; $index -lt $length; $index++) {
        $leftPart = if ($index -lt $leftParts.Count) { $leftParts[$index] } else { [System.Numerics.BigInteger]::Zero }
        $rightPart = if ($index -lt $rightParts.Count) { $rightParts[$index] } else { [System.Numerics.BigInteger]::Zero }
        if ($leftPart -lt $rightPart) { return [PSCustomObject]@{ Known = $true; Comparison = -1 } }
        if ($leftPart -gt $rightPart) { return [PSCustomObject]@{ Known = $true; Comparison = 1 } }
    }
    return [PSCustomObject]@{ Known = $true; Comparison = 0 }
}

function Compare-IACFilterScalar {
    param($Actual, [string]$ValueType, $Literal, [string]$Operator)

    if ($Literal.ValueType -eq 'Array') { return 'Unknown' }
    $expected = $Literal.Value
    if ($null -eq $Actual -or $Literal.ValueType -eq 'Null') {
        if ($Operator -notin @('eq', 'ne')) { return 'Unknown' }
        $equal = $null -eq $Actual -and $Literal.ValueType -eq 'Null'
        if ($Operator -eq 'ne') { $equal = -not $equal }
        return $(if ($equal) { 'Match' } else { 'NotMatch' })
    }

    if ($ValueType -eq 'Version') {
        $comparison = Compare-IACVersionValue -Left $Actual -Right $expected
        if (-not $comparison.Known) { return 'Unknown' }
        $matched = switch ($Operator) {
            'eq' { $comparison.Comparison -eq 0 }
            'ne' { $comparison.Comparison -ne 0 }
            'gt' { $comparison.Comparison -gt 0 }
            'ge' { $comparison.Comparison -ge 0 }
            'lt' { $comparison.Comparison -lt 0 }
            'le' { $comparison.Comparison -le 0 }
            default { return 'Unknown' }
        }
        return $(if ($matched) { 'Match' } else { 'NotMatch' })
    }

    $actualText = "$Actual"
    $expectedText = "$expected"
    $matched = switch ($Operator) {
        'eq' { [string]::Equals($actualText, $expectedText, [System.StringComparison]::OrdinalIgnoreCase) }
        'ne' { -not [string]::Equals($actualText, $expectedText, [System.StringComparison]::OrdinalIgnoreCase) }
        'contains' { $actualText.IndexOf($expectedText, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'notcontains' { $actualText.IndexOf($expectedText, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 }
        'startswith' { $actualText.StartsWith($expectedText, [System.StringComparison]::OrdinalIgnoreCase) }
        default { return 'Unknown' }
    }
    return $(if ($matched) { 'Match' } else { 'NotMatch' })
}

function Invoke-IACFilterAstEvaluation {
    param($Node, $Device, [System.Collections.Generic.List[string]]$Reasons)

    if ($Node.NodeType -eq 'And') {
        $left = Invoke-IACFilterAstEvaluation -Node $Node.Left -Device $Device -Reasons $Reasons
        $right = Invoke-IACFilterAstEvaluation -Node $Node.Right -Device $Device -Reasons $Reasons
        if ($left -eq 'NotMatch' -or $right -eq 'NotMatch') { return 'NotMatch' }
        if ($left -eq 'Unknown' -or $right -eq 'Unknown') { return 'Unknown' }
        return 'Match'
    }
    if ($Node.NodeType -eq 'Or') {
        $left = Invoke-IACFilterAstEvaluation -Node $Node.Left -Device $Device -Reasons $Reasons
        $right = Invoke-IACFilterAstEvaluation -Node $Node.Right -Device $Device -Reasons $Reasons
        if ($left -eq 'Match' -or $right -eq 'Match') { return 'Match' }
        if ($left -eq 'Unknown' -or $right -eq 'Unknown') { return 'Unknown' }
        return 'NotMatch'
    }

    $resolved = Get-IACDeviceFilterValue -Device $Device -Property $Node.Property
    if (-not $resolved.Known) {
        $Reasons.Add($resolved.Reason)
        return 'Unknown'
    }
    if ($resolved.Operators -notcontains $Node.Operator) {
        $Reasons.Add("Operator '$($Node.Operator)' is not documented for '$($Node.Property)'.")
        return 'Unknown'
    }
    if ($Node.Operator -in @('in', 'notin')) {
        if ($Node.Literal.ValueType -ne 'Array') {
            $Reasons.Add("Operator '$($Node.Operator)' requires an array value.")
            return 'Unknown'
        }
        $sawUnknown = $false
        $matched = $false
        foreach ($literal in @($Node.Literal.Value)) {
            $result = Compare-IACFilterScalar -Actual $resolved.Value -ValueType $resolved.ValueType -Literal $literal -Operator 'eq'
            if ($result -eq 'Match') { $matched = $true; break }
            if ($result -eq 'Unknown') { $sawUnknown = $true }
        }
        if (-not $matched -and $sawUnknown) { return 'Unknown' }
        if ($Node.Operator -eq 'notin') { $matched = -not $matched }
        return $(if ($matched) { 'Match' } else { 'NotMatch' })
    }

    $result = Compare-IACFilterScalar -Actual $resolved.Value -ValueType $resolved.ValueType -Literal $Node.Literal -Operator $Node.Operator
    if ($result -eq 'Unknown') {
        $Reasons.Add("Operator '$($Node.Operator)' or value type is not valid for '$($Node.Property)'.")
    }
    return $result
}

function Test-IACFilterPlatformCompatibility {
    param($Device, [string]$FilterPlatform)

    if ([string]::IsNullOrWhiteSpace($FilterPlatform)) {
        return [PSCustomObject]@{ Compatible = $true; Reason = $null }
    }
    $operatingSystemProperty = Get-IACObjectProperty -InputObject $Device -Names @('operatingSystem')
    if (-not $operatingSystemProperty.Found -or [string]::IsNullOrWhiteSpace("$($operatingSystemProperty.Value)")) {
        return [PSCustomObject]@{ Compatible = $false; Reason = "Device response does not contain operatingSystem required to validate filter platform '$FilterPlatform'." }
    }

    $platformOperatingSystems = @{
        android                   = @('Android')
        androidforwork            = @('Android')
        androidworkprofile        = @('Android')
        androidaosp               = @('Android')
        ios                       = @('iOS', 'iPadOS')
        macos                     = @('macOS')
        windows10andlater         = @('Windows')
        windows81andlater         = @('Windows')
        windowsphone81            = @('Windows Phone')
    }
    $key = $FilterPlatform.ToLowerInvariant()
    if (-not $platformOperatingSystems.ContainsKey($key)) {
        return [PSCustomObject]@{ Compatible = $false; Reason = "Unsupported assignment filter platform '$FilterPlatform'." }
    }
    if ($operatingSystemProperty.Value -notin $platformOperatingSystems[$key]) {
        return [PSCustomObject]@{
            Compatible = $false
            Reason = "Filter platform '$FilterPlatform' is not evaluated by Intune for device operating system '$($operatingSystemProperty.Value)'."
        }
    }
    return [PSCustomObject]@{ Compatible = $true; Reason = $null }
}

function Test-IACAssignmentFilter {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Filter')]
        $Filter,

        [Parameter(Mandatory, ParameterSetName = 'Rule')]
        [AllowEmptyString()]
        [string]$Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Device,

        [Parameter()]
        [string]$FilterMode = 'include'
    )

    $filterId = $filterName = $platform = $managementType = $null
    $ruleText = $Rule
    if ($PSCmdlet.ParameterSetName -eq 'Filter') {
        $filterId = (Get-IACObjectProperty -InputObject $Filter -Names @('Id')).Value
        $filterName = (Get-IACObjectProperty -InputObject $Filter -Names @('Name', 'DisplayName')).Value
        $platform = (Get-IACObjectProperty -InputObject $Filter -Names @('Platform')).Value
        $managementType = (Get-IACObjectProperty -InputObject $Filter -Names @('AssignmentFilterManagementType', 'ManagementType')).Value
        $ruleText = (Get-IACObjectProperty -InputObject $Filter -Names @('Rule')).Value
    }

    $mode = if ([string]::IsNullOrWhiteSpace($FilterMode)) { 'none' } else { $FilterMode.ToLowerInvariant() }
    $ruleResult = 'Unknown'
    $effectiveResult = 'Unknown'
    $reason = $null
    $platformCompatibility = Test-IACFilterPlatformCompatibility -Device $Device -FilterPlatform "$platform"

    if ($mode -eq 'none') {
        $ruleResult = $effectiveResult = 'Match'
        $reason = 'No assignment filter is applied.'
    }
    elseif ($mode -notin @('include', 'exclude')) {
        $reason = "Unsupported assignment filter mode '$FilterMode'."
    }
    elseif ($managementType -and "$managementType" -ine 'devices') {
        $reason = "Filter management type '$managementType' cannot be evaluated against a managed device."
    }
    elseif ($null -eq $Device) {
        $reason = 'Managed-device properties were not provided.'
    }
    elseif (-not $platformCompatibility.Compatible) {
        $reason = $platformCompatibility.Reason
    }
    elseif ([string]::IsNullOrWhiteSpace("$ruleText")) {
        $reason = 'The assignment filter rule is empty.'
    }
    else {
        try {
            $tokens = ConvertTo-IACTokenList -Rule "$ruleText"
            $ast = ConvertTo-IACFilterAst -Tokens $tokens
            $reasons = [System.Collections.Generic.List[string]]::new()
            $ruleResult = Invoke-IACFilterAstEvaluation -Node $ast -Device $Device -Reasons $reasons
            $effectiveResult = if ($mode -eq 'exclude') {
                switch ($ruleResult) {
                    'Match' { 'NotMatch' }
                    'NotMatch' { 'Match' }
                    default { 'Unknown' }
                }
            }
            else { $ruleResult }
            if ($ruleResult -eq 'Unknown') {
                $reason = @($reasons | Select-Object -Unique) -join ' '
                if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'The rule could not be evaluated safely.' }
            }
            else {
                $reason = "Rule evaluated to $ruleResult; $mode filter semantics produce $effectiveResult."
            }
        }
        catch {
            $reason = "Rule could not be parsed safely: $($_.Exception.Message)"
        }
    }

    $deviceId = (Get-IACObjectProperty -InputObject $Device -Names @('id')).Value
    $resolvedDeviceName = (Get-IACObjectProperty -InputObject $Device -Names @('deviceName', 'displayName')).Value
    $result = [PSCustomObject][ordered]@{
        Result         = $effectiveResult
        RuleResult     = $ruleResult
        DeviceId       = $deviceId
        DeviceName     = $resolvedDeviceName
        FilterMode     = $mode
        FilterId       = $filterId
        FilterName     = $filterName
        FilterPlatform = $platform
        ManagementType = $managementType
        Rule           = $ruleText
        Reason         = $reason
    }
    $result.PSObject.TypeNames.Insert(0, 'IntuneAssignmentChecker.AssignmentFilterEvaluation')
    return $result
}
