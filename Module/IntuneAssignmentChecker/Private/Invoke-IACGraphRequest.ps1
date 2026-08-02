function Invoke-IACGraphRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [object]$Body,

        [Parameter()]
        [switch]$AllPages,

        [Parameter()]
        [switch]$FirstPageOnly,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 3,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$MaxPageCount = 1000
    )

    if ([string]::IsNullOrWhiteSpace($script:GraphEndpoint)) {
        throw 'Microsoft Graph is not connected. Run Connect-IntuneAssignmentChecker first.'
    }
    if ($AllPages -and $FirstPageOnly) {
        throw '-AllPages and -FirstPageOnly cannot be used together.'
    }

    $graphBase = $script:GraphEndpoint.TrimEnd('/')
    $requestUri = $Uri.Trim()

    # OData filters commonly contain literal spaces. IsWellFormedUriString rejects those,
    # so detect the scheme first and validate a safely escaped copy of the authority.
    $isAbsolute = $requestUri -match '^[a-z][a-z0-9+.-]*://'
    if ($isAbsolute) {
        $parsedRequestUri = $null
        $parseCandidate = $requestUri -replace ' ', '%20'
        if (-not [uri]::TryCreate($parseCandidate, [System.UriKind]::Absolute, [ref]$parsedRequestUri)) {
            throw 'Graph request URI is not a valid absolute URI.'
        }
        $parsedGraphBase = [uri]$graphBase
        if ($parsedRequestUri.Scheme -ne $parsedGraphBase.Scheme -or
            $parsedRequestUri.Host -ne $parsedGraphBase.Host -or
            $parsedRequestUri.Port -ne $parsedGraphBase.Port -or
            -not $requestUri.StartsWith("$graphBase/", [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Graph request URI '$requestUri' does not match the active cloud endpoint '$graphBase'."
        }

        $relativePath = $requestUri.Substring($graphBase.Length)
    }
    else {
        $relativePath = if ($requestUri.StartsWith('/')) { $requestUri } else { "/$requestUri" }
    }

    # The module intentionally targets Microsoft Graph beta. Normalize callers and nextLink
    # values through the same path so a stale version cannot silently bypass this policy.
    $relativePath = $relativePath -replace '^/(?:v1\.0|beta)(?=/|$)', ''
    $currentUri = "$graphBase/beta$relativePath"
    $items = [System.Collections.Generic.List[object]]::new()
    $visitedPageUris = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pageCount = 0
    $includeBody = $PSBoundParameters.ContainsKey('Body')
    $firstResponse = $null

    do {
        $pageCount++
        if ($pageCount -gt $MaxPageCount) {
            throw "Microsoft Graph paging exceeded the configured maximum of $MaxPageCount pages."
        }
        if (-not $visitedPageUris.Add($currentUri)) {
            throw 'Microsoft Graph returned a repeated nextLink; paging was stopped to prevent an infinite loop.'
        }

        $attempt = 0
        while ($true) {
            try {
                $requestParameters = @{
                    Uri         = $currentUri
                    Method      = $Method
                    ErrorAction = 'Stop'
                }
                if ($includeBody) {
                    $requestParameters['Body'] = $Body
                }

                $response = Invoke-MgGraphRequest @requestParameters
                break
            }
            catch {
                $attempt++
                $statusCode = $null
                foreach ($candidate in @(
                        $_.Exception.Response.StatusCode,
                        $_.Exception.StatusCode,
                        $_.Exception.ResponseStatusCode
                    )) {
                    if ($null -eq $candidate) { continue }
                    try {
                        $statusCode = [int]$candidate
                        break
                    }
                    catch { }
                }
                if ($null -eq $statusCode) {
                    foreach ($pattern in @(
                            '(?i)\bHTTP(?:\s+status)?\s+(?<Status>4\d\d|5\d\d)\b',
                            '(?i)response status code does not indicate success:\s*(?<Status>4\d\d|5\d\d)\b'
                        )) {
                        if ($_.Exception.Message -match $pattern) {
                            $statusCode = [int]$Matches.Status
                            break
                        }
                    }
                }

                $retryAfterSeconds = $null
                try {
                    $retryAfterHeader = $_.Exception.Response.Headers.'Retry-After'
                    if ($retryAfterHeader -is [System.Collections.IEnumerable] -and $retryAfterHeader -isnot [string]) {
                        $retryAfterHeader = @($retryAfterHeader)[0]
                    }
                    if ($retryAfterHeader) { $retryAfterSeconds = [int]$retryAfterHeader }
                }
                catch { }
                if ($null -eq $retryAfterSeconds) {
                    try {
                        $delta = $_.Exception.Response.Headers.RetryAfter.Delta
                        if ($delta) { $retryAfterSeconds = [int][math]::Ceiling($delta.TotalSeconds) }
                    }
                    catch { }
                }

                $baseException = $_.Exception.GetBaseException()
                $isConnectionTransient = $null -eq $statusCode -and (
                    $baseException -is [System.TimeoutException] -or
                    $baseException -is [System.Net.Http.HttpRequestException] -or
                    $baseException -is [System.Net.WebException] -or
                    $baseException -is [System.Threading.Tasks.TaskCanceledException]
                )
                $isTransient = $statusCode -eq 429 -or
                    ($null -ne $statusCode -and $statusCode -ge 500 -and $statusCode -le 599) -or
                    $isConnectionTransient
                if ($isTransient -and $attempt -le $MaxRetryCount) {
                    $delaySeconds = if ($null -ne $retryAfterSeconds -and $retryAfterSeconds -ge 0) {
                        $retryAfterSeconds
                    }
                    else {
                        [math]::Min([math]::Pow(2, $attempt - 1), 30)
                    }
                    Write-Verbose "Microsoft Graph returned HTTP $statusCode for '$currentUri'. Retrying in $delaySeconds second(s) (attempt $attempt of $MaxRetryCount)."
                    if ($delaySeconds -gt 0) { Start-Sleep -Seconds $delaySeconds }
                    continue
                }

                $graphErrorCode = $null
                $graphErrorMessage = $_.Exception.Message
                $requestId = $null
                $clientRequestId = $null
                $errorPayload = $_.ErrorDetails.Message
                if (-not [string]::IsNullOrWhiteSpace($errorPayload)) {
                    try {
                        $parsedError = $errorPayload | ConvertFrom-Json -Depth 20 -ErrorAction Stop
                        $graphError = if ($parsedError.error) { $parsedError.error } else { $parsedError }
                        if ($graphError.code) { $graphErrorCode = [string]$graphError.code }
                        if ($graphError.message) { $graphErrorMessage = [string]$graphError.message }
                        $innerError = $graphError.innerError
                        if ($innerError) {
                            $requestId = $innerError.'request-id'
                            $clientRequestId = $innerError.'client-request-id'
                        }
                    }
                    catch { }
                }

                $statusText = if ($null -ne $statusCode) { "HTTP $statusCode" } else { 'HTTP status unavailable' }
                $codeText = if ($graphErrorCode) { " ($graphErrorCode)" } else { '' }
                $message = "Microsoft Graph request failed: $statusText$codeText - $graphErrorMessage"
                $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                $exception.Data['StatusCode'] = $statusCode
                $exception.Data['GraphErrorCode'] = $graphErrorCode
                $exception.Data['RequestId'] = $requestId
                $exception.Data['ClientRequestId'] = $clientRequestId
                $exception.Data['RequestUri'] = $currentUri
                $exception.Data['Method'] = $Method
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $exception,
                    'IntuneAssignmentChecker.GraphRequestFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $currentUri
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }

        if ($null -eq $firstResponse) { $firstResponse = $response }

        $nextLink = if ($response) { $response.'@odata.nextLink' } else { $null }
        if ($FirstPageOnly) { return $response }
        if (-not $AllPages -and $pageCount -eq 1 -and [string]::IsNullOrWhiteSpace($nextLink)) {
            return $response
        }

        if ($response -and $null -ne $response.value) {
            foreach ($item in @($response.value)) { $items.Add($item) }
        }
        elseif ($AllPages -and $null -ne $response) {
            $items.Add($response)
        }

        if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
            if (-not $nextLink.StartsWith("$graphBase/beta/", [System.StringComparison]::OrdinalIgnoreCase)) {
                $exception = [System.Security.SecurityException]::new('Microsoft Graph returned a nextLink outside the active beta endpoint.')
                $exception.Data['StatusCode'] = $null
                $exception.Data['RequestUri'] = $nextLink
                $exception.Data['Method'] = 'GET'
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $exception,
                    'IntuneAssignmentChecker.InvalidGraphNextLink',
                    [System.Management.Automation.ErrorCategory]::SecurityError,
                    $nextLink
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            $currentUri = $nextLink
            $Method = 'GET'
            $includeBody = $false
        }
    } while (-not [string]::IsNullOrWhiteSpace($currentUri) -and -not [string]::IsNullOrWhiteSpace($nextLink))

    if ($AllPages) {
        return , $items.ToArray()
    }

    # Preserve the normal response contract while replacing the first-page value with the
    # complete collection. This makes paging automatic for existing response.value callers.
    $combinedResponse = [ordered]@{}
    if ($firstResponse -is [System.Collections.IDictionary]) {
        foreach ($key in $firstResponse.Keys) {
            if ($key -notin @('value', '@odata.nextLink')) { $combinedResponse[$key] = $firstResponse[$key] }
        }
    }
    else {
        foreach ($property in $firstResponse.PSObject.Properties) {
            if ($property.Name -notin @('value', '@odata.nextLink')) { $combinedResponse[$property.Name] = $property.Value }
        }
    }
    $combinedResponse['value'] = $items.ToArray()
    return [PSCustomObject]$combinedResponse
}
