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

    . (Join-Path $moduleRoot 'Private/Invoke-IACGraphRequest.ps1')
}

Describe 'Invoke-IACGraphRequest' {
    BeforeEach {
        $script:GraphEndpoint = 'https://graph.test'
        $script:requestCount = 0
        Mock Start-Sleep
    }

    It 'normalizes relative and legacy-version paths to the active beta endpoint' {
        Mock Invoke-MgGraphRequest { @{ value = @() } }

        Invoke-IACGraphRequest -Uri '/v1.0/groups' | Out-Null
        Invoke-IACGraphRequest -Uri 'deviceManagement/configurationPolicies' | Out-Null

        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/groups' -and $Method -eq 'GET'
        }
        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter {
            $Uri -eq 'https://graph.test/beta/deviceManagement/configurationPolicies' -and $Method -eq 'GET'
        }
    }

    It 'preserves realistic OData filters, selects, and keyed resource paths' {
        Mock Invoke-MgGraphRequest { @{ value = @() } }
        $realisticUri = "https://graph.test/beta/groups?`$filter=displayName eq 'My Group'&`$select=id,displayName"
        $keyedUri = "https://graph.test/beta/deviceManagement/deviceShellScripts('script-id')/groupAssignments"

        Invoke-IACGraphRequest -Uri $realisticUri | Out-Null
        Invoke-IACGraphRequest -Uri $keyedUri | Out-Null

        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter { $Uri -eq $realisticUri }
        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter { $Uri -eq $keyedUri }
    }

    It 'follows beta nextLink pages when AllPages is requested' {
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*skiptoken=next') {
                return @{ value = @([PSCustomObject]@{ id = 'two' }) }
            }
            return @{
                value = @([PSCustomObject]@{ id = 'one' })
                '@odata.nextLink' = 'https://graph.test/beta/groups?$skiptoken=next'
            }
        }

        $result = Invoke-IACGraphRequest -Uri '/groups' -AllPages

        $result -is [array] | Should -BeTrue
        $result.id | Should -Be @('one', 'two')
        Should -Invoke Invoke-MgGraphRequest -Exactly 2
    }

    It 'automatically combines pages for existing response.value callers' {
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*skiptoken=next') {
                return @{ value = @([PSCustomObject]@{ id = 'two' }) }
            }
            return @{
                '@odata.context' = 'context'
                value = @([PSCustomObject]@{ id = 'one' })
                '@odata.nextLink' = 'https://graph.test/beta/groups?$skiptoken=next'
            }
        }

        $response = Invoke-IACGraphRequest -Uri '/groups'

        $response.'@odata.context' | Should -BeExactly 'context'
        $response.value.id | Should -Be @('one', 'two')
        $response.PSObject.Properties.Name | Should -Not -Contain '@odata.nextLink'
        Should -Invoke Invoke-MgGraphRequest -Exactly 2
    }

    It 'retries transient responses and succeeds' {
        Mock Invoke-MgGraphRequest {
            $script:requestCount++
            if ($script:requestCount -lt 3) { throw 'HTTP 429 Too Many Requests' }
            @{ value = @([PSCustomObject]@{ id = 'ok' }) }
        }

        $result = Invoke-IACGraphRequest -Uri '/groups' -MaxRetryCount 3

        $result.value[0].id | Should -BeExactly 'ok'
        Should -Invoke Invoke-MgGraphRequest -Exactly 3
        Should -Invoke Start-Sleep -Exactly 2
    }

    It 'retries typed connection failures without guessing status codes from unrelated numbers' {
        Mock Invoke-MgGraphRequest {
            $script:requestCount++
            if ($script:requestCount -eq 1) { throw [System.TimeoutException]::new('socket timeout') }
            @{ value = @() }
        }

        Invoke-IACGraphRequest -Uri '/groups?$top=500' | Out-Null

        Should -Invoke Invoke-MgGraphRequest -Exactly 2
        Should -Invoke Start-Sleep -Exactly 1
    }

    It 'does not retry permanent 4xx responses' {
        Mock Invoke-MgGraphRequest { throw 'HTTP 403 Forbidden' }

        { Invoke-IACGraphRequest -Uri '/groups' -MaxRetryCount 3 } | Should -Throw

        Should -Invoke Invoke-MgGraphRequest -Exactly 1
        Should -Invoke Start-Sleep -Exactly 0
    }

    It 'does not retry a status-bearing HttpRequestException for a permanent 4xx' {
        Mock Invoke-MgGraphRequest {
            throw [System.Net.Http.HttpRequestException]::new(
                'Response status code does not indicate success: 403 (Forbidden).',
                $null,
                [System.Net.HttpStatusCode]::Forbidden
            )
        }

        { Invoke-IACGraphRequest -Uri '/groups' -MaxRetryCount 3 } | Should -Throw

        Should -Invoke Invoke-MgGraphRequest -Exactly 1
        Should -Invoke Start-Sleep -Exactly 0
    }

    It 'throws after the configured transient retry count is exhausted' {
        Mock Invoke-MgGraphRequest { throw 'HTTP 503 Service Unavailable' }

        { Invoke-IACGraphRequest -Uri '/groups' -MaxRetryCount 2 } | Should -Throw

        Should -Invoke Invoke-MgGraphRequest -Exactly 3
        Should -Invoke Start-Sleep -Exactly 2
    }

    It 'honors Retry-After without shortening the server delay' {
        Mock Invoke-MgGraphRequest {
            $script:requestCount++
            if ($script:requestCount -eq 1) {
                $exception = [System.Exception]::new('HTTP 429 Too Many Requests')
                $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([PSCustomObject]@{
                        Headers = [PSCustomObject]@{ 'Retry-After' = '75' }
                    })
                throw $exception
            }
            @{ value = @() }
        }

        Invoke-IACGraphRequest -Uri '/groups' | Out-Null

        Should -Invoke Start-Sleep -Exactly 1 -ParameterFilter { $Seconds -eq 75 }
    }

    It 'forwards a POST body only on the first page' {
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*skiptoken=next') { return @{ value = @('two') } }
            return @{ value = @('one'); '@odata.nextLink' = 'https://graph.test/beta/reports/items?$skiptoken=next' }
        }
        $body = @{ select = @('id') }

        $result = Invoke-IACGraphRequest -Uri '/reports/items' -Method POST -Body $body -AllPages

        $result -is [array] | Should -BeTrue
        $result | Should -Be @('one', 'two')
        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter { $Method -eq 'POST' -and $Body -eq $body }
        Should -Invoke Invoke-MgGraphRequest -Exactly 1 -ParameterFilter { $Method -eq 'GET' }
    }

    It 'preserves structured Graph error details in a terminating error' {
        Mock Invoke-MgGraphRequest {
            $record = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('HTTP 403 Forbidden'),
                'GraphFailure',
                [System.Management.Automation.ErrorCategory]::PermissionDenied,
                $Uri
            )
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"Authorization_RequestDenied","message":"Denied","innerError":{"request-id":"request-1","client-request-id":"client-1"}}}')
            throw $record
        }

        $caught = $null
        try { Invoke-IACGraphRequest -Uri '/groups' -MaxRetryCount 0 }
        catch { $caught = $_ }

        $caught.FullyQualifiedErrorId | Should -Match '^IntuneAssignmentChecker.GraphRequestFailed'
        $caught.Exception.Data['StatusCode'] | Should -Be 403
        $caught.Exception.Data['GraphErrorCode'] | Should -BeExactly 'Authorization_RequestDenied'
        $caught.Exception.Data['RequestId'] | Should -BeExactly 'request-1'
        $caught.Exception.Data['ClientRequestId'] | Should -BeExactly 'client-1'
    }

    It 'rejects absolute URLs outside the active cloud endpoint' {
        Mock Invoke-MgGraphRequest
        { Invoke-IACGraphRequest -Uri 'https://graph.microsoft.com/beta/groups' } |
            Should -Throw '*does not match the active cloud endpoint*'
        Should -Invoke Invoke-MgGraphRequest -Exactly 0
    }

    It 'rejects a nextLink outside beta with a structured security error' {
        Mock Invoke-MgGraphRequest {
            @{ value = @(); '@odata.nextLink' = 'https://graph.test/v1.0/groups?$skiptoken=next' }
        }

        $caught = $null
        try { Invoke-IACGraphRequest -Uri '/groups' -AllPages }
        catch { $caught = $_ }

        $caught.FullyQualifiedErrorId | Should -Match '^IntuneAssignmentChecker.InvalidGraphNextLink'
        $caught.Exception.Data['RequestUri'] | Should -BeExactly 'https://graph.test/v1.0/groups?$skiptoken=next'
    }

    It 'stops repeated nextLink loops and enforces a page cap' {
        Mock Invoke-MgGraphRequest {
            @{ value = @(); '@odata.nextLink' = 'https://graph.test/beta/groups' }
        }

        { Invoke-IACGraphRequest -Uri '/groups' -AllPages } | Should -Throw '*repeated nextLink*'

        Mock Invoke-MgGraphRequest {
            @{ value = @(); '@odata.nextLink' = 'https://graph.test/beta/groups?page=2' }
        }
        { Invoke-IACGraphRequest -Uri '/groups' -AllPages -MaxPageCount 1 } | Should -Throw '*maximum of 1 pages*'
    }

    It 'returns an empty collection for an empty paged response' {
        Mock Invoke-MgGraphRequest { @{ value = @() } }

        $result = Invoke-IACGraphRequest -Uri '/groups' -AllPages

        $result -is [array] | Should -BeTrue
        $result.Count | Should -Be 0
    }

    It 'requires an active Graph endpoint' {
        Mock Invoke-MgGraphRequest
        $script:GraphEndpoint = $null

        { Invoke-IACGraphRequest -Uri '/groups' } | Should -Throw '*Connect-IntuneAssignmentChecker*'
        Should -Invoke Invoke-MgGraphRequest -Exactly 0
    }

    It 'keeps direct Graph SDK calls and v1.0 literals out of module code' {
        $files = Get-ChildItem -Path $moduleRoot -Recurse -File -Include *.ps1, *.psm1
        $sdkCalls = @($files | Where-Object { $_.Name -ne 'Invoke-IACGraphRequest.ps1' } |
                Select-String -Pattern 'Invoke-MgGraphRequest')
        $legacyVersions = @($files | Select-String -Pattern '/v1\.0/')

        $sdkCalls.Count | Should -Be 0
        $legacyVersions.Count | Should -Be 0
    }
}
