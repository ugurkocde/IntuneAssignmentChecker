#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $manifestPath = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/IntuneAssignmentChecker.psd1'
    Import-Module $manifestPath -Force
}

AfterAll {
    Remove-Module IntuneAssignmentChecker -Force -ErrorAction SilentlyContinue
}

Describe 'v5 task-oriented terminal UI' {
    It 'maps every operational export to at least one friendly task' {
        $module = Get-Module IntuneAssignmentChecker
        $expected = @($module.ExportedFunctions.Keys | Where-Object {
                $_ -notin @('Get-IntuneAssignmentOperation', 'Invoke-IntuneAssignmentChecker', 'Start-IntuneAssignmentCheckerTui')
            } | Sort-Object)
        $parity = & $module { param($CommandName) Test-IACTuiFeatureParity -CommandName $CommandName } $expected

        $parity.Complete | Should -BeTrue
        $parity.Mapped | Should -Be $expected
        $parity.Missing.Count | Should -Be 0
        $parity.Unknown.Count | Should -Be 0
    }

    It 'provides the approved Command Center workspaces' {
        $registry = & (Get-Module IntuneAssignmentChecker) { Get-IACTuiFeatureRegistry }

        $registry.Id | Should -Be @('Overview', 'Assignments', 'Governance', 'Simulator', 'Drift', 'Health', 'Access', 'Filters', 'Fleet', 'Reports', 'Settings')
        $registry.Title | Should -Contain 'Change simulator'
        $registry.Title | Should -Contain 'RBAC & scope'
        $registry.Title | Should -Contain 'Reports & data'
    }

    It 'keeps command names and PowerShell parameter syntax out of visible workflow copy' {
        $registry = @(& (Get-Module IntuneAssignmentChecker) { Get-IACTuiFeatureRegistry })
        $visibleCopy = @(
            $registry.Title
            $registry.Summary
            $registry.Actions.Label
            $registry.Actions.Description
        ) -join "`n"

        foreach ($commandName in @($registry.Commands)) {
            $visibleCopy | Should -Not -Match ([regex]::Escape($commandName))
        }
        $visibleCopy | Should -Not -Match '(?m)^\s*-[A-Z][A-Za-z]+'
    }

    It 'renders the Draft A layout with the Draft B palette and clickable targets' {
        $result = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState
            $plain = Get-IACTuiFrame -State $state -Width 120 -Height 36
            $ansi = Get-IACTuiFrame -State $state -Width 120 -Height 36 -Ansi
            [PSCustomObject]@{ Plain = $plain; Ansi = $ansi; HitTargets = @($state.HitTargets) }
        }

        $result.Plain | Should -Match 'INTUNE ASSIGNMENT CHECKER'
        $result.Plain | Should -Match 'WORKSPACES'
        $result.Plain | Should -Match 'PRIORITY FINDINGS'
        $result.Plain | Should -Not -Match 'Test-IntuneAssignmentGovernance'
        @($result.Plain -split "`n").Count | Should -Be 36
        @($result.Plain -split "`n" | Where-Object Length -NE 120).Count | Should -Be 0
        $result.Ansi | Should -Match ([regex]::Escape("`e[38;2;244;184;96m"))
        $result.Ansi | Should -Match ([regex]::Escape("`e[48;2;244;184;96m"))
        # Eleven workspace rows plus the clickable tenant/profile indicator.
        @($result.HitTargets | Where-Object Action -EQ Navigate).Count | Should -Be 12
        @($result.HitTargets | Where-Object Action -EQ InvokeAction).Count | Should -BeGreaterThan 0
    }

    It 'wraps every workspace action into a mouse-accessible button' {
        $counts = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Assignments
            $null = Get-IACTuiFrame -State $state -Width 120 -Height 36
            [PSCustomObject]@{
                Expected = @(($state.Registry | Where-Object Id -EQ Assignments).Actions).Count
                Actual = @($state.HitTargets | Where-Object Action -EQ InvokeAction).Count
            }
        }

        $counts.Actual | Should -Be $counts.Expected
        $counts.Actual | Should -BeGreaterThan 1
    }

    It 'parses SGR clicks, releases, movement, modifiers, and wheel input' {
        $events = & (Get-Module IntuneAssignmentChecker) {
            @(
                ConvertFrom-IACTuiInputSequence -Sequence "`e[<0;12;7M"
                ConvertFrom-IACTuiInputSequence -Sequence "`e[<0;12;7m"
                ConvertFrom-IACTuiInputSequence -Sequence "`e[<36;5;9M"
                ConvertFrom-IACTuiInputSequence -Sequence "`e[<64;9;4M"
                ConvertFrom-IACTuiInputSequence -Sequence "`e[<65;9;4M"
            )
        }

        $events[0].Kind | Should -BeExactly Mouse
        $events[0].Button | Should -BeExactly Left
        $events[0].Action | Should -BeExactly Down
        $events[0].X | Should -Be 11
        $events[0].Y | Should -Be 6
        $events[1].Action | Should -BeExactly Up
        $events[2].Action | Should -BeExactly Move
        $events[2].Shift | Should -BeTrue
        $events[3].WheelDelta | Should -Be 1
        $events[4].WheelDelta | Should -Be -1
    }

    It 'resolves the topmost mouse target and routes clicks without executing workflows' {
        $result = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState
            Add-IACTuiHitTarget -State $state -X 1 -Y 1 -Width 8 -Height 2 -Action Navigate -Value Overview
            Add-IACTuiHitTarget -State $state -X 3 -Y 1 -Width 3 -Height 1 -Action Navigate -Value Governance
            $resolved = Get-IACTuiHitTarget -State $state -X 4 -Y 1
            Invoke-IACTuiInputEvent -State $state -InputEvent ([PSCustomObject]@{
                    Kind = 'Mouse'; X = 4; Y = 1; Button = 'Left'; Action = 'Down'; WheelDelta = 0
                }) -SkipActionInvoke
            [PSCustomObject]@{ Resolved = $resolved; ActiveViewId = $state.ActiveViewId }
        }

        $result.Resolved.Value | Should -BeExactly Governance
        $result.ActiveViewId | Should -BeExactly Governance
    }

    It 'provides full keyboard navigation when mouse reporting is unavailable' {
        $state = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState
            Invoke-IACTuiInputEvent -State $state -InputEvent (New-IACTuiKeyEvent -Key DownArrow) -SkipActionInvoke
            Invoke-IACTuiInputEvent -State $state -InputEvent (New-IACTuiKeyEvent -Key Enter) -SkipActionInvoke
            Invoke-IACTuiInputEvent -State $state -InputEvent (New-IACTuiKeyEvent -Key Tab) -SkipActionInvoke
            $state
        }

        $state.ActiveViewId | Should -BeExactly Assignments
        $state.Focus | Should -BeExactly Navigation
    }

    It 'keeps tiny, minimum, and oversized terminal frames renderable' {
        $frames = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Assignments
            [PSCustomObject]@{
                Tiny = Get-IACTuiFrame -State $state -Width 1 -Height 1
                Small = Get-IACTuiFrame -State $state -Width 10 -Height 5
                Minimum = Get-IACTuiFrame -State $state -Width 90 -Height 26
                Oversized = Get-IACTuiFrame -State $state -Width 1200 -Height 600
            }
        }

        $frames.Tiny.Length | Should -Be 1
        @($frames.Small -split "`n").Count | Should -Be 5
        $frames.Minimum | Should -Match 'DETAIL'
        @($frames.Minimum -split "`n").Count | Should -Be 26
        @($frames.Oversized -split "`n").Count | Should -Be 500
    }

    It 'combines Windows VT and mouse flags while disabling Quick Edit' {
        $mode = & (Get-Module IntuneAssignmentChecker) { Get-IACWindowsTuiInputMode -Mode ([uint32]0x0041) }

        ($mode -band 0x0200) | Should -Be 0x0200
        ($mode -band 0x0010) | Should -Be 0x0010
        ($mode -band 0x0080) | Should -Be 0x0080
        ($mode -band 0x0040) | Should -Be 0
        ($mode -band 0x0001) | Should -Be 0x0001
    }

    It 'preserves keyboard-selected least-privilege capability combinations' {
        $selection = @(& (Get-Module IntuneAssignmentChecker) {
            $queue = [Collections.Generic.Queue[object]]::new()
            foreach ($key in @('Spacebar', 'DownArrow', 'Spacebar', 'DownArrow', 'DownArrow', 'Enter')) {
                $queue.Enqueue((New-IACTuiKeyEvent -Key $key))
            }
            $reader = { $queue.Dequeue() }.GetNewClosure()
            $state = New-IACTuiState
            Read-IACTuiMultiChoice -State $state -Title 'Test' -Prompt 'Test' `
                -Choice @('Core', 'Audit', 'Full') -DefaultChoice @('Full') `
                -InputProvider $reader -SuppressRender
        })

        $selection | Should -Be @('Core', 'Audit')
        $selection | Should -Not -Contain Full
    }

    It 'stops connect and switch workflows when capability selection is cancelled' {
        Mock Read-IACTuiChoice -ModuleName IntuneAssignmentChecker { 'Global' }
        Mock Read-IACTuiMultiChoice -ModuleName IntuneAssignmentChecker { $null }
        Mock Read-IACTuiConfirmation -ModuleName IntuneAssignmentChecker { $true }
        Mock Read-IACTuiTextInput -ModuleName IntuneAssignmentChecker { throw 'The workflow continued after cancellation.' }
        Mock Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker {}
        Mock Switch-IntuneAssignmentCheckerTenant -ModuleName IntuneAssignmentChecker {}

        & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Settings
            Invoke-IACTuiWorkflowAction -State $state -ActionId ConnectTenant
            Invoke-IACTuiWorkflowAction -State $state -ActionId SwitchTenant
        }

        Should -Invoke Read-IACTuiMultiChoice -ModuleName IntuneAssignmentChecker -Times 2
        Should -Invoke Read-IACTuiTextInput -ModuleName IntuneAssignmentChecker -Times 0
        Should -Invoke Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker -Times 0
        Should -Invoke Switch-IntuneAssignmentCheckerTenant -ModuleName IntuneAssignmentChecker -Times 0
    }

    It 'separates notices, preserves partial data, and fails only empty error results' {
        $result = & (Get-Module IntuneAssignmentChecker) {
            $warningState = New-IACTuiState -InitialView Settings
            $null = Invoke-IACTuiCapturedOperation -State $warningState -ViewId Settings -SuccessMessage 'Completed.' -SuppressRender -Operation {
                Write-Warning 'Partial workload coverage.'
                [PSCustomObject]@{ Title = 'Result'; Status = 'Available' }
            }
            $partialState = New-IACTuiState -InitialView Assignments
            $partialOutput = @(Invoke-IACTuiCapturedOperation -State $partialState -ViewId Assignments -SuccessMessage 'Loaded.' -SuppressRender -Operation {
                    Write-Error 'One workload was unavailable.'
                    [PSCustomObject]@{ Title = 'Usable result'; Status = 'Available' }
                })
            $errorState = New-IACTuiState -InitialView Settings
            $errorOutput = @(Invoke-IACTuiCapturedOperation -State $errorState -ViewId Settings -SuccessMessage 'Should not appear.' -SuppressRender -Operation {
                    Write-Error 'The requested user was not found.'
                })
            [PSCustomObject]@{
                WarningRows = @($warningState.Rows.Settings)
                WarningStatus = $warningState.StatusStyle
                WarningNotices = @($warningState.Notices.Settings)
                PartialRows = @($partialState.Rows.Assignments)
                PartialNotices = @($partialState.Notices.Assignments)
                PartialStatus = $partialState.StatusStyle
                PartialOutputCount = $partialOutput.Count
                ErrorRows = @($errorState.Rows.Settings)
                ErrorStatus = $errorState.StatusStyle
                ErrorMessage = $errorState.StatusMessage
                ErrorOutputCount = $errorOutput.Count
            }
        }

        $result.WarningRows.Count | Should -Be 1
        $result.WarningRows[0].Title | Should -BeExactly Result
        $result.WarningNotices.Count | Should -Be 1
        $result.WarningStatus | Should -BeExactly Warning
        $result.PartialRows.Count | Should -Be 1
        $result.PartialRows[0].Title | Should -BeExactly 'Usable result'
        $result.PartialNotices.Count | Should -Be 1
        $result.PartialStatus | Should -BeExactly Warning
        $result.PartialOutputCount | Should -Be 1
        $result.ErrorRows[0].Status | Should -BeExactly Error
        $result.ErrorStatus | Should -BeExactly Error
        $result.ErrorMessage | Should -Match 'not found'
        $result.ErrorOutputCount | Should -Be 0
    }

    It 'recognizes legacy host-rendered validation failures as errors' {
        $state = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Simulator
            $output = @(Invoke-IACTuiCapturedOperation -State $state -ViewId Simulator -SuccessMessage 'Should not appear.' -SuppressRender -Operation {
                    Write-Host "Multiple devices match name 'DESKTOP-01'. Use a more specific name." -ForegroundColor Red
                    Write-Host '  - DESKTOP-01 (ID: device-1, OS: Windows)'
                    Write-Host '  - DESKTOP-01 (ID: device-2, OS: Windows)'
                })
            [PSCustomObject]@{ State = $state; OutputCount = $output.Count }
        }

        $state.State.StatusStyle | Should -BeExactly Error
        $state.State.Rows.Simulator[0].Status | Should -BeExactly Error
        $state.State.Rows.Simulator.Count | Should -Be 3
        $state.State.StatusMessage | Should -Match 'Multiple devices match'
        $state.OutputCount | Should -Be 0
    }

    It 'keeps progress messages visible without treating them as semantic results' {
        $result = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Drift
            $output = @(Invoke-IACTuiCapturedOperation -State $state -ViewId Drift -SuccessMessage 'No drift detected.' -SuppressRender -Operation {
                    Write-Host '[1/2] Capturing Device configurations...'
                    Write-Host '[2/2] Capturing Applications...'
                })
            [PSCustomObject]@{ State = $state; OutputCount = $output.Count }
        }

        $result.OutputCount | Should -Be 0
        $result.State.Rows.Drift.Count | Should -Be 2
        $result.State.RawResults.Drift.Count | Should -Be 0
        $result.State.StatusStyle | Should -BeExactly Success
    }

    It 'replaces stale workspace data when an operation terminates' {
        $state = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Assignments
            $state.Rows.Assignments = @([PSCustomObject]@{ Title = 'Stale result'; Status = 'Available' })
            $state.RawResults.Assignments = @([PSCustomObject]@{ Id = 'stale' })
            $state.Notices.Assignments = @([PSCustomObject]@{ Status = 'Warning'; Message = 'Stale notice' })
            $null = Invoke-IACTuiCapturedOperation -State $state -ViewId Assignments -SuccessMessage 'Should not appear.' -SuppressRender -Operation {
                throw 'The operation terminated.'
            }
            $state
        }

        $state.Rows.Assignments.Count | Should -Be 1
        $state.Rows.Assignments[0].Title | Should -BeExactly 'Operation failed'
        $state.RawResults.Assignments[0].Title | Should -BeExactly 'Operation failed'
        $state.Notices.Assignments.Count | Should -Be 1
        $state.Notices.Assignments[0].Message | Should -BeExactly 'The operation terminated.'
        $state.StatusStyle | Should -BeExactly Error
    }

    It 'keeps overview and drift metrics unknown when their operations fail' {
        Mock Test-IACTuiConnected -ModuleName IntuneAssignmentChecker { $true }
        Mock Read-IACTuiTextInput -ModuleName IntuneAssignmentChecker {
            if ($Prompt -like 'Approved baseline*') { 'baseline.json' } else { 'current.json' }
        }
        Mock Invoke-IACTuiCapturedOperation -ModuleName IntuneAssignmentChecker {
            $State.StatusMessage = 'Graph request failed.'
            $State.StatusStyle = 'Error'
            @()
        }

        $states = & (Get-Module IntuneAssignmentChecker) {
            $overview = New-IACTuiState -InitialView Overview
            $overview.Metrics.Critical = 0
            $overview.Metrics.Coverage = 'Complete'
            Invoke-IACTuiWorkflowAction -State $overview -ActionId RefreshOverview

            $drift = New-IACTuiState -InitialView Drift
            $drift.Metrics.Drift = 0
            Invoke-IACTuiWorkflowAction -State $drift -ActionId RefreshDrift
            [PSCustomObject]@{ Overview = $overview; Drift = $drift }
        }

        $states.Overview.Metrics.Critical | Should -BeNullOrEmpty
        $states.Overview.Metrics.Coverage | Should -BeNullOrEmpty
        $states.Drift.Metrics.Drift | Should -BeNullOrEmpty
        $states.Overview.StatusStyle | Should -BeExactly Error
        $states.Drift.StatusStyle | Should -BeExactly Error
    }

    It 'exports scan records and preserves incomplete snapshot coverage' {
        $path = Join-Path $TestDrive 'tui-scan-snapshot.json'
        $snapshot = & (Get-Module IntuneAssignmentChecker) {
            param($Path)
            $script:CurrentTenantId = 'tenant-1'
            $record = New-IACAssignmentRecord -CategoryId Applications -Category Applications `
                -PolicyId app-1 -PolicyName 'Required App' -AssignmentMode Include -TargetType AllUsers
            $run = [PSCustomObject]@{
                Records = @($record)
                Selected = @('Applications', 'WindowsFeatureUpdates')
                Complete = $false
                Errors = @([PSCustomObject]@{ CategoryId = 'WindowsFeatureUpdates'; Message = 'Permission denied.' })
                Skipped = @()
            }
            Export-IACTuiScanRunSnapshot -Run $run -Path $Path
        } $path

        $snapshot.Records.Count | Should -Be 1
        $snapshot.Coverage.Complete | Should -BeFalse
        ($snapshot.Coverage.Categories | Where-Object CategoryId -EQ WindowsFeatureUpdates).Status | Should -BeExactly Failed
    }

    It 'uses Escape as back and reserves Q or Ctrl+C for clean exit' {
        $states = & (Get-Module IntuneAssignmentChecker) {
            $escapeState = New-IACTuiState -InitialView Assignments
            $escapeState.Focus = 'Content'
            Invoke-IACTuiInputEvent -State $escapeState -InputEvent (New-IACTuiKeyEvent -Key Escape) -SkipActionInvoke
            $quitState = New-IACTuiState
            Invoke-IACTuiInputEvent -State $quitState -InputEvent (New-IACTuiKeyEvent -Key Q -Character q) -SkipActionInvoke
            $controlState = New-IACTuiState
            Invoke-IACTuiInputEvent -State $controlState -InputEvent (New-IACTuiKeyEvent -Key C -Character ([char]3) -Modifiers Control) -SkipActionInvoke
            [PSCustomObject]@{ Escape = $escapeState; Quit = $quitState; Control = $controlState }
        }

        $states.Escape.ExitRequested | Should -BeFalse
        $states.Escape.Focus | Should -BeExactly Navigation
        $states.Quit.ExitRequested | Should -BeTrue
        $states.Control.ExitRequested | Should -BeTrue
    }

    It 'keeps the Settings tenant-switch shortcut available from the keyboard' {
        Mock Invoke-IACTuiWorkflowAction -ModuleName IntuneAssignmentChecker {}
        $state = & (Get-Module IntuneAssignmentChecker) {
            $state = New-IACTuiState -InitialView Settings
            $state.Focus = 'Content'
            Invoke-IACTuiInputEvent -State $state -InputEvent (New-IACTuiKeyEvent -Key T -Character t)
            $navigationState = New-IACTuiState -InitialView Settings
            $navigationState.Focus = 'Navigation'
            Invoke-IACTuiInputEvent -State $navigationState -InputEvent (New-IACTuiKeyEvent -Key T -Character t)
            [PSCustomObject]@{ Content = $state; Navigation = $navigationState }
        }

        $state.Content.ActiveViewId | Should -BeExactly Settings
        $state.Navigation.ActiveViewId | Should -BeExactly Settings
        Should -Invoke Invoke-IACTuiWorkflowAction -ModuleName IntuneAssignmentChecker -Times 2 -ParameterFilter { $ActionId -eq 'SwitchTenant' }
    }

    It 'exposes structured non-prompting output on every legacy workflow command' {
        foreach ($name in @(
                'Get-IntuneUserDeviceAssignment', 'Get-IntuneEmptyGroup', 'Search-IntuneSetting',
                'Compare-IntuneGroupAssignment', 'Test-IntuneGroupMembership',
                'Test-IntuneGroupRemoval', 'Get-IntuneFailedAssignment'
            )) {
            (Get-Command $name).Parameters.Keys | Should -Contain PassThru -Because "$name is called inside the command center"
        }
    }

    It 'keeps legacy one-shot switches non-interactive through PassThru dispatch' {
        Mock Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker {}
        Mock Get-MgContext -ModuleName IntuneAssignmentChecker { [PSCustomObject]@{ TenantId = 'tenant-1' } }
        Mock Get-IntuneEmptyGroup -ModuleName IntuneAssignmentChecker {}
        Mock Compare-IntuneGroupAssignment -ModuleName IntuneAssignmentChecker {}
        Mock Get-IntuneFailedAssignment -ModuleName IntuneAssignmentChecker {}
        Mock Test-IntuneGroupMembership -ModuleName IntuneAssignmentChecker {}
        Mock Test-IntuneGroupRemoval -ModuleName IntuneAssignmentChecker {}
        Mock Search-IntuneSetting -ModuleName IntuneAssignmentChecker {}
        Mock Get-IntuneUserDeviceAssignment -ModuleName IntuneAssignmentChecker {}

        Invoke-IntuneAssignmentChecker -CheckEmptyGroups
        Invoke-IntuneAssignmentChecker -CompareGroups -CompareGroupNames 'A,B'
        Invoke-IntuneAssignmentChecker -ShowFailedAssignments
        Invoke-IntuneAssignmentChecker -SimulateGroupMembership -UserPrincipalNames 'user@example.test' -SimulateTargetGroup Group
        Invoke-IntuneAssignmentChecker -SimulateRemoveFromGroup -UserPrincipalNames 'user@example.test' -SimulateRemoveTargetGroup Group
        Invoke-IntuneAssignmentChecker -SearchSetting -SettingKeyword Firewall
        Invoke-IntuneAssignmentChecker -CheckUserAndDevice -UserPrincipalNames 'user@example.test' -DeviceNames Device

        Should -Invoke Get-IntuneEmptyGroup -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Compare-IntuneGroupAssignment -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Get-IntuneFailedAssignment -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Test-IntuneGroupMembership -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Test-IntuneGroupRemoval -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Search-IntuneSetting -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
        Should -Invoke Get-IntuneUserDeviceAssignment -ModuleName IntuneAssignmentChecker -Times 1 -ParameterFilter { $PassThru }
    }

    It 'opens disconnected and does not force authentication before the UI starts' {
        Mock Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker {}
        Mock Start-IntuneAssignmentCheckerTui -ModuleName IntuneAssignmentChecker {}

        Invoke-IntuneAssignmentChecker

        Should -Invoke Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker -Times 0
        Should -Invoke Start-IntuneAssignmentCheckerTui -ModuleName IntuneAssignmentChecker -Times 1
    }
}

Describe 'v5 operation metadata API' {
    It 'continues to expose structured parameter metadata for automation integrations' {
        $operation = Get-IntuneAssignmentOperation -Name Test-IntuneAssignmentGovernance

        $operation.ParameterSets.Count | Should -BeGreaterThan 1
        @($operation.ParameterSets.Parameters.Name) | Should -Contain 'SnapshotPath'
        @($operation.ParameterSets.Parameters.Name) | Should -Contain 'FailOnSeverity'
    }

    It 'uses concise descriptions and parameter help instead of generated syntax' {
        $operations = @(Get-IntuneAssignmentOperation)
        @($operations | Where-Object { $_.Synopsis -match '[\r\n]' -or $_.Synopsis.StartsWith($_.Name) }).Count | Should -Be 0
        $governance = $operations | Where-Object Name -EQ Test-IntuneAssignmentGovernance
        $snapshotParameter = @($governance.ParameterSets.Parameters | Where-Object Name -EQ SnapshotPath)[0]
        $snapshotParameter.HelpMessage | Should -Match 'snapshot'
    }
}

Describe 'v5 capability profiles' {
    It 'resolves Core without unrelated optional permissions' {
        $permissions = @(& (Get-Module IntuneAssignmentChecker) {
                @(Resolve-IACCapabilityPermission -Capability Core).Permission
            })

        $permissions | Should -Contain 'User.Read.All'
        $permissions | Should -Contain 'GroupMember.Read.All'
        $permissions | Should -Contain 'DeviceManagementConfiguration.Read.All'
        $permissions | Should -Contain 'DeviceManagementServiceConfig.Read.All'
        $permissions | Should -Not -Contain 'CloudPC.Read.All'
        $permissions | Should -Not -Contain 'DeviceManagementApps.Read.All'
    }

    It 'reports requested, unavailable, and skipped capability states' {
        $states = @(& (Get-Module IntuneAssignmentChecker) {
            $script:RequestedCapabilities = @('Core')
            Get-IACCapabilityStatus -GrantedPermission @('User.Read.All')
        })

        ($states | Where-Object Name -EQ Core).Status | Should -BeExactly 'Unavailable'
        ($states | Where-Object Name -EQ Core).MissingPermissions | Should -Contain 'GroupMember.Read.All'
        ($states | Where-Object Name -EQ CloudPC).Status | Should -BeExactly 'Skipped'
    }
}

Describe 'v5 governance and simulation objects' {
    BeforeAll {
        $script:testGovernanceRecord = [PSCustomObject]@{
            SchemaName = 'IntuneAssignmentChecker.AssignmentRecord'; SchemaVersion = 2
            PolicyId = 'app-1'; PolicyName = 'Required App'; CategoryId = 'Applications'
            AssignmentId = 'assignment-1'; AssignmentMode = 'Include'; TargetType = 'AllUsers'
            TargetId = $null; TargetName = 'All Users'; Intent = 'required'; ReasonChain = @()
        }
    }

    It 'emits stable evidence-bearing governance findings' {
        $findings = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance)

        $findings.RuleId | Should -Contain 'IAC001'
        $findings.RuleId | Should -Contain 'IAC003'
        $findings[0].FindingId | Should -Match '^[0-9a-f]{24}$'
        $findings[0].Remediation | Should -Not -BeNullOrEmpty
    }

    It 'validates canonical records and findings against the shipped JSON Schemas' {
        $recordSchema = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Schemas/assignment-record.v2.schema.json'
        $findingSchema = Join-Path $PSScriptRoot '../../Module/IntuneAssignmentChecker/Schemas/governance-finding.v1.schema.json'
        $canonicalRecord = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications `
                -PolicyId app-1 -PolicyName 'Required App' -AssignmentMode Include -TargetType AllUsers
        }
        $finding = @($canonicalRecord | Test-IntuneAssignmentGovernance)[0]

        Test-Json -Json ($canonicalRecord | ConvertTo-Json -Depth 20) -SchemaFile $recordSchema | Should -BeTrue
        Test-Json -Json ($finding | ConvertTo-Json -Depth 20) -SchemaFile $findingSchema | Should -BeTrue
    }

    It 'models a broad required assignment without performing a write' {
        $simulation = $script:testGovernanceRecord | Test-IntuneAssignmentChange -ChangeType AddAssignment -PolicyId app-1 -TargetType AllDevices -Intent required

        $simulation.ReadOnly | Should -BeTrue
        $simulation.Risk | Should -BeExactly 'Critical'
        $simulation.After.TargetType | Should -BeExactly 'AllDevices'
        $simulation.After.ReasonChain[-1].Message | Should -Match 'no Microsoft Graph write'
    }

    It 'suppresses active waivers, restores expired findings, and rejects invalid expiry values' {
        $activePath = Join-Path $TestDrive 'active-waiver.json'
        $expiredPath = Join-Path $TestDrive 'expired-waiver.json'
        $invalidPath = Join-Path $TestDrive 'invalid-waiver.json'
        $baseWaiver = [ordered]@{ RuleId = 'IAC001'; PolicyId = 'app-1'; Owner = 'security@example.test'; Justification = 'Approved test'; ExpiresAtUtc = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        [IO.File]::WriteAllText($activePath, (@{ Waivers = @([PSCustomObject]$baseWaiver) } | ConvertTo-Json -Depth 10))
        $expired = [ordered]@{} + $baseWaiver; $expired.ExpiresAtUtc = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o')
        [IO.File]::WriteAllText($expiredPath, (@{ Waivers = @([PSCustomObject]$expired) } | ConvertTo-Json -Depth 10))
        $invalid = [ordered]@{} + $baseWaiver; $invalid.ExpiresAtUtc = 'not-a-date'
        [IO.File]::WriteAllText($invalidPath, (@{ Waivers = @([PSCustomObject]$invalid) } | ConvertTo-Json -Depth 10))

        $active = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $activePath -IncludeSuppressed)
        $expiredFindings = @($script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $expiredPath -IncludeSuppressed)

        ($active | Where-Object RuleId -EQ IAC001).Suppressed | Should -BeTrue
        ($expiredFindings | Where-Object RuleId -EQ IAC001).Suppressed | Should -BeFalse
        { $script:testGovernanceRecord | Test-IntuneAssignmentGovernance -WaiverPath $invalidPath } | Should -Throw '*not a valid UTC date-time*'
    }
}

Describe 'v5 structured output and drift' {
    It 'writes JSON, JSON Lines, and formula-safe CSV from the same object model' {
        $item = [PSCustomObject]@{ PolicyName = '=HYPERLINK("https://example.test")'; Evidence = @{ Value = '+SUM(1,1)' }; Count = 2 }
        $jsonPath = Join-Path $TestDrive 'result.json'
        $jsonLinesPath = Join-Path $TestDrive 'result.jsonl'
        $csvPath = Join-Path $TestDrive 'result.csv'
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format Json } $item $jsonPath | Out-Null
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format JsonLines } $item $jsonLinesPath | Out-Null
        & (Get-Module IntuneAssignmentChecker) { param($Item, $Path) Export-IACStructuredOutput -InputObject @($Item) -Path $Path -Format Csv } $item $csvPath | Out-Null

        (Get-Content $jsonPath -Raw | ConvertFrom-Json)[0].PolicyName | Should -BeExactly $item.PolicyName
        (Get-Content $jsonLinesPath -Raw | ConvertFrom-Json).Evidence.Value | Should -BeExactly '+SUM(1,1)'
        (Import-Csv $csvPath).PolicyName | Should -BeExactly "'$($item.PolicyName)"
    }

    It 'classifies broad added assignments and correlates beta audit evidence' {
        $baselinePath = Join-Path $TestDrive 'drift-baseline.json'
        $currentPath = Join-Path $TestDrive 'drift-current.json'
        $record = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications -PolicyId app-1 -PolicyName 'Required App' `
                -AssignmentId assignment-1 -AssignmentMode Include -TargetType AllUsers -Intent required
        }
        Export-IntuneAssignmentSnapshot -Path $baselinePath -InputObject @() -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        $record | Export-IntuneAssignmentSnapshot -Path $currentPath -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T11:00:00Z')
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker {
            @{ value = @([PSCustomObject]@{ id = 'audit-1'; displayName = 'Create assignment'; activityDateTime = '2026-08-01T10:30:00Z'; actor = [PSCustomObject]@{ userPrincipalName = 'admin@example.test' }; resources = @([PSCustomObject]@{ resourceId = 'app-1'; displayName = 'Required App' }) }) }
        }

        $event = Get-IntuneAssignmentDrift -BaselinePath $baselinePath -CurrentSnapshotPath $currentPath -IncludeAuditAttribution

        $event.Risk | Should -BeExactly 'Critical'
        $event.Attribution | Should -BeExactly 'Correlated'
        $event.AuditActor | Should -BeExactly 'admin@example.test'
    }

    It 'refuses non-HTTPS drift webhooks before transmitting data' {
        $path = Join-Path $TestDrive 'same-snapshot.json'
        & (Get-Module IntuneAssignmentChecker) { $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One' }
        Export-IntuneAssignmentSnapshot -Path $path -InputObject @() -CoverageCategory Applications -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        Mock Invoke-RestMethod -ModuleName IntuneAssignmentChecker

        { Get-IntuneAssignmentDrift -BaselinePath $path -CurrentSnapshotPath $path -WebhookUri 'http://example.test/hook' -Confirm:$false } |
            Should -Throw '*absolute HTTPS URI*'
        Should -Invoke Invoke-RestMethod -ModuleName IntuneAssignmentChecker -Exactly 0
    }
}

Describe 'v5 delivery health normalization' {
    It 'maps live report numeric states and string states consistently' {
        $states = & (Get-Module IntuneAssignmentChecker) {
            ConvertTo-IACDeliveryState 2
            ConvertTo-IACDeliveryState 3
            ConvertTo-IACDeliveryState conflict
            ConvertTo-IACDeliveryState notApplicable
        }
        $states | Should -Be @('Succeeded', 'Failed', 'Conflict', 'NotApplicable')
    }

    It 'maps schema columns to report values by position' {
        $row = & (Get-Module IntuneAssignmentChecker) {
            $report = [PSCustomObject]@{
                Schema = @([PSCustomObject]@{ Column = 'DeviceId' }, [PSCustomObject]@{ Column = 'PolicyStatus' })
                Values = @(, @('device-1', 2))
            }
            ConvertFrom-IACReportRows -Report $report
        }

        $row.DeviceId | Should -BeExactly 'device-1'
        $row.PolicyStatus | Should -Be 2
    }
}

Describe 'v5 resumable scan runner' {
    It 'writes a token-free category checkpoint and returns run diagnostics' {
        $checkpointPath = Join-Path $TestDrive 'scan.json'
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CurrentTenantId = 'tenant-1'
            $script:CurrentTenantName = 'Tenant One'
        }
        Mock Get-IntuneCategoryDefinition -ModuleName IntuneAssignmentChecker {
            @(
                [PSCustomObject]@{ Id = 'One'; DisplayName = 'One' }
                [PSCustomObject]@{ Id = 'Two'; DisplayName = 'Two' }
            )
        }
        Mock Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{ Records = @(); Errors = @(); Skipped = @() }
        }

        $run = Invoke-IntuneAssignmentScan -CheckpointPath $checkpointPath -KeepCheckpoint

        $run.Complete | Should -BeTrue
        $run.Completed | Should -Be @('One', 'Two')
        $run.Diagnostics.ProviderCount | Should -Be 2
        Test-Path -LiteralPath $checkpointPath | Should -BeTrue
        (Get-Content -LiteralPath $checkpointPath -Raw) | Should -Not -Match '(?i)access.?token|client.?secret|password'
        Should -Invoke Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker -Exactly 2

        $resumed = Invoke-IntuneAssignmentScan -CheckpointPath $checkpointPath -Resume -KeepCheckpoint
        $resumed.Complete | Should -BeTrue
        $resumed.Completed | Should -Be @('One', 'Two')
        Should -Invoke Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker -Exactly 2
    }
}

Describe 'v5 coverage-aware commands' {
    It 'treats optional skipped workloads as transparent but non-blocking coverage' {
        $snapshotPath = Join-Path $TestDrive 'optional-skip.json'
        $filterPath = Join-Path $TestDrive 'optional-filters.json'
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CurrentTenantId = 'tenant-1'
            $script:CurrentTenantName = 'Tenant One'
        }
        Mock Get-IntuneCategoryDefinition -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ Id = 'CloudPCProvisioningPolicies'; DisplayName = 'Cloud PC Provisioning Policies' })
        }
        Mock Get-AssignmentFilterLookup -ModuleName IntuneAssignmentChecker { @{} }
        Mock Invoke-IntuneCategoryScan -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{
                Records = @(); Errors = @()
                Skipped = @([PSCustomObject]@{ CategoryId = 'CloudPCProvisioningPolicies'; Message = 'Workload is not licensed.' })
            }
        }
        Export-IntuneAssignmentSnapshot -Path $snapshotPath -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        [IO.File]::WriteAllText($filterPath, (@{ Filters = @(@{ Id = 'filter-1'; Name = 'Unused'; Platform = 'windows10AndLater'; Rule = '(device.osVersion -startsWith "10.")'; AssignmentFilterManagementType = 'devices' }) } | ConvertTo-Json -Depth 10))

        $governance = @(Test-IntuneAssignmentGovernance -SnapshotPath $snapshotPath)
        $filters = @(Test-IntuneAssignmentFilterSet -SnapshotPath $snapshotPath -FilterDefinitionPath $filterPath)
        $approval = Get-IntuneAssignmentDrift -BaselinePath (Join-Path $TestDrive 'approved-optional.json') `
            -CurrentSnapshotPath $snapshotPath -ApproveBaseline

        $governance.RuleId | Should -Not -Contain IAC007
        $filters.RuleId | Should -Contain IAF001
        $filters.RuleId | Should -Not -Contain IAF007
        $approval.Complete | Should -BeTrue
    }

    It 'fails a tenant entry without unattended credentials and continues the fleet result contract' {
        $configurationPath = Join-Path $TestDrive 'fleet.json'
        [IO.File]::WriteAllText($configurationPath, (@{ schemaVersion = 1; tenants = @(@{ TenantId = 'tenant-1' }) } | ConvertTo-Json -Depth 10))
        Mock Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker
        Mock Disconnect-MgGraph -ModuleName IntuneAssignmentChecker
        Mock Read-Host -ModuleName IntuneAssignmentChecker { throw 'Interactive prompt was reached.' }

        $errors = @()
        $result = Invoke-IntuneAssignmentFleetScan -ConfigurationPath $configurationPath -ErrorVariable +errors

        $result.Status | Should -BeExactly 'Failed'
        $result.Error | Should -Match 'unattended'
        Should -Invoke Connect-IntuneAssignmentChecker -ModuleName IntuneAssignmentChecker -Exactly 0
        Should -Invoke Read-Host -ModuleName IntuneAssignmentChecker -Exactly 0
    }

    It 'suppresses unused-filter findings when assignment coverage is incomplete' {
        $snapshotPath = Join-Path $TestDrive 'filter-partial.json'
        $filterPath = Join-Path $TestDrive 'filters.json'
        $record = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId Applications -Category Applications -PolicyId app-1 -PolicyName App `
                -AssignmentId assignment-1 -AssignmentMode Include -TargetType Group -TargetId group-1
        }
        $coverageError = [PSCustomObject]@{ CategoryId = 'CompliancePolicies'; Message = 'HTTP 403' }
        $record | Export-IntuneAssignmentSnapshot -Path $snapshotPath -CoverageCategory Applications,CompliancePolicies -CoverageError $coverageError -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        [IO.File]::WriteAllText($filterPath, (@{ Filters = @(@{ Id = 'filter-1'; Name = 'Unused'; Platform = 'windows10AndLater'; Rule = '(device.osVersion -startsWith "10.")'; AssignmentFilterManagementType = 'devices' }) } | ConvertTo-Json -Depth 10))

        $findings = @(Test-IntuneAssignmentFilterSet -SnapshotPath $snapshotPath -FilterDefinitionPath $filterPath)

        $findings.RuleId | Should -Contain IAF007
        $findings.RuleId | Should -Not -Contain IAF001
    }

    It 'collapses broad RBAC access to one result while preserving policy count' {
        $snapshotPath = Join-Path $TestDrive 'access.json'
        $records = & (Get-Module IntuneAssignmentChecker) {
            $script:CurrentTenantId = 'tenant-1'; $script:CurrentTenantName = 'Tenant One'
            New-IACAssignmentRecord -CategoryId DeviceConfigurations -Category Configuration -PolicyId policy-1 -PolicyName One -AssignmentMode None -TargetType None
            New-IACAssignmentRecord -CategoryId DeviceConfigurations -Category Configuration -PolicyId policy-2 -PolicyName Two -AssignmentMode None -TargetType None
        }
        $records | Export-IntuneAssignmentSnapshot -Path $snapshotPath -CoverageCategory DeviceConfigurations -CoverageComplete -CapturedAtUtc ([datetimeoffset]'2026-08-01T10:00:00Z')
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com'; $script:CurrentTenantId = 'tenant-1' }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker {
            if ($Uri -like '*roleDefinitions*') { return @{ value = @([PSCustomObject]@{ id = 'definition-1'; displayName = 'Intune Administrator'; roleAssignments = @([PSCustomObject]@{ id = 'role-1' }) }) } }
            @{ value = @([PSCustomObject]@{ id = 'role-1'; displayName = 'Broad administrators'; members = @('group-1'); resourceScopes = @(); roleScopeTagIds = @('0') }) }
        }

        $access = @(Get-IntuneAssignmentAccess -SnapshotPath $snapshotPath)

        $access.Count | Should -Be 1
        $access[0].BoundaryStatus | Should -BeExactly 'Broad'
        $access[0].MatchingPolicyCount | Should -Be 2
    }

    It 'reports inventory permission failures as failed health coverage' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker { throw 'HTTP 403 Forbidden' }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        $health.Count | Should -Be 1
        $health[0].RecordType | Should -BeExactly 'Coverage'
        $health[0].CoverageStatus | Should -BeExactly 'Failed'
        $health[0].CoverageMessage | Should -Match '403'
    }

    It 'keeps legitimate multi-user rows for the same managed device' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ id = 'policy-1'; displayName = 'Shared device policy' })
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportResponse -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportRows -ModuleName IntuneAssignmentChecker {
            @(
                [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'SharedPC'; UPN = 'one@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
                [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'SharedPC'; UPN = 'two@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
            )
        }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        @($health | Where-Object RecordType -EQ Status).Count | Should -Be 2
        ($health | Where-Object RecordType -EQ Coverage).CoverageStatus | Should -BeExactly 'Complete'
    }

    It 'stops an exact repeated health row and reports failed coverage' {
        & (Get-Module IntuneAssignmentChecker) { $script:GraphEndpoint = 'https://graph.microsoft.com' }
        Mock Get-IntuneEntities -ModuleName IntuneAssignmentChecker {
            @([PSCustomObject]@{ id = 'policy-1'; displayName = 'Repeated report policy' })
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportResponse -ModuleName IntuneAssignmentChecker { @{} }
        Mock ConvertFrom-IACReportRows -ModuleName IntuneAssignmentChecker {
            $row = [PSCustomObject]@{ IntuneDeviceId = 'device-1'; DeviceName = 'PC'; UPN = 'one@example.test'; PolicyStatus = 2; PspdpuLastModifiedTimeUtc = '2026-08-01T10:00:00Z' }
            @($row, $row.PSObject.Copy())
        }

        $health = @(Get-IntuneAssignmentHealth -Workload DeviceConfiguration)

        @($health | Where-Object RecordType -EQ Status).Count | Should -Be 0
        ($health | Where-Object RecordType -EQ Coverage).CoverageStatus | Should -BeExactly 'Failed'
        ($health | Where-Object RecordType -EQ Coverage).CoverageMessage | Should -Match 'repeated device rows'
    }
}

Describe 'v5 environment diagnostics' {
    It 'uses first-page-only beta probes for every applicable workload' {
        & (Get-Module IntuneAssignmentChecker) {
            $script:GraphEndpoint = 'https://graph.microsoft.com'
            $script:CapabilityStatus = @()
        }
        Mock Get-MgContext -ModuleName IntuneAssignmentChecker {
            [PSCustomObject]@{ TenantId = 'tenant-1'; Environment = 'Global' }
        }
        Mock Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker { @{ value = @() } }

        $diagnostics = @(Test-IntuneAssignmentCheckerEnvironment)

        @($diagnostics | Where-Object Check -Like 'Graph.*' | Where-Object Check -NE GraphConnection).Count | Should -Be 4
        Should -Invoke Invoke-IACGraphRequest -ModuleName IntuneAssignmentChecker -Exactly 4 -ParameterFilter {
            $Method -eq 'GET' -and $FirstPageOnly
        }
    }
}
