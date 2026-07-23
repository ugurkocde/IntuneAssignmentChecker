#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $repoRoot = Join-Path $PSScriptRoot '../..'
    $script:registrationScript = Get-Content -Path (Join-Path $repoRoot 'Register-IntuneAssignmentCheckerApp.ps1') -Raw
    $script:moduleScript = Get-Content -Path (Join-Path $repoRoot 'Module/IntuneAssignmentChecker/IntuneAssignmentChecker.psm1') -Raw
    $script:readme = Get-Content -Path (Join-Path $repoRoot 'README.md') -Raw
}

Describe 'Least-privilege group permission configuration' {
    It 'configures GroupMember.Read.All as an application role' {
        $script:registrationScript | Should -Match '98830695-27a2-44f7-8c18-0c3ebc9698f6'
        $script:registrationScript | Should -Match 'displayName\s*=\s*"GroupMember\.Read\.All"'
        $script:registrationScript | Should -Match '\$permissions \| ForEach-Object \{ @\{ id = \$_.id; type = "Role" \} \}'
    }

    It 'does not configure the broader Group.Read.All application role' {
        $script:registrationScript | Should -Not -Match '5b567255-7703-4780-807c-7be8301ae99b'
        $script:registrationScript | Should -Not -Match 'displayName\s*=\s*"Group\.Read\.All"'
    }

    It 'requires GroupMember.Read.All at runtime' {
        $script:moduleScript | Should -Match 'Permission\s*=\s*"GroupMember\.Read\.All"'
        $script:moduleScript | Should -Not -Match 'Permission\s*=\s*"Group\.Read\.All"'
    }

    It 'documents the least-privilege permission and migration path' {
        $script:readme | Should -Match '\|\s*GroupMember\.Read\.All\s*\|\s*Application\s*\|'
        $script:readme | Should -Match 'Add `GroupMember\.Read\.All` and grant administrator consent before removing `Group\.Read\.All`'
    }
}
