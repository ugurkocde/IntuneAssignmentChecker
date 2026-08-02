# Windows and WinGet packaging

Version 5 remains a PowerShell module. The Windows artifact is an MSI that copies
the exact module source plus the pinned `Microsoft.Graph.Authentication` runtime
dependency into `C:\Program Files\PowerShell\Modules`. It does not compile or wrap
the module as an executable.

The MSI also installs a small `IntuneAssignmentChecker.cmd` handoff and its
PowerShell 7 bootstrap in `C:\Program Files\Intune Assignment Checker\bin`, then
adds that directory to the system `PATH`. The handoff contains no application
logic: it starts PowerShell 7 and invokes `Start-IntuneAssignmentCheckerTui` from
the installed module. This lets someone type `IntuneAssignmentChecker` from
Windows PowerShell 5.1, Command Prompt, or a fresh PowerShell 7 session without
receiving the module-manifest compatibility error. A new terminal is required
after the first installation so it inherits the updated `PATH`.

The bootstrap supports side-by-side PowerShell Gallery and WinGet installations.
It imports the highest available module version by its exact manifest path. When
the highest version exists in more than one scope, the machine-wide WinGet/MSI
copy wins the tie. A one-line warning identifies copies found in multiple module
scopes and the selected path in the TUI status bar (and in `--check` output);
`Test-IntuneAssignmentCheckerEnvironment` reports the full list. Multiple versions
retained within one scope are treated as a normal PowerShell module update history
and do not produce a warning. Stable releases take precedence over prereleases
with the same base version.

Build on Windows with PowerShell 7, the .NET SDK, and WiX 6.0.2:

```powershell
dotnet tool install --global wix --version 6.0.2
./packaging/Build-WindowsInstaller.ps1
```

The release workflow signs the MSI, emits an SBOM and provenance attestation,
and generates versioned WinGet manifests after the signed artifact hash is known.
The generated manifest directory is ready for `winget validate` and submission to
`microsoft/winget-pkgs`.
