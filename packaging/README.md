# Windows and WinGet packaging

Version 5 remains a PowerShell module. The Windows artifact is an MSI that copies
the exact module source plus the pinned `Microsoft.Graph.Authentication` runtime
dependency into `C:\Program Files\PowerShell\Modules`. It does not compile or wrap
the module as an executable.

The MSI also installs a small `IntuneAssignmentChecker.cmd` handoff in
`C:\Program Files\Intune Assignment Checker\bin` and adds that directory to the
system `PATH`. The handoff contains no application logic: it starts PowerShell 7
and invokes `Start-IntuneAssignmentCheckerTui` from the installed module. This lets
someone type `IntuneAssignmentChecker` from Windows PowerShell 5.1, Command Prompt,
or a fresh PowerShell 7 session without receiving the module-manifest compatibility
error. A new terminal is required after the first installation so it inherits the
updated `PATH`.

Build on Windows with PowerShell 7, the .NET SDK, and WiX 6.0.2:

```powershell
dotnet tool install --global wix --version 6.0.2
./packaging/Build-WindowsInstaller.ps1
```

The release workflow signs the MSI, emits an SBOM and provenance attestation,
and generates versioned WinGet manifests after the signed artifact hash is known.
The generated manifest directory is ready for `winget validate` and submission to
`microsoft/winget-pkgs`.
