# Windows and WinGet packaging

Version 5 remains a PowerShell module. The Windows artifact is an MSI that copies
the exact module source plus the pinned `Microsoft.Graph.Authentication` runtime
dependency into `C:\Program Files\PowerShell\Modules`. It does not compile or wrap
the module as an executable.

Build on Windows with PowerShell 7, the .NET SDK, and WiX 6.0.2:

```powershell
dotnet tool install --global wix --version 6.0.2
./packaging/Build-WindowsInstaller.ps1
```

The release workflow signs the MSI, emits an SBOM and provenance attestation,
and generates versioned WinGet manifests after the signed artifact hash is known.
The generated manifest directory is ready for `winget validate` and submission to
`microsoft/winget-pkgs`.
