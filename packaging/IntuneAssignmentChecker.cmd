@echo off
setlocal

set "IAC_PWSH="
if defined ProgramW6432 if exist "%ProgramW6432%\PowerShell\7\pwsh.exe" set "IAC_PWSH=%ProgramW6432%\PowerShell\7\pwsh.exe"
if not defined IAC_PWSH if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "IAC_PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
if not defined IAC_PWSH for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do if not defined IAC_PWSH set "IAC_PWSH=%%P"
if not defined IAC_PWSH goto powershell_not_found

if "%~1"=="" goto launch
if not "%~2"=="" goto usage
if /I "%~1"=="--disable-mouse" goto launch_without_mouse
if /I "%~1"=="--check" goto check
goto usage

:launch
echo Intune Assignment Checker requires PowerShell 7.
echo Starting it now...
echo.
"%IAC_PWSH%" -NoLogo -NoProfile -Command "Import-Module IntuneAssignmentChecker -ErrorAction Stop; Start-IntuneAssignmentCheckerTui"
goto finish

:launch_without_mouse
echo Intune Assignment Checker requires PowerShell 7.
echo Starting it now with terminal mouse reporting disabled...
echo.
"%IAC_PWSH%" -NoLogo -NoProfile -Command "Import-Module IntuneAssignmentChecker -ErrorAction Stop; Start-IntuneAssignmentCheckerTui -DisableMouse"
goto finish

:check
"%IAC_PWSH%" -NoLogo -NoProfile -Command "$required = [version]'7.0'; if ($PSVersionTable.PSVersion -lt $required) { Write-Error 'Intune Assignment Checker requires PowerShell 7 or newer.'; exit 1 }; Import-Module IntuneAssignmentChecker -ErrorAction Stop; $module = Get-Module IntuneAssignmentChecker; Write-Output ('Intune Assignment Checker {0} is ready in PowerShell {1}.' -f $module.Version, $PSVersionTable.PSVersion)"
goto finish

:powershell_not_found
echo Intune Assignment Checker requires PowerShell 7, but pwsh.exe was not found.
echo Install it with:
echo   winget install --id Microsoft.PowerShell --exact
exit /b 1

:usage
echo Usage: IntuneAssignmentChecker [--disable-mouse ^| --check]
exit /b 2

:finish
set "IAC_EXIT_CODE=%ERRORLEVEL%"
if not "%IAC_EXIT_CODE%"=="0" (
    echo.
    echo Intune Assignment Checker closed with exit code %IAC_EXIT_CODE%.
)
exit /b %IAC_EXIT_CODE%
