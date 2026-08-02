@echo off
setlocal

set "IAC_PWSH="
if defined ProgramW6432 if exist "%ProgramW6432%\PowerShell\7\pwsh.exe" set "IAC_PWSH=%ProgramW6432%\PowerShell\7\pwsh.exe"
if not defined IAC_PWSH if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "IAC_PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
if not defined IAC_PWSH for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do if not defined IAC_PWSH set "IAC_PWSH=%%P"
if not defined IAC_PWSH goto powershell_not_found
set "IAC_BOOTSTRAP=%~dp0Start-IntuneAssignmentChecker.ps1"
if not exist "%IAC_BOOTSTRAP%" goto bootstrap_not_found

if "%~1"=="" goto launch
if not "%~2"=="" goto usage
if /I "%~1"=="--disable-mouse" goto launch_without_mouse
if /I "%~1"=="--check" goto check
goto usage

:launch
echo Intune Assignment Checker requires PowerShell 7.
echo Starting it now...
echo.
"%IAC_PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%IAC_BOOTSTRAP%"
goto finish

:launch_without_mouse
echo Intune Assignment Checker requires PowerShell 7.
echo Starting it now with terminal mouse reporting disabled...
echo.
"%IAC_PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%IAC_BOOTSTRAP%" -DisableMouse
goto finish

:check
"%IAC_PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%IAC_BOOTSTRAP%" -Check
goto finish

:powershell_not_found
echo Intune Assignment Checker requires PowerShell 7, but pwsh.exe was not found.
echo Install it with:
echo   winget install --id Microsoft.PowerShell --exact
exit /b 1

:bootstrap_not_found
echo Intune Assignment Checker's PowerShell launcher was not found:
echo   %IAC_BOOTSTRAP%
echo Reinstall it with:
echo   winget install --id UgurKoc.IntuneAssignmentChecker --exact --force
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
