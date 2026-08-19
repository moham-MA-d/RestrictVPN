@echo off
setlocal
rem Builds RestrictVPN.exe using the C# compiler that ships with Windows.
rem No SDK, no NuGet, no internet required.

rem A running instance holds a lock on the exe, and the compiler's complaint about
rem it is easy to miss. Catch it here and say what to do instead.
tasklist /FI "IMAGENAME eq RestrictVPN.exe" /NH 2>nul | find /I "RestrictVPN.exe" >nul
if not errorlevel 1 (
  if /I "%~1"=="/force" (
    echo Stopping the running RestrictVPN.exe...
    taskkill /IM RestrictVPN.exe /F >nul 2>&1
    rem Give the handle a moment to actually drop.
    ping -n 2 127.0.0.1 >nul
    tasklist /FI "IMAGENAME eq RestrictVPN.exe" /NH 2>nul | find /I "RestrictVPN.exe" >nul
    if not errorlevel 1 (
      echo.
      echo ERROR: could not stop RestrictVPN.exe.
      echo        It runs as administrator, so this window has to be elevated too.
      echo        Right-click Command Prompt, "Run as administrator", and try again -
      echo        or just use Exit on the tray icon.
      echo.
      exit /b 1
    )
  ) else (
    echo.
    echo ERROR: RestrictVPN.exe is running, so the new build cannot replace it.
    echo.
    echo   Right-click the RestrictVPN tray icon and choose EXIT, then run this again.
    echo   Closing the window is not enough - it only hides to the tray.
    echo.
    echo   Or, to stop it automatically:   build.cmd /force
    echo.
    exit /b 1
  )
)

set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo ERROR: could not find the .NET Framework C# compiler.
  exit /b 1
)

set "SRC=%~dp0src"
set "OUT=%~dp0RestrictVPN.exe"

echo Compiling...
"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /warn:4 ^
  /out:"%OUT%" ^
  /win32manifest:"%SRC%\app.manifest" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  /reference:System.Web.Extensions.dll ^
  /reference:System.Management.dll ^
  "%SRC%\*.cs"

if errorlevel 1 (
  echo.
  echo BUILD FAILED
  exit /b 1
)

echo.
echo Built: %OUT%
rem Printing the stamp makes it obvious whether the exe you are about to run is
rem the one you just compiled. The app logs the same line when it starts.
for %%F in ("%OUT%") do echo Stamp: %%~tF   %%~zF bytes
exit /b 0
