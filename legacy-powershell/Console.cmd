@echo off
title RestrictVPN - Console
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Launch.ps1" -Target Cli %*
