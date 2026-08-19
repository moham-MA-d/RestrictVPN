@echo off
title RestrictVPN - Install
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Launch.ps1" -Target Install %*
