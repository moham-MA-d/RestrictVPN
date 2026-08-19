@echo off
title RestrictVPN
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Launch.ps1" -Target Gui
