@echo off
title Cloak Installer
echo.
echo  ===========================================
echo   Cloak 0.4.0  ^|  Installing...
echo  ===========================================
echo.
echo  Running installer. You may see a UAC prompt.
echo  Choose "Yes" for a system-wide install,
echo  or "No" / cancel to install for your user only.
echo.

:: Run the PowerShell installer bypassing execution policy
:: This works regardless of your system's script policy setting
PowerShell -ExecutionPolicy Bypass -NoProfile -File "%~dp0install.ps1"

echo.
pause
