#Requires -Version 5.1
<#
.SYNOPSIS
    ev-chat Installer
.DESCRIPTION
    Installs ev-chat (Encrypted LAN Chat) to %ProgramFiles%\ev-chat,
    installs VC++ Redistributable if needed, and creates a Start Menu shortcut.
    Run as Administrator for system-wide install, or without for per-user install.
#>

$ErrorActionPreference = "Stop"

$AppName    = "ev-chat"
$AppVersion = "0.1.0"

# Determine install directory
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $InstallDir   = Join-Path $env:ProgramFiles $AppName
    $ShortcutDir  = [Environment]::GetFolderPath("CommonPrograms")
} else {
    $InstallDir   = Join-Path $env:LOCALAPPDATA $AppName
    $ShortcutDir  = [Environment]::GetFolderPath("Programs")
}

Write-Host ""
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  ev-chat $AppVersion Installer" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  Install location: $InstallDir"
Write-Host ""

# Confirm
$confirm = Read-Host "Proceed? [Y/n]"
if ($confirm -ne "" -and $confirm -notmatch "^[Yy]") {
    Write-Host "Cancelled." -ForegroundColor Yellow
    exit 0
}

# 1. Install VC++ Redist if needed
$vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
$needRedist = $true
if (Test-Path $vcKey) {
    $installed = (Get-ItemProperty $vcKey -ErrorAction SilentlyContinue).Installed
    if ($installed -eq 1) { $needRedist = $false }
}

if ($needRedist) {
    $redist = Join-Path $PSScriptRoot "vc_redist.x64.exe"
    if (Test-Path $redist) {
        Write-Host "Installing Visual C++ Redistributable..." -ForegroundColor Yellow
        Start-Process -FilePath $redist -ArgumentList "/install", "/quiet", "/norestart" -Wait
        Write-Host "  VC++ Redist installed." -ForegroundColor Green
    } else {
        Write-Host "  WARNING: vc_redist.x64.exe not found. If ev-chat fails to launch, download it from:" -ForegroundColor Yellow
        Write-Host "  https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
    }
} else {
    Write-Host "Visual C++ Redistributable already installed." -ForegroundColor Green
}

# 2. Create install directory and copy files
Write-Host "Copying files to $InstallDir ..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot "ev-chat.exe") $InstallDir -Force
Copy-Item (Join-Path $PSScriptRoot "*.dll") $InstallDir -Force

# 3. Create Start Menu shortcut
Write-Host "Creating Start Menu shortcut..." -ForegroundColor Yellow
$shortcutPath = Join-Path $ShortcutDir "ev-chat.lnk"
$wsh = New-Object -ComObject WScript.Shell
$sc  = $wsh.CreateShortcut($shortcutPath)
$sc.TargetPath       = Join-Path $InstallDir "ev-chat.exe"
$sc.WorkingDirectory = $InstallDir
$sc.Description      = "ev-chat: Encrypted LAN Messenger"
$sc.Save()

# 4. Write uninstaller helper
$uninstScript = @"
Remove-Item '$InstallDir' -Recurse -Force
Remove-Item '$shortcutPath' -Force -ErrorAction SilentlyContinue
Write-Host 'ev-chat uninstalled.'
"@
Set-Content -Path (Join-Path $InstallDir "uninstall.ps1") -Value $uninstScript

Write-Host ""
Write-Host "===========================================" -ForegroundColor Green
Write-Host "  ev-chat installed successfully!" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Launch from Start Menu -> ev-chat"
Write-Host "  Or run directly: $InstallDir\ev-chat.exe"
Write-Host ""
Write-Host "  First launch: you will be prompted for your display name."
Write-Host "  Usage:  ev-chat.exe --port 8080"
Write-Host "  Connect: ev-chat.exe --port 9090 --connect <IP>:8080"
Write-Host ""
