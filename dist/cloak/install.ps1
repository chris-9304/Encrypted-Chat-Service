#Requires -Version 5.1
<#
.SYNOPSIS
    Cloak Installer — plug-and-play setup
.DESCRIPTION
    Unzip the Cloak release package, then run this script.
    It installs cloak.exe (and optionally cloak-relay.exe) to your chosen
    directory, installs the VC++ Runtime if missing, adds cloak to PATH, and
    creates Start Menu shortcuts.  No build tools required.

    Run as Administrator for a system-wide install;
    run without elevation for a per-user install.
.EXAMPLE
    # Typical per-user install (no elevation needed):
    .\install.ps1

    # System-wide install (requires "Run as Administrator"):
    .\install.ps1
#>

$ErrorActionPreference = "Stop"

$AppName        = "Cloak"
$AppVersion     = "0.4.0"
$ExeName        = "cloak.exe"
$RelayExeName   = "cloak-relay.exe"

# ── Detect elevation ──────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]"Administrator")

if ($isAdmin) {
    $InstallDir  = Join-Path $env:ProgramFiles $AppName
    $ShortcutDir = [Environment]::GetFolderPath("CommonPrograms")
    $PathTarget  = "Machine"
} else {
    $InstallDir  = Join-Path $env:LOCALAPPDATA $AppName
    $ShortcutDir = [Environment]::GetFolderPath("Programs")
    $PathTarget  = "User"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Cloak $AppVersion  — Encrypted P2P Chat" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install location : $InstallDir"
Write-Host "  Elevation        : $(if ($isAdmin) { 'System-wide (Admin)' } else { 'Per-user (no Admin)' })"
Write-Host ""

$confirm = Read-Host "Proceed with installation? [Y/n]"
if ($confirm -ne "" -and $confirm -notmatch "^[Yy]") {
    Write-Host "Installation cancelled." -ForegroundColor Yellow
    exit 0
}

# ── 1. VC++ Redistributable ───────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 1/4  Checking Visual C++ Runtime..." -ForegroundColor Yellow

$vcInstalled = $false
foreach ($vcKey in @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
)) {
    if (Test-Path $vcKey) {
        $prop = Get-ItemProperty $vcKey -ErrorAction SilentlyContinue
        if ($prop -and $prop.Installed -eq 1) { $vcInstalled = $true; break }
    }
}

if (-not $vcInstalled) {
    $redist = Join-Path $PSScriptRoot "vc_redist.x64.exe"
    if (Test-Path $redist) {
        Write-Host "  Installing Visual C++ Redistributable (silent)..." -ForegroundColor Yellow
        Start-Process -FilePath $redist -ArgumentList "/install","/quiet","/norestart" -Wait
        Write-Host "  VC++ Runtime installed." -ForegroundColor Green
    } else {
        Write-Host "  vc_redist.x64.exe not found in this folder." -ForegroundColor Yellow
        Write-Host "  If Cloak fails to start, download and install:" -ForegroundColor Yellow
        Write-Host "    https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Visual C++ Runtime already installed. OK." -ForegroundColor Green
}

# ── 2. Copy files ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 2/4  Copying files to $InstallDir ..." -ForegroundColor Yellow

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# Copy main executable
$srcExe = Join-Path $PSScriptRoot $ExeName
if (Test-Path $srcExe) {
    Copy-Item $srcExe $InstallDir -Force
    Write-Host "  Copied $ExeName" -ForegroundColor Green
} else {
    Write-Host "  ERROR: $ExeName not found next to install.ps1" -ForegroundColor Red
    exit 1
}

# Copy relay executable (optional — not required for basic use)
$srcRelay = Join-Path $PSScriptRoot $RelayExeName
if (Test-Path $srcRelay) {
    Copy-Item $srcRelay $InstallDir -Force
    Write-Host "  Copied $RelayExeName (relay server)" -ForegroundColor Green
} else {
    Write-Host "  $RelayExeName not found — relay server not installed (optional)." -ForegroundColor DarkGray
}

# Copy all DLLs bundled with the release
$dlls = Get-ChildItem (Join-Path $PSScriptRoot "*.dll") -ErrorAction SilentlyContinue
foreach ($dll in $dlls) {
    Copy-Item $dll.FullName $InstallDir -Force
}
if ($dlls.Count -gt 0) {
    Write-Host "  Copied $($dlls.Count) bundled DLL(s)" -ForegroundColor Green
}

# ── 3. Add to PATH ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 3/4  Adding Cloak to PATH..." -ForegroundColor Yellow

$currentPath = [Environment]::GetEnvironmentVariable("Path", $PathTarget)
if ($currentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", $PathTarget)
    Write-Host "  Added to $PathTarget PATH. Restart your terminal to use 'cloak' from anywhere." -ForegroundColor Green
} else {
    Write-Host "  Already on PATH. OK." -ForegroundColor Green
}

# ── 4. Start Menu shortcuts ───────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 4/4  Creating Start Menu shortcuts..." -ForegroundColor Yellow

$cloakShortcut = Join-Path $ShortcutDir "Cloak.lnk"
$wsh = New-Object -ComObject WScript.Shell

$sc = $wsh.CreateShortcut($cloakShortcut)
$sc.TargetPath       = Join-Path $InstallDir $ExeName
$sc.WorkingDirectory = $InstallDir
$sc.Description      = "Cloak — End-to-End Encrypted P2P Messenger"
$sc.Save()
Write-Host "  Start Menu shortcut: Cloak" -ForegroundColor Green

if (Test-Path (Join-Path $InstallDir $RelayExeName)) {
    $relayShortcut = Join-Path $ShortcutDir "Cloak Relay Server.lnk"
    $sr = $wsh.CreateShortcut($relayShortcut)
    $sr.TargetPath       = Join-Path $InstallDir $RelayExeName
    $sr.WorkingDirectory = $InstallDir
    $sr.Arguments        = "--port 8765"
    $sr.Description      = "Cloak Relay Server — run on a publicly reachable host"
    $sr.Save()
    Write-Host "  Start Menu shortcut: Cloak Relay Server" -ForegroundColor Green
}

# ── Write uninstaller ─────────────────────────────────────────────────────────
$uninstScript = @"
#Requires -Version 5.1
`$ErrorActionPreference = "SilentlyContinue"
Remove-Item '$InstallDir' -Recurse -Force
Remove-Item '$cloakShortcut' -Force
Write-Host "Cloak uninstalled from $InstallDir"
"@
Set-Content -Path (Join-Path $InstallDir "uninstall.ps1") -Value $uninstScript -Encoding UTF8

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Cloak $AppVersion installed successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  QUICK START:"
Write-Host ""
Write-Host "  1. Open a terminal and run:"
Write-Host "       cloak.exe --name YourName --port 8080" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. On another machine (or another terminal), run:"
Write-Host "       cloak.exe --name FriendName --port 9090 --connect <IP>:8080" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. For internet connections (bypasses NAT/firewalls):"
Write-Host "       a. Run relay on a public server:"
Write-Host "            cloak-relay.exe --port 8765" -ForegroundColor Cyan
Write-Host "       b. Inviter starts with relay flag and generates invite code:"
Write-Host "            cloak.exe --name Alice --relay yourserver.com:8765" -ForegroundColor Cyan
Write-Host "            /make-invite" -ForegroundColor Cyan
Write-Host "       c. Invitee connects with the code:"
Write-Host "            cloak.exe --name Bob" -ForegroundColor Cyan
Write-Host "            /connect-invite <code>" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. Send files/images/videos:  /send C:\path\to\file.jpg" -ForegroundColor Cyan
Write-Host "  5. Offline messages are queued and delivered automatically on reconnect."
Write-Host ""
Write-Host "  Data stored at: %APPDATA%\Cloak\"
Write-Host "  Uninstall:      $InstallDir\uninstall.ps1"
Write-Host ""
