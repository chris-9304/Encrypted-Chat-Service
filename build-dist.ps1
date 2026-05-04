#Requires -Version 5.1
<#
.SYNOPSIS
    Build Cloak release binaries and produce both distribution artifacts.

.DESCRIPTION
    1. Runs cmake --preset release inside the Visual Studio 2022 Build Tools
       environment.
    2. Collects cloak.exe, cloak-relay.exe, and runtime DLLs into dist\cloak\.
    3. Produces dist\cloak-<version>-win64.zip  (portable archive).
    4. Produces dist\installer.exe  (Inno Setup installer — recommended
       for end users; creates Start Menu shortcuts, handles VC++ runtime, registers
       in Add/Remove Programs).

    Prerequisites (build machine):
      - Visual Studio 2022 Build Tools
      - vcpkg (set VCPKG_ROOT env var or pass -VcpkgRoot)
      - Inno Setup 6  (winget install JRSoftware.InnoSetup)

    End users need NOTHING extra — installer.exe is fully self-contained.

.EXAMPLE
    .\build-dist.ps1                          # full build + both artifacts
    .\build-dist.ps1 -SkipBuild               # re-package existing binaries
    .\build-dist.ps1 -VcpkgRoot D:\vcpkg     # custom vcpkg root
#>

param(
    [switch] $SkipBuild,
    [string] $VcpkgRoot = $env:VCPKG_ROOT
)

$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$AppVersion  = "0.4.0"
$AppName     = "Cloak"
$ZipName     = "cloak-$AppVersion-win64.zip"
$SetupName   = "installer.exe"

$ProjectRoot = $PSScriptRoot
$DistDir     = Join-Path $ProjectRoot "dist\cloak"
$ZipPath     = Join-Path $ProjectRoot "dist\$ZipName"
$SetupPath   = Join-Path $ProjectRoot "dist\$SetupName"
$IssScript   = Join-Path $ProjectRoot "installer\cloak.iss"

# Visual Studio 2022 Build Tools paths
$VsBuildTools = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$Vcvars64     = Join-Path $VsBuildTools "VC\Auxiliary\Build\vcvars64.bat"
$VsCmake      = Join-Path $VsBuildTools "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

# Fall back to cmake on PATH if VS cmake not found
if (-not (Test-Path $VsCmake)) { $VsCmake = "cmake" }

# Inno Setup compiler — try common install locations + PATH
$IsccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$IsccExe = $null
foreach ($c in $IsccCandidates) {
    if (Test-Path $c) { $IsccExe = $c; break }
}
if (-not $IsccExe) {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { $IsccExe = $cmd.Source }
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host ">>> $msg" -ForegroundColor Cyan
}

function Invoke-WithVsEnv([string]$command) {
    if (Test-Path $Vcvars64) {
        $bat = @"
@echo off
call "$Vcvars64" >nul 2>&1
set VCPKG_ROOT=$VcpkgRoot
$command
"@
    } else {
        $bat = @"
@echo off
set VCPKG_ROOT=$VcpkgRoot
$command
"@
    }
    $tmpBat = [IO.Path]::GetTempFileName() + ".bat"
    Set-Content -Path $tmpBat -Value $bat -Encoding ASCII
    try {
        cmd /c $tmpBat
        if ($LASTEXITCODE -ne 0) { throw "Command failed (exit $LASTEXITCODE): $command" }
    } finally {
        Remove-Item $tmpBat -ErrorAction SilentlyContinue
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Cloak $AppVersion - Build and Package"      -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Project : $ProjectRoot"
Write-Host "  VCPKG   : $VcpkgRoot"
Write-Host "  ZIP     : $ZipPath"
Write-Host "  Setup   : $SetupPath"
Write-Host "  ISCC    : $(if ($IsccExe) { $IsccExe } else { 'NOT FOUND (installer.exe will be skipped)' })"
Write-Host ""

if (-not $VcpkgRoot) {
    Write-Host "ERROR: VCPKG_ROOT is not set. Pass -VcpkgRoot or set the VCPKG_ROOT env var." -ForegroundColor Red
    exit 1
}

# ── Step 1: Build ─────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "1/4  Configuring CMake (release preset)..."

    # Clear stale cache so a fresh compiler detection runs
    Remove-Item "$ProjectRoot\build\release\CMakeCache.txt" -ErrorAction SilentlyContinue
    Remove-Item "$ProjectRoot\build\release\CMakeFiles"     -Recurse -ErrorAction SilentlyContinue

    Invoke-WithVsEnv "cd /d `"$ProjectRoot`" && `"$VsCmake`" --preset release"

    Write-Step "2/4  Building (cmake --build release)..."
    Invoke-WithVsEnv "cd /d `"$ProjectRoot`" && `"$VsCmake`" --build --preset release"
} else {
    Write-Step "1/4  Skipping build (-SkipBuild specified)."
    Write-Step "2/4  Skipping build."
}

# ── Step 2: Locate built binaries ─────────────────────────────────────────────
Write-Step "3/4  Collecting build artifacts..."

# CMake puts the executables in build/release/src/<module>/
$buildRelease = Join-Path $ProjectRoot "build\release"

$cloakExe  = Join-Path $buildRelease "src\app\cloak.exe"
$relayExe  = Join-Path $buildRelease "src\relay\cloak-relay.exe"

if (-not (Test-Path $cloakExe)) {
    Write-Host "ERROR: cloak.exe not found at $cloakExe" -ForegroundColor Red
    Write-Host "  Run 'cmake --build --preset release' first, or check build output." -ForegroundColor Red
    exit 1
}

Write-Host "  Found: cloak.exe"
if (Test-Path $relayExe) { Write-Host "  Found: cloak-relay.exe" }
else { Write-Host "  Note: cloak-relay.exe not found (optional)" -ForegroundColor DarkGray }

# CMake (via vcpkg) copies exactly the needed runtime DLLs next to each executable.
# Union the DLLs from the app and relay output directories — these are the only
# DLLs the user's machine needs (no over-bundling of unused vcpkg DLLs).
$appOutputDir   = Join-Path $buildRelease "src\app"
$relayOutputDir = Join-Path $buildRelease "src\relay"

$dllSources = @()
foreach ($dir in @($appOutputDir, $relayOutputDir)) {
    if (Test-Path $dir) {
        $dllSources += Get-ChildItem $dir -Filter "*.dll"
    }
}
$dllSources = $dllSources | Sort-Object Name -Unique

Write-Host "  Found $($dllSources.Count) runtime DLL(s): $($dllSources.Name -join ', ')"

# Find vc_redist if already in dist (we don't redownload it here)
$vcRedist = Join-Path $DistDir "vc_redist.x64.exe"

# ── Step 3: Populate dist\cloak\ ──────────────────────────────────────────────
Write-Host ""
Write-Host "  Updating $DistDir ..."
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

# Copy executables
Copy-Item $cloakExe $DistDir -Force
Write-Host "  Copied cloak.exe"

if (Test-Path $relayExe) {
    Copy-Item $relayExe $DistDir -Force
    Write-Host "  Copied cloak-relay.exe"
}

# Copy DLLs
foreach ($dll in $dllSources) {
    Copy-Item $dll.FullName $DistDir -Force
    Write-Host "  Copied $($dll.Name)"
}

# install.ps1 is already in dist\cloak\; leave it in place (don't overwrite)
$installScript = Join-Path $DistDir "install.ps1"
if (-not (Test-Path $installScript)) {
    Write-Host "  WARNING: install.ps1 not found in $DistDir" -ForegroundColor Yellow
}

# vc_redist.x64.exe — keep if present, warn if missing
if (-not (Test-Path $vcRedist)) {
    Write-Host ""
    Write-Host "  WARNING: vc_redist.x64.exe not found in $DistDir" -ForegroundColor Yellow
    Write-Host "  Download it and place it there before distributing:" -ForegroundColor Yellow
    Write-Host "    https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
}

# ── Step 4: Create ZIP ─────────────────────────────────────────────────────────
Write-Step "4/5  Creating $ZipName ..."

if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

Add-Type -Assembly System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($DistDir, $ZipPath,
    [IO.Compression.CompressionLevel]::Optimal, $false)

$zipSizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 1)
Write-Host "  Created $ZipName  ($zipSizeMB MB)" -ForegroundColor Green

# ── Step 5: Build Inno Setup installer ────────────────────────────────────────
Write-Step "5/5  Building $SetupName (Inno Setup installer)..."

if (-not $IsccExe) {
    Write-Host "  SKIPPED: Inno Setup (ISCC.exe) not found." -ForegroundColor Yellow
    Write-Host "  Install it with: winget install JRSoftware.InnoSetup" -ForegroundColor Yellow
} else {
    if (Test-Path $SetupPath) { Remove-Item $SetupPath -Force }
    & $IsccExe $IssScript 2>&1 | Where-Object { $_ -match "Warning|Error|Success|Compress" }
    if ($LASTEXITCODE -eq 0 -and (Test-Path $SetupPath)) {
        $setupSizeMB = [math]::Round((Get-Item $SetupPath).Length / 1MB, 1)
        Write-Host "  Created $SetupName  ($setupSizeMB MB)" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Inno Setup compile failed (exit $LASTEXITCODE)" -ForegroundColor Red
    }
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Distribution artifacts ready"            -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  PRIMARY (recommended for end users):"
Write-Host "    dist\$SetupName"                       -ForegroundColor Cyan
Write-Host "    -> Double-click to install. Creates Start Menu shortcut."
Write-Host "    -> Handles VC++ runtime automatically."
Write-Host "    -> Registers in Add/Remove Programs."
Write-Host ""
Write-Host "  PORTABLE (advanced / no install needed):"
Write-Host "    dist\$ZipName"                         -ForegroundColor Cyan
Write-Host "    -> Unzip anywhere, run cloak.exe directly."
Write-Host ""
Write-Host "  After install, open a NEW terminal and run:"
Write-Host "    cloak.exe --name YourName --port 8080" -ForegroundColor Cyan
Write-Host ""
