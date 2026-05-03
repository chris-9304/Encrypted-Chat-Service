#Requires -Version 5.1
<#
.SYNOPSIS
    Build Cloak release binaries and package them into a distributable ZIP.

.DESCRIPTION
    Runs cmake --preset release inside the Visual Studio 2022 Build Tools
    environment, collects cloak.exe, cloak-relay.exe, and all required DLLs,
    updates dist\cloak\, and produces dist\cloak-<version>-win64.zip.

    Prerequisites:
      - Visual Studio 2022 Build Tools  (C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools)
      - vcpkg at C:\vcpkg  (or set VCPKG_ROOT env var before running this script)
      - cmake in PATH  (comes with VS Build Tools, or install separately)

.EXAMPLE
    # Build and package from the project root:
    .\build-dist.ps1

    # Skip building (just re-package existing binaries):
    .\build-dist.ps1 -SkipBuild

    # Override vcpkg root:
    .\build-dist.ps1 -VcpkgRoot D:\vcpkg
#>

param(
    [switch] $SkipBuild,
    [string] $VcpkgRoot = $env:VCPKG_ROOT
)

$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$AppVersion = "0.4.0"
$AppName    = "Cloak"
$ZipName    = "cloak-$AppVersion-win64.zip"

$ProjectRoot = $PSScriptRoot
$DistDir     = Join-Path $ProjectRoot "dist\cloak"
$ZipPath     = Join-Path $ProjectRoot "dist\$ZipName"

# Visual Studio 2022 Build Tools paths
$VsBuildTools = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$Vcvars64     = Join-Path $VsBuildTools "VC\Auxiliary\Build\vcvars64.bat"
$VsCmake      = Join-Path $VsBuildTools "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

# Fall back to cmake on PATH if VS cmake not found
if (-not (Test-Path $VsCmake)) { $VsCmake = "cmake" }

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
Write-Host "  Output  : $ZipPath"
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
Write-Step "4/4  Creating $ZipName ..."

if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

# Use ZipFile directly to avoid Compress-Archive file-lock issues on freshly copied DLLs.
Add-Type -Assembly System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($DistDir, $ZipPath,
    [IO.Compression.CompressionLevel]::Optimal, $false)

$sizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 1)

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Package ready: $ZipName  ($sizeMB MB)"  -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Distribute: dist\$ZipName"
Write-Host ""
Write-Host "  User install steps:"
Write-Host "    1. Download and unzip $ZipName"        -ForegroundColor Cyan
Write-Host "    2. Right-click install.ps1 -> Run with PowerShell"  -ForegroundColor Cyan
Write-Host "       (or open PowerShell in that folder and run: .\install.ps1)"
Write-Host "    3. Follow the on-screen prompts"        -ForegroundColor Cyan
Write-Host "    4. Open a new terminal and run: cloak.exe --name YourName --port 8080"  -ForegroundColor Cyan
Write-Host ""
