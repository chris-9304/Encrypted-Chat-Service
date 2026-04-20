# Windows Build

EncryptiV targets Windows 10 version 1903+ and builds natively with MSVC 2022. No WSL, no MinGW.

## One-time setup

**1. Install Visual Studio 2022 or Build Tools 2022.**

Download the Visual Studio 2022 Community installer (free) or Build Tools (no IDE). Select the workload:

- **Desktop development with C++**

Required components under that workload:
- MSVC v143 — VS 2022 C++ x64/x86 build tools (latest)
- Windows 11 SDK (latest)
- C++ CMake tools for Windows
- C++ AddressSanitizer

**2. Install vcpkg.**

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
setx VCPKG_ROOT "C:\vcpkg"
```

Close and reopen PowerShell so `VCPKG_ROOT` is picked up.

**3. Install the WiX Toolset v4** (needed for the installer; not needed for core development).

```powershell
dotnet tool install --global wix
```

**4. Install Git and a terminal.**

Git for Windows is fine. Windows Terminal + PowerShell 7 is recommended.

**5. Optional: Gemini Antigravity or Claude Code** set up according to each tool's Windows installation instructions.

## Clone and build

```powershell
git clone <repo-url> encryptiv-chat
cd encryptiv-chat

cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
```

On first build, vcpkg downloads and builds all dependencies. This takes 15–30 minutes depending on machine. Subsequent builds reuse the vcpkg binary cache.

## Build presets

- `debug` — MSVC Debug, no optimization, full symbols.
- `release` — MSVC Release with `/O2 /DNDEBUG`.
- `asan` — Debug + AddressSanitizer (`/fsanitize=address`). Used in CI.
- `analyze` — Runs MSVC's `/analyze` static analyzer. Used in CI.

## Common problems

**"VCPKG_ROOT not set"** — Close and reopen your shell after `setx`. `setx` doesn't affect the current session.

**vcpkg dependency build fails** — Usually a missing Windows SDK component or outdated vcpkg. Run `git pull` in `C:\vcpkg` and `C:\vcpkg\bootstrap-vcpkg.bat` to update.

**"cannot open source file <ev/...>.h"** — You're likely using the wrong CMake preset or building without the configured preset. `cmake --preset debug` regenerates.

**Antivirus false positive on the built .exe** — Common for crypto/networking binaries on Windows until the installer is properly code-signed. Add a project-folder exclusion in Windows Security during development; do not ship unsigned binaries.

## Running the installer build

```powershell
cmake --preset release
cmake --build --preset release
cmake --build --preset release --target installer
```

Outputs an MSI under `build/release/installer/`. In development builds this is self-signed (the installer will warn on install; that's expected).

## IDE integration

- **Visual Studio 2022.** Open the folder directly; it detects `CMakePresets.json` and presents the presets in the Configuration dropdown.
- **VS Code.** Install the C/C++, CMake Tools, and CMake extensions. Open the folder. Select the `debug` preset when prompted.
- **CLion.** Open the folder; CLion detects `CMakePresets.json` automatically.

## Architecture note

The choice to target MSVC native (not MinGW, not WSL) is documented in `docs/adr/0002-windows-native-msvc.md`. Tooling assumptions in this repo (ASan flags, analyzer usage, installer build) all follow from that decision.
