# Windows Build

Cloak targets Windows 10 version 1903+ and builds natively with MSVC 2022. No WSL, no MinGW.

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

**3. Install the WiX Toolset v4** (needed for the MSI installer target; not needed for development).

```powershell
dotnet tool install --global wix
```

**4. Install Git and a terminal.**

Git for Windows is fine. Windows Terminal + PowerShell 7 is recommended.

## Clone and build

```powershell
git clone <repo-url> cloak
cd cloak

cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
```

On first build, vcpkg downloads and builds all dependencies. This takes 15-30 minutes. Subsequent builds reuse the vcpkg binary cache.

## Build presets

| Preset | Description |
|--------|-------------|
| `debug` | MSVC Debug, no optimization, full symbols |
| `release` | MSVC Release with `/O2 /DNDEBUG` |
| `asan` | Debug + AddressSanitizer (`/fsanitize=address`). Used in CI. |
| `analyze` | Runs MSVC `/analyze` static analyzer. Used in CI. |

## Build output locations

After `cmake --build --preset release`:

| Binary | Path |
|--------|------|
| `cloak.exe` | `build/release/src/app/cloak.exe` |
| `cloak-relay.exe` | `build/release/src/relay/cloak-relay.exe` |

Runtime DLLs are copied by CMake (via vcpkg) next to each executable automatically:
- `libsodium.dll`
- `boost_program_options-vc143-mt-x64-1_90.dll`
- `sqlite3.dll`

## Packaging the release zip

`build-dist.ps1` in the project root automates the full build-to-zip workflow:

```powershell
# Full build + create dist/cloak-0.4.0-win64.zip
.\build-dist.ps1

# Re-package without rebuilding (use existing binaries in build/release/)
.\build-dist.ps1 -SkipBuild

# Override vcpkg root if VCPKG_ROOT is not set
.\build-dist.ps1 -VcpkgRoot D:\vcpkg
```

This script:
1. Calls `vcvars64.bat` to initialise the MSVC environment
2. Runs `cmake --preset release` (clears stale cache first)
3. Runs `cmake --build --preset release`
4. Copies `cloak.exe`, `cloak-relay.exe`, and the three runtime DLLs into `dist/cloak/`
5. Produces `dist/cloak-0.4.0-win64.zip` ready for distribution

The `dist/cloak/` directory always reflects the most recent packaging run.

## Release package contents

`dist/cloak-0.4.0-win64.zip` (approximately 25 MB) contains:

| File | Purpose |
|------|---------|
| `cloak.exe` | Main application |
| `cloak-relay.exe` | Standalone relay server (optional) |
| `libsodium.dll` | Cryptographic primitives (libsodium) |
| `boost_program_options-vc143-mt-x64-1_90.dll` | CLI argument parsing |
| `sqlite3.dll` | Embedded database engine |
| `vc_redist.x64.exe` | Visual C++ 2022 Runtime installer |
| `install.ps1` | Plug-and-play installer script |

## End-user install (from zip, no build tools needed)

```powershell
# 1. Unzip cloak-0.4.0-win64.zip anywhere, then:
.\install.ps1

# 2. Open a NEW terminal and run:
cloak.exe --name "Alice" --port 8080
```

What `install.ps1` does:

| Step | Action |
|------|--------|
| 1 | Checks registry for VC++ 2022 Runtime; installs `vc_redist.x64.exe` silently if missing |
| 2 | Copies all files to `%ProgramFiles%\Cloak\` (admin) or `%LOCALAPPDATA%\Cloak\` (per-user) |
| 3 | Adds install directory to the system or user PATH |
| 4 | Creates Start Menu shortcuts: **Cloak** and **Cloak Relay Server** |
| 5 | Writes `uninstall.ps1` inside the install directory for clean removal |

Run as Administrator for a system-wide install; run normally for a per-user install.

## Running the installer build (WiX MSI)

```powershell
cmake --preset release
cmake --build --preset release
cmake --build --preset release --target installer
```

Outputs an MSI under `build/release/installer/`. In development builds this is self-signed.

## Common problems

**"VCPKG_ROOT not set"** — Close and reopen your shell after `setx`. It does not affect the current session.

**vcpkg dependency build fails** — Run `git pull` in `C:\vcpkg` and `C:\vcpkg\bootstrap-vcpkg.bat` to update, then reconfigure.

**cmake picks up MSYS2 GCC instead of MSVC** — CMake found a different compiler on PATH first. Run the build through a Visual Studio Developer Command Prompt, or use `build-dist.ps1` which calls `vcvars64.bat` automatically.

**"CMakeCache.txt does not match the generator"** — Delete `build/<preset>/CMakeCache.txt` and `build/<preset>/CMakeFiles/`, then reconfigure.

**Antivirus false positive on built .exe** — Common for crypto/networking binaries before code-signing. Add a project-folder exclusion in Windows Security during development.

## IDE integration

- **Visual Studio 2022.** Open the folder directly; it detects `CMakePresets.json` and presents the presets in the Configuration dropdown.
- **VS Code.** Install the C/C++, CMake Tools, and CMake extensions. Open the folder. Select the `debug` preset when prompted.
- **CLion.** Open the folder; CLion detects `CMakePresets.json` automatically.

## Architecture note

The choice to target MSVC native (not MinGW, not WSL) is documented in `docs/adr/0002-windows-native-msvc.md`. Tooling assumptions in this repo (ASan flags, analyzer usage, installer build) all follow from that decision.
