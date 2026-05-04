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

**3. Install Inno Setup 6** (needed to build `installer.exe`; not needed for development).

```powershell
winget install JRSoftware.InnoSetup
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

## Packaging the release

`build-dist.ps1` in the project root automates the full build-to-distribution workflow:

```powershell
# Full build + produce both artifacts
.\build-dist.ps1

# Re-package without rebuilding (use existing binaries in build/release/)
.\build-dist.ps1 -SkipBuild

# Override vcpkg root if VCPKG_ROOT is not set
.\build-dist.ps1 -VcpkgRoot D:\vcpkg
```

This script (5 steps):
1. Calls `vcvars64.bat` to initialise the MSVC environment
2. Runs `cmake --preset release` (clears stale cache first)
3. Runs `cmake --build --preset release`
4. Copies `cloak.exe`, `cloak-relay.exe`, and the three runtime DLLs into `dist/cloak/`
5. Produces `dist/cloak-0.4.0-win64.zip` (portable archive)
6. Produces `dist/installer.exe` via Inno Setup (`installer/cloak.iss`)

Requires Inno Setup 6 for the installer.exe step. The ZIP is always produced regardless.

The `dist/cloak/` directory always reflects the most recent packaging run.

## Distribution artifacts

`build-dist.ps1` produces two artifacts in `dist/`:

### `installer.exe` — recommended for end users

A standard Windows installer (Inno Setup 6). Double-click to install:

| Step | What happens |
|------|-------------|
| 1 | Welcome screen with quick-start instructions |
| 2 | Choose install location (`%ProgramFiles%\Cloak\` or per-user) |
| 3 | Choose tasks: desktop shortcut, add to PATH |
| 4 | VC++ 2022 Runtime installed silently if missing |
| 5 | Files installed, Start Menu shortcuts created |
| 6 | Registered in Add/Remove Programs for clean uninstall |

After install, **search "Cloak" in Start Menu** or open any terminal:
```
cloak.exe --name "Alice" --port 8080
```

### `cloak-0.4.0-win64.zip` — portable (no install)

| File | Purpose |
|------|---------|
| `cloak.exe` | Main application |
| `cloak-relay.exe` | Standalone relay server |
| `libsodium.dll` | Cryptographic primitives |
| `boost_program_options-vc143-mt-x64-1_90.dll` | CLI argument parsing |
| `sqlite3.dll` | Embedded database engine |
| `vc_redist.x64.exe` | Visual C++ 2022 Runtime (install if missing) |
| `install.ps1` | Fallback PowerShell installer |

Unzip anywhere and run `cloak.exe` directly. No Start Menu entry, no Add/Remove Programs registration.

## Building the Inno Setup installer manually

```powershell
# After running cmake --build --preset release:
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" installer\cloak.iss
# Output: dist\installer.exe
```

Or just use `build-dist.ps1` which handles everything automatically.

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
