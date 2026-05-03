# Installer

Cloak has two distribution methods:

## Current: PowerShell ZIP package (`dist/`)

The primary release format is a self-contained ZIP archive located at `dist/cloak-0.4.0-win64.zip`.

**Contents:**

| File | Purpose |
|------|---------|
| `cloak.exe` | Main application |
| `cloak-relay.exe` | Standalone relay server |
| `libsodium.dll` | Crypto runtime |
| `boost_program_options-vc143-mt-x64-1_90.dll` | CLI runtime |
| `sqlite3.dll` | Database runtime |
| `vc_redist.x64.exe` | Visual C++ 2022 Runtime |
| `install.ps1` | Plug-and-play installer |

**User steps:** unzip → right-click `install.ps1` → Run with PowerShell → follow prompts → open new terminal → run `cloak.exe`.

**What `install.ps1` installs to:**
- Admin: `%ProgramFiles%\Cloak\` + system PATH + CommonPrograms shortcuts
- Per-user: `%LOCALAPPDATA%\Cloak\` + user PATH + user Programs shortcuts

**To rebuild the ZIP** after making source changes:
```powershell
.\build-dist.ps1          # from the project root
```

## Planned: WiX Toolset v4 MSI

A signed MSI installer is planned for the v1.0 production release. It will be built with **WiX Toolset v4** and will:

- Install `cloak.exe` and `cloak-relay.exe` to `%ProgramFiles%\Cloak\`
- Create a Start Menu shortcut
- Register a proper Add/Remove Programs entry
- Handle clean uninstall (preserving `%APPDATA%\Cloak\` by default)
- Be signed with a CA-issued Authenticode certificate

To build the MSI (placeholder target):
```powershell
cmake --preset release
cmake --build --preset release --target installer
```

The WiX `.wxs` project files will live in this directory when implemented.

## Install layout

Regardless of method, the installed layout is:

```
<InstallDir>\
    cloak.exe
    cloak-relay.exe
    libsodium.dll
    boost_program_options-vc143-mt-x64-1_90.dll
    sqlite3.dll
    uninstall.ps1              (written by install.ps1)

%APPDATA%\Cloak\               (per-user, preserved on uninstall)
    identity.bin               (encrypted long-term identity)
    store.db                   (encrypted message database)
    logs\                      (rotating log files)
```
