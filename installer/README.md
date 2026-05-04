# Installer

Cloak ships two distribution artifacts, both produced by `build-dist.ps1`:

---

## Primary: `installer.exe` (Inno Setup)

A standard Windows installer. **Double-click to install on any Windows 10/11 machine.**

**Script:** `installer/cloak.iss`  
**Compiler:** Inno Setup 6 (`winget install JRSoftware.InnoSetup`)  
**Output:** `dist/installer.exe` (~25 MB, self-contained)

### What the installer does

1. Presents a modern wizard UI with version info and quick-start instructions
2. Lets the user choose install location (`%ProgramFiles%\Cloak\` or per-user)
3. Optional tasks: desktop shortcut, add to PATH
4. Silently installs the Visual C++ 2022 Runtime if not present (from bundled `vc_redist.x64.exe`)
5. Copies `cloak.exe`, `cloak-relay.exe`, and runtime DLLs to the install directory
6. Creates Start Menu shortcuts: **Cloak** and **Cloak Relay Server**
7. Registers in **Add/Remove Programs** with a proper uninstaller

### Build the installer

```powershell
# From the project root — builds release binaries AND produces installer.exe:
.\build-dist.ps1

# Or compile the .iss directly (requires existing release binaries in dist\cloak\):
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" installer\cloak.iss
```

### Installed layout

```
%ProgramFiles%\Cloak\  (or %LOCALAPPDATA%\Programs\Cloak\ for per-user)
    cloak.exe
    cloak-relay.exe
    libsodium.dll
    boost_program_options-vc143-mt-x64-1_90.dll
    sqlite3.dll
    unins000.exe     <- Inno Setup uninstaller

%APPDATA%\Cloak\     (per-user data, preserved on uninstall)
    identity.bin     <- encrypted long-term identity
    store.db         <- encrypted message history
    logs\            <- rotating log files
```

---

## Portable: `cloak-0.4.0-win64.zip`

A self-contained ZIP with no installer. Unzip anywhere and:

| Method | Steps |
|--------|-------|
| **Easy (no PowerShell knowledge)** | Double-click `Install Cloak.bat` — runs the PowerShell installer with the execution policy bypassed |
| **Direct** | Run `cloak.exe` directly from the command line or terminal |
| **PowerShell (advanced)** | Run `install.ps1` directly for automated deployments |

No Start Menu entry, no Add/Remove Programs entry. Suitable for running from a USB drive, for portable installs, or for users who prefer not to use the standard installer.

---

## Inno Setup `.iss` script notes

`installer/cloak.iss` key settings:

| Setting | Value |
|---------|-------|
| `AppId` | Fixed GUID — preserves upgrade detection across versions |
| `PrivilegesRequired` | `lowest` with `OverridesAllowed=dialog` — user chooses Admin or per-user |
| `ArchitecturesInstallIn64BitMode` | `x64compatible` — 64-bit only |
| `MinVersion` | `10.0.17763` — Windows 10 1809 minimum |
| `Compression` | `lzma2/ultra64` — maximum compression |
| VC++ check | `VCRedistNeedsInstall()` reads `HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64` |
| PATH update | `NeedsPathEntry()` avoids duplicate PATH entries |
