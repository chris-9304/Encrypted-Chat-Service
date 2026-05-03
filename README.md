# Cloak

> **End-to-end encrypted, peer-to-peer terminal messenger for Windows.**  
> No accounts. No servers that can read your messages. No setup for local chat.

[![Build](https://img.shields.io/badge/build-MSVC%202022%20%2F%20C%2B%2B23-blue)](WINDOWS_BUILD.md)
[![Version](https://img.shields.io/badge/version-v0.4.0-green)](ROADMAP.md)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](#)

---

## Features

| Feature | Status |
|---------|--------|
| LAN text chat (auto-discovery via mDNS) | ✅ Phase 1 |
| Double Ratchet encryption (Signal protocol) | ✅ Phase 2 |
| File transfer (per-file AEAD, 64 KiB chunks) | ✅ Phase 2 |
| Delivery + read receipts | ✅ Phase 2 |
| Disappearing messages | ✅ Phase 2 |
| Group chat (Sender Key model) | ✅ Phase 3 |
| Multi-device support (device certificates) | ✅ Phase 3 |
| Encrypted persistent message history (SQLite + AEAD) | ✅ Phase 2/3 |
| Internet relay for NAT traversal | ✅ Phase 4 |
| Invite-code peer discovery | ✅ Phase 4 |
| Offline message queue | ✅ Phase 4 |
| TOFU identity verification + safety numbers | ✅ All phases |
| MSI installer (WiX v4) | ✅ Phase 1 |

---

## Install (No Build Required)

Download `cloak-0.4.0-win64.zip` from the `dist/` directory, unzip it, then run the installer:

```powershell
# Right-click install.ps1 → "Run with PowerShell"
# — or open PowerShell in the unzipped folder and run:
.\install.ps1
```

The script:
1. Checks for and silently installs the **Visual C++ 2022 Runtime** if missing
2. Copies `cloak.exe`, `cloak-relay.exe`, and all required DLLs to `%ProgramFiles%\Cloak\` (admin) or `%LOCALAPPDATA%\Cloak\` (per-user)
3. Adds the install directory to your **PATH**
4. Creates **Start Menu shortcuts** for Cloak and Cloak Relay Server
5. Writes an `uninstall.ps1` for clean removal

After install, open a **new** terminal and run:
```powershell
cloak.exe --name "Alice" --port 8080
```

> **What's in the zip?**
> `cloak.exe` · `cloak-relay.exe` · `libsodium.dll` · `boost_program_options-vc143-mt-x64-1_90.dll` · `sqlite3.dll` · `vc_redist.x64.exe` · `install.ps1`

---

## Quick Start

### LAN (same network)

```powershell
# Both parties run this — they find each other automatically via mDNS
.\cloak.exe --name "Alice" --port 5000
.\cloak.exe --name "Bob"   --port 5001
```

### Internet (via relay)

```powershell
# 1. Run a relay server on a public host
.\cloak-relay.exe --port 8765

# 2. Alice creates an invite code
.\cloak.exe --name "Alice" --port 5000 --relay relay.example.com:8765
# Inside Cloak: /make-invite
# → prints: relay.example.com:8765/a3f8c2...

# 3. Bob connects with the invite code
.\cloak.exe --name "Bob" --port 5001
# Inside Cloak: /connect-invite relay.example.com:8765/a3f8c2...
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [report.md](report.md) | **Full technical report** — OOP design, C++ features, every protocol, every feature explained for all audiences |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, class model, concurrency model |
| [WINDOWS_BUILD.md](WINDOWS_BUILD.md) | Step-by-step build instructions |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security threat model and cryptographic choices |
| [ROADMAP.md](ROADMAP.md) | Phase-by-phase feature delivery |
| [DEPENDENCIES.md](DEPENDENCIES.md) | All vcpkg dependencies with versions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style and contribution rules |
| [SECURITY.md](SECURITY.md) | Security policy and responsible disclosure |
| [docs/DEMO.md](docs/DEMO.md) | CLI walkthrough with example sessions |
| [docs/adr/](docs/adr/) | Architecture Decision Records |

---

## Build from Source

**Requirements:** MSVC 2022 (v143), CMake ≥ 3.25, Ninja, vcpkg with `VCPKG_ROOT` set.

```powershell
cmake --preset debug                                   # configure
cmake --build --preset debug                           # build
ctest --preset debug --output-on-failure               # test
```

First build downloads all vcpkg dependencies (15–30 min). Subsequent builds are fast.

**Presets:** `debug`, `release`, `asan` (AddressSanitizer), `analyze` (MSVC static analyzer).

**Binary output locations:**
- `build/release/src/app/cloak.exe`
- `build/release/src/relay/cloak-relay.exe`

**Build + package in one step** (creates `dist/cloak-0.4.0-win64.zip`):
```powershell
.\build-dist.ps1              # full build then package
.\build-dist.ps1 -SkipBuild  # re-package existing binaries only
```

See [WINDOWS_BUILD.md](WINDOWS_BUILD.md) for the full setup guide.

---

## Security

Cloak uses:
- **X25519** Diffie-Hellman key agreement
- **Ed25519** signatures (identity authentication, group message signing)
- **XChaCha20-Poly1305** AEAD (all message and file encryption)
- **HKDF-SHA256** key derivation (Double Ratchet)
- **Argon2id** (passphrase → database key)
- **BLAKE2b-256** (room ID derivation, safety numbers)

All cryptographic operations go through **libsodium** — no custom crypto. Key material lives in `SecureBuffer<N>` (mlock'd RAM, zeroed on destruction). See [THREAT_MODEL.md](THREAT_MODEL.md) for full details.

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

---

## Key Commands

```
/peers                     List connected peers
/switch <name>             Switch active peer
/safety                    Show safety number for current peer
/verify                    Mark current peer as verified
/send <path>               Send a file
/history                   Show message history
/group-create <name>       Create a group
/group-list                List groups
/group-switch <name>       Switch to a group
/group-invite <peer>       Invite peer to group
/group-leave               Leave current group
/make-invite               Generate an invite code (relay mode)
/connect-invite <code>     Connect via invite code
/devices                   List linked devices
/link-device <pub_hex>     Link a secondary device
```

See [docs/DEMO.md](docs/DEMO.md) for a full walkthrough.

---

## Relay Server

Run `cloak-relay.exe` on any publicly reachable host. The relay forwards encrypted bytes between peers — it never has keys and cannot read messages.

```powershell
cloak-relay.exe --port 8765

# For networks that block non-standard ports:
cloak-relay.exe --port 443
```

---

## Runtime Paths

| File | Path |
|------|------|
| Identity | `%APPDATA%\Cloak\identity.bin` |
| Database | `%APPDATA%\Cloak\store.db` |
| Logs | `%APPDATA%\Cloak\logs\` |
