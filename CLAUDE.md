# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build commands

Requires: MSVC 2022 (v143), CMake ≥ 3.25, Ninja, vcpkg with `VCPKG_ROOT` set. First build downloads all vcpkg dependencies (15–30 min).

```powershell
cmake --preset debug               # configure
cmake --build --preset debug       # build
ctest --preset debug --output-on-failure   # all tests
ctest --preset debug -R <name> --output-on-failure  # single test by name
```

Presets: `debug`, `release`, `asan` (MSVC ASan), `analyze` (MSVC `/analyze`). Build outputs go to `build/<preset>/`.

Installer (WiX MSI, not needed for development):
```powershell
cmake --preset release && cmake --build --preset release --target installer
```

## Architecture

EncryptiV is a Windows-native terminal P2P messenger (v0.4.0 — Phase 4 complete). Phase 1: LAN text chat. Phase 2: Double Ratchet, file transfer, receipts. Phase 3: Sender-Key group chat, multi-device via device certs, group/peer persistence. Phase 4: Internet relay transport, invite-code peer discovery.

**Module ownership** (each is a separate CMake library under `src/`):

| Module | Role |
|--------|------|
| `core` | Shared types (`PeerId`, `SessionId`, `TrustStatus`, `Result<T, Error>`) |
| `crypto` | Static libsodium facade; the only place `sodium_init()` is called. All key material in `SecureBuffer` (mlock + zero on destroy, move-only) |
| `identity` | Long-term Ed25519+X25519 keypair, Argon2id-encrypted at rest. `PeerDirectory` tracks TOFU trust (`Unknown→Tofu→Verified→Changed`) |
| `wire` | Frame encode/decode. Format: `[4-byte BE length][1-byte MessageType][payload]`. Hand-rolled, not protobuf |
| `transport` | Abstract `Transport` base. Phase 1: `TcpTransport`. Phase 2 adds `LanMailboxTransport`. Phase 4 adds `RelayTransport` |
| `session` | Noise XX handshake + per-message symmetric ratchet (Phase 2: full Double Ratchet). Not thread-safe; caller must use a strand |
| `discovery` | Abstract `DiscoveryService`. Phase 1: mDNS via Win32 DNS-SD |
| `store` | SQLite with column-level XChaCha20-Poly1305 AEAD. DB key derived from passphrase via Argon2id at startup |
| `group` | Phase 3 multi-party encryption (Sender Key model, Ed25519-signed) |
| `transfer` | Phase 2 file transfer, 64 KiB chunks, per-file AEAD key |
| `relay` | Phase 4 relay server (`ev-relay.exe`) — transparent TCP multiplexer for NAT traversal |
| `ui` | FTXUI terminal TUI |
| `app` | `ChatApplication` — top-level orchestrator. Owns all the above. One per process |

**Data flow (send):** `ChatApplication` → `SessionManager` → `Session` (DR encrypt) → `wire::encode_app()` → `Transport::send()`

**Data flow (receive):** `Transport` bytes → `wire::decode()` → `Session` (DR decrypt) → `ChatApplication` display + `MessageStore` persist

**Concurrency:** UI thread never blocks. One Asio `io_context` thread for all I/O. Each `Session` has its own Asio strand — multiple sessions progress concurrently, one session is serialized. Cross-thread: lock-free SPSC queues or `asio::post`.

## Key design invariants

- **No custom crypto.** libsodium primitives only via `ev::crypto::Crypto`. Never call libsodium directly.
- **Secrets in `SecureBuffer` only.** Never copy key material into `std::vector` or `std::string`.
- **`EV_UNSAFE_LOG_SECRETS=1`** enables secret logging in debug builds. CI forbids logging on secret-bearing types.
- **`std::expected<T, Error>`** for recoverable errors throughout. Exceptions only for genuinely unexpected situations.
- **TOFU is loud.** `TrustStatus::Changed` must surface as a user-visible alert — never silently accept a new key.

## Public headers

The `include/ev/` tree mirrors `src/` and exposes the public API of each module. The `src/` tree has the implementations. Both are on the include path so `<ev/core/types.h>` and `"core/types.h"` both work; prefer the angle-bracket form in headers.

## Testing

Tests live in `tests/unit/<module>/`. The `cmake/ev_add_library.cmake` macro auto-discovers `tests/unit/<name>/*.cpp` and creates `test_<name>` executables linked against `Catch2::Catch2WithMain`. RFC test vectors are in `tests/vectors/`. Fuzz harnesses in `tests/fuzz/`.

Coverage targets: `crypto/`, `identity/`, `session/` ≥ 85%; others ≥ 70%.

## Key design invariants (do not violate)

- **`send_inner(type, payload)` / `recv_message()` are the canonical Session API.** `send_text()` / `recv_text()` are convenience wrappers for `InnerType::Text` only.
- **Group messages** must be sent with `InnerType::GroupMessage` via `send_inner()`. Never wrap them in `send_text()`.
- **Group ops** (invite/leave/kick) must use `InnerType::GroupOp` via `send_inner()`.
- **Receipts** use `InnerType::Receipt` via `send_receipt()` which calls `send_inner()` internally.
- **`session_recv_func_impl`** drives a `switch` on `InnerType` — add new cases here for new inner types.
- **Group persistence:** call `store_->save_group(group_mgr_.snapshot(gid))` on create/join/leave. Groups are loaded into `GroupManager` via `restore()` on startup.
- **Safety numbers** are 60 decimal digits in groups of 10 separated by spaces (6 groups of 2 digits × 5 bytes, each byte `% 100`).
- **Relay protocol:** 37-byte client handshake (magic EVR1 + role + 32-byte room_id), 1-byte server response. After pairing, raw bytes forwarded transparently.
- **Invite codes** format: `<relay_host>:<relay_port>/<room_id_hex64>`. Room ID derived as BLAKE2b-256(sign_pub || random_16).

## Phase 4: Internet Relay

`ev-relay.exe` is a standalone relay server. Run it on any publicly reachable host:

```powershell
ev-relay.exe --port 8765
```

Client workflow:
1. Both parties need network access to the relay host.
2. Inviter: `--relay <host:port>` flag at startup, then `/make-invite` → prints an invite code.
3. Invitee: `/connect-invite <code>` → connects through relay → full EncryptiV session established.

The relay never sees plaintext — all cryptography runs on top of the relay transport.

## ADRs

`docs/adr/` records key decisions. Notable ones:
- `0002` — MSVC-native only (no MinGW/WSL)
- `0003` — Noise XX for Phase 1 handshake (not Signal X3DH; both peers are online)
- `0004` — Column-level AEAD over SQLCipher (finer control, no full-DB key in memory)
- `0005` — mDNS for LAN discovery (Win32 DNS-SD)
- `0006` — Thread-per-connection relay (simple, sufficient for dev deployments)

## Runtime paths

- Identity: `%APPDATA%\EncryptiV\identity.bin`
- Database: `%APPDATA%\EncryptiV\store.db`
- Logs: `%APPDATA%\EncryptiV\logs\` (spdlog rotating, default level info)
