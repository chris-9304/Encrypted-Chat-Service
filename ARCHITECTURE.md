# Architecture

Cloak is a Windows-native, terminal-based, end-to-end encrypted peer-to-peer messenger. v0.4.0 completes all four phases: LAN chat, Double Ratchet encryption + file transfer, group messaging + multi-device, and internet relay + invite codes.

The architecture was deliberately more ambitious than Phase 1's feature set required — each phase added a new concrete implementation behind an existing abstraction without touching upstream code.

## System shape

```
┌─ Cloak (one installed binary per machine) ───────────────────────┐
│                                                                    │
│   ChatApplication          ← top-level orchestrator               │
│       │                                                            │
│   ┌───┴────────────────┬─────────────┬──────────────┬──────────┐  │
│   │                    │             │              │          │  │
│  ChatUi           Identity      PeerDirectory  MessageStore   │  │
│  (FTXUI TUI)      (keys)        (known peers)  (SQLite+AEAD)  │  │
│                                      │                          │  │
│                              ┌───────┴────────┐                 │  │
│                              │                │                 │  │
│                       DiscoveryService  SessionManager          │  │
│                       (mDNS/Relay)     (sessions by peer)       │  │
│                                              │                  │  │
│                                       ┌──────┴──────┐           │  │
│                                       │             │           │  │
│                                    Session      Session ...     │  │
│                                       │                         │  │
│                                Transport (abstract)             │  │
│                                       │                         │  │
│                             ┌─────────┼──────────┐              │  │
│                             │         │          │              │  │
│                      TcpTransport  LanMailbox  RelayTransport   │  │
│                                                                  │  │
│   GroupManager + GroupSession  ← Phase 3 group encryption        │  │
│   DeviceRegistry               ← Phase 3 multi-device certs      │  │
│   FileTransfer                 ← Phase 2 chunked file transfer    │  │
│   RelayServer (cloak-relay.exe) ← standalone relay binary        │  │
│                                                                    │
│   Crypto (static class)  ← libsodium facade                       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Design principles

1. **Real OOP, not C with classes.** Abstract base classes for extension points. Virtual dispatch where the future will add implementations. Concrete classes with clean public interfaces and hidden state. RAII for every resource.
2. **Extensibility is designed in, not retrofitted.** Transport, message type, discovery, and storage are all polymorphic from day one. Adding a second implementation is a new class, not a refactor.
3. **No custom cryptographic primitives.** libsodium only, via `cloak::crypto::Crypto`. Composition of primitives into protocols (Noise, Double Ratchet, Sender Key) happens in our code; primitives never do.
4. **Windows-native.** MSVC 2022, vcpkg, native Win32 APIs (DNS-SD for mDNS discovery, VirtualLock for memory pinning). No WSL dependency. The binary is a single .exe plus an MSI installer.
5. **Plug and play.** Install, launch, chat. Zero configuration for LAN use. Defaults are safe.
6. **Failure is loud.** No silent fallback to weaker crypto. No TOFU-then-forget. Identity changes alert the user; `TrustStatus::Changed` is visible and must be acknowledged.
7. **Testing discipline.** Unit tests everywhere, RFC test vectors for protocol code, integration tests that spin up two instances and exchange messages, ASan in CI.
8. **Secrets never leave secure containers.** All key material in `SecureBuffer<N>` that mlocks and zeros on destruction. Never logged. Never serialized unencrypted.

## Class model

### ChatApplication
Top-level orchestrator. Owns the UI, identity, peer directory, store, session list, group manager, and device registry. One per process. Drives the command REPL and background threads.

### Identity
Long-term cryptographic identity. Ed25519 signing keypair + X25519 key-agreement keypair. Persisted to disk encrypted with a key derived from the user's passphrase via Argon2id. The public halves form the identity peers see. The private halves never leave `SecureBuffer<N>`.

### PeerDirectory
Known peers and their identity pubkeys. Trust-on-first-use (TOFU): first contact stores the pubkey; subsequent contacts verify. Identity-key change raises an alert the UI surfaces loudly. Backed by `MessageStore` tables.

TrustStatus values: `Unknown`, `Tofu`, `Verified`, `Changed`.

### DiscoveryService (abstract)
Advertises this peer on the network and browses for others. Phase 1 implementation: `LoopbackDiscoveryService` (manual peer connections for testing/demo). A full mDNS implementation (`MdnsDiscoveryService`) uses the Win32 DNS-SD API (`DnsServiceRegister`, `DnsServiceBrowse`). Phase 4: invite codes via relay discover peers across the internet.

`LocalAdvertisement` includes the identity signing pubkey (base32-encoded in a TXT record) so peers know *who* they're discovering, not just *that* someone is there.

### Transport (abstract)
Byte-stream pipe between two peers after connection establishment. Framing, crypto, and peer semantics live above.

```
Transport (abstract)
├── TcpTransport         ← Phase 1: direct TCP connection
├── LanMailboxTransport  ← Phase 2: in-memory store-and-forward for offline LAN delivery
└── RelayTransport       ← Phase 4: internet relay, NAT traversal
```

`Session` holds a `unique_ptr<Transport>` and calls the virtual interface. It does not know which transport it is using.

### Session
One live, authenticated, Double-Ratchet encrypted conversation with one peer. Holds the Noise-derived shared secret (Phase 1 handshake), current send/recv chain keys, message counters, and the skipped-message-key cache.

**Handshake:** Both peers exchange X25519 public key, Ed25519 public key, Ed25519 signature over X25519 key, a DR ephemeral key, and a signature over the DR key. The X25519 shared secret initializes the Double Ratchet root key.

**Double Ratchet (Signal protocol):**
- `KDF_RK = HKDF-SHA256(rk, DH(our_dr_priv, peer_dr_pub))` → `(new_rk, new_ck)`
- `KDF_CK = HMAC-SHA256(ck, 0x01)` → `message_key`; `HMAC-SHA256(ck, 0x02)` → `new_ck`
- `AEAD = XChaCha20-Poly1305(mk, nonce, aad=header_bytes, plaintext)`
- `nonce = first 24 bytes of HKDF(mk, info="CLOAK_MK_NONCE")`

Not internally thread-safe. `ChatApplication` serializes access via a mutex.

### SessionManager
Maintains the list of `Session` objects. Routes incoming connections. Access serialized via `session_mutex_`.

### GroupSession + GroupManager (Phase 3)
Group encryption using the Sender Key model. Each member has a (chain key, Ed25519 signing keypair). Group messages are encrypted with a per-message key derived from the sender's chain key, and signed with the sender's Ed25519 key. Invites distribute the sender's chain key through pairwise Double Ratchet sessions.

### DeviceRegistry (Phase 3)
Manages multi-device relationships. The primary device issues `DeviceCert` objects (Ed25519 signatures over secondary device public keys). Secondaries present their cert during handshake; peers verify it against the primary's known key.

### MessageStore
Persistent storage: message history, peer records, group sessions. SQLite with XChaCha20-Poly1305 column-level encryption for sensitive fields. DB key derived from user passphrase via Argon2id at startup; held in `SecureBuffer<32>`; never written to disk.

Schema migrations: v1 (messages + peers), v2 (group_sessions + group_members), v3 (to_peer column for bidirectional conversation history).

### FileTransfer (Phase 2)
Chunked file transfer with per-file AEAD encryption. A random 32-byte per-file key is generated and sent to the peer inside a Double Ratchet AppPayload. Each 64 KiB chunk is encrypted with XChaCha20-Poly1305 using a chunk-specific nonce derived from the per-file key and chunk index.

### RelayServer (Phase 4)
Standalone relay binary (`cloak-relay.exe`). Accepts TCP connections, pairs two connections with the same 32-byte room ID, and forwards bytes bidirectionally. Thread-per-paired-connection model. Never decrypts or inspects content.

### ChatUi
FTXUI-based terminal interface. Split-pane: peer list (presence + trust status), conversation view, input field, status bar. Keyboard-driven.

### Crypto
Static facade over libsodium. Exposes typed operations (`kx_keypair`, `ed25519_keypair`, `sign_detached`, `aead_encrypt`, `aead_decrypt`, `hkdf_sha256`, `hmac_sha256`, `argon2id_derive`, `blake2b_256`, `random_bytes`, `constant_time_equal`) all returning `std::expected`. Single place where `sodium_init()` is called.

### SecureBuffer\<N\>
Owning, fixed-size buffer for secret material. `VirtualLock` on construction; `SecureZeroMemory` + `VirtualUnlock` on destruction. Move-only, no copy. The only legitimate container for private keys, chain keys, and database keys.

## Wire format

All messages use a hand-rolled binary framing (not protobuf):

```
[4-byte BE length][1-byte MessageType][payload]
```

Length covers the type byte + payload. Maximum frame body: 1 MiB. Wire version: 2.

**MessageType values:**
- `Handshake (1)` — session setup payload
- `AppMessage (2)` — Double Ratchet encrypted inner payload
- `FileChunk (3)` — per-file AEAD-encrypted chunk
- `Receipt (4)` — delivered / read acknowledgement
- `GroupMessage (5)` — Sender Key group ciphertext + signature
- `GroupOp (6)` — group lifecycle (create / invite / leave / kick)

**Inner plaintext types** (first byte after AEAD decryption of an AppMessage):

| Byte | InnerType |
|------|-----------|
| 0x00 | Text |
| 0x01 | FileMetadata |
| 0x02 | Receipt |
| 0x03 | Typing |
| 0x04 | GroupOp |
| 0x05 | DeviceLink |
| 0x06 | GroupMessage |

## Concurrency model

- **UI thread.** Main thread runs the FTXUI event loop. Never blocks on I/O or crypto.
- **Listen thread.** Accepts inbound TCP connections; calls `Session::accept()` and spawns a per-session receive thread.
- **Discovery thread.** mDNS browse loop; initiates outbound connections on peer discovery.
- **Cleanup thread.** Periodically removes dead `SessionEntry` objects and purges expired messages from `MessageStore`.
- **Per-session receive threads.** One per live session. Drains the offline message queue for that peer, then loops on `recv_message()`.
- **Lock order.** Always acquire `session_mutex_` before `queue_mutex_`. Never reverse.
- **Cross-thread communication.** Atomic flags for session dead-flag; mutex-protected queues for message delivery.

Crypto calls are synchronous and fast. Argon2id (only at app startup for DB key derivation) runs on the main thread before entering the event loop.

## Repo layout

```
cloak/
├── CMakeLists.txt               ← root build file
├── CMakePresets.json            ← debug / release / asan / analyze
├── vcpkg.json                   ← dependency manifest (baseline SHA pinned)
├── vcpkg-configuration.json
│
├── cmake/
│   ├── warnings.cmake           ← /W4 /WX /permissive-
│   ├── msvc_options.cmake       ← /utf-8 WIN32_LEAN_AND_MEAN etc.
│   └── cloak_add_library.cmake  ← macro: library + auto-wired tests
│
├── src/                         ← implementations (also accessible via include/cloak/ junction)
│   ├── core/                    ← Error, Result<T>, PeerId, TrustStatus, etc.
│   ├── crypto/                  ← Crypto facade + SecureBuffer<N>
│   ├── identity/                ← Identity, PeerDirectory, DeviceRegistry
│   ├── wire/                    ← Frame encode/decode, payload structs
│   ├── transport/               ← Transport (abstract), TcpTransport, LanMailboxTransport, RelayTransport
│   ├── session/                 ← Session (Double Ratchet), SessionManager
│   ├── discovery/               ← DiscoveryService (abstract), LoopbackDiscoveryService
│   ├── store/                   ← MessageStore (SQLite + AEAD)
│   ├── group/                   ← GroupSession, GroupManager (Phase 3)
│   ├── transfer/                ← File transfer (Phase 2)
│   ├── relay/                   ← RelayServer (cloak-relay.exe, Phase 4)
│   ├── ui/                      ← ChatUi (FTXUI)
│   └── app/                     ← ChatApplication + main()
│
├── include/cloak/               ← NTFS junction → src/  (enables #include <cloak/module/file.h>)
│
├── tests/
│   ├── unit/                    ← one directory per module, auto-discovered by cloak_add_library.cmake
│   └── vectors/                 ← RFC test vectors (X25519, Ed25519, ChaCha20-Poly1305, Argon2id)
│
├── docs/
│   ├── DEMO.md                  ← CLI usage walkthrough
│   └── adr/                     ← Architecture Decision Records
│       ├── 0001-oop-cpp-not-c-abi.md
│       ├── 0002-windows-native-msvc.md
│       ├── 0003-noise-xx-for-phase-1.md
│       ├── 0004-sqlite-column-aead-over-sqlcipher.md
│       ├── 0005-mdns-for-discovery.md
│       └── 0006-thread-per-connection-relay.md
│
├── installer/                   ← WiX MSI project (planned v1.0; current distribution uses dist/ ZIP)
└── .github/workflows/           ← CI pipelines
```

## Build and toolchain

- **Compiler.** MSVC 2022 (v143 toolset). C++23 (`/std:c++latest`) for `std::expected`, `std::span`, designated initializers.
- **Generator.** Ninja via CMake ≥ 3.25.
- **Dependencies.** vcpkg manifest mode, baseline SHA pinned. libsodium, boost-asio, boost-program-options, sqlite3, spdlog, fmt, catch2, ftxui, wil.
- **Warnings.** `/W4 /WX /permissive-` plus `/Zc:__cplusplus /Zc:preprocessor /utf-8`.
- **Static analysis.** MSVC `/analyze` in the `analyze` preset.
- **Sanitizers.** Windows ASan in the `asan` preset.

## Distribution

**Current (v0.4.0):** `dist/cloak-0.4.0-win64.zip` — self-contained archive with `cloak.exe`, `cloak-relay.exe`, runtime DLLs, `vc_redist.x64.exe`, and `install.ps1`. No build tools needed on end-user's machine.

Run `.\build-dist.ps1` from the project root to rebuild the zip from a fresh release build.

**Planned (v1.0):** WiX Toolset v4 MSI with Authenticode signing.

## Testing

- **Unit.** Catch2 v3; auto-discovered by `cloak_add_library.cmake`.
- **RFC vectors.** RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 8439 (ChaCha20-Poly1305), Argon2id.
- **ASan.** Enabled via the `asan` preset.
- **Coverage targets.** `crypto/` `identity/` `session/` ≥ 85%; elsewhere ≥ 70%.

## Logging

spdlog, rotating file logs under `%APPDATA%\Cloak\logs\`. Default level: info.

Never logged: private keys, passphrases, plaintext message bodies, session keys, DB key. `CLOAK_UNSAFE_LOG_SECRETS=1` enables secret logging in debug builds only. CI rejects `spdlog::` calls on secret-bearing types.

## Error handling

`std::expected<T, Error>` for all recoverable errors. `Error` carries an `ErrorCode` enum value, a human-readable message, and an optional chained cause. Exceptions reserved for genuinely unexpected situations.

## Extensibility seams

Each seam is a virtual interface with one production implementation per phase:

| Seam | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|------|---------|---------|---------|---------|
| `Transport` | `TcpTransport` | `LanMailboxTransport` | — | `RelayTransport` |
| `DiscoveryService` | `LoopbackDiscoveryService` | — | — | Invite codes |
| `InnerType` dispatch | Text | File, Receipt, Typing | GroupOp, DeviceLink, GroupMessage | — |
| Session encryption | Noise XX + per-msg ratchet | Full Double Ratchet | — | — |
| Group encryption | — | — | Sender Key | — |
| Multi-device | — | — | Device certs | — |
| MessageStore schema | v1 | v1 (encryption) | v2 (groups) | v3 (to_peer) |

Adding a new transport is a new class that inherits from `Transport` — no changes to `Session`, `ChatApplication`, or any other module.
