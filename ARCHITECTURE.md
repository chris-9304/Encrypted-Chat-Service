# Architecture

EncryptiV is a Windows-native, terminal-based, end-to-end encrypted peer-to-peer messenger. v0.4.0 completes Phase 4 (Internet relay + invite-code discovery). The architecture was deliberately more ambitious than Phase 1's feature set required — each phase added a new concrete implementation behind an existing abstraction without touching upstream code.

## System shape

```
┌─ EncryptiV (one installed binary per machine) ───────────┐
│                                                          │
│   ChatApplication         ← top-level orchestrator       │
│       │                                                  │
│   ┌───┴───────────────┬─────────────┬──────────────┐     │
│   │                   │             │              │     │
│  ChatUi          Identity     PeerDirectory   MessageStore
│  (FTXUI TUI)     (keys)      (known peers)   (SQLite+AEAD)
│                                  │                       │
│                           ┌──────┴────────┐              │
│                           │               │              │
│                    DiscoveryService  SessionManager      │
│                    (mDNS)            (sessions by peer)  │
│                                          │               │
│                                    ┌─────┴──────┐        │
│                                    │            │        │
│                                 Session    Session ...   │
│                                    │                     │
│                             Transport (abstract)         │
│                                    │                     │
│                          ┌─────────┼─────────┐           │
│                          │         │         │           │
│                   TcpTransport  LanMailbox  RelayTransport │
│                                                          │
│   RelayServer (ev-relay.exe) ← standalone relay binary   │
│                                                          │
│   Crypto (static class)  ← libsodium facade              │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Two installed instances on the same LAN discover each other via mDNS, handshake with Noise over TCP, and exchange end-to-end encrypted messages. Everything above `Transport` is transport-agnostic so later phases can plug in alternatives without rewrites.

## Design principles

1. **Real OOP, not C with classes.** Abstract base classes for extension points. Virtual dispatch where the future will add implementations. Concrete classes with clean public interfaces and hidden state. RAII for every resource.
2. **Extensibility is designed in, not retrofitted.** Transport, message type, discovery, and storage are all polymorphic from day one even though Phase 1 has one implementation of each. Adding a second implementation is a new class, not a refactor.
3. **No custom cryptographic primitives.** libsodium only. Composition of primitives into protocols (Noise, identity, ratcheting) happens in our code; primitives never do.
4. **Windows-native.** MSVC 2022, vcpkg, native Win32 APIs for discovery and service integration. No WSL dependency. The binary is a single .exe plus an MSI installer.
5. **Plug and play.** Install, launch, chat. Zero configuration for the common case. Defaults are safe.
6. **Failure is loud.** No silent fallback to weaker crypto. No TOFU-then-forget. Identity changes alert the user.
7. **Testing discipline.** Unit tests everywhere, property tests for protocol code, integration tests that spin up two instances and exchange messages, ASan in CI, fuzzers on every parser.
8. **Secrets never leave secure containers.** All key material in an `ev::SecureBuffer` that mlocks and zeros. Never logged. Never serialized unencrypted.

## Class model

### ChatApplication
Top-level orchestrator. Owns the UI, identity, directory, store, and session manager. One per process. Drives the main loop.

### Identity
Long-term cryptographic identity of this install. Ed25519 signing keypair + X25519 key-agreement keypair. Persisted to disk, encrypted at rest with a key derived from a user passphrase via Argon2id. The public halves form the identity peers see.

### PeerDirectory
Known peers and their identity pubkeys. Trust-on-first-use: first contact stores the pubkey; subsequent contacts verify. Identity-key change raises an alert the UI surfaces loudly. Backed by `MessageStore` tables.

TrustStatus values: `Unknown`, `Tofu`, `Verified`, `Changed`.

### DiscoveryService (abstract)
Advertises this peer on the network and browses for others. Phase 1 implementation is `MdnsDiscoveryService` using the Win32 DNS-SD API (`DnsServiceRegister`, `DnsServiceBrowse`). Later phases can add manual peer-list discovery, invite-code-based discovery, or relay-based discovery without touching anything upstream.

`LocalAdvertisement` includes the identity signing pubkey (base32-encoded in a TXT record) so peers know *who* they're discovering, not just *that* someone is there.

### Transport (abstract)
Byte-stream pipe between two peers after connection establishment. Framing, crypto, and peer semantics live above. Phase 1 is `TcpTransport`; Phase 2 adds `LanMailbox` for offline delivery; Phase 4 could add `InternetRelay`. The abstraction isolates every session from transport concerns.

`TransportCapabilities` is a bitset (streaming, datagram, reliable, supports-out-of-order, etc.) that higher layers can query. Phase 1 sets `kStreaming | kReliable`; the bitset exists so later transports can advertise their properties without header changes.

### Session
One live, authenticated, encrypted conversation with one peer. Holds Noise handshake result, current send/recv chain keys, message counters, skipped-message-key cache. Owns its `Transport`. Not thread-safe internally — `SessionManager` serializes access via an Asio strand.

Noise (`XX` pattern, `25519_ChaChaPoly_BLAKE2s`) is used for handshake because both peers are online at handshake time, it gives mutual authentication and forward secrecy in one round trip, and it's simpler to get right than Signal's X3DH+Double-Ratchet for a LAN-first product. A per-message symmetric ratchet provides forward secrecy across the long-lived session. When Phase 2 adds offline delivery, full Double Ratchet replaces the per-message ratchet; the `Session` public interface does not change.

### SessionManager
Maintains the map of `PeerId → Session`. Routes incoming connections to the right `Session` (or creates one for a new peer). Serializes access to each `Session` on its own strand.

### Message
Typed message. Phase 1 has `TextMessage`; Phase 2 adds `FileMessage`. The discriminated union is a `std::variant` that serializes through a versioned wire format so new types don't break old clients.

### MessageStore
Persistent storage: identities, peers, sessions, message history. SQLite with libsodium column-level AEAD for sensitive fields. Database file at `%APPDATA%\EncryptiV\store.db`. Schema migrations from day one.

DB key is derived via Argon2id from the user's passphrase at application startup, held in a `SecureBuffer`, and never written to disk.

### ChatUi
FTXUI-based terminal interface. Split-pane: peer list (with presence and trust status), conversation view, input field, status bar. Keyboard-driven. Color and Unicode where the terminal supports it.

### Crypto
Static facade over libsodium. Exposes typed operations (`kx_keypair`, `sign_detached`, `aead_encrypt`, `hkdf`, `argon2id_derive`, `constant_time_equal`, etc.) returning `std::expected`. Every other class uses this instead of calling libsodium directly. Single place where `sodium_init()` is called.

### SecureBuffer
Owning, fixed-size buffer holding secret material. mlocks on construction, zeros on destruction, move-only, no copy. The only legitimate container for key material.

## Concurrency model

- **UI thread.** Main thread runs the FTXUI event loop. Never blocks on I/O or crypto.
- **I/O thread.** One `boost::asio::io_context` on a dedicated thread. All network I/O happens here.
- **Session strands.** Each `Session` accessed on its own Asio strand. Multiple sessions progress concurrently; any one session is serialized.
- **Crypto calls.** Synchronous. Fast enough that offloading is unnecessary. Argon2id (only at app startup) runs on a throwaway thread with UI progress.
- **Cross-thread communication.** Lock-free SPSC queues where possible; `asio::post` otherwise.

Rule: no shared mutable state without a strand. Invariant is enforced by keeping state inside objects only accessed from their owning strand.

## Repo layout

```
encryptiv-chat/
├── GEMINI.md                    ← operational brief for agent
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── ROADMAP.md
├── WINDOWS_BUILD.md
├── SECURITY.md
├── DEPENDENCIES.md
├── CONTRIBUTING.md
├── README.md
├── CMakeLists.txt
├── CMakePresets.json
├── vcpkg.json
├── vcpkg-configuration.json
├── .clang-format
├── .clang-tidy
├── .editorconfig
├── .gitignore
├── .gitattributes
├── cmake/
│   ├── warnings.cmake
│   ├── msvc_options.cmake
│   └── ev_add_library.cmake
├── docs/
│   ├── adr/
│   │   ├── README.md
│   │   ├── 0001-oop-cpp-not-c-abi.md
│   │   ├── 0002-windows-native-msvc.md
│   │   ├── 0003-noise-xx-for-phase-1.md
│   │   ├── 0004-sqlite-column-aead-over-sqlcipher.md
│   │   └── 0005-mdns-for-discovery.md
│   └── archive/
│       └── v1-signal-inspired/
├── src/
│   ├── core/                    ← Error, Result, PeerId, etc.
│   ├── crypto/                  ← Crypto facade + SecureBuffer
│   ├── identity/
│   ├── wire/                    ← protobuf + framing
│   ├── discovery/
│   ├── transport/
│   ├── session/
│   ├── store/
│   ├── ui/
│   └── app/                     ← ChatApplication + main
├── include/ev/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fuzz/
│   └── vectors/
├── proto/
├── installer/                   ← WiX MSI project
└── .github/workflows/
```

## Build and toolchain

- **Compiler.** MSVC 2022 (v143 toolset). C++23 mode (`/std:c++latest`) for `std::expected`, designated initializers, `std::print` where handy.
- **Generator.** Ninja via CMake ≥ 3.25. `CMakePresets.json` exposes `debug`, `release`, `asan` (MSVC ASan), `analyze` (MSVC static analyzer).
- **Dependencies.** vcpkg manifest mode, baseline SHA pinned. Phase 1: libsodium, boost-asio, boost-program-options, protobuf, sqlite3, spdlog, fmt, catch2, ftxui, wil.
- **Warnings.** `/W4 /WX /permissive-` plus analyzer flags.
- **Static analysis.** MSVC `/analyze` in CI. clang-tidy where feasible with MSVC compile commands.
- **Sanitizers.** Windows ASan for Debug CI builds. UBSan/TSan not available on MSVC; accepted.

## Installer

- **WiX Toolset v4** produces a signed MSI.
- Installs to `%ProgramFiles%\EncryptiV\`.
- Start menu shortcut.
- Registers mDNS service class on first run (no admin required).
- Per-user data under `%APPDATA%\EncryptiV\`: `identity.bin`, `store.db`, `config.toml`, `logs/`.
- Clean uninstall. User data preserved unless full-removal is opted into.
- Code-signing: self-signed Authenticode cert for development, real cert before distribution.

"Plug and play" operationally: download MSI → double-click → Next → Finish → launch → pick display name + passphrase on first run → see other EncryptiV instances on the LAN.

## Wire format

All messages are protobuf, length-prefixed (32-bit big-endian), AEAD-sealed by the session.

- `HandshakeMessage` — Noise XX handshake payloads.
- `ApplicationMessage` — post-handshake, AEAD-encrypted inner payload.
- `InnerPayload` — typed content: `TextPayload`, future `FilePayload`, control messages, receipts.

Reserved field ranges, optional fields, version integers in envelopes — designed for forward compatibility.

## Testing

- **Unit.** Catch2 v3.
- **RFC vectors.** RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 8439 (ChaCha20-Poly1305).
- **Property.** Round-trip invariants. Session agreement under thousands of random interleavings.
- **Integration.** Two in-process instances, full discovery/handshake/message path with a fake DiscoveryService.
- **Fuzz.** libFuzzer harnesses per parser (protobuf decoders, wire framing, Noise parsing). 60s per target per PR.
- **Coverage.** `crypto/` `identity/` `session/` ≥ 85%; elsewhere ≥ 70%.

## Logging

spdlog, rotating file logs under `%APPDATA%\EncryptiV\logs\`. Default level info.

**Never logged:** private keys, passphrases, plaintext message bodies, raw Noise handshake messages, session keys, DB key. `log_sensitive(...)` wrapper expands to `<redacted>` unless `EV_UNSAFE_LOG_SECRETS=1` in a debug build. CI lint forbids `spdlog::` calls on secret-bearing types.

## Error handling

`std::expected<T, Error>` everywhere for recoverable errors. Exceptions for genuinely exceptional situations only. `Error` is a single struct with a code, message, and optional cause — no hierarchy.

## Extensibility seams

The reason Phase 1 is "overkill":

- **Transport abstraction** — Phase 2's LAN mailbox plugs in here.
- **DiscoveryService abstraction** — manual peers, invite codes, relays plug in here.
- **MessageBody variant** — files, receipts, typing indicators, group ops become new variants.
- **Session serialization** — supports migration to full Double Ratchet without interface change.
- **PeerDirectory device model** — `PeerRecord` carries a device-id field; Phase 3 multi-device populates it.
- **MessageStore schema** — tables for attachments and groups exist (empty) from day one; no migration at Phase 2/3.

Each is a concrete class or interface on day one.

## Explicit non-goals in Phase 1

No cross-network messaging. No offline/async delivery. No file transfer. No groups. No multi-device. No non-Windows builds. No mobile. Deferred, not forgotten — each has a designed seam.
