# Cloak — Complete Project Overview

> A detailed guide to what this project is, how it works, every tool and component used, and where every major programming principle appears in the codebase. Written to be understandable by both technical and non-technical readers.

---

## Table of Contents

1. [What Is Cloak?](#1-what-is-cloak)
2. [What Problem Does It Solve?](#2-what-problem-does-it-solve)
3. [How It Works — A Plain-English Walkthrough](#3-how-it-works--a-plain-english-walkthrough)
4. [Project Development Phases](#4-project-development-phases)
5. [Complete List of Tools and Technologies Used](#5-complete-list-of-tools-and-technologies-used)
6. [Architecture and Module Breakdown](#6-architecture-and-module-breakdown)
7. [Object-Oriented Programming Principles](#7-object-oriented-programming-principles)
8. [C++ Language Fundamentals in This Project](#8-c-language-fundamentals-in-this-project)
9. [Security Design — How Privacy Is Protected](#9-security-design--how-privacy-is-protected)
10. [Build System and Project Organization](#10-build-system-and-project-organization)
11. [Testing Strategy](#11-testing-strategy)
12. [Design Patterns Used](#12-design-patterns-used)
13. [Key Architectural Decisions](#13-key-architectural-decisions)

---

## 1. What Is Cloak?

**Cloak** (pronounced "Encrypt-IV") is a **Windows-native, terminal-based, end-to-end encrypted peer-to-peer chat application**. It is written entirely in **modern C++** (the C++23 standard) and runs as a command-line program on Windows 11.

Think of it like a private version of a messaging app — but instead of your messages going through a company's servers where employees could potentially read them, every message is scrambled (encrypted) on your computer before it ever leaves, and only the intended recipient can unscramble it. Not even the developers can read the messages.

**Key facts at a glance:**

| Feature | Detail |
|---|---|
| Language | C++23 |
| Platform | Windows 11 (native) |
| Version | v0.4.0 (Phase 4 complete) |
| Interface | Terminal / command-line (TUI) |
| Encryption | Military-grade (libsodium) |
| Network | LAN (local) and Internet (relay) |
| Storage | Encrypted SQLite database |
| Group chat | Supported (Phase 3+) |
| File transfer | Supported (Phase 2+) |

---

## 2. What Problem Does It Solve?

Most modern messaging apps — WhatsApp, Telegram, iMessage — route your messages through the company's servers. Even when they claim end-to-end encryption, you are trusting that company to handle your keys correctly and not access your data.

Cloak takes a completely different approach:

- **No central server** is needed to exchange messages (for LAN connections).
- **Your encryption keys never leave your device** in unprotected form.
- **Nobody in the middle** — not the developer, not your ISP, not your network administrator — can read what you send.
- The application is **auditable**: the code is all here, nothing hidden.

It is built for scenarios like:

- Secure communication within a company's internal network (LAN)
- Journalists, researchers, or professionals who need provably private communication
- People who understand cryptography and want full control over their privacy
- Learning/demonstration of advanced cryptographic protocols in a real application

---

## 3. How It Works — A Plain-English Walkthrough

### Step 1: Identity Creation

When you first launch Cloak, it creates your **cryptographic identity** — a unique pair of mathematical keys (think of it like a very complex padlock + key pair) that proves you are who you say you are. This identity is saved to your disk, but it is protected with your passphrase using a very slow, computationally expensive algorithm called **Argon2id** — designed specifically to make brute-force password guessing take years.

### Step 2: Finding Peers

Cloak discovers other users on your local network (LAN) using a technology called **mDNS** (Multicast DNS) — the same protocol your phone uses to find AirPrint printers or Chromecast devices. When it finds someone, it sees their public key (the public half of their identity) embedded in the discovery advertisement.

For internet connections (Phase 4), Cloak uses an **invite code system**: one person runs a relay server, generates an invite code, and sends it to the other person through any channel (even a regular email or text). The invite code contains the relay address and a meeting room ID.

### Step 3: The Handshake (Proving Identity)

Before any messages are sent, both parties perform a **cryptographic handshake** using a protocol called **Noise XX**. Think of this like two spies meeting and exchanging secret phrases to confirm neither is an impostor — except it is mathematically guaranteed rather than trust-based. After the handshake:

- Both parties are mutually authenticated (each knows the other is genuine)
- A unique session key is created for this conversation (and only this conversation)
- An eavesdropper who recorded the connection cannot decrypt it even if they later steal one of the private keys

### Step 4: Trust On First Use (TOFU)

The first time you connect to a peer, Cloak records their public key and marks them as "seen" (TOFU = Trust On First Use). If that same peer later appears with a *different* key, Cloak **loudly alerts you** — this could mean someone is attempting a man-in-the-middle attack. You can optionally verify identity via **Safety Numbers** — a 60-digit code both parties can compare over a phone call.

### Step 5: Messaging with the Double Ratchet

Every message uses a technique called the **Double Ratchet Algorithm** — the same algorithm that powers Signal Messenger. This means:

- Each message is encrypted with a fresh key derived from the previous one.
- If someone steals your current key, they cannot decrypt past messages (forward secrecy).
- If a key for one message is compromised, it does not expose other messages (break-in recovery).

### Step 6: Group Chat

For group conversations, Cloak uses the **Sender Key** model (similar to WhatsApp's group encryption). Each member has their own encryption "chain". Messages are signed so you can verify who actually sent each message.

### Step 7: File Transfer

Files are split into 64 KB chunks, each chunk encrypted with a per-file key. The file key is itself encrypted using the session key. This means even if someone intercepts one chunk, they gain nothing without the file key.

### Step 8: Persistence

All messages are stored in a **SQLite database** on your disk. But unlike a typical app, the sensitive columns are individually encrypted using **XChaCha20-Poly1305** AEAD encryption. Even if someone steals your database file, they get only scrambled data.

---

## 4. Project Development Phases

Cloak was built incrementally in four phases, each adding more capabilities:

### Phase 1 — v0.1.0: Basic LAN Chat
- Terminal chat over local network (TCP)
- Noise XX handshake for authenticated encryption
- mDNS peer discovery
- Basic peer trust (TOFU) model

### Phase 2 — v0.2.0: Double Ratchet, Files, Receipts
- Full **Double Ratchet** algorithm (Signal-style per-message keys)
- File transfer with chunk-level encryption
- Delivery and read receipts
- LAN mailbox (store messages for offline peers)
- SQLite message persistence

### Phase 3 — v0.3.0: Group Chat and Multi-Device
- **Group messaging** using the Sender Key protocol (Ed25519-signed)
- **Multi-device** support via device certificates (a secondary device vouched for by a primary)
- Group creation, invite, leave, kick operations
- Group persistence across restarts

### Phase 4 — v0.4.0 (Current): Internet Relay
- Standalone **relay server** (`cloak-relay.exe`) for internet connectivity
- **Invite code** peer discovery (works through NAT/firewalls)
- `RelayTransport` — transparent TCP multiplexer
- Full internet P2P while keeping all cryptography end-to-end

---

## 5. Complete List of Tools and Technologies Used

### Programming Language

| Tool | Purpose |
|---|---|
| **C++23** | Core language. Uses modern features: `std::expected`, move semantics, templates, constexpr, `std::span` |
| **MSVC 2022 (v143)** | Microsoft's C++ compiler. Enforces strict warnings (`/W4 /WX`) and MSVC static analysis |

### Build System

| Tool | Purpose |
|---|---|
| **CMake 3.25+** | Cross-platform build configuration. Defines all targets, presets, and dependencies |
| **Ninja** | Fast build generator (used instead of MSBuild for speed) |
| **CMakePresets.json** | Pre-defined build configurations: `debug`, `release`, `asan`, `analyze` |
| **vcpkg** | Microsoft's C++ package manager. Handles automatic downloading and building of all dependencies |

### Libraries (Dependencies via vcpkg)

| Library | What It Does | Used In |
|---|---|---|
| **libsodium** | All cryptographic operations — encryption, signing, key exchange, hashing | `crypto/` module exclusively |
| **Boost.Asio** | Asynchronous networking (TCP connections, timers, strands) | `transport/` and `app/` |
| **Boost.Program Options** | Command-line argument parsing (`--port`, `--connect`, `--relay`, etc.) | `app/main.cpp` |
| **SQLite3** | Embedded relational database for message and peer storage | `store/` module |
| **spdlog** | Fast, structured logging with rotating log files | All modules |
| **fmtlib** | String formatting (used by spdlog and throughout) | All modules |
| **Catch2** | Unit testing framework with `TEST_CASE` / `REQUIRE` macros | `tests/unit/` |
| **FTXUI** | Terminal UI framework for the chat interface (windows, panels, text input) | `ui/` module |
| **WIL (Windows Implementation Library)** | Safe wrappers for Win32 APIs (handles, error handling) | Platform code |

### Operating System and Platform APIs

| API / Feature | Purpose |
|---|---|
| **Win32 VirtualLock / VirtualUnlock** | Lock secret key memory pages to prevent OS swapping to disk |
| **Win32 SecureZeroMemory** | Cryptographically safe memory zeroing (compiler cannot optimize it away) |
| **Win32 DNS-SD (mDNS)** | LAN peer discovery without a central server |
| **Windows Sockets (Winsock2)** | Underlying TCP networking |

### Development and Quality Tools

| Tool | Purpose |
|---|---|
| **MSVC Address Sanitizer (ASan)** | Detects memory bugs (buffer overflows, use-after-free) at runtime |
| **MSVC /analyze** | Static analysis to find potential bugs without running the code |
| **WiX Toolset** | Creates the Windows MSI installer package |
| **Git** | Version control; branch-per-phase development model |

### Cryptographic Protocols (not libraries, but standards)

| Protocol | Purpose |
|---|---|
| **Noise XX** | Authenticated key exchange handshake (mutual auth + forward secrecy) |
| **Double Ratchet Algorithm** | Per-message forward secrecy (same as Signal Messenger) |
| **X25519** | Elliptic curve Diffie-Hellman key agreement |
| **Ed25519** | Digital signatures for identity and group messages |
| **XChaCha20-Poly1305** | Authenticated encryption (AEAD) for all ciphertexts |
| **HKDF-SHA256** | Key derivation (generating session keys from shared secrets) |
| **HMAC-SHA256** | Per-message ratchet key derivation |
| **Argon2id** | Password-based key derivation (slow, memory-hard; protects stored identity) |
| **BLAKE2b-256** | Fast hashing for invite code room IDs |
| **Sender Keys** | Group encryption model (WhatsApp-style) with per-member ratchet chains |

---

## 6. Architecture and Module Breakdown

The project is organized into **13 independent modules**, each with a clear single responsibility. Here is every module explained:

```
ChatApplication (top-level orchestrator)
│
├── crypto/         All cryptographic operations (libsodium facade)
├── identity/       Who you are: keypairs, trust, multi-device
├── wire/           How bytes are packaged and sent over the network
├── transport/      How bytes physically move (TCP, mailbox, relay)
├── session/        Encrypted conversation per peer (handshake + ratchet)
├── discovery/      Finding peers on the network
├── store/          Saving messages and peers to encrypted database
├── group/          Group chat encryption and management
├── transfer/       File chunking and encrypted file sending
├── relay/          Standalone relay server for internet connections
├── ui/             Terminal user interface
├── core/           Shared types used by all other modules
└── app/            Wires everything together; the main program
```

### `core/` — Shared Foundation
- **What it is:** Defines the basic data types that every other module uses.
- **Key types:**
  - `PeerId` — A 32-byte identifier for a peer (their public signing key)
  - `SessionId` — A 16-byte identifier for a live conversation
  - `MessageId`, `FileId`, `GroupId` — Unique identifiers for database records
  - `Result<T>` — The universal error type (`std::expected<T, Error>`)
  - `Error` and `ErrorCode` — Structured errors with 13 distinct codes and error chaining
  - `TrustStatus` — Enum: Unknown, Tofu, Verified, Changed

### `crypto/` — The Cryptographic Engine
- **What it is:** The only module that touches raw libsodium. All other modules go through this.
- **`Crypto` class** (static facade):
  - `initialize()` — Must be called once at startup; thread-safe via `std::once_flag`
  - `kx_keypair()` / `ed25519_keypair()` — Generate X25519 and Ed25519 key pairs
  - `kx_agree()` — Compute shared secret (X25519 Diffie-Hellman)
  - `sign_detached()` / `verify_detached()` — Create and verify Ed25519 signatures
  - `aead_encrypt()` / `aead_decrypt()` — XChaCha20-Poly1305 encryption/decryption
  - `hkdf_sha256()` / `hmac_sha256()` — Key derivation functions
  - `argon2id_derive()` — Passphrase to key derivation (slow; used for identity at rest)
  - `constant_time_equal()` — Timing-attack safe comparison
  - `random_bytes()` / `blake2b_256()` — Random data and hashing
- **`SecureBuffer<N>`** (template class):
  - Fixed-size buffer that holds exactly N bytes of secret key material
  - Calls `VirtualLock()` on creation (pins memory, prevents paging to disk)
  - Calls `SecureZeroMemory()` + `VirtualUnlock()` on destruction
  - **Move-only**: cannot be copied; moving zeros the source — secrets cannot leak through copies

### `identity/` — Who You Are
- **`Identity`** class:
  - Holds your long-term Ed25519 signing keypair and X25519 key-agreement keypair
  - `generate()` — Creates a brand-new random identity
  - `save(path, passphrase)` — Encrypts identity to disk with Argon2id + XChaCha20-Poly1305
  - `load(path, passphrase)` — Decrypts from disk; fails with `AuthenticationFailed` on wrong passphrase
  - `fingerprint()` — 12-character base32 string for quick visual identity check
  - `safety_number(a, b)` — 60-digit decimal code for out-of-band verification
  - Stored at: `%APPDATA%\Cloak\identity.bin`
- **`PeerDirectory`** class:
  - Tracks every peer you have ever connected to
  - Stores their public key and current `TrustStatus`
  - Thread-safe: protected by `std::mutex`
  - Raises `Changed` alert if a peer's key changes (possible MITM attack)
- **`DeviceRegistry`** class (Phase 3):
  - Manages multi-device linking (Primary device authorizes Secondary devices)
  - `DeviceCert` structure: secondary's signing key + primary's signature over it
  - Thread-safe: protected by `std::mutex`

### `wire/` — Message Framing
- **What it is:** Defines exactly how bytes are laid out in network packets.
- **Frame format:** `[4-byte length (big-endian)][1-byte type][payload bytes]`
- **`MessageType` enum:** Handshake (1), AppMessage (2), FileChunk (3), Receipt (4), GroupMessage (5), GroupOp (6)
- **`InnerType` enum (inside decrypted payloads):** Text, FileMetadata, Receipt, Typing, GroupOp, DeviceLink, GroupMessage
- **Handshake payload** (when two peers first meet):
  - `x25519_pub` [32 bytes] — Public key for key agreement
  - `ed25519_pub` [32 bytes] — Public signing key (identity)
  - `sig_over_x25519` [64 bytes] — Signature proving ownership
  - `dr_pub` [32 bytes] — Double Ratchet initial key
  - `sig_over_dr` [64 bytes] — Signature proving DR key ownership
  - `version` [1 byte] — Wire protocol version
  - `display_name` [up to 64 bytes UTF-8]

### `transport/` — How Bytes Move
- **`Transport`** (abstract base class) — pure virtual interface:
  - `send(data)` — Send bytes
  - `receive(n)` — Receive exactly n bytes
  - `close()` — End the connection
  - `is_open()` — Check if connection is alive
- **`TcpTransport`** (Phase 1):
  - Direct TCP connection over LAN
  - Uses Boost.Asio TCP sockets
  - `connect(endpoint)` — Initiator dials peer
  - `accept_from(port)` — Responder listens for incoming connections
- **`LanMailboxTransport`** (Phase 2):
  - Store-and-forward: holds encrypted messages for temporarily offline peers
  - Max 64 MiB per recipient, messages expire after 7 days
  - Mailbox never decrypts anything — end-to-end encryption is preserved
- **`RelayTransport`** (Phase 4):
  - Routes connections through a relay server for internet connectivity
  - 37-byte handshake: magic "CLK1" + role + 32-byte room ID
  - After pairing, relay forwards raw bytes transparently
  - All cryptography runs above the relay layer — relay sees only ciphertext

### `session/` — Encrypted Conversation State
- **`Session`** class — the heart of the protocol:
  - **Phase 1:** Noise_XX_25519_ChaChaPoly_BLAKE2s handshake (mutual authentication)
  - **Phase 2+:** Full Double Ratchet on top
  - `Session::initiate()` — Create a session as the connection starter
  - `Session::accept()` — Create a session as the receiver
  - `send_text(text)` / `recv_text()` — Convenience wrappers
  - `send_inner(type, payload)` / `recv_message()` — General API for all message types
  - Double Ratchet state: root key, sending/receiving chain keys, message keys, skipped-key cache
  - Skipped message key cache: up to 500 entries for out-of-order delivery
  - **Move-only** (due to `SecureBuffer` members — keys can only be moved, never copied)
  - **Not thread-safe** — `SessionManager` is responsible for serializing access
- **`SessionManager`** class:
  - Thread-safe registry of all active sessions
  - `add_session()`, `remove_session()`, `for_each()`, `count()`
  - Protected by `std::mutex`; template `for_each()` holds lock during iteration

### `discovery/` — Finding Peers
- **`DiscoveryService`** (abstract base class):
  - `start_advertising(advertisement)` — Broadcast your presence
  - `stop_advertising()` — Go silent
  - `get_discovered_peers()` — List all found peers
- **`LoopbackDiscoveryService`** (Phase 1 / testing):
  - Stub implementation for local testing (no network traffic)
  - Peers connect explicitly with `--connect` flag
- Production implementation uses **Win32 DNS-SD** (mDNS) with the identity signing key embedded in TXT records, so peers are authenticated cryptographically from the moment of discovery.

### `store/` — Encrypted Database
- **`MessageStore`** class:
  - SQLite database with per-column XChaCha20-Poly1305 encryption
  - DB key derived from passphrase via Argon2id; held in `SecureBuffer` (never written to disk)
  - `open(path, db_key)` — Open/create and run migrations
  - `save_message()`, `get_messages_for_peer()`, `get_conversation()` — Message CRUD
  - `mark_delivered()`, `mark_read()` — Receipt tracking
  - `purge_expired()` — Clean up self-destructing messages
  - `save_peers()` / `load_peers()` — PeerDirectory persistence across restarts
  - `save_group()` / `load_groups()` / `delete_group()` — Group persistence (Phase 3)
  - Thread-safe: `std::mutex` on all public methods
  - Move-only: owns the `sqlite3*` handle
  - Stored at: `%APPDATA%\Cloak\store.db`

### `group/` — Group Messaging (Phase 3)
- **`GroupSession`** class — manages one group from this device's perspective:
  - Owns: `group_id`, your signing keypair (`SecureBuffer<64>`), your chain key, member list
  - `create(name, identity)` — Start a new group
  - `from_state(...)` — Reconstruct from saved state
  - `encrypt(text)` → encrypted + signed payload
  - `decrypt(payload)` → (sender_pub, plaintext)
  - `make_invite_op(invitee_pub)` — Distribute your chain key to a new member (encrypted per-member)
  - `make_leave_op()` / `apply_op(op)` — Group lifecycle operations
- **`GroupManager`** class — thread-safe orchestrator:
  - Manages map of `GroupId → GroupSession`
  - Protected by `std::mutex`
  - `create_group()`, `accept_invite()`, `send()`, `recv()`, `invite()`, `leave()`, `restore()`, `snapshot()`

### `transfer/` — File Transfer (Phase 2)
- Free functions (no class needed — stateless operations):
  - `send_file(session, path, mime_type, progress_callback)` — Splits file into 64 KB chunks, encrypts each, sends
  - `receive_file(session, save_dir, progress_callback)` — Receives all chunks, decrypts, saves to disk
  - `chunk_nonce(file_key, chunk_idx)` — Derives 24-byte nonce per chunk via HKDF
- Per-file random 32-byte key (generated fresh for each transfer)
- File key itself is encrypted in the FileMetadata message using the session key

### `relay/` — Relay Server (Phase 4)
- **`RelayServer`** class — standalone `cloak-relay.exe`:
  - Thread-per-connection model
  - Accepts 37-byte handshake from each client
  - Pairs clients that share the same 32-byte room ID
  - Forwards raw bytes between paired clients transparently
  - Never sees plaintext — all crypto runs above the relay
  - Usage: `cloak-relay.exe --port 8765`

### `ui/` — Terminal Interface
- **`ChatUi`** class:
  - Built with FTXUI (a C++ terminal UI framework)
  - Split-panel terminal view: message history + input field
  - Displays peer name, trust status, message timestamps
  - Non-blocking: UI thread never waits for network I/O
  - Asynchronous updates via post to `io_context`

### `app/` — The Orchestrator
- **`ChatApplication`** class — owns and wires together every other module:
  - Parses command-line arguments (Boost.Program Options)
  - Loads or generates identity
  - Opens message store (prompts for passphrase)
  - Starts discovery service
  - Listens for incoming TCP connections
  - Creates sessions for each peer (handshake, Double Ratchet init)
  - Processes all incoming messages (dispatches by `InnerType`)
  - Routes outgoing messages to correct session
  - Saves groups, receipts, file chunks
  - Manages UI lifecycle

---

## 7. Object-Oriented Programming Principles

Object-Oriented Programming (OOP) is a way of writing code by organizing it into **"objects"** — bundles of data and the functions that operate on that data. There are four core OOP principles: **Encapsulation**, **Abstraction**, **Inheritance**, and **Polymorphism**. Here is exactly where and how each appears in Cloak.

---

### 7.1 Encapsulation

**What it means:** Hiding internal details inside a class and only exposing what is necessary through a clean public interface. Callers do not need to know how something works — only what it does.

**Where it appears:**

#### `SecureBuffer<N>` (`src/crypto/secure_buffer.h`)
The secret key bytes inside `SecureBuffer` are completely private. You cannot reach in and read the raw memory directly from outside the class. The class controls all access through:
- `data()` — returns a pointer (read-only in const contexts)
- `operator[]` — indexed access
- Iterators for range-based for loops

Crucially, the class controls its own **lifecycle**: the memory locking (`VirtualLock`) and secure zeroing (`SecureZeroMemory`) happen automatically inside the constructor and destructor. Callers never need to remember to zero out key material — the class enforces it.

#### `Crypto` class (`src/crypto/crypto.h`)
The `Crypto` class completely hides the fact that it uses libsodium. From the perspective of any caller, there is simply a `Crypto::aead_encrypt()` function that takes plaintext and returns ciphertext. If the team later wanted to replace libsodium with a different library, only `crypto.cpp` would need to change — nothing else in the codebase would notice. This is the essence of encapsulation.

The thread-safe initialization flag (`std::once_flag`) is also fully private — callers just call `Crypto::initialize()` and do not think about thread safety.

#### `Session` class (`src/session/session.h`)
The Double Ratchet state — all the chain keys, root keys, message counters, skipped key cache — is entirely private. Outside code only sees:
- `send_text()` / `recv_text()` — Simple, clean public API
- `send_inner()` / `recv_message()` — General-purpose message API

The caller does not know about ratchet steps, HKDF calls, or cipher nonces. All that complexity is encapsulated inside the class.

#### `MessageStore` class (`src/store/message_store.h`)
The SQLite connection (`sqlite3*` handle) is private. Callers use high-level methods like `save_message()` and `get_conversation()`. The encryption of column data is invisible to callers — they pass and receive plaintext strings; the class silently encrypts before writing and decrypts after reading.

#### `Identity` class (`src/identity/identity.h`)
The secret key bytes (`SecureBuffer<64>` for the Ed25519 secret key) are private. Callers can ask the Identity to `sign()` data, but they can never extract the raw private key bytes. The key is protected at all times.

---

### 7.2 Abstraction

**What it means:** Defining a simplified "interface" that describes *what* something can do, without specifying *how* it does it. Abstraction lets you write code that works with any implementation that fulfills the contract.

**Where it appears:**

#### `Transport` abstract base class (`src/transport/transport.h`)
This is the clearest example of abstraction in the project. `Transport` defines four pure virtual methods:

```cpp
virtual Result<void> send(std::span<const std::byte> data) = 0;
virtual Result<std::vector<std::byte>> receive(size_t exact) = 0;
virtual void close() = 0;
virtual bool is_open() = 0;
```

The `= 0` makes these **pure virtual** — `Transport` itself cannot be instantiated. You must use one of the concrete implementations: `TcpTransport`, `LanMailboxTransport`, or `RelayTransport`.

The `Session` class holds a `std::unique_ptr<Transport>`. It does not know or care whether bytes are flowing over a local TCP socket, through a LAN mailbox, or through an internet relay. The session just calls `transport_->send()` and `transport_->receive()`. This is abstraction in action: the session is written against the abstract interface, not any specific implementation.

#### `DiscoveryService` abstract base class (`src/discovery/discovery_service.h`)
Same pattern: pure virtual `start_advertising()`, `stop_advertising()`, and `get_discovered_peers()`. The `ChatApplication` holds a `std::unique_ptr<DiscoveryService>`. In Phase 1, this is a `LoopbackDiscoveryService` (for testing). In production, it would be replaced with a real mDNS implementation. The rest of the application does not change.

#### `Result<T>` / `std::expected<T, Error>` (`src/core/error.h`)
The `Result<T>` type abstracts error handling. Instead of checking return codes or catching exceptions, every function returns either a value (`T`) or an error (`Error`). This is a standardized contract that abstracts error propagation throughout the codebase. Callers interact with errors through the `Error` struct, not through raw integers or exception types.

---

### 7.3 Inheritance

**What it means:** A child class (derived class) builds on a parent class (base class), inheriting its interface and optionally its implementation. It creates an "is-a" relationship.

**Where it appears:**

#### `TcpTransport : public Transport`
`TcpTransport` is a `Transport` — it inherits the interface and provides its implementation for LAN-direct TCP connections. The `Session` class can use it without modification via the `Transport*` pointer.

#### `LanMailboxTransport : public Transport`
`LanMailboxTransport` is also a `Transport` — same interface, completely different implementation (store-and-forward instead of direct connection). The entire Session code works unchanged with this transport.

#### `RelayTransport : public Transport`
`RelayTransport` is also a `Transport` — connects through a relay server, but the Session code above it has zero knowledge of this. The three transport implementations share the same abstract parent, forming a clean inheritance hierarchy.

#### `LoopbackDiscoveryService : public DiscoveryService`
`LoopbackDiscoveryService` inherits from the abstract `DiscoveryService` base class. It implements the stub behavior used for local testing. A future `MdnsDiscoveryService` would also inherit from the same base.

**The pattern in action:** Because `Transport` and `DiscoveryService` are both abstract base classes with concrete derived classes, Cloak can swap out implementations at construction time — for example, providing a `TcpTransport` for LAN mode and a `RelayTransport` for internet mode — without touching the session logic at all.

---

### 7.4 Polymorphism

**What it means:** "Many forms." The ability to call the same method on different objects and get different behavior, depending on the actual type of the object at runtime. This is the payoff of inheritance and abstraction.

**Where it appears:**

#### Virtual dispatch via `Transport*`
When `Session` calls `transport_->send(data)`, C++ uses a **virtual function table** (vtable) to figure out at runtime which implementation to call. If the transport is a `TcpTransport`, it calls `TcpTransport::send()`. If it is a `RelayTransport`, it calls `RelayTransport::send()`. Same line of code in `Session`, three different behaviors — that is polymorphism.

#### Virtual dispatch via `DiscoveryService*`
When `ChatApplication` calls `discovery_->get_discovered_peers()`, the same polymorphism applies. The `LoopbackDiscoveryService` version returns a hardcoded empty list; the real mDNS version would query the network. The application code does not change.

#### `std::unique_ptr<Transport>` as the polymorphic handle
Throughout `Session`, the transport is held as `std::unique_ptr<Transport>`. This smart pointer holds the abstract base type, so any concrete `Transport` subclass can be stored in it. The virtual destructor on `Transport` ensures that when the `unique_ptr` goes out of scope, the correct derived class destructor is called (closing the socket properly).

#### `GroupSession::encrypt()` / `GroupSession::decrypt()`
These methods behave differently depending on whether the local user is the one who created the group (has the initial chain key) vs a member who joined via invite. The state within the object — not the caller — determines the cryptographic path taken.

---

### OOP Summary Table

| Principle | Where Applied | File(s) |
|---|---|---|
| **Encapsulation** | `SecureBuffer<N>` — hides raw key bytes | `crypto/secure_buffer.h` |
| **Encapsulation** | `Crypto` — hides libsodium internals | `crypto/crypto.h` |
| **Encapsulation** | `Session` — hides Double Ratchet state | `session/session.h` |
| **Encapsulation** | `MessageStore` — hides SQLite + encryption | `store/message_store.h` |
| **Encapsulation** | `Identity` — hides private key bytes | `identity/identity.h` |
| **Abstraction** | `Transport` — pure virtual interface | `transport/transport.h` |
| **Abstraction** | `DiscoveryService` — pure virtual interface | `discovery/discovery_service.h` |
| **Abstraction** | `Result<T>` — unified error contract | `core/error.h` |
| **Inheritance** | `TcpTransport : Transport` | `transport/tcp_transport.h` |
| **Inheritance** | `LanMailboxTransport : Transport` | `transport/mailbox_transport.h` |
| **Inheritance** | `RelayTransport : Transport` | `transport/relay_transport.h` |
| **Inheritance** | `LoopbackDiscoveryService : DiscoveryService` | `discovery/loopback_discovery.h` |
| **Polymorphism** | `transport_->send()` dispatches at runtime | `session/session.cpp` |
| **Polymorphism** | `discovery_->get_discovered_peers()` dispatches at runtime | `app/chat_application.cpp` |
| **Polymorphism** | Virtual destructors ensure proper cleanup | All base classes |

---

## 8. C++ Language Fundamentals in This Project

C++ is a powerful language with many features that set it apart from simpler languages. Here is where every major C++ fundamental appears in Cloak.

---

### 8.1 Classes and Objects

Every meaningful concept in Cloak is modeled as a class:
- `Identity` — your cryptographic identity (an object that holds your keys)
- `Session` — a live encrypted conversation (an object that holds ratchet state)
- `MessageStore` — a database connection (an object that owns a file handle)
- `GroupSession` — a group encryption context (an object that holds chain keys)

Classes bundle related data (`private` members) with related operations (`public` methods). This is the most fundamental C++ feature used throughout the entire codebase.

---

### 8.2 Constructors and Destructors (RAII)

**RAII** stands for Resource Acquisition Is Initialization — a fundamental C++ idiom. The rule: acquire a resource in the constructor, release it in the destructor. This guarantees that resources are always cleaned up, even if an error occurs.

**In `SecureBuffer<N>` (`src/crypto/secure_buffer.h`):**
```
Constructor:  VirtualLock(memory)       — pin memory so OS cannot page it to disk
Destructor:   SecureZeroMemory(memory)  — overwrite key material with zeros
              VirtualUnlock(memory)     — unpin memory
```
This means it is physically impossible to forget to zero out a secret key. When the `SecureBuffer` object goes out of scope (function returns, exception thrown, etc.), C++ automatically calls the destructor, which wipes the memory.

**In `MessageStore` (`src/store/message_store.h`):**
```
Constructor (open()):  sqlite3_open()    — open the database file
Destructor:           sqlite3_close()   — close and release the file handle
```

**In `TcpTransport` (`src/transport/tcp_transport.h`):**
```
Constructor (connect()):  socket.connect()  — establish TCP connection
Destructor:              socket.close()    — close TCP connection
```

RAII appears in every single module that manages a resource (memory, file, socket, lock).

---

### 8.3 Move Semantics (Move Constructor and Move Assignment)

Modern C++ (C++11 onwards) introduced **move semantics** — the ability to transfer ownership of a resource from one object to another without copying it. This is critical for performance and for security (you cannot have two objects holding the same secret key).

**In `SecureBuffer<N>`:**
The copy constructor and copy assignment are `= delete` (explicitly forbidden). The move constructor transfers the raw byte buffer to the destination and zeros the source. After a move, the original `SecureBuffer` is empty and harmless.

**In `Session`:**
Because `Session` contains `SecureBuffer` members (for the Double Ratchet root key, chain keys, etc.), it inherits move-only semantics. A `Session` can be moved into a container (`std::vector`) but never copied — preventing accidental duplication of live cryptographic state.

**In `MessageStore`:**
The `sqlite3*` handle can be moved to a new `MessageStore` object, transferring ownership. The original object's handle is set to `nullptr`, preventing double-close.

**In `Identity`:**
The `SecureBuffer<64>` (Ed25519 secret key) and `SecureBuffer<32>` (X25519 secret key) make `Identity` move-only. You cannot accidentally make a second copy of your private key.

Move semantics appear in **every class that owns a secret or a resource** — which is most major classes in the project.

---

### 8.4 Templates

**What they are:** Templates let you write code once that works with many different types. The type is specified when you use the template.

**`SecureBuffer<N>` (`src/crypto/secure_buffer.h`):**
```cpp
template <size_t N>
class SecureBuffer { ... };
```
`N` is the number of bytes. `SecureBuffer<32>` holds a 32-byte X25519 key. `SecureBuffer<64>` holds a 64-byte Ed25519 signing key. The same class handles both — no code duplication.

**`Result<T>` / `std::expected<T, Error>` (`src/core/error.h`):**
```cpp
template <typename T>
using Result = std::expected<T, Error>;
```
`Result<Identity>` means "either an Identity or an Error". `Result<void>` means "either success or an Error". Same pattern, any type.

**`SessionManager::for_each<F>` (`src/session/session_manager.h`):**
```cpp
template <typename F>
void for_each(F&& f) {
    std::lock_guard lock(mutex_);
    for (auto& [id, session] : sessions_) f(id, *session);
}
```
This template accepts any callable (lambda, function pointer, functor). The caller decides what to do with each session; the template handles the locking and iteration.

**`std::array<uint8_t, N>` used for all fixed-size identifiers:**
`PeerId`, `SessionId`, `MessageId`, `FileId`, `GroupId` are all `std::array<uint8_t, N>` with different sizes — all using the same template, providing type safety (a `PeerId` and a `SessionId` are different types even if both are 16 bytes).

---

### 8.5 Smart Pointers

Raw pointers (`new` / `delete`) are dangerous — forgetting to `delete` causes memory leaks; deleting twice causes crashes. Smart pointers manage this automatically.

**`std::unique_ptr<T>` (exclusive ownership):**
- `ChatApplication` holds `std::unique_ptr<Transport>` — one and only one owner
- `ChatApplication` holds `std::unique_ptr<Identity>` — one owner, auto-deleted on destruction
- `ChatApplication` holds `std::unique_ptr<DiscoveryService>` — polymorphic, auto-deleted
- `Session` holds `std::unique_ptr<Transport>` — session exclusively owns its transport
- `TcpTransport` holds `std::unique_ptr<io_context>` — so it can be moved (unique_ptr is movable)
- `SessionManager` stores `std::unique_ptr<Session>` in its internal vector

When the owning object is destroyed, `unique_ptr` automatically calls `delete` on the held pointer — no memory leak possible.

**`std::shared_ptr<T>` (shared ownership — used sparingly):**
- `Error::cause` — an error can chain to another error as its cause; both the original and the chained error share ownership of the cause `Error` struct

---

### 8.6 The Standard Library (`std::`)

Cloak uses the C++ Standard Library extensively:

| Container/Utility | Used For |
|---|---|
| `std::vector<T>` | Peer lists, byte buffers, chunk collections |
| `std::map<K, V>` | Skipped message key cache (`SkippedKeyId → SecureBuffer<32>`) |
| `std::unordered_map` | GroupManager's session map (faster lookups) |
| `std::string` | Display names, file paths, text messages |
| `std::optional<T>` | `DeviceRegistry::own_cert_`, optional return values |
| `std::span<const std::byte>` | Non-owning view of byte buffers (no copy) |
| `std::array<uint8_t, N>` | All fixed-size ID types |
| `std::mutex` | Thread safety in SessionManager, PeerDirectory, GroupManager, MessageStore |
| `std::lock_guard<std::mutex>` | RAII mutex locking (unlocks automatically on scope exit) |
| `std::atomic<bool>` | Thread-safe boolean flags (running_, open_, dead_) |
| `std::once_flag` | One-time initialization in `Crypto::initialize()` |
| `std::thread` | Receive threads spawned per peer in ChatApplication |
| `std::expected<T, E>` | Universal result type for all fallible operations (C++23) |
| `std::filesystem::path` | Cross-platform file path handling |
| `std::chrono` | Timestamps for messages and expiry logic |

---

### 8.7 Enumerations (`enum class`)

Strongly-typed enums prevent accidents where an integer from one domain is used where another is expected:

```cpp
enum class MessageType : uint8_t { Handshake=1, AppMessage=2, FileChunk=3, ... };
enum class InnerType   : uint8_t { Text=0x00, FileMetadata=0x01, Receipt=0x02, ... };
enum class TrustStatus         { Unknown, Tofu, Verified, Changed };
enum class ErrorCode           { CryptoError, AuthenticationFailed, IdentityChanged, ... };
enum class DeviceRole          { Primary, Secondary };
```

`enum class` (scoped enum) means you cannot accidentally use a `MessageType` where a `TrustStatus` is expected — the compiler rejects it. This eliminates an entire class of bugs.

---

### 8.8 Error Handling with `std::expected` (No Exceptions)

Traditional C++ uses exceptions for error handling (`throw` / `catch`). Cloak makes a deliberate choice **not** to use exceptions for recoverable errors. Instead, it uses `std::expected<T, Error>` — a type that holds either a successful value or an error.

**Example pattern:**
```cpp
Result<std::vector<std::byte>> receive_frame() {
    auto header = transport_->receive(5);
    if (!header) return std::unexpected(header.error());
    // ... process
    return payload;
}
```

Every function that can fail returns `Result<T>`. Callers must explicitly check (or propagate) the error. This makes control flow completely predictable and prevents errors from being silently ignored.

**Why this matters for security:** Silent error handling is a common source of security vulnerabilities. If an authentication check returns an error and the error is ignored, an attacker might bypass authentication. `std::expected` makes this impossible to accidentally ignore — the code will not compile if you use the result without checking it.

---

### 8.9 `const` Correctness

Throughout the codebase, `const` is used to prevent accidental mutation:

- `const std::span<const std::byte>` — passing bytes to encrypt: the buffer will not be modified
- `const Identity&` — passing an identity to read from: it will not be mutated
- `const std::string&` — passing a display name to use: no copy, no modification
- Member functions marked `const` (e.g., `is_open() const`) — these methods promise not to change the object's state

`const` correctness serves as a form of documentation that is enforced by the compiler, and it prevents a class of bugs where data is unintentionally modified.

---

### 8.10 Namespaces

All Cloak code lives under the `cloak::` namespace, with sub-namespaces per module:

```cpp
cloak::crypto::Crypto          // The crypto facade
cloak::crypto::SecureBuffer<N> // Secure key storage
cloak::identity::Identity      // The identity class
cloak::session::Session        // Encrypted conversation
cloak::transport::Transport    // Abstract transport
cloak::store::MessageStore     // Encrypted database
cloak::group::GroupManager     // Group chat
```

Namespaces prevent name collisions (if libsodium also had a class called `Crypto`, there would be no ambiguity) and provide logical grouping that mirrors the module structure.

---

### 8.11 Deleted Special Member Functions

When a class should not be copied (because copying would duplicate a secret key, or because it does not make semantic sense), the copy operations are explicitly deleted:

```cpp
SecureBuffer(const SecureBuffer&)            = delete;
SecureBuffer& operator=(const SecureBuffer&) = delete;
```

This is better than simply not providing these functions — it gives the compiler error message clearly states that copying is intentionally forbidden, rather than a confusing message about inaccessible members.

---

### 8.12 Operator Overloading

`SecureBuffer<N>` overloads `operator[]` so that indexing feels natural:
```cpp
buffer[0]  // Access first byte — same syntax as an array
```

`std::array` (used for all ID types) supports `operator==` for comparison. This means two `PeerId` values can be compared with `==` naturally, even though they are 32-byte arrays under the hood.

---

### C++ Fundamentals Summary Table

| Feature | Where Applied |
|---|---|
| **Classes and Objects** | Every major module (Session, Identity, Crypto, etc.) |
| **RAII** | SecureBuffer, MessageStore, TcpTransport, Session |
| **Constructors / Destructors** | All resource-owning classes |
| **Move semantics** | SecureBuffer, Session, Identity, MessageStore (move-only) |
| **Templates** | SecureBuffer\<N\>, Result\<T\>, for_each\<F\>, fixed-size IDs |
| **Smart pointers** | unique_ptr everywhere; shared_ptr for error chaining |
| **Standard Library** | vector, map, mutex, atomic, optional, span, expected, thread |
| **enum class** | MessageType, InnerType, TrustStatus, ErrorCode, DeviceRole |
| **std::expected / Result\<T\>** | Every fallible function in the entire codebase |
| **const correctness** | Parameters, member functions, spans |
| **Namespaces** | cloak::crypto, cloak::session, cloak::identity, cloak::store, etc. |
| **Deleted functions** | Copy constructor/assignment on all key-holding classes |
| **Operator overloading** | SecureBuffer::operator[], ID types via std::array |
| **Pure virtual functions** | Transport, DiscoveryService (abstraction + polymorphism) |

---

## 9. Security Design — How Privacy Is Protected

### Cryptographic Primitives

All cryptographic operations go through libsodium — a reputable, audited library. Cloak never implements its own cryptography (a common and dangerous mistake).

| Operation | Algorithm | Purpose |
|---|---|---|
| Signing | Ed25519 | Prove identity, sign group messages |
| Key agreement | X25519 | Establish shared secrets |
| Handshake | Noise XX | Mutual authentication + session key |
| Symmetric encryption | XChaCha20-Poly1305 | Encrypt messages, files, database |
| Message key ratchet | HMAC-SHA256 | Per-message forward secrecy |
| Session key derivation | HKDF-SHA256 | Derive session keys from shared secrets |
| Passphrase protection | Argon2id | Protect identity and database at rest |
| Room ID generation | BLAKE2b-256 | Derive invite code room identifiers |

### Forward Secrecy

Even if an attacker steals your current private key, they cannot decrypt past messages. The Double Ratchet ensures each message is encrypted with a key that is immediately discarded after use. Past keys cannot be reconstructed from current state.

### TOFU and Safety Numbers

Trust is established on first contact and verified through safety numbers — a 60-digit code that both parties see and can compare over a phone call or in person. If the code matches, you know you are communicating with the genuine peer and not an impostor.

### Memory Safety

All secret key material lives in `SecureBuffer` objects that:
- Are pinned in RAM (cannot be swapped to disk where they might linger)
- Are zeroed immediately when the object is destroyed
- Cannot be copied (move-only)
- Are never logged (a compile-time guard prevents this in secret-bearing types)

### No Cleartext Storage

The database on disk contains only encrypted data. The identity file on disk is encrypted. An attacker who steals your hard drive gets only encrypted blobs — useless without your passphrase.

---

## 10. Build System and Project Organization

### Directory Structure

```
encrypted-chat-service/
├── src/                    Source code for all modules
│   ├── core/               Shared types and error definitions
│   ├── crypto/             libsodium facade, SecureBuffer
│   ├── identity/           Identity, PeerDirectory, DeviceRegistry
│   ├── wire/               Frame encoding/decoding, message types
│   ├── session/            Noise handshake, Double Ratchet, Session
│   ├── transport/          Abstract Transport + TCP/Mailbox/Relay implementations
│   ├── discovery/          Abstract DiscoveryService + Loopback stub
│   ├── store/              SQLite message store with AEAD encryption
│   ├── transfer/           File transfer (chunked, encrypted)
│   ├── group/              Sender Key group messaging
│   ├── relay/              Standalone relay server
│   ├── ui/                 FTXUI terminal interface
│   └── app/                ChatApplication, main.cpp
├── include/cloak/             Public headers (mirrors src/ structure)
├── tests/
│   ├── unit/               Catch2 unit tests (one per module)
│   ├── integration/        Multi-instance tests (future)
│   └── fuzz/               Protocol fuzzing harnesses (future)
├── docs/
│   ├── ARCHITECTURE.md     Technical architecture documentation
│   ├── THREAT_MODEL.md     Security threat model
│   └── adr/                Architecture Decision Records (6 decisions)
├── cmake/                  Custom CMake helper modules
├── CMakeLists.txt          Root build configuration
├── CMakePresets.json       Preset configurations (debug, release, asan, analyze)
├── vcpkg.json              Dependency manifest (all libraries pinned by SHA)
├── installer/              WiX MSI installer project
└── CLAUDE.md               Guidance file for AI-assisted development
```

### Build Presets

| Preset | Purpose |
|---|---|
| `debug` | Development build with full symbols and assertions |
| `release` | Optimized build for distribution |
| `asan` | Address Sanitizer enabled — catches memory bugs at runtime |
| `analyze` | MSVC static analyzer — catches bugs without running code |

---

## 11. Testing Strategy

### Unit Tests (Catch2)

Each module has its own test file in `tests/unit/<module>/`. Tests use the **Catch2** framework, which provides natural-language assertions:

```cpp
TEST_CASE("SecureBuffer zeros on destruction") {
    REQUIRE(buffer[0] == 0);
}
```

### Coverage Targets

| Module | Minimum Coverage Required |
|---|---|
| `crypto/` | 85% |
| `identity/` | 85% |
| `session/` | 85% |
| All others | 70% |

### Quality Gates

- Every phase must pass all tests before the next phase begins
- ASan (Address Sanitizer) runs in CI to catch memory bugs
- MSVC `/analyze` static analysis catches potential bugs without running code
- `/W4 /WX` compiler flags: all warnings are treated as errors — no warnings allowed to accumulate

---

## 12. Design Patterns Used

Design patterns are proven, named solutions to common programming problems. Here is every design pattern applied in Cloak:

| Pattern | Where Applied | Explanation |
|---|---|---|
| **Factory** | `Session::initiate()`, `Session::accept()`, `Identity::generate()`, `Identity::load()`, `GroupSession::create()`, `GroupSession::from_state()` | Static factory methods replace constructors for complex initialization |
| **Strategy** | `Transport` hierarchy, `DiscoveryService` hierarchy | Different algorithms (TCP vs Relay vs Mailbox) are interchangeable behind the same interface |
| **Facade** | `Crypto` static class | Provides a single, simplified interface to the complex libsodium library |
| **RAII / Resource Acquisition Is Initialization** | `SecureBuffer`, `MessageStore`, `Session`, `TcpTransport` | Resources are tied to object lifetime — acquired in constructor, released in destructor |
| **Template Method** | `Session` handshake flow | Overall algorithm structure is defined; subphases (initiator vs responder) are private methods |
| **Composition over Inheritance** | `ChatApplication` | Rather than subclassing, the application owns and composes: Identity, Transport, Session, GroupManager, etc. |
| **Result / Monad** | `Result<T>` / `std::expected<T, Error>` | Error propagation without exceptions; callers explicitly handle or propagate errors |
| **Observer** (implicit) | Receive threads → `ChatApplication` | Background receive threads post events to the main application via Asio strands |
| **Registry** | `SessionManager`, `GroupManager`, `PeerDirectory`, `DeviceRegistry` | Centralized registries for live objects with thread-safe access |
| **Proxy** | `RelayTransport` | The relay transport acts as a proxy: the session thinks it is talking directly to the peer, but bytes actually go through a relay server |

---

## 13. Key Architectural Decisions

The `docs/adr/` directory records the rationale behind major design decisions (Architecture Decision Records). These are the most important choices:

### ADR-0002: Windows-Native MSVC Only
Cloak targets only Windows 11 with MSVC 2022. It does not support WSL, MinGW, or cross-platform builds. This allows full use of native Win32 APIs (VirtualLock, SecureZeroMemory, DNS-SD) and a single `.exe + MSI` installer model.

### ADR-0003: Noise XX for Phase 1 Handshake
The Noise XX handshake protocol was chosen over alternatives (like Signal's X3DH) because LAN chat requires both parties to be online simultaneously anyway. Noise XX provides mutual authentication and forward secrecy in a single round trip with a simpler implementation.

### ADR-0004: Column-Level AEAD Instead of SQLCipher
Rather than encrypting the entire database (SQLCipher approach), Cloak encrypts only the sensitive columns. This provides finer-grained control, a smaller attack surface, and makes it easier to audit exactly what is protected.

### ADR-0005: mDNS for LAN Discovery
Standard mDNS (Multicast DNS) is used for peer discovery instead of a custom broadcast protocol. The peer's signing public key is embedded in the mDNS TXT record, so peers are cryptographically authenticated from the moment of discovery — not just by name.

### ADR-0006: Thread-Per-Connection Relay
The Phase 4 relay server uses one thread per connection rather than async I/O. This is simpler to implement and reason about, appropriate for development and small deployments, without the complexity of an async event loop.

---

*This document covers Cloak v0.4.0 — Phase 4 complete. All four phases of development are reflected: LAN chat (Phase 1), Double Ratchet + file transfer (Phase 2), group chat + multi-device (Phase 3), and internet relay (Phase 4).*
