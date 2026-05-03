# Cloak — Technical Report

> **Version:** v0.4.0 (all four phases complete)  
> **Platform:** Windows 10/11 (x64), MSVC 2022  
> **Language:** C++23  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What Is Cloak? (For Non-Technical Readers)](#2-what-is-cloak-for-non-technical-readers)
3. [Why C++? — Language Features Used](#3-why-c-language-features-used)
4. [Object-Oriented Design Principles](#4-object-oriented-design-principles)
5. [Every Feature Explained](#5-every-feature-explained)
6. [Protocols and Standards](#6-protocols-and-standards)
7. [Tools and Libraries](#7-tools-and-libraries) — 7.1 libsodium · 7.2 Boost.Asio · 7.3 SQLite3 · 7.4 FTXUI · 7.5 spdlog · 7.6 Catch2 · 7.7 CMake+Ninja+vcpkg · 7.8 Distribution ZIP · 7.9 WiX MSI · 7.10 MSVC 2022
8. [Security Design](#8-security-design)
9. [Architecture Walkthrough](#9-architecture-walkthrough)
10. [Project Phases](#10-project-phases)
11. [Testing Strategy](#11-testing-strategy)
12. [How to Build and Run](#12-how-to-build-and-run)

---

## 1. Executive Summary

Cloak is a Windows-native, terminal-based, end-to-end encrypted peer-to-peer (P2P) messaging application. It was built in four phases, each adding a meaningful layer of capability without altering the interfaces designed in the previous phase — a textbook demonstration of the Open/Closed Principle.

**At a glance:**

| Property | Value |
|----------|-------|
| Encryption model | Double Ratchet (Signal protocol) |
| Key exchange | X25519 Diffie-Hellman + Ed25519 signing |
| Group encryption | Sender Key model (per-member ratchet) |
| Storage encryption | XChaCha20-Poly1305, column-level |
| Identity at rest | Argon2id-derived key + AEAD |
| Relay transport | TCP multiplexer for NAT traversal |
| Network discovery | mDNS / DNS-SD (LAN) + invite codes (internet) |
| Build system | CMake 3.25 + Ninja + vcpkg manifest mode |
| Target OS | Windows 10/11 (MSVC v143, C++23) |

---

## 2. What Is Cloak? (For Non-Technical Readers)

### The problem Cloak solves

Sending a message over the internet normally means your message travels through someone else's server. That server — operated by a company, a cloud provider, or a government — can potentially read, store, or share your messages. Even apps that claim to encrypt messages sometimes keep copies of the encryption keys.

Cloak eliminates the middleman. When you send a message with Cloak, it travels **directly** from your computer to your contact's computer. No server in the middle ever sees the contents. The encryption happens entirely on your machine, and only the intended recipient's machine can decrypt it.

### How you use it

1. **Install Cloak** on your Windows PC. Your contact does the same.
2. **On first launch**, Cloak generates a cryptographic identity unique to your installation — like a passport that only you control.
3. **On the same network (LAN)**, Cloak automatically finds other Cloak users and lets you start chatting immediately — no setup, no accounts, no passwords shared with any service.
4. **Across the internet**, one person creates an invite code and shares it (by email, text, any channel). The other person enters the code, and a secure connection is established through an optional relay server. The relay never sees your messages — it only forwards encrypted bytes.
5. **Every message is encrypted** before it leaves your computer and can only be decrypted by the recipient. Even if someone intercepts the network traffic, they see only meaningless scrambled data.

### What makes it trustworthy

- **Open design** — the cryptographic protocols used are public, standardized, and used by Signal and WhatsApp.
- **Forward secrecy** — even if your keys were somehow stolen today, past messages cannot be decrypted. Each message uses a fresh one-time key.
- **Identity verification** — you can verify your contact's identity out-of-band using a 60-digit "safety number" (like Signal's safety numbers). If someone is impersonating your contact, the numbers won't match.
- **No accounts** — Cloak has no sign-up, no email, no phone number, no cloud account.
- **No telemetry** — Cloak doesn't phone home.

---

## 3. Why C++? — Language Features Used

C++ was chosen for Cloak for four reasons:

1. **Direct access to OS and hardware** — Cloak uses Win32 APIs (DNS-SD for mDNS, VirtualLock for memory pinning), which are best accessed from C++.
2. **Zero-overhead abstractions** — the polymorphic transport hierarchy, RAII resource management, and template-based type safety carry no runtime penalty.
3. **Mature, audited crypto libraries** — libsodium is a C library with C++ bindings, and it integrates naturally.
4. **Control over memory** — key material must be locked in RAM and zeroed on destruction. C++ gives precise control over object lifetime that garbage-collected languages do not.

### 3.1 C++23 Features

Cloak targets C++23 (`/std:c++latest` on MSVC), using:

| Feature | Where used |
|---------|-----------|
| `std::expected<T, E>` | `Result<T>` — all recoverable error returns |
| `std::span<T>` | All buffer arguments to crypto and framing functions (safe slice, no raw pointer + length pairs) |
| `std::print` | Debug utilities |
| Designated initializers | Struct initialization throughout (e.g., `Frame{.type = ..., .payload = ...}`) |

**`std::expected<T, E>`** deserves special mention. Instead of throwing exceptions for predictable failures (network drop, bad key, corrupt frame), every function that can fail returns `Result<T>` = `std::expected<T, Error>`. The caller *must* handle both paths — the compiler enforces it. This makes the control flow of the entire program explicit and auditable.

```cpp
// Example: decrypting a frame, handling both paths
auto frame = wire::decode(received_bytes);
if (!frame) {
    // frame.error() is an Error with an ErrorCode and message
    log_and_close(frame.error());
    return;
}
// frame.value() is the Frame — no exception, no null check forgotten
process_frame(*frame);
```

### 3.2 Templates — `SecureBuffer<N>` and `Result<T>`

**`SecureBuffer<N>`** is a fixed-size template for secret key material:

```cpp
template <size_t N>
class SecureBuffer {
    std::array<uint8_t, N> buf_{};
public:
    SecureBuffer()  { VirtualLock(buf_.data(), N); }   // pin to RAM
    ~SecureBuffer() { SecureZeroMemory(buf_.data(), N); VirtualUnlock(buf_.data(), N); }
    // Move-only — copy is deleted
};
```

The template parameter `N` is the key size in bytes (32 for chain keys, 64 for Ed25519 private keys). The size is a compile-time constant, so the compiler can:
- Allocate the buffer on the stack or inline — no heap allocation.
- Verify that two `SecureBuffer<32>` values are not accidentally passed where a `SecureBuffer<64>` is expected.

**`Result<T>`** = `std::expected<T, cloak::core::Error>` is a type alias used everywhere recoverable errors can occur. Combined with `std::unexpected` for the error path, it produces clean, chainable error handling:

```cpp
auto key_res = Crypto::hkdf_sha256(root_key, {}, info);
if (!key_res) return std::unexpected(key_res.error());
auto new_key = std::move(*key_res);
```

### 3.3 Move Semantics and RAII

**RAII (Resource Acquisition Is Initialization)** is the idiom that ties resource lifetime to object lifetime. When an object goes out of scope, its destructor runs — guaranteed, even if an exception is thrown. Cloak uses RAII for:

- **`SecureBuffer`** — memory lock acquired in constructor, released and zeroed in destructor.
- **`MessageStore`** — SQLite `sqlite3*` handle opened in the factory `open()`, closed in destructor.
- **`Stmt` (internal)** — SQLite `sqlite3_stmt*` finalized in destructor.
- **`Session`** — all Double Ratchet chain keys (in `SecureBuffer`) are zeroed when the session object is destroyed.
- **`std::unique_ptr<Transport>`** — the transport socket is closed when the unique_ptr goes out of scope.

**Move semantics** allow expensive objects to be transferred without copying. Because `SecureBuffer` is move-only (copy constructor deleted), the compiler enforces that key material is never accidentally duplicated:

```cpp
SecureBuffer<32> a;
SecureBuffer<32> b = a;            // ← compile error: copy deleted
SecureBuffer<32> c = std::move(a); // ← OK: a is now empty (zeroed)
```

### 3.4 Smart Pointers

| Pointer | Usage |
|---------|-------|
| `std::unique_ptr<Transport>` | Sole ownership of a transport connection; auto-closes on destruction |
| `std::unique_ptr<Session>` | Sessions owned by `SessionEntry`; destroyed when session ends |
| `std::unique_ptr<Identity>` | Long-term identity owned by `ChatApplication` |
| `std::unique_ptr<DiscoveryService>` | Polymorphic discovery service, owned by `ChatApplication` |
| `std::shared_ptr<std::atomic<bool>>` | The `dead` flag shared between a `SessionEntry` and its receive thread |

`shared_ptr` is used sparingly — only where genuine shared ownership is required (the dead-flag case above). Everywhere else, `unique_ptr` is preferred because it makes ownership unambiguous.

### 3.5 Threading Primitives

Cloak is multi-threaded. The threading model uses:

| Primitive | Usage |
|-----------|-------|
| `std::thread` | Listen thread, discovery thread, cleanup thread, per-session receive thread |
| `std::mutex` | `session_mutex_` (session list), `queue_mutex_` (offline queue), `mu_` (MessageStore, PeerDirectory, GroupManager) |
| `std::lock_guard<std::mutex>` | RAII mutex acquisition — lock released when guard goes out of scope |
| `std::atomic<bool>` | `running_` flag (main loop), `dead` flag per session (shared between session owner and receive thread) |

Lock ordering is enforced by convention: always acquire `session_mutex_` before `queue_mutex_`. Violating this order can cause deadlock, so the rule is documented in the code.

### 3.6 `std::optional` and `std::variant`

- **`std::optional<cloak::core::Endpoint>`** — the relay endpoint is present only when the user passed `--relay`. Accessing it without checking would be a bug. `optional` makes "not set" explicit and prevents null-pointer dereferences.
- **`std::optional<cloak::store::MessageStore>`** — the store is opened conditionally. `optional` avoids null-checking a pointer.
- **`std::optional<cloak::core::GroupId>`** — the current active group is selected or not.

### 3.7 Lambdas and `std::function`

Lambdas are used for progress callbacks:

```cpp
using ProgressCallback = std::function<void(uint64_t bytes_done, uint64_t total)>;
```

The file transfer functions take an optional callback so the UI can display a progress bar without the transfer layer knowing anything about the UI. This is the Observer pattern expressed as a first-class value.

Lambdas also appear as SQL row-reading helpers and as the function passed to `SessionManager::for_each()`.

### 3.8 `std::filesystem`

`std::filesystem::path` is used throughout for:
- Identity file path (`%APPDATA%\Cloak\identity.bin`)
- Database path (`%APPDATA%\Cloak\store.db`)
- File transfer save path and source path

In `receive_file()`, the path sanitization fix uses:

```cpp
const std::string file_name =
    std::filesystem::path(file_name_raw).filename().string();
```

This extracts only the last component of the path, discarding any `../` or absolute-path components that a malicious peer might send.

### 3.9 Compile-Time Constants (`constexpr`)

```cpp
constexpr size_t kMaxFrameBodySize  = 1024 * 1024;   // 1 MiB
constexpr size_t kFileChunkMaxBytes = 64 * 1024;      // 64 KiB
constexpr uint8_t kWireVersion      = 2;
constexpr int     kMaxSkip          = 500;            // DR skipped-key cache
```

Using `constexpr` means these values are substituted at compile time — no runtime cost, and the compiler can use them in static assertions and array sizes.

---

## 4. Object-Oriented Design Principles

Cloak demonstrates all four pillars of OOP — encapsulation, abstraction, inheritance, and polymorphism — and applies several classic design patterns.

### 4.1 Encapsulation

Each class hides its implementation behind a clean public interface. For example, `Session`:

```
Public API:
  initiate(), accept()       ← factories
  send_text(), send_inner()  ← send path
  recv_message(), recv_text()← receive path
  send_receipt()             ← receipt
  peer_display_name(), peer_fingerprint(), is_established()

Private state (no external access):
  dr_rk_, dr_cks_, dr_ckr_  ← Double Ratchet chain keys
  dr_mkskipped_              ← skipped message key cache
  transport_                 ← transport layer
  state_                     ← session state machine
```

Callers of `Session` cannot access or mutate the Double Ratchet state. They can only call the public API and trust that the session correctly maintains forward secrecy.

### 4.2 Abstraction

Abstract base classes define *what* can be done, not *how*:

**`Transport` (abstract):**
```cpp
class Transport {
public:
    virtual ~Transport() = default;
    virtual Result<void> send(std::span<const std::byte>) = 0;
    virtual Result<std::vector<std::byte>> receive(size_t exact_bytes) = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;
};
```

**`DiscoveryService` (abstract):**
```cpp
class DiscoveryService {
public:
    virtual ~DiscoveryService() = default;
    virtual Result<void> start_advertising(const LocalAdvertisement&) = 0;
    virtual void stop_advertising() = 0;
    virtual Result<std::vector<DiscoveredPeer>> get_discovered_peers() = 0;
};
```

The `Session` class knows only about `Transport`. It does not know whether the underlying transport is TCP, LAN mailbox, or an internet relay. Adding a new transport is a new class — zero changes to `Session`.

### 4.3 Inheritance and Polymorphism

**Transport hierarchy:**

```
Transport (abstract)
├── TcpTransport         ← Phase 1: direct TCP connection
├── LanMailboxTransport  ← Phase 2: store-and-forward for offline LAN delivery
└── RelayTransport       ← Phase 4: internet relay, NAT traversal
```

**DiscoveryService hierarchy:**

```
DiscoveryService (abstract)
└── LoopbackDiscoveryService  ← Phase 1 testing: manual peer connections
```

All transports are held as `std::unique_ptr<Transport>`, and `Session` calls the virtual methods. At runtime, the correct implementation (TCP, Relay, etc.) is dispatched automatically. This is polymorphism: same interface, different behavior.

### 4.4 RAII as an OOP Principle

RAII binds resource lifetime to object lifetime. In Cloak, this is applied systematically:

| Object | Resource acquired | Resource released |
|--------|-----------------|------------------|
| `SecureBuffer<N>` | `VirtualLock` (pin to RAM) | `SecureZeroMemory` + `VirtualUnlock` |
| `MessageStore` | `sqlite3_open` | `sqlite3_close` |
| `Stmt` | `sqlite3_prepare_v2` | `sqlite3_finalize` |
| `Session` | DR chain keys in `SecureBuffer` | Zeroed on `~Session()` |
| `TcpTransport` | TCP socket (Boost.Asio) | Socket closed in destructor |
| Thread handles | `std::thread` | `join()` called in `~ChatApplication()` |

This means resources are never leaked, even when errors occur. A `Result<void>` early return still destroys all local objects in order, releasing everything they hold.

### 4.5 Factory Methods

Rather than exposing constructors (which would require the caller to correctly initialize complex state), Cloak uses static factory methods that return `Result<T>`:

```cpp
// Session: factory performs handshake before returning a usable object
static Result<Session> Session::initiate(identity, name, transport);
static Result<Session> Session::accept(identity, name, transport);

// MessageStore: factory opens the database and runs migrations
static Result<MessageStore> MessageStore::open(path, db_key);

// Identity: factory either generates or loads from disk
static Result<Identity> Identity::generate();
static Result<Identity> Identity::load(path, passphrase);

// Transport factories
static Result<unique_ptr<Transport>> TcpTransport::connect(endpoint);
static Result<unique_ptr<Transport>> TcpTransport::accept_from(port);
static Result<unique_ptr<Transport>> RelayTransport::host(relay, room);
static Result<unique_ptr<Transport>> RelayTransport::join(relay, room);

// GroupSession factory
static Result<GroupSession> GroupSession::create(name, self);
static Result<GroupSession> GroupSession::from_state(...);
```

The factory pattern ensures an object is only returned to the caller in a fully initialized, valid state. It is impossible to use an uninitialized `Session` or an unopened `MessageStore`.

### 4.6 State Machine Pattern — `SessionState`

`Session` is a state machine. Every state transition is explicit, and operations that are only valid in certain states check state first:

```
Unconnected → HandshakeSent (initiator) → Established
Unconnected → HandshakeReceived (responder) → Established
Any state → Closed (on error or explicit close)
```

Calling `send_text()` on a session in `Unconnected` state returns an error — it does not silently drop the message or crash. The state machine makes illegal transitions visible.

### 4.7 Strategy Pattern — Transport Hierarchy

The `Transport` abstraction is an application of the Strategy pattern: the algorithm for sending and receiving bytes is encapsulated behind an interface, and can be swapped at runtime. `ChatApplication` injects the transport strategy when creating a session:

```cpp
// Phase 1: TCP
auto transport = TcpTransport::connect(endpoint);
auto session   = Session::initiate(identity, name, std::move(*transport));

// Phase 4: Relay
auto transport = RelayTransport::join(relay_endpoint, room_id);
auto session   = Session::initiate(identity, name, std::move(*transport));
```

The session code is identical in both cases. The strategy (transport) is swapped without touching Session.

### 4.8 Observer Pattern — Progress Callbacks

File transfer uses the Observer pattern via `std::function`:

```cpp
using ProgressCallback = std::function<void(uint64_t done, uint64_t total)>;

Result<FileId> send_file(Session&, const Path&, const std::string& mime,
                         const ProgressCallback& on_progress);
```

The file transfer module is the subject; the UI is the observer. The subject notifies the observer (calls the callback) on each chunk. The transfer module has no dependency on the UI — it only knows about the callback type.

---

## 5. Every Feature Explained

### 5.1 End-to-End Encryption (Double Ratchet)

**What it means:** Your messages are encrypted on your device and decrypted on your contact's device. No intermediate server ever possesses the keys.

**How it works:** Cloak implements the [Signal Double Ratchet protocol](https://signal.org/docs/specifications/doubleratchet/). Think of it as two interlocking ratchets:

1. **Diffie-Hellman ratchet** — periodically, both parties exchange new ephemeral public keys. Even if an attacker records all traffic and later steals your long-term keys, they cannot derive the session keys from previous exchanges.

2. **Symmetric-key ratchet** — for every individual message, a unique one-time key is derived from a "chain key" using HMAC-SHA-256. The chain key advances after each derivation — it cannot be reversed.

Each message is encrypted with XChaCha20-Poly1305 using its own unique key. The key is derived, used, and discarded.

### 5.2 Forward Secrecy

**What it means:** Past messages cannot be decrypted even if future keys are compromised.

**How it works:** Because the Double Ratchet derives a new key for every message and discards the old one, an attacker who steals your phone today cannot read messages you sent last month. The keys that encrypted those messages no longer exist anywhere.

### 5.3 Trust On First Use (TOFU)

**What it means:** When you connect to a peer for the first time, Cloak records their cryptographic identity (their Ed25519 public key). On every subsequent connection, Cloak checks that the identity matches.

**Trust states:**

| State | Meaning |
|-------|---------|
| `Unknown` | Never seen before |
| `Tofu` | Seen and recorded; identity not yet out-of-band verified |
| `Verified` | User has confirmed via safety number comparison |
| `Changed` | The identity key has changed — **loud alert** required |

If a peer's key changes (e.g., because someone is attempting a man-in-the-middle attack, or because they reinstalled Cloak), the `Changed` state is set and the user is alerted. Cloak never silently accepts a new key.

### 5.4 Safety Numbers

**What it means:** A 60-digit number derived from both parties' identity keys that you can compare out-of-band (over the phone, in person) to confirm there is no man-in-the-middle.

**Format:** 60 digits grouped as six groups of ten, e.g.:
```
3847291056  2938470156  8472916035  4729381056  9384720165  1092837465
```

**How it's derived:** `BLAKE2b-256(sort(alice_signing_pub, bob_signing_pub))` — symmetric, so both parties compute the same number. If the numbers match, you are talking directly to each other with no interception.

### 5.5 File Transfer

**What it means:** Send any file — images, videos, documents, archives — with the same end-to-end encryption as messages.

**How it works:**
1. A random 32-byte per-file key is generated.
2. The per-file key is sent to the recipient inside a Double Ratchet `AppPayload` (so it inherits DR forward secrecy).
3. The file is split into 64 KiB chunks. Each chunk is encrypted with XChaCha20-Poly1305 using the per-file key and a chunk-specific nonce derived from the chunk index.
4. Chunks are sent sequentially. The receiver reassembles and decrypts.

This means the transfer layer (which sends `FileChunk` frames) never sees plaintext — only encrypted chunks. The nonce derivation ensures two chunks cannot produce the same keystream even with the same file key.

### 5.6 Group Messaging (Sender Key)

**What it means:** Efficient group chat where each member encrypts once and all members can decrypt.

**How it works:** Cloak implements the [Sender Key protocol](https://signal.org/docs/specifications/senderkey/) used by Signal for group messaging:

Each member generates:
- An **Ed25519 signing keypair** — used to authenticate group messages.
- A **chain key** — a 32-byte value that advances with each message via HMAC-SHA-256.

For each message:
1. A message key is derived: `mk = HMAC-SHA-256(chain_key, counter || 0x01)`
2. The chain key advances: `new_ck = HMAC-SHA-256(chain_key, counter || 0x02)`
3. The message is encrypted with `mk` using XChaCha20-Poly1305.
4. The encrypted message is signed with the sender's Ed25519 key.

When a new member is invited, they receive the current chain key and counter of each existing member (sent via pairwise Double Ratchet sessions — so the invite is also end-to-end encrypted). This allows the new member to decrypt future messages. Past messages remain inaccessible.

### 5.7 Multi-Device Support

**What it means:** Use Cloak on multiple devices under the same identity.

**How it works:** One device is designated the **primary**. It issues a **device certificate** — an Ed25519 signature over the secondary device's public key. The secondary presents this certificate during handshake. Other peers check the certificate's signature against the primary's key to confirm the secondary is authorized.

Device certificates prevent a rogue device from claiming to be you. Only a device holding the primary's signing key can issue a valid certificate.

### 5.8 Offline Message Queue

**What it means:** If your peer disconnects while you're typing, Cloak queues your messages in memory and delivers them automatically when the peer reconnects.

**How it works:** When a session dies (receive thread detects EOF), the session entry is marked dead. If the user types a message to that peer, it is added to an in-memory `deque<QueuedMessage>` keyed by the peer's fingerprint. When the peer reconnects (via TCP or relay), the receive thread drains the queue before entering the normal receive loop.

The queue is in-memory only — it is not persisted across application restarts. This is an explicit design decision (no promises about offline delivery across restarts).

### 5.9 Internet Relay / NAT Traversal

**What it means:** Connect to peers who are not on your local network, even if either party is behind a NAT (home router, corporate firewall).

**How it works:** A standalone relay server (`cloak-relay.exe`) can be run on any publicly reachable host. The relay acts as a transparent TCP multiplexer — it forwards encrypted bytes between two peers but never has the keys to decrypt them.

**Relay handshake protocol:**
1. Both parties send a 37-byte handshake: `[4-byte magic "CLK1"][1-byte role][32-byte room ID]`
2. The relay replies with a 1-byte status. When both a host and a guest with the same room ID connect, the relay pairs them and starts forwarding bytes in both directions.
3. After pairing, the Cloak session handshake runs transparently over the relay — the relay sees only ciphertext.

For networks that block non-standard ports (university, office WiFi), the relay can run on port 443 (HTTPS), which is rarely blocked.

### 5.10 Invite Codes

**What it means:** A human-readable string that encodes enough information for your peer to connect to you through the relay.

**Format:**
```
relay.example.com:8765/a3f8c2e1b4d7920f1e5a3c8b2d4f6e091a2b3c4d5e6f7081920a1b2c3d4e5f6
```

**Structure:** `<relay_host>:<relay_port>/<room_id_hex64>`

**Room ID derivation:** `BLAKE2b-256(your_signing_pub || random_16_bytes)` — the room ID is unique per invite, ties the invite to your identity, and is not guessable.

The inviter generates the code with `/make-invite`. The invitee pastes it into `/connect-invite <code>`. Both connect to the relay with the same room ID, get paired, and the Cloak session handshake begins.

### 5.11 Encrypted Persistent Storage

**What it means:** Your message history, peer list, and group sessions are stored on disk in an encrypted database.

**How it works:**
- An SQLite database at `%APPDATA%\Cloak\store.db` holds all data.
- At application startup, the user's passphrase is processed by **Argon2id** to derive a 32-byte database key. The key is stored in a `SecureBuffer<32>` and never written to disk.
- Message bodies are encrypted with **XChaCha20-Poly1305** before being written to the database. The format is `[24-byte random nonce][ciphertext + 16-byte auth tag]`.
- Group signing keys and chain keys are encrypted the same way.
- The database key is discarded when the application closes.

This means: even if someone copies your `store.db` file, they cannot read your messages without your passphrase. The passphrase is never stored anywhere.

### 5.12 LAN Discovery (mDNS)

**What it means:** On a local network, Cloak users find each other automatically with zero configuration.

**How it works:** Cloak uses **mDNS / DNS-SD** (the same protocol used by Apple Bonjour and Chromecasts). When Cloak starts, it registers a service record on the local network advertising its hostname, port, and identity public key. Other Cloak instances browse for these records and detect each other within seconds.

The identity public key is included in the service advertisement so that, before connecting, you already know who you're going to talk to (enabling TOFU to work on first contact).

### 5.13 Terminal UI (FTXUI)

**What it means:** Cloak runs in a terminal window with a full-featured interface — no graphical window required.

**Architecture:** FTXUI (Functional Terminal UI) provides a React-inspired component model for terminal applications. The UI thread runs the FTXUI event loop and never blocks on I/O. All network I/O happens on a dedicated Boost.Asio thread. Communication between the UI and network threads uses lock-free queues and `asio::post`.

**UI panels:**
- **Peer list** — connected peers with trust status indicators
- **Conversation view** — message history for the selected peer or group
- **Input field** — text input with line editing
- **Status bar** — current peer, group, connection state

---

## 6. Protocols and Standards

### 6.1 Noise XX Handshake

The initial authenticated key exchange uses the **Noise Protocol Framework**, `XX` pattern. In this pattern:
- Both parties exchange ephemeral Diffie-Hellman public keys.
- Each party authenticates the other's static key.
- The handshake produces a shared secret that becomes the Double Ratchet root key.

The `XX` pattern requires both parties to be online simultaneously — appropriate for Cloak's LAN-first model.

### 6.2 Signal Double Ratchet Protocol

The core message encryption protocol. Specified at [signal.org/docs/specifications/doubleratchet](https://signal.org/docs/specifications/doubleratchet/). Cloak's implementation:

- **KDF_RK** = `HKDF-SHA256(root_key, DH(our_dr_priv, their_dr_pub))` → `(new_root_key, new_chain_key)`
- **KDF_CK** = `HMAC-SHA256(chain_key, 0x01)` → `message_key`; `HMAC-SHA256(chain_key, 0x02)` → `new_chain_key`
- **AEAD** = `XChaCha20-Poly1305(message_key, nonce, AAD=header_bytes, plaintext)`
- **Nonce** = first 24 bytes of `HKDF-SHA256(message_key, info="CLOAK_MK_NONCE")`

Out-of-order messages are handled with a skipped-key cache (`std::map<SkippedKeyId, SecureBuffer<32>>`), capped at 500 entries.

### 6.3 Sender Key (Group Messaging)

Each group member has a (signing keypair, chain key, counter). When encrypting a group message:
1. `mk = HMAC-SHA256(chain_key, counter || 0x01)` — derive message key
2. `new_ck = HMAC-SHA256(chain_key, counter || 0x02)` — advance chain key
3. Encrypt: `ct = XChaCha20-Poly1305(mk, nonce, aad = group_id || msg_num, plaintext)`
4. Sign: `sig = Ed25519_sign(signing_sk, group_id || sender_pub || msg_num || ct)`

Members verify the signature before decrypting.

### 6.4 X25519 Diffie-Hellman

Elliptic-curve Diffie-Hellman over Curve25519. Used for:
- Long-term key agreement (`Identity.kx_public`)
- Noise XX handshake ephemeral keys
- Double Ratchet ratchet steps

The shared secret from `X25519(our_private, their_public)` is the same as `X25519(their_private, our_public)` — this symmetry is what allows two parties to agree on a secret without transmitting it.

Low-order point rejection is implemented: if the peer's public key is a low-order point (all-zeros output), the key exchange is rejected as potentially malicious.

### 6.5 Ed25519 Signatures

Edwards-curve signatures over Curve25519. Used for:
- Long-term identity signing (`Identity.signing_public`)
- Authenticating X25519 and DR public keys in the handshake
- Authenticating group messages (Sender Key)
- Device certificates (multi-device linking)

Ed25519 signatures are 64 bytes. Public keys are 32 bytes.

### 6.6 XChaCha20-Poly1305 AEAD

Authenticated Encryption with Associated Data. Used for:
- All Double Ratchet message encryption
- File chunk encryption (per-file key)
- Database column encryption
- Identity file encryption at rest

The "X" variant (XChaCha20 rather than ChaCha20) uses a 192-bit nonce instead of 96-bit. This means random nonces can be safely used — even if billions of messages are sent with the same key, nonce collision probability is negligible.

The 16-byte Poly1305 authentication tag ensures that any modification of the ciphertext (by a network attacker) will be detected and rejected.

### 6.7 HKDF-SHA256

HMAC-based Key Derivation Function (RFC 5869). Used to derive:
- Double Ratchet root key and chain key from DH output
- Per-message nonces from message keys
- Chunk nonces for file transfer

HKDF takes an input key material (IKM), an optional salt, and an info string. The info string domain-separates different uses of the same key — a key derived with `info="CLOAK_MK_NONCE"` cannot be confused with a key derived with any other info string.

### 6.8 Argon2id

A memory-hard password hashing function. Used to derive the database key from the user's passphrase. "Memory-hard" means that brute-forcing the passphrase requires not just CPU time but large amounts of RAM — making GPU-based attacks expensive.

Parameters:
- `opslimit`: number of iterations (higher = slower = harder to brute-force)
- `memlimit`: RAM used per derivation

These parameters are stored alongside the salt in the identity file so they can be adjusted in future versions without breaking existing identities.

### 6.9 BLAKE2b-256

A fast cryptographic hash function. Used for:
- Deriving relay room IDs: `BLAKE2b-256(signing_pub || random_16)`
- Safety number computation: `BLAKE2b-256(sort(pub_a, pub_b))`

BLAKE2b is faster than SHA-256 on 64-bit platforms and is not susceptible to length-extension attacks.

### 6.10 mDNS / DNS-SD

Multicast DNS (RFC 6762) and DNS-based Service Discovery (RFC 6763). Implemented via the Win32 DNS-SD API (`DnsServiceRegister`, `DnsServiceBrowse`). Cloak registers itself as a `_cloak._tcp.local.` service and browses for other instances on the same network segment.

Each service record includes a TXT record containing the node's identity public key (base32-encoded), allowing TOFU verification before the TCP connection is established.

### 6.11 SQLite with Column-Level AEAD

SQLite is a lightweight, file-based relational database. Cloak stores message history, peer records, and group session data in SQLite.

Rather than encrypting the entire database file (as SQLCipher does), Cloak encrypts individual sensitive columns (message body, group keys) with XChaCha20-Poly1305. This approach:
- Avoids keeping the database key resident in memory for every SQLite operation (it is used only when reading/writing sensitive columns).
- Allows SQLite's WAL journaling and query planner to work normally on non-sensitive columns (timestamps, peer IDs, flags).
- Provides finer-grained control: non-sensitive metadata (message IDs, timestamps) can be queried without decryption.

---

## 7. Tools and Libraries

### 7.1 libsodium

The foundational cryptographic library. Cloak uses libsodium exclusively for all cryptographic operations — no custom primitives.

libsodium provides:
- `crypto_kx_*` — X25519 key exchange
- `crypto_sign_*` — Ed25519 sign/verify
- `crypto_aead_xchacha20poly1305_ietf_*` — AEAD encryption
- `crypto_kdf_hkdf_sha256_*` — HKDF key derivation
- `crypto_pwhash_*` — Argon2id password hashing
- `crypto_generichash_*` — BLAKE2b hashing
- `randombytes_buf` — Cryptographically secure random bytes
- `sodium_memzero` — Secure memory zeroing

All libsodium calls are wrapped behind the `cloak::crypto::Crypto` static class. No code outside `src/crypto/` ever calls libsodium directly.

### 7.2 Boost.Asio

A cross-platform C++ library for asynchronous I/O. Cloak uses it for:
- TCP client connections (`tcp::socket`, `tcp::resolver`)
- TCP server listener (`tcp::acceptor`)
- The relay server's accept loop

Boost.Asio's `io_context` runs on a dedicated I/O thread. Session strands ensure that even if multiple sessions share the I/O thread, each session's operations are serialized.

### 7.3 SQLite3

The world's most widely deployed database engine — a single C source file that compiles into a library. Cloak uses it for persistent message history, peer records, and group session state.

The schema supports migrations (a `schema_version` table tracks which migrations have run). Phase 3 added group tables; Phase 4 added a `to_peer` column — both were applied as migrations without disrupting existing data.

### 7.4 FTXUI

Functional Terminal UI library for C++. Provides terminal rendering and input handling without needing a graphical display. Cloak's terminal interface is built with FTXUI components: containers, text input, scrollable views, and separators.

FTXUI uses a functional, React-inspired API: UI is a pure function of state. When the state changes (new message received), the UI is re-rendered.

### 7.5 spdlog

A fast C++ logging library. Cloak uses spdlog for:
- Rotating log files under `%APPDATA%\Cloak\logs\`
- Structured severity levels (debug, info, warn, error, critical)
- `CLOAK_UNSAFE_LOG_SECRETS=1` guard — secret-bearing types cannot be logged in production builds

### 7.6 Catch2

A modern C++ unit testing framework (v3+). All module unit tests use Catch2. Features used:
- `REQUIRE` / `CHECK` assertions
- `SECTION` for test grouping
- `TEST_CASE` registration
- RFC test vectors loaded from files and verified against libsodium outputs

### 7.7 CMake + Ninja + vcpkg

**CMake** (≥3.25) manages the build system. `CMakePresets.json` exposes four build configurations:
- `debug` — unoptimized, debug symbols, assertions enabled
- `release` — fully optimized, stripped
- `asan` — AddressSanitizer (detects buffer overflows, use-after-free)
- `analyze` — MSVC static analyzer (`/analyze` flag)

**Ninja** is the build backend — faster than MSBuild for incremental builds.

**vcpkg** in manifest mode manages all C++ dependencies. `vcpkg.json` pins the exact version of every dependency via a baseline SHA. First build downloads and compiles all dependencies (15–30 minutes); subsequent builds use the cached built artifacts.

The custom `cloak_add_library.cmake` macro auto-discovers unit tests under `tests/unit/<module>/` and wires them into CTest.

**`build-dist.ps1`** — a PowerShell script in the project root that automates the full build-to-distribution workflow: it initialises the MSVC environment via `vcvars64.bat`, runs `cmake --preset release`, runs `cmake --build --preset release`, collects the two executables and three runtime DLLs, updates `dist/cloak/`, and produces `dist/cloak-0.4.0-win64.zip`.

### 7.8 Distribution Package (`install.ps1` + ZIP)

The primary distribution mechanism is a self-contained ZIP archive (`dist/cloak-0.4.0-win64.zip`) that requires no build tools on the end-user's machine. Contents:

| File | Purpose |
|------|---------|
| `cloak.exe` | Main application (442 KB, built with MSVC v143) |
| `cloak-relay.exe` | Relay server (152 KB, optional) |
| `libsodium.dll` | Cryptographic primitives |
| `boost_program_options-vc143-mt-x64-1_90.dll` | CLI argument parsing |
| `sqlite3.dll` | Embedded database engine |
| `vc_redist.x64.exe` | Visual C++ 2022 Runtime (25 MB, installed silently if missing) |
| `install.ps1` | PowerShell installer |

`install.ps1` is a single-file installer that:
1. Detects elevation (Admin vs. per-user)
2. Checks the registry for the VC++ 2022 Runtime and installs it silently if missing
3. Copies all files to `%ProgramFiles%\Cloak\` (Admin) or `%LOCALAPPDATA%\Cloak\` (per-user)
4. Adds the install directory to the system or user PATH
5. Creates Start Menu shortcuts for Cloak and Cloak Relay Server
6. Writes `uninstall.ps1` inside the install directory for clean removal

### 7.9 WiX Toolset (MSI Installer — planned)

WiX Toolset v4 will produce a signed MSI installer for formal distribution. The WiX project is scaffolded in `installer/`. In the current release, the `install.ps1` ZIP approach is the primary distribution method. The WiX MSI is planned for the v1.0 production release.

### 7.10 MSVC 2022 Toolchain

The Microsoft Visual C++ compiler (v143 toolset). Key flags enforced on every translation unit:
- `/std:c++latest` — C++23 mode
- `/W4 /WX` — all warnings, warnings as errors
- `/permissive-` — strict standards conformance
- `/utf-8` — UTF-8 source and execution encoding
- `/Zc:__cplusplus` — correct `__cplusplus` macro
- `/Zc:preprocessor` — conforming preprocessor

These flags ensure the code compiles cleanly under the strictest mode MSVC offers.

---

## 8. Security Design

### 8.1 Threat Model Summary

Cloak defends against these adversaries:

| Adversary | Description | Cloak's defense |
|-----------|-------------|-----------------|
| Passive LAN observer | Can record all network traffic | All messages are AEAD-encrypted; ciphertext reveals nothing |
| Active LAN attacker (MITM) | Can intercept and modify traffic | Poly1305 authentication tag detects modification; identity changed → user alerted |
| Rogue peer | Connects claiming to be your contact | Ed25519 signature verification + TOFU state machine |
| Device thief | Physical access to your PC | Identity file encrypted with Argon2id; database columns AEAD-encrypted |
| Passive internet relay observer | Can see relay traffic | Relay receives only ciphertext; relay has no keys |

**Out of scope:** Nation-state adversary with zero-days, endpoint compromise (keylogger on your machine), denial-of-service attacks, metadata analysis.

### 8.2 Key Invariants Enforced

1. **No custom crypto** — every cryptographic operation goes through `cloak::crypto::Crypto`, which is a thin wrapper over libsodium. No hand-rolled ciphers.

2. **Secrets in `SecureBuffer` only** — `SecureBuffer<N>` is mlock'd (pinned to RAM, not swapped to disk) and zeroed on destruction. Private keys, session keys, and database keys are never stored in `std::string` or `std::vector`.

3. **TOFU is loud** — `TrustStatus::Changed` triggers a visible alert. The user must explicitly acknowledge a key change before communication resumes. Silent key rotation is not allowed.

4. **Errors are not ignored** — `std::expected` forces the caller to handle both success and failure. Compile-time enforcement.

5. **No frame without size validation** — every decode function validates lengths before allocating buffers. A peer cannot cause OOM by sending a frame with a fabricated large length.

6. **Relay sees no plaintext** — the relay transport is a byte pipe. Cloak sessions run their handshake and DR encryption on top of the relay. The relay operator cannot read messages.

### 8.3 What Cloak Protects Against

- Passive interception of LAN or internet traffic
- Replay attacks (AEAD nonces are unique per message; replaying a ciphertext fails authentication)
- Key impersonation (Ed25519 signatures verify the sender's long-term identity)
- Manipulation of ciphertext (Poly1305 tag detects any bit flip)
- Brute-force of the local identity passphrase (Argon2id makes each guess expensive)
- Path traversal in received files (filename is sanitized to the last component only)
- OOM via oversized frames (frame decoder enforces 1 MiB limit before allocating)
- Invalid enum injection in wire protocol (receipt type byte is validated against known values)

### 8.4 Known Limitations

- **Metadata** — Cloak encrypts content but not metadata. An observer on the LAN can see which IP addresses are communicating with each other, when, and how many bytes.
- **Relay availability** — The relay server is a single point of failure for internet connections. Relay operator can perform denial-of-service (drop connections), but not read messages.
- **No forward secrecy for groups at member removal** — When a member leaves or is kicked, the group does not perform a "healing" ratchet (sender key rotation for all remaining members). New messages from remaining members are encrypted with chain keys the departed member had. For high-security use, recreate the group without the departed member.
- **In-memory offline queue** — The offline message queue is not persisted. If the application restarts, queued messages are lost.
- **Single relay** — Invite codes encode a single relay address. If that relay is unreachable, the connection fails. Production deployments should run multiple relays.

---

## 9. Architecture Walkthrough

### 9.1 Send Path (Step by Step)

```
User types:  "Hello, Alice!"
                │
                ▼
[ChatApplication] ─ handle_command() detects regular text
                │
                ▼
[Session] ─ send_text("Hello, Alice!")
                │
                ├─ Prepend InnerType::Text byte (0x00)
                │
                ▼
[Session] ─ dr_encrypt(plaintext)
                │
                ├─ kdf_ck(sending_chain_key) → (message_key, new_chain_key)
                ├─ dr_nonce_from_mk(message_key) → 24-byte nonce
                ├─ Crypto::aead_encrypt(mk, nonce, aad=header, plaintext) → ciphertext
                └─ If DH ratchet needed: dr_ratchet() → new root key, new chain key
                │
                ▼
[wire::encode_app] ─ Serialize AppPayload {header, ciphertext}
                │
                ▼
[wire::encode] ─ Wrap in Frame {type=AppMessage, payload}
                │
                ▼
[Transport::send] ─ Write bytes to TCP socket (or relay, or mailbox)
                │
                ▼
Network ──────────────────────────────────────────────────────────── Alice's machine
```

### 9.2 Receive Path (Step by Step)

```
Network bytes arrive on Alice's TCP socket
                │
                ▼
[Transport::receive] ─ Read exactly frame_length bytes
                │
                ▼
[wire::decode] ─ Parse [4-byte length][1-byte type][payload]
                │        Validates: length ≤ 1 MiB, type is known
                ▼
[wire::decode_app] ─ Parse AppPayload {header, ciphertext}
                │
                ▼
[Session] ─ dr_decrypt(payload)
                │
                ├─ Check skipped-key cache for header.dh_pub + header.n
                ├─ If new DH key: dr_ratchet() → advance root key, new recv chain
                ├─ kdf_ck(recv_chain_key) until message number matches
                ├─ dr_nonce_from_mk(message_key)
                └─ Crypto::aead_decrypt(mk, nonce, aad=header, ciphertext) → plaintext
                │
                ▼
Examine first byte (InnerType):
                │
                ├─ 0x00 (Text)          → display message in UI
                ├─ 0x01 (FileMetadata)  → begin receive_file()
                ├─ 0x02 (Receipt)       → mark_delivered() or mark_read()
                ├─ 0x04 (GroupOp)       → group_mgr_.apply_op()
                ├─ 0x05 (DeviceLink)    → device_registry_.install_cert()
                └─ 0x06 (GroupMessage)  → group_mgr_.recv()
                │
                ▼
[MessageStore] ─ save_message() ─ encrypt_column(body) → store in SQLite
```

### 9.3 Concurrency Model

```
┌─ Main Thread ──────────────────────────────────────────────────┐
│  FTXUI event loop                                               │
│  Reads from UI input queue                                      │
│  Calls ChatApplication::handle_command()                       │
│  NEVER blocks on I/O or crypto                                 │
└─────────────────────────────────────────────────────────────────┘

┌─ Listen Thread ────────────────────────────────────────────────┐
│  tcp::acceptor.accept() loop                                    │
│  On connection: Session::accept() → add_session()              │
│  Spawns per-session receive thread                              │
└─────────────────────────────────────────────────────────────────┘

┌─ Discovery Thread ─────────────────────────────────────────────┐
│  mDNS browse loop                                               │
│  On peer found: initiate outbound connection if not connected  │
└─────────────────────────────────────────────────────────────────┘

┌─ Cleanup Thread ───────────────────────────────────────────────┐
│  Periodic: remove dead SessionEntry objects                    │
│  Periodic: purge_expired() from MessageStore                   │
└─────────────────────────────────────────────────────────────────┘

┌─ Per-Session Receive Threads (one per session) ────────────────┐
│  Drain offline message queue for this peer                     │
│  Loop: recv_message() → dispatch by InnerType                  │
│  On EOF/error: mark session dead                               │
└─────────────────────────────────────────────────────────────────┘

Shared state access:
  session_mutex_    → protects sessions_ vector
  queue_mutex_      → protects message_queue_ (always taken after session_mutex_)
  MessageStore.mu_  → protects SQLite handle
  print_mutex_      → protects console output
```

---

## 10. Project Phases

Cloak was built in four phases. Each phase added capability through new implementations of existing abstractions — no phase required rewriting code from a previous phase.

### Phase 1 — Foundation + LAN Text Chat (v0.1.0)

**What was built:**
- Core types (`PeerId`, `SessionId`, `TrustStatus`, `Result<T>`, `Error`)
- `Crypto` static facade over libsodium
- `SecureBuffer<N>` — mlock'd, zeroed-on-destroy key container
- `Identity` — Ed25519+X25519 long-term keypair, persisted encrypted
- `PeerDirectory` — TOFU trust model
- `TcpTransport` — TCP byte-stream transport
- `LoopbackDiscoveryService` — manual peer connections (testing)
- Noise XX handshake in `Session` — mutual authentication, shared secret
- `Session::send_text()` / `recv_text()` — basic message exchange
- `ChatApplication` — orchestrator, REPL loop
- `wire::encode()` / `decode()` — hand-rolled frame format

**What was deliberately deferred:** files, offline delivery, groups, internet relay.

### Phase 2 — Double Ratchet, File Transfer, Receipts (v0.2.0)

**What was built:**
- Full Signal Double Ratchet replacing the Phase 1 symmetric ratchet (no Session interface change)
- `InnerType` dispatch in `session_recv_func_impl` (Text, FileMetadata, Receipt, Typing)
- `send_receipt()` / receipt decode for delivered/read acknowledgements
- File transfer (`send_file`, `receive_file`) with per-file AEAD key and 64 KiB chunks
- `LanMailboxTransport` — store-and-forward for offline LAN delivery
- Wire format version bump to 2 (DR ephemeral key in handshake)
- DR ratchet state in handshake: `dr_pub` + `sig_over_dr` fields
- `MessageStore` with SQLite + AEAD column encryption

### Phase 3 — Groups + Multi-Device (v0.3.0)

**What was built:**
- `GroupSession` — Sender Key group encryption (one encrypt, N decrypts)
- `GroupManager` — manages all group sessions, lifecycle ops (create/invite/leave/kick)
- `GroupOpPayload` / `GroupMessagePayload` wire formats
- `InnerType::GroupOp` / `InnerType::GroupMessage` dispatch
- Group session persistence in `MessageStore` (group_sessions + group_members tables)
- `DeviceRegistry` — multi-device certificate issuance and verification
- `DeviceLink` / `DeviceCert` types
- Safety numbers for group verification
- Schema migration v2 (group tables)

### Phase 4 — Internet Relay + Invite Codes (v0.4.0)

**What was built:**
- `RelayTransport` — relay client that implements `Transport` (same interface as TCP)
- `RelayServer` (`cloak-relay.exe`) — standalone TCP multiplexer, thread-per-paired-connection
- Relay wire protocol: 37-byte handshake (`CLK1` magic + role + room ID), 1-byte status
- `make_invite_code()` / `parse_invite_code()` — invite code encode/decode
- `cmd_make_invite()` / `cmd_connect_invite()` in `ChatApplication`
- Room ID derivation: `BLAKE2b-256(signing_pub || random_16)`
- Offline message queue: in-memory `deque<QueuedMessage>` per peer fingerprint
- Schema migration v3 (to_peer column for bidirectional conversation history)

---

## 11. Testing Strategy

### Unit Tests

Each module has a dedicated unit test file under `tests/unit/<module>/`. Tests are compiled automatically by the `cloak_add_library.cmake` macro and registered with CTest.

| Test file | What it covers |
|-----------|---------------|
| `test_core.cpp` | `Result<T>`, `Error` chaining |
| `test_crypto.cpp` | AEAD round-trip, X25519 symmetry, HKDF determinism, DR KDF, low-order point rejection, Ed25519 sign/verify |
| `test_identity.cpp` | Identity fingerprint, ECDH symmetry, safety number format, save/load encryption, wrong passphrase rejection |
| `test_device_registry.cpp` | Primary issues cert, secondary installs, tamper detection, peer device registration |
| `test_session.cpp` | Full Double Ratchet over TCP loopback, GroupOp/GroupMessage dispatch, receipt round-trip |
| `test_wire.cpp` | Frame encode/decode, handshake format, version negotiation, GroupMessage/GroupOp round-trips, AppMessage, fuzz (random bytes crash test) |
| `test_transport.cpp` | TCP loopback echo, exact-byte receive |
| `test_store.cpp` | Save/retrieve messages, conversation queries, delivery/read status, expiry purging, peer persistence |
| `test_relay.cpp` | Invite code round-trip, malformed input rejection, host+guest pairing |
| `test_discovery.cpp` | Loopback discovery bindings |
| `test_group.cpp` | GroupSession create/encrypt/decrypt, signature verification, tamper rejection, wire encode/decode |
| `test_ui.cpp` | UI smoke test |

### RFC Test Vectors

Files in `tests/vectors/crypto/` contain official test vectors from:
- RFC 7748 (X25519 Diffie-Hellman)
- RFC 8032 (Ed25519 Digital Signatures)
- RFC 8439 (ChaCha20-Poly1305)

These verify that Cloak's crypto calls (through libsodium) produce the exact outputs specified by the cryptographic standards bodies.

### Fuzz Testing

`tests/fuzz/` contains libFuzzer harnesses for the wire format parsers. Each parser (`decode()`, `decode_handshake()`, `decode_app()`, `decode_file_chunk()`, `decode_receipt()`, `decode_group_op()`, `decode_group_message()`) is fuzz-tested independently. Any crash or assertion failure in the parser under random input is a bug.

### Sanitizers

- **AddressSanitizer (ASan)** — the `asan` preset compiles with `/fsanitize=address`. ASan detects buffer overflows, heap use-after-free, stack use-after-return, and memory leaks at runtime.
- **MSVC Static Analyzer** — the `analyze` preset runs `/analyze`, which detects null dereference, use of uninitialized memory, and arithmetic overflow at compile time.

### Coverage Targets

| Module | Minimum coverage |
|--------|----------------|
| `crypto/` | ≥ 85% |
| `identity/` | ≥ 85% |
| `session/` | ≥ 85% |
| All others | ≥ 70% |

---

## 12. How to Build and Run

### Option A — Install from the release package (no build tools required)

This is the recommended path for end users.

1. Download `cloak-0.4.0-win64.zip` from the `dist/` directory (or a release page).
2. Unzip it anywhere.
3. Right-click `install.ps1` and choose **Run with PowerShell**, or open PowerShell in that folder and run:
   ```powershell
   .\install.ps1
   ```
4. Follow the on-screen prompts (choose Y to proceed, Admin or per-user).
5. Open a **new** terminal — PATH is now updated — and run:
   ```powershell
   cloak.exe --name "Alice" --port 8080
   ```

The installer handles the VC++ 2022 Runtime automatically. No other dependencies are needed on the end-user's machine.

To uninstall:
```powershell
# Find the install directory (printed at end of install) and run:
%ProgramFiles%\Cloak\uninstall.ps1
# or for per-user:
%LOCALAPPDATA%\Cloak\uninstall.ps1
```

---

### Option B — Build from source

#### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Windows | 10 or 11 (x64) | |
| Visual Studio 2022 | v143 toolset | Community or Build Tools edition |
| CMake | ≥ 3.25 | Bundled with VS 2022 |
| Ninja | Any | Bundled with VS 2022 |
| vcpkg | Any | Set `VCPKG_ROOT` environment variable |
| Git | Any | |

#### First-Time Setup

```powershell
# Clone vcpkg (if not already done)
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\vcpkg"

# Clone Cloak
git clone https://github.com/<your-org>/cloak.git
cd cloak
```

#### Build

```powershell
# Configure (first time: downloads and builds all dependencies, 15-30 min)
cmake --preset debug

# Build
cmake --build --preset debug

# Run tests
ctest --preset debug --output-on-failure
```

#### Build Variants

| Preset | Purpose |
|--------|---------|
| `debug` | Development: no optimization, debug symbols |
| `release` | Deployment: fully optimized |
| `asan` | Bug hunting: AddressSanitizer enabled |
| `analyze` | Code quality: MSVC static analyzer |

#### Release binary locations

After `cmake --build --preset release`:

```
build/release/src/app/cloak.exe
build/release/src/relay/cloak-relay.exe
```

Runtime DLLs are placed next to each executable automatically by CMake:
`libsodium.dll`, `boost_program_options-vc143-mt-x64-1_90.dll`, `sqlite3.dll`

#### Packaging the ZIP

```powershell
.\build-dist.ps1              # full build + create dist/cloak-0.4.0-win64.zip
.\build-dist.ps1 -SkipBuild  # re-package existing release binaries
```

#### Running Cloak (from source build)

```powershell
# LAN mode
.\build\debug\src\app\cloak.exe --name "Alice" --port 5000

# Internet mode (with relay)
.\build\debug\src\app\cloak.exe --name "Alice" --port 5000 --relay relay.example.com:8765
```

#### Running the Relay Server

```powershell
.\build\debug\src\relay\cloak-relay.exe --port 8765

# Port 443 for networks that block non-standard ports
.\build\debug\src\relay\cloak-relay.exe --port 443
```

### Key Commands (Inside Cloak)

| Command | What it does |
|---------|-------------|
| `/peers` | List connected peers |
| `/switch <name>` | Switch active peer |
| `/safety` | Show safety number for current peer |
| `/verify` | Mark current peer as verified |
| `/send <path>` | Send a file to the current peer |
| `/history` | Show message history |
| `/group-create <name>` | Create a new group |
| `/group-list` | List all groups |
| `/group-switch <name>` | Switch to a group |
| `/group-invite <peer>` | Invite a peer to the current group |
| `/group-leave` | Leave the current group |
| `/make-invite` | Generate an invite code (relay mode) |
| `/connect-invite <code>` | Connect via invite code |
| `/devices` | List linked devices |
| `/link-device <pub_hex>` | Link a secondary device |

### WiX MSI Installer (planned for v1.0)

```powershell
cmake --preset release
cmake --build --preset release --target installer
# Output: build/release/installer/cloak-0.4.0.msi
```

The WiX MSI project is scaffolded in `installer/`. Code-signing with a CA-issued Authenticode certificate is required before formal distribution.

---

*Cloak v0.4.0 — All four phases complete. Built with MSVC 2022 / C++23 on Windows.*
