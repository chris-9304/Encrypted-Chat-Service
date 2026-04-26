# Roadmap

---

## Phase 1 — Foundation + LAN Text Chat ✅ v0.1.0

Crypto facade, SecureBuffer, Wire framing v2, TCP transport, Loopback discovery, REPL `ChatApplication`. Two instances on a LAN discover each other, handshake with Noise XX over TCP, and exchange E2E encrypted text messages.

---

## Phase 2 — Files, Double Ratchet, Offline LAN Delivery ✅ v0.2.0

- **Double Ratchet:** Full Signal-protocol DR replacing the Phase 1 per-message symmetric ratchet.
- **File transfer:** 64 KiB chunks, per-file AEAD key, `/send <path>` command.
- **Delivery + read receipts:** `send_receipt()`, `InnerType::Receipt`.
- **LAN Mailbox:** `LanMailboxTransport` for store-and-forward to temporarily offline peers.
- **MessageStore integration:** SQLite with column-level AEAD; messages persisted on send/receive.

---

## Phase 3 — Groups and Multi-Device ✅ v0.3.0

- **Group chat (Sender Keys):** `GroupSession` + `GroupManager`; per-member chain key + Ed25519 signing; `InnerType::GroupMessage` / `InnerType::GroupOp`.
- **Multi-device:** `DeviceCert` (primary signs secondary), `DeviceRegistry`, `/link-device`, `/install-cert`, `InnerType::DeviceLink`.
- **Group persistence:** `MessageStore` schema v2 adds `group_sessions` + `group_members` tables; groups saved on create/join/leave.
- **Bidirectional history:** `Message.to_peer` field, schema v3 migration, `get_conversation()`.

---

## Phase 4 — Internet Relay ✅ v0.4.0

**Goal.** Connect two peers that are not on the same LAN, without requiring either party to open a port, via an optional user-hosted relay. No plaintext ever reaches the relay.

### What was built

**Relay transport (`src/transport/relay_transport.h/.cpp`):**
- `RelayTransport::host(relay, room_id)` — connects as EncryptiV responder, blocks until a guest arrives.
- `RelayTransport::join(relay, room_id)` — connects as EncryptiV initiator, returns when pairing is confirmed.
- `make_invite_code()` / `parse_invite_code()` — encode/decode `host:port/room_hex64` invite strings.
- After pairing the relay is a transparent byte pipe; all EncryptiV crypto runs on top unmodified.

**Relay server (`src/relay/relay_server.h/.cpp`, `ev-relay.exe`):**
- Thread-per-connection TCP server.
- Wire protocol: 37-byte client handshake (magic `EVR1` + role byte + 32-byte room ID), 1-byte server response.
- Roles: `0x01` = host (becomes EncryptiV responder), `0x02` = join (becomes EncryptiV initiator).
- Status codes: `0x00` = waiting, `0x01` = initiator paired, `0x02` = responder paired, `0xFF` = error.
- Host blocks waiting; guest hand-off via `shared_ptr<socket>`, no data races.

**Invite-code discovery:**
- Inviter: `ev-chat --relay <host:port>`, then `/make-invite` → prints a self-contained invite code.
- Room ID = BLAKE2b-256(sign_pub ‖ random_16), uniquely bound to the inviter's identity.
- Invitee: `/connect-invite <code>` → connects through relay → full EncryptiV session.

**App integration:**
- New `--relay <host:port>` flag for `ev-chat`.
- Two new commands: `/make-invite`, `/connect-invite <code>`.
- TOFU / peer directory / session machinery unchanged — relay is transport-transparent.

### Phase 4 success criteria

- `ev-relay.exe` starts, binds port, prints confirmation. Ctrl+C shuts down cleanly.
- Alice runs `ev-chat --relay relay:8765`, types `/make-invite`, copies the invite code.
- Bob runs `ev-chat`, types `/connect-invite <code>`. Session established.
- All existing Phase 1–3 tests remain green.
- Relay is a transparent pipe: no plaintext visible in relay process memory.

---

## Cross-phase principles

- No phase begins until the previous phase's success criteria are met.
- Threat model reviewed at each boundary.
- Every phase increases test coverage, never decreases it.
- DB schema is additive — forward-only migrations, no destructive changes.
