# Roadmap

Phase 1 is committed and delivers a foundation that grows. Phases 2–4 are sketched; only Phase 1 is scheduled.

---

## Phase 1 — Foundation + LAN Text Chat

**Goal.** Two Windows machines on the same LAN install the MSI, launch `ev-chat.exe`, automatically find each other via mDNS, establish a mutually-authenticated Noise session, and exchange end-to-end encrypted text messages through an FTXUI terminal interface. The class model, abstractions, and extension seams supporting Phases 2–4 are all in place.

**Duration estimate.** 10–14 weeks of focused work.

### Milestones

1. **M1.1 — Scaffold & core types.** Repo scaffolding, CMake+vcpkg, Windows CI, `src/core/` (Error, Result, PeerId, PublicKey, SecureBuffer, basic types), `.clang-format` / `.clang-tidy`, ADR 0001–0005 written, empty class headers for every class in the architecture.
2. **M1.2 — Crypto facade.** `src/crypto/` implementing `Crypto` as a static facade over libsodium. `SecureBuffer` with `VirtualLock`. RFC test vectors pass.
3. **M1.3 — Identity.** `src/identity/` implementing `Identity` with keypair generation, Argon2id-derived at-rest encryption, save/load, fingerprints/safety numbers.
4. **M1.4 — Wire format.** `src/wire/` protobuf definitions for `HandshakeMessage`, `ApplicationMessage`, `InnerPayload`, `TextPayload`. Length-prefixed framing. Fuzz harnesses.
5. **M1.5 — Store.** `src/store/` implementing `MessageStore` with SQLite, column-level AEAD, schema migrations, peer/session/message tables (plus empty Phase 2/3 tables).
6. **M1.6 — Transport.** `src/transport/` with the abstract `Transport` class + concrete `TcpTransport` using Boost.Asio. Accept + connect paths. Integration test for byte-stream round-trip.
7. **M1.7 — Session + Noise.** `src/session/` implementing `Session` with Noise XX handshake (using a vetted Noise library via vcpkg, or hand-rolled over libsodium primitives — ADR required), per-message symmetric ratchet, serialize/restore. Property tests for two-session agreement.
8. **M1.8 — Discovery.** `src/discovery/` with abstract `DiscoveryService` + `MdnsDiscoveryService` using Win32 DNS-SD. Integration test with fake discovery + real TCP.
9. **M1.9 — App wiring.** `src/app/` with `ChatApplication` orchestrating everything. Basic end-to-end path works from a CLI harness (no TUI yet).
10. **M1.10 — Terminal UI.** `src/ui/` FTXUI-based `ChatUi`. Peer list, conversation view, input. Safety-number display and verify workflow.
11. **M1.11 — Installer & plug-and-play.** WiX MSI. First-run onboarding (display name + passphrase). `%APPDATA%` paths. Start menu shortcut. Uninstaller.
12. **M1.12 — Hardening & release.** Fuzz sweep, ASan sweep, `/analyze` sweep, coverage fills, docs polish, tag `v0.1.0`, cut signed MSI.

### Phase 1 success criteria

- Install MSI on two fresh Windows 10/11 VMs on the same LAN. Both launch. Both discover each other within 10 seconds.
- First-run onboarding completes in under 60 seconds per machine.
- Send and receive 100 messages including Unicode and long text.
- Disconnect one peer mid-conversation; the other surfaces the disconnect within 5 seconds.
- Impersonation test: a third machine advertises the same display name as an existing peer. The target sees a different safety number and the UI distinguishes them.
- Identity-change test: uninstall+reinstall on one machine. The peer sees a loud identity-changed alert.
- MITM test: a test harness intercepts and modifies bytes on the wire. Handshake fails; no plaintext leaks.
- All RFC test vectors pass. All fuzz targets survive 10 minutes with no crashes. ASan CI green for 30 consecutive runs.
- Coverage: `crypto/` `identity/` `session/` ≥ 85%; elsewhere ≥ 70%.

### Opus vs Sonnet (and Gemini) allocation

**Claude Opus, `ultrathink`** — highest-leverage, security-critical:

- M1.2: SecureBuffer lifecycle; Crypto facade API shape.
- M1.7: Noise handshake implementation and the per-message ratchet. Either adopting a Noise library (ADR choosing which) or composing from libsodium primitives.
- ADRs in M1.1.
- PR review on anything in `crypto/` `identity/` `session/`.
- Debugging any crypto or session-state finding.

**Claude Sonnet or Gemini (Antigravity)** — execution, well-specified:

- M1.1: scaffolding, CMake, CI YAML.
- M1.3: identity persistence code once Crypto is frozen.
- M1.4: protobuf plumbing once schemas are frozen.
- M1.5: storage implementation once schema is set.
- M1.6: Asio TCP transport once the interface is fixed.
- M1.8: mDNS glue — Win32 APIs are well-documented.
- M1.10: FTXUI screens once information architecture is decided.
- M1.11: WiX installer — declarative, mechanical.
- All test writing from fixed specs.
- Docs polish.

**Reserve Opus for** the hard design and review work. Let Gemini/Sonnet handle the bulk.

### Effort guidance

- `ultrathink` / deep reasoning mode: Noise, ratcheting, SecureBuffer, ADRs, crypto bug debugging.
- Medium reasoning: abstract class design, integration test design, PR review on sensitive modules.
- Default / light: scaffolding, plumbing, UI, installer, documentation.

---

## Phase 2 — Files, Pictures, Videos, Offline LAN Delivery

**Goal.** Send files (pictures first, then video) with chunked encrypted transfer. A peer who was offline receives messages sent earlier when they come back online, via a chosen "mailbox peer" on the LAN.

Sketch — not yet scheduled.

- `FilePayload` variant added to `InnerPayload`.
- Chunked upload protocol; per-file key; ciphertext-only at rest.
- `LanMailboxTransport` implementing `Transport` — a peer on the LAN acts as store-and-forward for others it trusts.
- Upgrade `Session` to full Double Ratchet for async scenarios.
- Disappearing messages.
- Delivery and read receipts.

---

## Phase 3 — Groups and Multi-Device

Sketch — not yet scheduled.

- MLS groups (RFC 9420) via a vetted library.
- Multi-device per identity — one primary device signs for linked devices.
- Key-backup opt-in.
- Remote session termination on linked devices.

---

## Phase 4 — Beyond the LAN

Sketch — not yet scheduled.

- Optional user-hosted relay (`InternetRelayTransport`).
- Invite-code discovery (no mDNS dependency).
- Possible Tor fallback.

---

## Cross-phase principles

- No phase begins until the previous phase's success criteria are met and documented in `docs/retros/phase-N.md`.
- Threat model reviewed at each boundary.
- Benchmarks captured at phase end for regression tracking.
- Every phase increases test coverage, never decreases it.
