# Threat Model

Who Cloak protects, against whom, under what assumptions. Features not serving these goals are out of scope. User-facing claims must not exceed what this document asserts.

## Assets, in priority order

1. **Message content.** Confidentiality and integrity of plaintext exchanged between users.
2. **Long-term identity keys.** Compromise enables permanent impersonation.
3. **Session state.** Compromise reveals past and/or future messages in an active session.
4. **At-rest local data.** Message history and peer directory on the device.
5. **Identity pubkey association.** Linking a pubkey to a real-world person.
6. **Availability.** Delivery between peers while both are on the LAN.

## Security goals

### In scope

- **Confidentiality.** Only the intended peer can read plaintext.
- **Integrity.** The peer detects any modification of ciphertext.
- **Mutual authentication.** Both peers confirm they are talking to the holder of the expected identity key.
- **Forward secrecy.** Past messages remain secret even if a long-term key is later compromised.
- **At-rest encryption.** Local database and identity file unreadable without the user's passphrase.
- **Trust-on-first-use with loud change alerts.** First contact establishes trust; identity-pubkey changes are surfaced prominently.
- **Safety-number verification.** Users can verify each other out-of-band.
- **Secrets-never-in-logs.** No key material in spdlog output.
- **Plug-and-play defaults.** Defaults are the secure path; users must opt in to anything weaker.

### Out of scope for Phase 1

- Cross-network messaging and its adversaries.
- Server-relayed offline delivery.
- Traffic-analysis resistance beyond what TLS/Noise naturally provides.
- Deniability across conversations (Phase 2 with full Double Ratchet).
- Anonymity from the LAN operator. An on-LAN observer sees connections between IPs.
- Defense against a compromised endpoint.
- Defense against a malicious peer (they can always screenshot/record).
- Defense against physical or coercive attacks.
- Supply-chain attacks on the OS, compiler, or installer toolchain.
- Post-quantum security (deferred to a future phase; hybrid X25519+Kyber is the likely direction).

## Adversaries

### A1. Passive LAN observer (in scope)

*Someone connected to the same Wi-Fi or wired LAN.*

- **Capabilities.** Captures packets with Wireshark, sees all traffic between peers, observes mDNS broadcasts.
- **Goals.** Read message content. Identify who is using Cloak and who is talking to whom.
- **Mitigations.** Noise XX over TCP provides confidentiality, integrity, and mutual authentication. The handshake includes identity-pubkey authentication so the observer learns only identities that are broadcast by mDNS anyway.
- **Residual risk.** Observer sees the mDNS service advertisements (by design — that's how discovery works). Observer knows someone is running Cloak and sees connection metadata. Plaintext is not accessible.

### A2. Active LAN attacker (in scope)

*On-LAN attacker with packet injection, ARP-spoofing, or rogue AP capability.*

- **Capabilities.** A1 plus modify, drop, inject, MITM at IP layer.
- **Goals.** MITM a session; impersonate one peer to another.
- **Mitigations.** Noise XX mutual authentication binds the session to the peer's identity pubkey. A MITM without the peer's signing key cannot complete the handshake. Identity-change detection fires on re-connection attempts with different pubkeys.
- **Residual risk.** An attacker can drop traffic (denial of service). An attacker who somehow learns a peer's identity signing key can impersonate — but that key lives in an encrypted, mlocked buffer and never leaves the device.

### A3. Rogue peer on the LAN (in scope)

*Someone runs Cloak on the LAN intending to trick others into chatting with them believing they are someone else.*

- **Capabilities.** Runs Cloak legitimately, chooses any display name, advertises any mDNS record.
- **Goals.** Be mistaken for another user.
- **Mitigations.** Display names are not authenticated; **identity pubkeys are**. The UI shows the short safety number for every peer. Users compare safety numbers out of band for high-assurance conversations. Identity-change alerts trigger on pubkey mismatch with a previously-seen peer.
- **Residual risk.** A user who never verifies safety numbers is vulnerable to social-engineering impersonation on first contact. This is disclosed plainly in the UI's first-run onboarding.

### A4. Device thief / post-compromise attacker (partially in scope)

*Gets hold of an unlocked or later-compromised device.*

- **Capabilities.** Read any state the user could read on that device.
- **Goals.** Read past messages; impersonate the user going forward.
- **Mitigations.** `identity.bin` and `store.db` are encrypted at rest with a key derived via Argon2id from the user's passphrase. If the attacker has the passphrase, the game is over; if not, the files are opaque. Forward secrecy protects past messages on the *peer's* device.
- **Residual risk.** An unlocked, running Cloak process has the derived key in memory. A running-process compromise reveals message history on that device. Remote wipe is a Phase 3 feature.

### A5. Curious or malicious network administrator (in scope)

*Corporate, school, or home IT with LAN visibility and possibly DNS control.*

- **Capabilities.** A1 + A2, plus may block mDNS traffic entirely or filter specific ports.
- **Goals.** Prevent Cloak from working; identify users of it.
- **Mitigations.** Cryptographic guarantees hold. Admin can block mDNS or the chosen TCP port — Phase 1 accepts this. A future phase may add manual peer entry as a fallback.
- **Residual risk.** Admin can prevent Cloak from functioning. Admin cannot read messages that do get exchanged.

### A6. Supply-chain attacker (partially in scope)

*Compromises a dependency, the installer, or the signing cert.*

- **Capabilities.** Inject code into binaries distributed to users.
- **Goals.** Backdoor the client.
- **Mitigations.** vcpkg manifest with pinned baseline SHA. Reproducible builds where achievable on Windows. Authenticode signing of the MSI with integrity chain. Minimum dependency surface.
- **Residual risk.** Non-zero. An upstream compromise (libsodium, Boost, MSVC runtime) is catastrophic and largely undefendable at app level.

## Trust assumptions

We trust:

- The CPU, OS, and MSVC runtime.
- libsodium's primitive implementations.
- The user to keep their passphrase and device secret.
- The user's willingness to verify a safety number out-of-band at least once for high-assurance conversations.

We do NOT trust:

- The LAN.
- Other peers on the LAN.
- Display names, SSIDs, or hostnames as identity.
- Any third party with the MSI download URL.

## Cryptographic choices

- **Identity signing.** Ed25519.
- **Key agreement.** X25519.
- **Handshake.** Noise protocol, `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern. Chosen because both peers are online at handshake, mutual authentication is required, and forward secrecy is provided in one round trip.
- **AEAD.** XChaCha20-Poly1305 for application messages.
- **KDF.** HKDF-SHA-256 for deriving session keys from Noise handshake output.
- **Password-based KDF.** Argon2id for deriving the database key from the user's passphrase (interactive parameters by default; sensitive parameters as a user option).
- **Per-message ratcheting.** Inside a Noise session, a symmetric KDF ratchet advances the chain key after each message for forward secrecy. Full Double Ratchet is a Phase 2 upgrade for async scenarios.

## Explicit non-claims

Cloak does not claim to be "unbreakable." No system is. We do not claim:

- That it works off-LAN in Phase 1.
- That display names are authenticated.
- That it defeats a LAN admin who blocks the port.
- That it protects against a compromised endpoint.
- That it is bug-free. Disclosure policy: `SECURITY.md`.

## Review cadence

This document is revisited:

- At every phase boundary.
- When a new dependency handles secret material.
- When a new adversary class comes into scope (e.g. Phase 4 non-LAN transports).
- On any security finding.
