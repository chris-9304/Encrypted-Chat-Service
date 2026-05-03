# Cloak — Demo Walkthrough

This guide shows how to run Cloak end-to-end: LAN chat, file transfer, group chat, and internet relay with invite codes.

---

## Prerequisites

Build Cloak in debug mode:

```powershell
cmake --preset debug
cmake --build --preset debug
```

Binaries are at:
- `build/debug/cloak.exe` — main application
- `build/debug/cloak-relay.exe` — relay server

---

## Demo 1: LAN Text Chat

Open two terminals.

**Terminal 1 — Bob (listener)**
```powershell
.\build\debug\cloak.exe --name Bob --port 13370
```

**Terminal 2 — Alice (connects to Bob)**
```powershell
.\build\debug\cloak.exe --name Alice --port 13371 --connect 127.0.0.1:13370
```

Both terminals will show:
```
[System] Connected to Bob (fingerprint: ABCD-EFGH-IJKL)
[System] Trust: Tofu
```

Type in Alice's terminal — the message appears in Bob's terminal, end-to-end encrypted.

**What's happening under the hood:**
1. Alice connects via TCP. Both exchange X25519 + Ed25519 keys, each signs the other's key.
2. The X25519 shared secret initializes the Double Ratchet root key.
3. Every message is encrypted with a unique per-message key derived from the ratchet chain.
4. Bob's terminal shows Alice's fingerprint. Alice's shows Bob's. You can verify these match out-of-band.

---

## Demo 2: Identity Verification (Safety Numbers)

After connecting, in either terminal:

```
/safety
```

Output:
```
Safety number with Bob:
3847291056  2938470156  8472916035  4729381056  9384720165  1092837465
Read this number to Bob over the phone. If Bob's terminal shows the same number, you are not being intercepted.
```

Once verified (call Bob, compare numbers):
```
/verify
```

The peer's trust status changes from `Tofu` to `Verified`.

---

## Demo 3: File Transfer

In Alice's terminal (while connected to Bob):

```
/send C:\Users\Alice\Documents\photo.jpg
```

Output:
```
[Transfer] Sending photo.jpg (2.4 MB, 37 chunks)...
[Transfer] photo.jpg sent (2.4 MB)
```

In Bob's terminal:
```
[Transfer] Receiving photo.jpg from Alice...
[Transfer] photo.jpg saved to C:\Users\Bob\Downloads\photo.jpg
```

**Security:** A random 32-byte per-file key is generated and encrypted inside the Double Ratchet session. Each 64 KiB chunk is independently AEAD-encrypted. Bob's filesystem only ever sees plaintext after decryption.

---

## Demo 4: Group Chat

**Step 1: Alice creates a group**
```
/group-create ProjectAlpha
```

**Step 2: Alice invites Bob**
```
/group-invite Bob
```
Bob receives an invite via their pairwise session. The invite includes Alice's Sender Key chain key (encrypted via Double Ratchet).

**Step 3: Switch to the group and send a message**
```
/group-switch ProjectAlpha
/group-msg Hello from Alice!
```

In Bob's terminal, after switching to the group:
```
[Group: ProjectAlpha] Alice: Hello from Alice!
```

**Security:** Each group message is encrypted with a per-message key derived from Alice's Sender Key chain. The chain key advances after every message — Bob cannot decrypt future messages from chain keys he received during the invite if Alice's chain has advanced.

---

## Demo 5: Internet Relay (NAT Traversal)

Use this when Alice and Bob are on different networks (different internet connections, behind different routers).

**Step 1: Run the relay server** (on a publicly reachable host — can be the same machine for testing)
```powershell
.\build\debug\cloak-relay.exe --port 8765
```

**Step 2: Alice starts with relay and creates an invite code**
```powershell
.\build\debug\cloak.exe --name Alice --port 13371 --relay 127.0.0.1:8765
```
Inside Cloak:
```
/make-invite
```
Output:
```
Invite code: 127.0.0.1:8765/a3f8c2e1b4d7920f1e5a3c8b2d4f6e091a2b3c4d5e6f7081920a1b2c3d4e5f6
Share this with your contact.
```

**Step 3: Bob connects using the invite code**
```powershell
.\build\debug\cloak.exe --name Bob --port 13370
```
Inside Cloak:
```
/connect-invite 127.0.0.1:8765/a3f8c2e1b4d7920f1e5a3c8b2d4f6e091a2b3c4d5e6f7081920a1b2c3d4e5f6
```

Both terminals show the connection established. From this point, the session works identically to LAN chat — all features (file transfer, groups, receipts) work transparently over the relay.

**Security:** The relay only ever sees encrypted bytes. The Cloak handshake and Double Ratchet run on top of the relay transport. The relay operator cannot read your messages.

---

## Demo 6: Multi-Device

**Step 1: Alice (primary device) links a secondary device**

On the primary device:
```
/link-device <secondary_device_signing_pub_hex>
```

The secondary device's signing public key (a 64-character hex string) is obtained from the secondary device by running:
```powershell
.\build\debug\cloak.exe --name "Alice-Phone" --port 13372
# The device fingerprint is displayed at startup
```

**Step 2: Install the certificate on the secondary**

The primary outputs a certificate hex string. On the secondary device:
```
/install-cert <cert_hex>
```

Now the secondary device can connect to peers and they will recognize it as an authorized device of Alice.

---

## All Commands Reference

| Command | Description |
|---------|-------------|
| `/peers` | List all connected peers with trust status |
| `/switch <name>` | Switch the active (selected) peer |
| `/safety` | Show safety number for the current peer |
| `/verify` | Mark the current peer as verified |
| `/send <path>` | Send a file to the current peer |
| `/history` | Show stored message history for the current peer |
| `/group-create <name>` | Create a new group with the given name |
| `/group-list` | List all known groups |
| `/group-switch <name>` | Switch the active group |
| `/group-msg <text>` | Send a text message to the active group |
| `/group-invite <peer>` | Invite a connected peer to the active group |
| `/group-leave` | Leave the active group |
| `/make-invite` | Generate an invite code (requires `--relay` flag at startup) |
| `/connect-invite <code>` | Connect to a peer using an invite code |
| `/devices` | List all linked devices |
| `/link-device <pub_hex>` | Issue a device certificate for a secondary device |
| `/install-cert <cert_hex>` | Install a device certificate on a secondary device |

---

## Clean Shutdown

Press `Ctrl+C` in any terminal. Cloak:
1. Signals all background threads to stop (`running_ = false`)
2. Joins listen thread, discovery thread, cleanup thread, and all per-session receive threads
3. Closes all sessions (transport `close()` called in `~Session()`)
4. Writes pending data to `MessageStore` and closes the SQLite connection
5. Zeros all `SecureBuffer` contents on destruction

RAII ensures all resources are released in the correct order even if shutdown is triggered by an error.
