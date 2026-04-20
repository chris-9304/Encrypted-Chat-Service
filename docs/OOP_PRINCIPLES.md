# Object-Oriented Principles

This project has been explicitly engineered around robust OOP parameters, validated throughout the demo implementation sequence. Below are the definitive class mappings resolving the five core principles expected in review:

### 1. Abstraction
- Defined in `src/transport/transport.h:10`. The pure virtual base `Transport` exposes critical functional schemas (`send`, `receive`, `close`) without leaking networking contexts. 
- Similarly mapped in `src/discovery/discovery_service.h:23` protecting local advertisements.

### 2. Encapsulation
- Cryptographic states are explicitly shielded. Found inside `src/session/session.h:46`, fields like `session_key_` (type `SecureBuffer<32>`), `send_counter_`, and `peer_display_name_` are inherently private, managed solely by validated `send_text` / `recv_text` logic boundaries ensuring external subsystems can never interact with them.

### 3. Composition over Inheritance
- Demonstrated vividly in the orchestration wrapper: `src/app/chat_application.h:31`.
- `ChatApplication` does not structurally subclass `Identity` or `Session`. Instead, it intrinsically composes them, utilizing `std::unique_ptr`s to define rigid lifecycle graphs natively triggering `Session` states safely across background threads. 

### 4. RAII (Resource Acquisition Is Initialization)
- The entire cryptography schema mandates this mapping. For example, `src/crypto/secure_buffer.h:31` uses explicit `VirtualLock` mechanisms passing scope, unlocking and securely executing `SecureZeroMemory` precisely when destructors cascade.
- Sockets share this trait natively: `src/transport/tcp_transport.cpp:9` automatically tears down boundaries via `close()` on destruction, halting any hanging TCP contexts instantly upon `<Ctrl+C>`.

### 5. Polymorphism
- Core messaging hooks rely directly on Base-Type dispatch. 
- In `src/session/session.h:20`, we instantiate endpoints passing strictly `std::unique_ptr<ev::transport::Transport>`. At runtime, these uniquely hold the blocking `TcpTransport` concrete class (`src/transport/tcp_transport.h:10`), yet `Session` inherently remains blind to WinSock implementations or networking parameters, satisfying the requirement natively.

---
**Note on Cryptography:**
This demo limits the Noise Protocol configuration to an *Ephemeral Static-DH authenticated sequence* bypassing full Forward Secrecy logic demanded in Noise XX purely to align with rapid REPL validations. Full ratcheting boundaries remain scheduled for Phase 2 implementation.
