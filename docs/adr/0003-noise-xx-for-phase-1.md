# 0003: Noise XX for Phase 1

**Status:** Accepted

## Context
We need a mutually authenticated key exchange over an adversarial LAN (where TCP connection gives no cryptographic binding).

## Decision
Use the Noise Protocol pattern `XX` (`Noise_XX_25519_ChaChaPoly_BLAKE2s`).

## Consequences
- `XX` requires both peers to be online, matching our Phase 1 functional constraints.
- Gives identity privacy and mutual authentication natively.
- Eliminates the complexity of X3DH/Double Ratchet until Phase 2 introduces async delivery.
