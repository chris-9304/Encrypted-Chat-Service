# 0004: SQLite Column AEAD Over SQLCipher

**Status:** Accepted

## Context
At-rest data must be secured, requiring database-level encryption. Using full SQLCipher poses heavier dependency chains and black-box encryption scopes.

## Decision
Use standard SQLite3 but enforce application-level libsodium column-AEAD encryption prior to storing sensitive fields. 

## Consequences
- SQLite schema is visible, but column contexts are robustly encrypted.
- Better alignment with our centralized Crypto facade handling application keys.
- Requires manual integration logic around database reads/writes but reduces third-party exposure.
