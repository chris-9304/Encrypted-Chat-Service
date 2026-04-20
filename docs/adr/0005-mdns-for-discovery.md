# 0005: mDNS for Discovery

**Status:** Accepted

## Context
In Phase 1, users install the software and need zero-configuration LAN peer discovery.

## Decision
Use standard mDNS (zero-configuration networking) tied closely to Win32 DNS-SD APIs (`DnsServiceRegister`, `DnsServiceBrowse`).

## Consequences
- Eliminates manual IP exchanges or central coordinating servers.
- The LAN administrator could block mDNS ports (an accepted partial risk).
- Provides deterministic identity discovery before TCP connection attempts.
