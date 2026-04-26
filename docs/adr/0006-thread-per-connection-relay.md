# ADR 0006 — Thread-per-connection relay server

**Status:** Accepted  
**Date:** 2026-04-26  
**Phase:** 4

## Context

Phase 4 requires a relay server that pairs two peers and forwards their encrypted byte streams. The relay is transparent — it cannot decrypt Cloak traffic — and is intended for small deployments (development, self-hosted, friend-group scale).

Two architectural options were considered:

1. **Async / io_context-per-server** — single-threaded event loop with Boost.Asio async operations. Scales to thousands of connections; complex error handling.
2. **Thread-per-connection** — blocking synchronous I/O; one thread per accepted connection, two forwarding threads per paired connection pair.

## Decision

Thread-per-connection (option 2).

## Rationale

- The relay is a development and small-deployment tool. Simultaneous pair count will be low (< 100 in practice).
- Synchronous blocking I/O is far simpler to reason about for correctness, especially for the pairing state machine (host blocks on `condition_variable::wait`, guest signals, no callback chains).
- The existing `TcpTransport` and `RelayTransport` are synchronous; a synchronous relay is consistent with the rest of the stack.
- Scaling to thousands of relay connections is explicitly out of scope. If a production relay is needed, a dedicated reverse proxy (e.g., nginx stream) is the right tool.

## Consequences

- Each active relay connection consumes one OS thread while waiting (host) and two while forwarding. This is acceptable for the stated scale.
- The relay is not suitable as a high-concurrency public service without redesign.
- No async complexity in relay_server.cpp — the pairing logic is easy to audit.
