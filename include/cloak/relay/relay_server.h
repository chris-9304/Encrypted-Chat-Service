#pragma once

#include <cloak/core/error.h>
#include <atomic>
#include <array>
#include <cstdint>

namespace cloak::relay {

// Simple TCP relay server for Cloak Phase 4.
//
// Peers connect and register with a 32-byte room ID.  When two peers register
// with the same room ID the relay pairs them and forwards bytes transparently.
// All Cloak cryptography happens between the peers; the relay sees only
// opaque ciphertext.
//
// Concurrency model: one accept thread + two forwarding threads per paired
// connection.  Suitable for development and small deployments.
class RelayServer {
public:
    explicit RelayServer(uint16_t port);
    ~RelayServer();

    // Block, accepting and relaying connections until stop() is called.
    cloak::core::Result<void> run();

    // Signal the accept loop to stop (safe to call from any thread).
    void stop();

    // Port this server is bound to (useful if port was ephemeral).
    uint16_t bound_port() const { return bound_port_; }

private:
    uint16_t              port_;
    uint16_t              bound_port_{0};
    std::atomic<bool>     running_{false};
};

} // namespace cloak::relay
