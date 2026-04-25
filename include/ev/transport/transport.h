#pragma once

#include <ev/core/error.h>
#include <cstddef>
#include <span>
#include <vector>

namespace ev::transport {

// Abstract byte-stream transport.
// Phase 1: TcpTransport.
// Phase 2: LanMailboxTransport (store-and-forward for offline delivery).
// Phase 4: InternetRelayTransport.
class Transport {
public:
    virtual ~Transport() = default;

    // Reliable byte-stream send.  Blocks until all bytes are sent or error.
    virtual ev::core::Result<void> send(std::span<const std::byte> data) = 0;

    // Read exactly exact_bytes bytes.  Blocks until satisfied or error.
    virtual ev::core::Result<std::vector<std::byte>> receive(size_t exact_bytes) = 0;

    // Shutdown and close the underlying connection.
    virtual ev::core::Result<void> close() = 0;

    // True if the connection is open.
    virtual bool is_open() const = 0;
};

} // namespace ev::transport
