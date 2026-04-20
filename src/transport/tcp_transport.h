#pragma once

#include "transport.h"
#include <ev/core/types.h>

namespace ev::transport {

class TcpTransport final : public Transport {
public:
    static ev::core::Result<TcpTransport> connect(const ev::core::Endpoint& endpoint);

    ~TcpTransport() override = default;

    ev::core::Result<void> send(std::span<const uint8_t> data) override;
    ev::core::Result<std::vector<uint8_t>> receive() override;
    ev::core::Result<void> close() override;

private:
    TcpTransport() = default;
    
    // TODO(M1.x): Asio socket state
};

} // namespace ev::transport
