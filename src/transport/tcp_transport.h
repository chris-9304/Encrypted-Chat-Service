#pragma once

#include "transport.h"
#include <ev/core/types.h>
#include <boost/asio.hpp>
#include <memory>

namespace ev::transport {

class TcpTransport final : public Transport {
public:
    static ev::core::Result<std::unique_ptr<Transport>> connect(const ev::core::Endpoint& endpoint);
    static ev::core::Result<std::unique_ptr<Transport>> accept_from(uint16_t port);

    ~TcpTransport() override;

    ev::core::Result<void> send(std::span<const std::byte> data) override;
    ev::core::Result<std::vector<std::byte>> receive(size_t exact_bytes) override;
    ev::core::Result<void> close() override;
    bool is_open() const override;

private:
    TcpTransport(boost::asio::ip::tcp::socket socket);
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::socket socket_;
    bool is_open_{true};
};

} // namespace ev::transport
