#pragma once

#include <cloak/transport/transport.h>
#include <cloak/core/types.h>
#include <boost/asio.hpp>
#include <memory>

namespace cloak::transport {

class TcpTransport final : public Transport {
public:
    static cloak::core::Result<std::unique_ptr<Transport>> connect(const cloak::core::Endpoint& endpoint);
    static cloak::core::Result<std::unique_ptr<Transport>> accept_from(uint16_t port);

    ~TcpTransport() override;

    cloak::core::Result<void>                     send(std::span<const std::byte> data) override;
    cloak::core::Result<std::vector<std::byte>>   receive(size_t exact_bytes) override;
    cloak::core::Result<void>                     close() override;
    bool                                       is_open() const override;

private:
    // io_context must outlive the socket — store it on the heap so that the
    // static factory can move-construct a TcpTransport safely.
    explicit TcpTransport(std::unique_ptr<boost::asio::io_context> io,
                          boost::asio::ip::tcp::socket socket);

    std::unique_ptr<boost::asio::io_context> io_context_;
    boost::asio::ip::tcp::socket             socket_;
    bool                                     is_open_{true};
};

} // namespace cloak::transport
