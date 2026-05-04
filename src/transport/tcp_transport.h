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

    friend class TcpListener; // TcpListener::accept_one() calls the private ctor.
};

// One-shot TCP listener.  Binds immediately (port 0 → OS picks a free port),
// exposes the bound port, then blocks on accept_one() for a single connection.
// Designed for relay-free LAN invite codes.
class TcpListener {
public:
    // Bind on `preferred_port` (0 = let OS pick).  Returns error on bind failure.
    static cloak::core::Result<TcpListener> bind(uint16_t preferred_port = 0);

    // Port the OS assigned (valid immediately after bind()).
    uint16_t local_port() const;

    // Block until one inbound connection arrives.  Can only be called once.
    cloak::core::Result<std::unique_ptr<Transport>> accept_one();

    // Non-copyable, movable.
    TcpListener(TcpListener&&)            = default;
    TcpListener& operator=(TcpListener&&) = default;
    TcpListener(const TcpListener&)       = delete;
    TcpListener& operator=(const TcpListener&) = delete;

private:
    TcpListener(std::unique_ptr<boost::asio::io_context> io,
                boost::asio::ip::tcp::acceptor           acceptor);

    std::unique_ptr<boost::asio::io_context> io_;
    boost::asio::ip::tcp::acceptor           acceptor_;
};

} // namespace cloak::transport
