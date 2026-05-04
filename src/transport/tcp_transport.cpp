#include <cloak/transport/tcp_transport.h>
#include <boost/asio.hpp>

namespace cloak::transport {

TcpTransport::TcpTransport(std::unique_ptr<boost::asio::io_context> io,
                            boost::asio::ip::tcp::socket socket)
    : io_context_(std::move(io)), socket_(std::move(socket)), is_open_(true) {}

TcpTransport::~TcpTransport() {
    static_cast<void>(close());
}

cloak::core::Result<std::unique_ptr<Transport>> TcpTransport::connect(
    const cloak::core::Endpoint& endpoint) {
    try {
        auto io = std::make_unique<boost::asio::io_context>();
        boost::asio::ip::tcp::resolver resolver(*io);
        auto results = resolver.resolve(endpoint.address,
                                        std::to_string(endpoint.port));

        boost::asio::ip::tcp::socket socket(*io);
        // Set TCP_NODELAY: reduce latency for small encrypted frames.
        static_cast<void>(boost::asio::connect(socket, results));
        socket.set_option(boost::asio::ip::tcp::no_delay(true));

        return std::unique_ptr<Transport>(
            new TcpTransport(std::move(io), std::move(socket)));
    } catch (const boost::system::system_error& e) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TCP connect failed: ") + e.what()));
    }
}

cloak::core::Result<std::unique_ptr<Transport>> TcpTransport::accept_from(
    uint16_t port) {
    try {
        auto io = std::make_unique<boost::asio::io_context>();
        boost::asio::ip::tcp::acceptor acceptor(
            *io,
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::tcp::v4(), port));

        // Reuse address so restarts don't hit TIME_WAIT.
        acceptor.set_option(boost::asio::socket_base::reuse_address(true));

        boost::asio::ip::tcp::socket socket(*io);
        acceptor.accept(socket);
        socket.set_option(boost::asio::ip::tcp::no_delay(true));

        return std::unique_ptr<Transport>(
            new TcpTransport(std::move(io), std::move(socket)));
    } catch (const boost::system::system_error& e) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TCP accept failed: ") + e.what()));
    }
}

cloak::core::Result<void> TcpTransport::send(
    std::span<const std::byte> data) {

    if (!is_open_) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError, "Socket closed"));
    }
    try {
        boost::asio::write(socket_,
                           boost::asio::buffer(data.data(), data.size()));
        return {};
    } catch (const boost::system::system_error& e) {
        static_cast<void>(close());
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TCP send failed: ") + e.what()));
    }
}

cloak::core::Result<std::vector<std::byte>> TcpTransport::receive(
    size_t exact_bytes) {

    if (!is_open_) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError, "Socket closed"));
    }

    std::vector<std::byte> buf(exact_bytes);
    try {
        if (exact_bytes > 0) {
            boost::asio::read(socket_,
                              boost::asio::buffer(buf.data(), exact_bytes));
        }
        return buf;
    } catch (const boost::system::system_error& e) {
        static_cast<void>(close());
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TCP receive failed: ") + e.what()));
    }
}

cloak::core::Result<void> TcpTransport::close() {
    if (is_open_) {
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        is_open_ = false;
    }
    return {};
}

bool TcpTransport::is_open() const { return is_open_; }

// ── TcpListener ───────────────────────────────────────────────────────────────

TcpListener::TcpListener(std::unique_ptr<boost::asio::io_context> io,
                         boost::asio::ip::tcp::acceptor           acceptor)
    : io_(std::move(io)), acceptor_(std::move(acceptor)) {}

cloak::core::Result<TcpListener> TcpListener::bind(uint16_t preferred_port) {
    try {
        auto io = std::make_unique<boost::asio::io_context>();
        boost::asio::ip::tcp::acceptor acceptor(
            *io,
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::tcp::v4(), preferred_port));
        acceptor.set_option(boost::asio::socket_base::reuse_address(true));
        return TcpListener(std::move(io), std::move(acceptor));
    } catch (const boost::system::system_error& e) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TcpListener bind failed: ") + e.what()));
    }
}

uint16_t TcpListener::local_port() const {
    return acceptor_.local_endpoint().port();
}

cloak::core::Result<std::unique_ptr<Transport>> TcpListener::accept_one() {
    try {
        boost::asio::ip::tcp::socket socket(*io_);
        acceptor_.accept(socket);
        acceptor_.close();
        socket.set_option(boost::asio::ip::tcp::no_delay(true));
        return std::unique_ptr<Transport>(
            new TcpTransport(std::move(io_), std::move(socket)));
    } catch (const boost::system::system_error& e) {
        return std::unexpected(cloak::core::Error::from(
            cloak::core::ErrorCode::TransportError,
            std::string("TcpListener accept failed: ") + e.what()));
    }
}

} // namespace cloak::transport
