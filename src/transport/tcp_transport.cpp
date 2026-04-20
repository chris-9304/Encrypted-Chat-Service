#include "tcp_transport.h"

namespace ev::transport {

TcpTransport::TcpTransport(boost::asio::ip::tcp::socket socket)
    : socket_(std::move(socket)), is_open_(true) {}

TcpTransport::~TcpTransport() {
    close();
}

ev::core::Result<std::unique_ptr<Transport>> TcpTransport::connect(const ev::core::Endpoint& endpoint) {
    try {
        boost::asio::io_context io;
        boost::asio::ip::tcp::resolver resolver(io);
        auto results = resolver.resolve(endpoint.address, std::to_string(endpoint.port));
        
        boost::asio::ip::tcp::socket socket(io);
        boost::asio::connect(socket, results);
        
        return std::unique_ptr<Transport>(new TcpTransport(std::move(socket)));
    } catch(const boost::system::system_error&) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "TCP Connect failed", std::nullopt});
    }
}

ev::core::Result<std::unique_ptr<Transport>> TcpTransport::accept_from(uint16_t port) {
    try {
        boost::asio::io_context io;
        boost::asio::ip::tcp::acceptor acceptor(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
        boost::asio::ip::tcp::socket socket(io);
        acceptor.accept(socket);
        
        return std::unique_ptr<Transport>(new TcpTransport(std::move(socket)));
    } catch(const boost::system::system_error&) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "TCP Accept failed", std::nullopt});
    }
}

ev::core::Result<void> TcpTransport::send(std::span<const std::byte> data) {
    if (!is_open_) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Socket closed", std::nullopt});
    try {
        boost::asio::write(socket_, boost::asio::buffer(data.data(), data.size()));
        return {};
    } catch(const boost::system::system_error&) {
        close();
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Send failed", std::nullopt});
    }
}

ev::core::Result<std::vector<std::byte>> TcpTransport::receive(size_t exact_bytes) {
    if (!is_open_) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Socket closed", std::nullopt});
    
    std::vector<std::byte> buf(exact_bytes);
    try {
        if (exact_bytes > 0) {
            boost::asio::read(socket_, boost::asio::buffer(buf.data(), exact_bytes));
        }
        return buf;
    } catch(const boost::system::system_error&) {
        close();
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Receive failed", std::nullopt});
    }
}

ev::core::Result<void> TcpTransport::close() {
    if (is_open_) {
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        is_open_ = false;
    }
    return {};
}

bool TcpTransport::is_open() const { return is_open_; }

} // namespace ev::transport
