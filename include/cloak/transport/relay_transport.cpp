#include <cloak/transport/relay_transport.h>
#include <boost/asio.hpp>
#include <charconv>
#include <iomanip>
#include <sstream>

namespace cloak::transport {

using namespace cloak::core;

// ── Protocol constants ────────────────────────────────────────────────────────

static constexpr uint8_t kMagic[4] = {0x43, 0x4C, 0x4B, 0x31}; // "CLK1"
static constexpr uint8_t kRoleHost = 0x01;
static constexpr uint8_t kRoleJoin = 0x02;
static constexpr uint8_t kStatusWaiting   = 0x00;
static constexpr uint8_t kStatusInitiator = 0x01;
static constexpr uint8_t kStatusResponder = 0x02;
static constexpr uint8_t kStatusError     = 0xFF;

// ── Invite-code helpers ───────────────────────────────────────────────────────

std::string make_invite_code(const Endpoint& relay, const RelayRoomId& room) {
    std::ostringstream ss;
    ss << relay.address << ":" << relay.port << "/";
    for (uint8_t b : room)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

bool parse_invite_code(const std::string& code,
                       Endpoint& out_relay, RelayRoomId& out_room) {
    // Format: "host:port/room_hex_64"
    const auto slash_pos = code.rfind('/');
    if (slash_pos == std::string::npos) return false;

    const std::string relay_part = code.substr(0, slash_pos);
    const std::string room_hex   = code.substr(slash_pos + 1);

    if (room_hex.size() != 64) return false;

    // Parse room hex — from_chars avoids exceptions and per-byte allocations.
    for (size_t i = 0; i < 32; ++i) {
        unsigned int byte_val = 0;
        const char* begin = room_hex.data() + i * 2;
        auto [ptr, ec] = std::from_chars(begin, begin + 2, byte_val, 16);
        if (ec != std::errc{} || ptr != begin + 2) return false;
        out_room[i] = static_cast<uint8_t>(byte_val);
    }

    // Parse relay "host:port".
    const auto colon_pos = relay_part.rfind(':');
    if (colon_pos == std::string::npos) return false;

    out_relay.address = relay_part.substr(0, colon_pos);

    unsigned int port_val = 0;
    const std::string port_str = relay_part.substr(colon_pos + 1);
    auto [ptr, ec] = std::from_chars(port_str.data(),
                                     port_str.data() + port_str.size(),
                                     port_val);
    if (ec != std::errc{} || port_val == 0 || port_val > 65535) return false;
    out_relay.port = static_cast<uint16_t>(port_val);

    return true;
}

// ── Constructor / Destructor ──────────────────────────────────────────────────

RelayTransport::RelayTransport(std::unique_ptr<boost::asio::io_context> io,
                               boost::asio::ip::tcp::socket socket)
    : io_context_(std::move(io)), socket_(std::move(socket)), is_open_(true) {}

RelayTransport::~RelayTransport() {
    static_cast<void>(close());
}

// ── Internal: connect, send handshake, wait for pairing ──────────────────────

Result<std::unique_ptr<Transport>>
RelayTransport::connect_and_pair(const Endpoint& relay,
                                 uint8_t role, const RelayRoomId& room) {
    try {
        auto io = std::make_unique<boost::asio::io_context>();
        boost::asio::ip::tcp::resolver resolver(*io);
        auto results = resolver.resolve(relay.address, std::to_string(relay.port));

        boost::asio::ip::tcp::socket socket(*io);
        boost::asio::connect(socket, results);
        socket.set_option(boost::asio::ip::tcp::no_delay(true));

        // Send 37-byte handshake: magic[4] + role[1] + room[32].
        std::array<uint8_t, 37> hs{};
        std::memcpy(hs.data(), kMagic, 4);
        hs[4] = role;
        std::memcpy(hs.data() + 5, room.data(), 32);
        boost::asio::write(socket, boost::asio::buffer(hs));

        // For host: wait for 0x00, then block for the pairing status.
        // For guest: wait for a single status byte.
        uint8_t status = 0;
        boost::asio::read(socket, boost::asio::buffer(&status, 1));

        if (status == kStatusWaiting) {
            // Host path: relay acknowledged registration, wait for guest arrival.
            boost::asio::read(socket, boost::asio::buffer(&status, 1));
        }

        if (status == kStatusError) {
            // Read error message from relay.
            uint8_t len_bytes[2];
            boost::asio::read(socket, boost::asio::buffer(len_bytes, 2));
            const uint16_t msg_len =
                (static_cast<uint16_t>(len_bytes[0]) << 8) | len_bytes[1];
            std::string err_msg(msg_len, '\0');
            if (msg_len > 0)
                boost::asio::read(socket, boost::asio::buffer(err_msg.data(), msg_len));
            return std::unexpected(Error::from(ErrorCode::TransportError,
                "Relay error: " + err_msg));
        }

        if (status != kStatusInitiator && status != kStatusResponder) {
            return std::unexpected(Error::from(ErrorCode::TransportError,
                "Relay: unexpected status byte"));
        }

        return std::unique_ptr<Transport>(
            new RelayTransport(std::move(io), std::move(socket)));

    } catch (const boost::system::system_error& e) {
        return std::unexpected(Error::from(ErrorCode::TransportError,
            std::string("Relay connect failed: ") + e.what()));
    }
}

// ── Public factories ──────────────────────────────────────────────────────────

Result<std::unique_ptr<Transport>>
RelayTransport::host(const Endpoint& relay, const RelayRoomId& room) {
    return connect_and_pair(relay, kRoleHost, room);
}

Result<std::unique_ptr<Transport>>
RelayTransport::join(const Endpoint& relay, const RelayRoomId& room) {
    return connect_and_pair(relay, kRoleJoin, room);
}

// ── Transport interface ───────────────────────────────────────────────────────

Result<void> RelayTransport::send(std::span<const std::byte> data) {
    if (!is_open_)
        return std::unexpected(Error::from(ErrorCode::TransportError, "Socket closed"));
    try {
        boost::asio::write(socket_, boost::asio::buffer(data.data(), data.size()));
        return {};
    } catch (const boost::system::system_error& e) {
        static_cast<void>(close());
        return std::unexpected(Error::from(ErrorCode::TransportError,
            std::string("Relay send failed: ") + e.what()));
    }
}

Result<std::vector<std::byte>> RelayTransport::receive(size_t exact_bytes) {
    if (!is_open_)
        return std::unexpected(Error::from(ErrorCode::TransportError, "Socket closed"));

    std::vector<std::byte> buf(exact_bytes);
    try {
        if (exact_bytes > 0)
            boost::asio::read(socket_, boost::asio::buffer(buf.data(), exact_bytes));
        return buf;
    } catch (const boost::system::system_error& e) {
        static_cast<void>(close());
        return std::unexpected(Error::from(ErrorCode::TransportError,
            std::string("Relay receive failed: ") + e.what()));
    }
}

Result<void> RelayTransport::close() {
    if (is_open_) {
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        is_open_ = false;
    }
    return {};
}

bool RelayTransport::is_open() const { return is_open_; }

} // namespace cloak::transport
