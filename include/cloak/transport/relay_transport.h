#pragma once

#include <cloak/transport/transport.h>
#include <cloak/core/types.h>
#include <boost/asio.hpp>
#include <array>
#include <memory>

namespace cloak::transport {

// Relay wire protocol (Phase 4).
//
// Client → Relay handshake (37 bytes):
//   magic  [4] = {0x43, 0x4C, 0x4B, 0x31}  ("CLK1")
//   role   [1] = 0x01 (host/responder) | 0x02 (join/initiator)
//   room   [32]                              room identifier
//
// Relay → Client response (1 byte):
//   0x00 = registered, waiting for peer  (host only; another byte follows when peer arrives)
//   0x01 = paired as Cloak initiator (guest after host responds; host never gets this)
//   0x02 = paired as Cloak responder (host when guest arrives)
//   0xFF = error (followed by 2-byte BE message length + UTF-8 message)
//
// After 0x01 or 0x02, all bytes are forwarded transparently between the two clients.
//
// Typical flows:
//   Invite flow — host:  connect → send 0x01+room → recv 0x00 (wait) → recv 0x02 (paired)
//   Invite flow — guest: connect → send 0x02+room → recv 0x01 (paired)

// Room identifier: 32 bytes, derived by the inviter.
using RelayRoomId = std::array<uint8_t, 32>;

// Invite-code helpers.
// Code format: "<relay_host>:<relay_port>/<room_hex_64>"
std::string make_invite_code(const cloak::core::Endpoint& relay, const RelayRoomId& room);
bool parse_invite_code(const std::string& code,
                       cloak::core::Endpoint& out_relay, RelayRoomId& out_room);

// RelayTransport wraps a TCP socket that has completed the relay handshake.
// After construction, it behaves identically to TcpTransport.
class RelayTransport final : public Transport {
public:
    // Connect to relay as HOST (Cloak responder).
    // Blocks until a guest connects or an error occurs.
    // Returns the transport; caller must use Session::accept().
    static cloak::core::Result<std::unique_ptr<Transport>>
        host(const cloak::core::Endpoint& relay, const RelayRoomId& room);

    // Connect to relay as GUEST (Cloak initiator).
    // Blocks until the relay confirms pairing.
    // Returns the transport; caller must use Session::initiate().
    static cloak::core::Result<std::unique_ptr<Transport>>
        join(const cloak::core::Endpoint& relay, const RelayRoomId& room);

    ~RelayTransport() override;

    cloak::core::Result<void>                   send(std::span<const std::byte> data) override;
    cloak::core::Result<std::vector<std::byte>> receive(size_t exact_bytes) override;
    cloak::core::Result<void>                   close() override;
    bool                                     is_open() const override;

private:
    explicit RelayTransport(std::unique_ptr<boost::asio::io_context> io,
                            boost::asio::ip::tcp::socket socket);

    static cloak::core::Result<std::unique_ptr<Transport>>
        connect_and_pair(const cloak::core::Endpoint& relay,
                         uint8_t role, const RelayRoomId& room);

    std::unique_ptr<boost::asio::io_context> io_context_;
    boost::asio::ip::tcp::socket             socket_;
    bool                                     is_open_{true};
};

} // namespace cloak::transport
