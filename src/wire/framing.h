#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <vector>
#include <span>
#include <cstdint>
#include <string>

namespace ev::wire {

enum class MessageType : uint8_t { Handshake = 1, AppMessage = 2 };

constexpr size_t kMaxFrameBodySize = 1024 * 1024; // 1 MiB

struct Frame {
    MessageType type;
    std::vector<std::byte> payload;
};

ev::core::Result<std::vector<std::byte>> encode(const Frame& f);  // [4-byte BE len][1-byte type][payload]
ev::core::Result<Frame> decode(std::span<const std::byte> bytes);

struct HandshakePayload {
    ev::core::PublicKey x25519_pub;
    ev::core::PublicKey ed25519_pub;
    ev::core::Signature sig_over_x25519;
    std::string display_name;  // max 64 chars
};

ev::core::Result<std::vector<std::byte>> encode_handshake(const HandshakePayload& h);
ev::core::Result<HandshakePayload> decode_handshake(std::span<const std::byte> bytes);

struct AppPayload {
    uint64_t counter;
    std::vector<std::byte> ciphertext;  // includes 24-byte nonce prefix
};

ev::core::Result<std::vector<std::byte>> encode_app(const AppPayload& p);
ev::core::Result<AppPayload> decode_app(std::span<const std::byte> bytes);

} // namespace ev::wire
