#include "framing.h"
#include <cstring>
#include <winsock2.h>

namespace ev::wire {

constexpr size_t kMaxFrameSize = 1024 * 1024; // 1 MiB

ev::core::Result<std::vector<std::byte>> encode(const Frame& f) {
    if (f.payload.size() > kMaxFrameSize - 5) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Frame size exceeds 1 MiB", std::nullopt});
    }

    uint32_t len = static_cast<uint32_t>(f.payload.size() + 1); // +1 for type
    uint32_t len_be = htonl(len);

    std::vector<std::byte> out;
    out.reserve(4 + len);
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>(reinterpret_cast<uint8_t*>(&len_be)[i]));
    out.push_back(static_cast<std::byte>(f.type));
    out.insert(out.end(), f.payload.begin(), f.payload.end());
    
    return out;
}

ev::core::Result<Frame> decode(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Underflow", std::nullopt});
    
    uint32_t len_be;
    std::memcpy(&len_be, bytes.data(), 4);
    uint32_t len = ntohl(len_be);

    if (len > kMaxFrameSize) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Frame size exceeds 1 MiB", std::nullopt});
    if (bytes.size() < 4 + len) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Incomplete frame", std::nullopt});
    
    Frame f;
    f.type = static_cast<MessageType>(bytes[4]);
    if (f.type != MessageType::Handshake && f.type != MessageType::AppMessage) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Invalid frame type", std::nullopt});
    }

    f.payload = std::vector<std::byte>(bytes.begin() + 5, bytes.begin() + 4 + len);
    return f;
}

ev::core::Result<std::vector<std::byte>> encode_handshake(const HandshakePayload& h) {
    if (h.display_name.length() > 64) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Display name too long", std::nullopt});
    
    std::vector<std::byte> out;
    out.insert(out.end(), reinterpret_cast<const std::byte*>(h.x25519_pub.bytes.data()), reinterpret_cast<const std::byte*>(h.x25519_pub.bytes.data() + 32));
    out.insert(out.end(), reinterpret_cast<const std::byte*>(h.ed25519_pub.bytes.data()), reinterpret_cast<const std::byte*>(h.ed25519_pub.bytes.data() + 32));
    out.insert(out.end(), reinterpret_cast<const std::byte*>(h.sig_over_x25519.bytes.data()), reinterpret_cast<const std::byte*>(h.sig_over_x25519.bytes.data() + 64));
    
    uint16_t name_len = static_cast<uint16_t>(h.display_name.size());
    uint16_t name_len_be = htons(name_len);
    out.insert(out.end(), reinterpret_cast<const std::byte*>(&name_len_be), reinterpret_cast<const std::byte*>(&name_len_be) + 2);
    out.insert(out.end(), reinterpret_cast<const std::byte*>(h.display_name.data()), reinterpret_cast<const std::byte*>(h.display_name.data() + name_len));
    
    return out;
}

ev::core::Result<HandshakePayload> decode_handshake(std::span<const std::byte> bytes) {
    if (bytes.size() < 32 + 32 + 64 + 2) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Handshake payload too short", std::nullopt});
    
    HandshakePayload h;
    std::memcpy(h.x25519_pub.bytes.data(), bytes.data(), 32);
    std::memcpy(h.ed25519_pub.bytes.data(), bytes.data() + 32, 32);
    std::memcpy(h.sig_over_x25519.bytes.data(), bytes.data() + 64, 64);
    
    uint16_t name_len_be;
    std::memcpy(&name_len_be, bytes.data() + 128, 2);
    uint16_t name_len = ntohs(name_len_be);
    
    if (name_len > 64) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Display name too long", std::nullopt});
    if (bytes.size() < 130 + name_len) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Handshake payload truncated name", std::nullopt});
    
    h.display_name = std::string(reinterpret_cast<const char*>(bytes.data() + 130), name_len);
    return h;
}

ev::core::Result<std::vector<std::byte>> encode_app(const AppPayload& p) {
    std::vector<std::byte> out(8);
    uint64_t counter_be = _byteswap_uint64(p.counter);
    std::memcpy(out.data(), &counter_be, 8);
    out.insert(out.end(), p.ciphertext.begin(), p.ciphertext.end());
    return out;
}

ev::core::Result<AppPayload> decode_app(std::span<const std::byte> bytes) {
    if (bytes.size() < 8) return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "App payload too short", std::nullopt});
    
    AppPayload p;
    uint64_t counter_be;
    std::memcpy(&counter_be, bytes.data(), 8);
    p.counter = _byteswap_uint64(counter_be);
    
    p.ciphertext = std::vector<std::byte>(bytes.begin() + 8, bytes.end());
    return p;
}

} // namespace ev::wire
