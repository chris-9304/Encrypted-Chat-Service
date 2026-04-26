#include <ev/wire/framing.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <cstring>

namespace ev::wire {

// ── Frame envelope ────────────────────────────────────────────────────────────

ev::core::Result<std::vector<std::byte>> encode(const Frame& f) {
    const size_t payload_len = f.payload.size();
    if (payload_len + 1 > kMaxFrameBodySize) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Frame payload exceeds 1 MiB limit"));
    }

    // On-wire: [4-byte BE (payload_len + 1)][1-byte type][payload]
    const uint32_t len     = static_cast<uint32_t>(payload_len + 1);
    const uint32_t len_be  = htonl(len);

    std::vector<std::byte> out;
    out.reserve(4 + len);

    const auto* lb = reinterpret_cast<const std::byte*>(&len_be);
    out.insert(out.end(), lb, lb + 4);
    out.push_back(static_cast<std::byte>(f.type));
    out.insert(out.end(), f.payload.begin(), f.payload.end());

    return out;
}

ev::core::Result<Frame> decode(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError, "Frame underflow (< 5 bytes)"));
    }

    uint32_t len_be{};
    std::memcpy(&len_be, bytes.data(), 4);
    const uint32_t len = ntohl(len_be);

    if (len == 0) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError, "Frame length is zero"));
    }
    if (len > kMaxFrameBodySize) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError, "Frame too large"));
    }
    if (bytes.size() < static_cast<size_t>(4 + len)) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError, "Incomplete frame"));
    }

    const auto type_byte = static_cast<uint8_t>(bytes[4]);
    auto       msg_type  = static_cast<MessageType>(type_byte);

    switch (msg_type) {
    case MessageType::Handshake:
    case MessageType::AppMessage:
    case MessageType::FileChunk:
    case MessageType::Receipt:
    case MessageType::GroupMessage:
    case MessageType::GroupOp:
        break;
    default:
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Unknown frame type: " + std::to_string(type_byte)));
    }

    Frame f;
    f.type    = msg_type;
    f.payload = std::vector<std::byte>(bytes.begin() + 5,
                                        bytes.begin() + 4 + len);
    return f;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace {

void push_u16_be(std::vector<std::byte>& v, uint16_t x) {
    const uint16_t be = htons(x);
    const auto* p = reinterpret_cast<const std::byte*>(&be);
    v.insert(v.end(), p, p + 2);
}

void push_u32_be(std::vector<std::byte>& v, uint32_t x) {
    const uint32_t be = htonl(x);
    const auto* p = reinterpret_cast<const std::byte*>(&be);
    v.insert(v.end(), p, p + 4);
}

void push_u64_be(std::vector<std::byte>& v, uint64_t x) {
    const uint64_t be = _byteswap_uint64(x);
    const auto* p = reinterpret_cast<const std::byte*>(&be);
    v.insert(v.end(), p, p + 8);
}

uint16_t read_u16_be(std::span<const std::byte> bytes, size_t off) {
    uint16_t be{};
    std::memcpy(&be, bytes.data() + off, 2);
    return ntohs(be);
}

uint32_t read_u32_be(std::span<const std::byte> bytes, size_t off) {
    uint32_t be{};
    std::memcpy(&be, bytes.data() + off, 4);
    return ntohl(be);
}

uint64_t read_u64_be(std::span<const std::byte> bytes, size_t off) {
    uint64_t be{};
    std::memcpy(&be, bytes.data() + off, 8);
    return _byteswap_uint64(be);
}

void push_bytes(std::vector<std::byte>& v,
                const uint8_t* src, size_t n) {
    v.insert(v.end(),
             reinterpret_cast<const std::byte*>(src),
             reinterpret_cast<const std::byte*>(src) + n);
}

void push_bytes(std::vector<std::byte>& v,
                const std::string& s) {
    v.insert(v.end(),
             reinterpret_cast<const std::byte*>(s.data()),
             reinterpret_cast<const std::byte*>(s.data()) + s.size());
}

} // anonymous namespace

// ── Handshake payload ─────────────────────────────────────────────────────────
//
// Layout:
//   x25519_pub  [32]
//   ed25519_pub [32]
//   sig_x25519  [64]
//   dr_pub      [32]   -- Phase 2
//   sig_dr      [64]   -- Phase 2
//   version     [1]
//   name_len    [2 BE]
//   name        [name_len]

ev::core::Result<std::vector<std::byte>> encode_handshake(
    const HandshakePayload& h) {

    if (h.display_name.size() > 64) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::InvalidArgument,
            "Display name exceeds 64 characters"));
    }

    std::vector<std::byte> out;
    out.reserve(32 + 32 + 64 + 32 + 64 + 1 + 2 + h.display_name.size());

    push_bytes(out, h.x25519_pub.bytes.data(), 32);
    push_bytes(out, h.ed25519_pub.bytes.data(), 32);
    push_bytes(out, h.sig_over_x25519.bytes.data(), 64);
    push_bytes(out, h.dr_pub.bytes.data(), 32);
    push_bytes(out, h.sig_over_dr.bytes.data(), 64);
    out.push_back(static_cast<std::byte>(h.version));
    push_u16_be(out, static_cast<uint16_t>(h.display_name.size()));
    push_bytes(out, h.display_name);

    return out;
}

ev::core::Result<HandshakePayload> decode_handshake(
    std::span<const std::byte> bytes) {

    // Fixed prefix: 32+32+64+32+64+1+2 = 227 bytes minimum
    constexpr size_t kMinSize = 32 + 32 + 64 + 32 + 64 + 1 + 2;
    if (bytes.size() < kMinSize) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Handshake payload too short"));
    }

    HandshakePayload h;
    size_t off = 0;

    std::memcpy(h.x25519_pub.bytes.data(),     bytes.data() + off, 32); off += 32;
    std::memcpy(h.ed25519_pub.bytes.data(),    bytes.data() + off, 32); off += 32;
    std::memcpy(h.sig_over_x25519.bytes.data(),bytes.data() + off, 64); off += 64;
    std::memcpy(h.dr_pub.bytes.data(),         bytes.data() + off, 32); off += 32;
    std::memcpy(h.sig_over_dr.bytes.data(),    bytes.data() + off, 64); off += 64;

    // Version byte: store and reject peer versions newer than what we support.
    h.version = static_cast<uint8_t>(bytes[off]); off += 1;
    if (h.version > kWireVersion) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Peer wire version " + std::to_string(h.version) +
            " > our version " + std::to_string(kWireVersion) +
            "; upgrade required"));
    }

    const uint16_t name_len = read_u16_be(bytes, off); off += 2;
    if (name_len > 64) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Display name too long in handshake"));
    }
    if (bytes.size() < off + name_len) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Handshake name truncated"));
    }

    h.display_name.assign(
        reinterpret_cast<const char*>(bytes.data() + off), name_len);

    return h;
}

// ── App message payload ───────────────────────────────────────────────────────
//
// On-wire:
//   dh_pub   [32]
//   pn       [4 BE]
//   n        [4 BE]
//   ct_len   [4 BE]
//   ct       [ct_len]

std::vector<std::byte> encode_app_header(const AppMessageHeader& h) {
    std::vector<std::byte> out;
    out.reserve(32 + 4 + 4);
    push_bytes(out, h.dh_pub.bytes.data(), 32);
    push_u32_be(out, h.pn);
    push_u32_be(out, h.n);
    return out;
}

ev::core::Result<std::vector<std::byte>> encode_app(const AppPayload& p) {
    constexpr size_t kMaxCt = kMaxFrameBodySize - 32 - 4 - 4 - 4;
    if (p.ciphertext.size() > kMaxCt) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "App payload ciphertext too large"));
    }

    std::vector<std::byte> out;
    out.reserve(32 + 4 + 4 + 4 + p.ciphertext.size());

    push_bytes(out, p.header.dh_pub.bytes.data(), 32);
    push_u32_be(out, p.header.pn);
    push_u32_be(out, p.header.n);
    push_u32_be(out, static_cast<uint32_t>(p.ciphertext.size()));
    out.insert(out.end(), p.ciphertext.begin(), p.ciphertext.end());

    return out;
}

ev::core::Result<AppPayload> decode_app(std::span<const std::byte> bytes) {
    constexpr size_t kMinSize = 32 + 4 + 4 + 4; // 44 bytes
    if (bytes.size() < kMinSize) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "App payload too short"));
    }

    AppPayload p;
    size_t off = 0;

    std::memcpy(p.header.dh_pub.bytes.data(), bytes.data() + off, 32); off += 32;
    p.header.pn = read_u32_be(bytes, off); off += 4;
    p.header.n  = read_u32_be(bytes, off); off += 4;

    const uint32_t ct_len = read_u32_be(bytes, off); off += 4;
    if (bytes.size() < off + ct_len) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "App payload ciphertext truncated"));
    }

    p.ciphertext.assign(bytes.begin() + static_cast<ptrdiff_t>(off),
                        bytes.begin() + static_cast<ptrdiff_t>(off + ct_len));
    return p;
}

// ── File chunk payload ────────────────────────────────────────────────────────
//
// file_id   [16]
// chunk_idx [4 BE]
// total     [4 BE]
// is_last   [1]
// data_len  [4 BE]
// data      [data_len]

ev::core::Result<std::vector<std::byte>> encode_file_chunk(
    const FileChunkPayload& c) {

    if (c.data.size() > kFileChunkMaxBytes) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::InvalidArgument,
            "File chunk data exceeds 64 KiB limit"));
    }

    std::vector<std::byte> out;
    out.reserve(16 + 4 + 4 + 1 + 4 + c.data.size());

    push_bytes(out, c.file_id.bytes.data(), 16);
    push_u32_be(out, c.chunk_idx);
    push_u32_be(out, c.total_chunks);
    out.push_back(static_cast<std::byte>(c.is_last ? 1 : 0));
    push_u32_be(out, static_cast<uint32_t>(c.data.size()));
    out.insert(out.end(), c.data.begin(), c.data.end());

    return out;
}

ev::core::Result<FileChunkPayload> decode_file_chunk(
    std::span<const std::byte> bytes) {

    constexpr size_t kMin = 16 + 4 + 4 + 1 + 4; // 29 bytes
    if (bytes.size() < kMin) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "FileChunk payload too short"));
    }

    FileChunkPayload c;
    size_t off = 0;

    std::memcpy(c.file_id.bytes.data(), bytes.data() + off, 16); off += 16;
    c.chunk_idx    = read_u32_be(bytes, off); off += 4;
    c.total_chunks = read_u32_be(bytes, off); off += 4;
    c.is_last      = (static_cast<uint8_t>(bytes[off]) != 0); off += 1;

    const uint32_t data_len = read_u32_be(bytes, off); off += 4;
    if (bytes.size() < off + data_len) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "FileChunk data truncated"));
    }

    c.data.assign(bytes.begin() + static_cast<ptrdiff_t>(off),
                  bytes.begin() + static_cast<ptrdiff_t>(off + data_len));
    return c;
}

// ── Receipt payload ───────────────────────────────────────────────────────────
//
// receipt_type [1]
// message_id   [16]

ev::core::Result<std::vector<std::byte>> encode_receipt(
    const ReceiptPayload& r) {

    std::vector<std::byte> out;
    out.reserve(1 + 16);
    out.push_back(static_cast<std::byte>(r.receipt_type));
    push_bytes(out, r.message_id.bytes.data(), 16);
    return out;
}

ev::core::Result<ReceiptPayload> decode_receipt(
    std::span<const std::byte> bytes) {

    if (bytes.size() < 17) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Receipt payload too short"));
    }

    ReceiptPayload r;
    r.receipt_type = static_cast<ReceiptType>(bytes[0]);
    std::memcpy(r.message_id.bytes.data(), bytes.data() + 1, 16);
    return r;
}

// ── Group message payload (Phase 3) ──────────────────────────────────────────
//
// group_id        [16]
// sender_sign_pub [32]
// message_number  [4 BE]
// ct_len          [4 BE]
// ciphertext      [ct_len]
// signature       [64]

ev::core::Result<std::vector<std::byte>> encode_group_message(
    const GroupMessagePayload& g) {

    constexpr size_t kMaxCt = kMaxFrameBodySize - 16 - 32 - 4 - 4 - 64;
    if (g.ciphertext.size() > kMaxCt) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Group message ciphertext too large"));
    }

    std::vector<std::byte> out;
    out.reserve(16 + 32 + 4 + 4 + g.ciphertext.size() + 64);

    push_bytes(out, g.group_id.bytes.data(), 16);
    push_bytes(out, g.sender_sign_pub.bytes.data(), 32);
    push_u32_be(out, g.message_number);
    push_u32_be(out, static_cast<uint32_t>(g.ciphertext.size()));
    out.insert(out.end(), g.ciphertext.begin(), g.ciphertext.end());
    push_bytes(out, g.signature.bytes.data(), 64);

    return out;
}

ev::core::Result<GroupMessagePayload> decode_group_message(
    std::span<const std::byte> bytes) {

    constexpr size_t kMin = 16 + 32 + 4 + 4 + 64; // no ciphertext
    if (bytes.size() < kMin) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "GroupMessage payload too short"));
    }

    GroupMessagePayload g;
    size_t off = 0;

    std::memcpy(g.group_id.bytes.data(),        bytes.data() + off, 16); off += 16;
    std::memcpy(g.sender_sign_pub.bytes.data(), bytes.data() + off, 32); off += 32;
    g.message_number = read_u32_be(bytes, off); off += 4;

    const uint32_t ct_len = read_u32_be(bytes, off); off += 4;
    if (bytes.size() < off + ct_len + 64) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "GroupMessage ciphertext or signature truncated"));
    }

    g.ciphertext.assign(bytes.begin() + static_cast<ptrdiff_t>(off),
                        bytes.begin() + static_cast<ptrdiff_t>(off + ct_len));
    off += ct_len;

    std::memcpy(g.signature.bytes.data(), bytes.data() + off, 64);

    return g;
}

// ── Group operation payload (Phase 3) ────────────────────────────────────────
//
// op_type           [1]
// group_id          [16]
// group_name_len    [2 BE]
// group_name        [name_len]
// member_key        [32]   affected member signing pub
// chain_key         [32]   sender chain key (Invite only, zero otherwise)
// chain_counter     [4 BE]

ev::core::Result<std::vector<std::byte>> encode_group_op(
    const GroupOpPayload& g) {

    if (g.group_name.size() > 64) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::InvalidArgument,
            "Group name exceeds 64 characters"));
    }

    std::vector<std::byte> out;
    out.reserve(1 + 16 + 2 + g.group_name.size() + 32 + 32 + 4);

    out.push_back(static_cast<std::byte>(g.op));
    push_bytes(out, g.group_id.bytes.data(), 16);
    push_u16_be(out, static_cast<uint16_t>(g.group_name.size()));
    push_bytes(out, g.group_name);
    push_bytes(out, g.member_key.bytes.data(), 32);
    push_bytes(out, g.chain_key.data(), 32);
    push_u32_be(out, g.chain_counter);

    return out;
}

ev::core::Result<GroupOpPayload> decode_group_op(
    std::span<const std::byte> bytes) {

    constexpr size_t kMin = 1 + 16 + 2 + 32 + 32 + 4; // no name
    if (bytes.size() < kMin) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "GroupOp payload too short"));
    }

    GroupOpPayload g;
    size_t off = 0;

    g.op = static_cast<GroupOpType>(bytes[off]); off += 1;
    std::memcpy(g.group_id.bytes.data(), bytes.data() + off, 16); off += 16;

    const uint16_t name_len = read_u16_be(bytes, off); off += 2;
    if (name_len > 64) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "Group name too long"));
    }
    if (bytes.size() < off + name_len + 32 + 32 + 4) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::FramingError,
            "GroupOp payload truncated"));
    }

    g.group_name.assign(
        reinterpret_cast<const char*>(bytes.data() + off), name_len);
    off += name_len;

    std::memcpy(g.member_key.bytes.data(), bytes.data() + off, 32); off += 32;
    std::memcpy(g.chain_key.data(),        bytes.data() + off, 32); off += 32;
    g.chain_counter = read_u32_be(bytes, off);

    return g;
}

} // namespace ev::wire
