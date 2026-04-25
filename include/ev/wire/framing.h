#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/secure_buffer.h>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ev::wire {

// ── Frame envelope ────────────────────────────────────────────────────────────
// On-wire: [4-byte BE length][1-byte type][payload]
// length covers type + payload bytes.

enum class MessageType : uint8_t {
    Handshake    = 1,
    AppMessage   = 2,
    // Phase 2
    FileChunk    = 3,
    Receipt      = 4,
    // Phase 3
    GroupMessage = 5, // broadcast group ciphertext
    GroupOp      = 6, // group lifecycle (create/invite/leave/kick)
};

// Maximum on-wire frame body size (type + payload).  1 MiB hard limit.
// File chunks are split to stay well below this.
constexpr size_t kMaxFrameBodySize  = 1024 * 1024;      // 1 MiB
constexpr size_t kFileChunkMaxBytes = 64 * 1024;         // 64 KiB payload per chunk
constexpr uint8_t kWireVersion      = 2;                 // bumped for Phase 2

struct Frame {
    MessageType             type;
    std::vector<std::byte>  payload;
};

ev::core::Result<std::vector<std::byte>> encode(const Frame& f);
ev::core::Result<Frame>                  decode(std::span<const std::byte> bytes);

// ── Handshake payload ─────────────────────────────────────────────────────────
// Phase 2: adds a Double-Ratchet ephemeral key (dr_pub) sent during session setup.
// The existing Ed25519/X25519 fields authenticate the DR key.
//
// On-wire layout (fixed-size prefix, then 2-byte name_len, then name):
//   x25519_pub      [32]
//   ed25519_pub     [32]
//   sig_x25519      [64]  -- Ed25519 sig over x25519_pub bytes
//   dr_pub          [32]  -- Double Ratchet ephemeral public key
//   sig_dr          [64]  -- Ed25519 sig over dr_pub bytes
//   version         [1]   -- kWireVersion
//   name_len        [2 BE]
//   display_name    [name_len, UTF-8, max 64]

struct HandshakePayload {
    ev::core::PublicKey x25519_pub;
    ev::core::PublicKey ed25519_pub;
    ev::core::Signature sig_over_x25519;
    ev::core::PublicKey dr_pub;           // DR ephemeral key (Phase 2)
    ev::core::Signature sig_over_dr;      // authenticates dr_pub
    uint8_t             version{kWireVersion}; // wire protocol version
    std::string         display_name;     // UTF-8, max 64 chars
};

ev::core::Result<std::vector<std::byte>> encode_handshake(const HandshakePayload& h);
ev::core::Result<HandshakePayload>        decode_handshake(std::span<const std::byte> bytes);

// ── Application message payload ───────────────────────────────────────────────
// Phase 2: carries the Double-Ratchet message header in the clear so the
// receiver can identify the right chain key.  The inner plaintext is AEAD-
// encrypted with the per-message key.
//
// On-wire:
//   dh_pub    [32]  -- sender's current DR ratchet public key
//   pn        [4 BE]-- previous chain length (for skipped-key recovery)
//   n         [4 BE]-- message number in current sending chain
//   ct_len    [4 BE]-- ciphertext length (includes 16-byte Poly1305 tag)
//   ciphertext[ct_len]

struct AppMessageHeader {
    ev::core::PublicKey dh_pub; // sender's current DR ratchet key
    uint32_t            pn{0};  // previous chain length
    uint32_t            n{0};   // message number
};

struct AppPayload {
    AppMessageHeader       header;
    std::vector<std::byte> ciphertext; // AEAD(message_key, plaintext, aad=header_bytes)
};

ev::core::Result<std::vector<std::byte>> encode_app(const AppPayload& p);
ev::core::Result<AppPayload>              decode_app(std::span<const std::byte> bytes);

// Serialise just the header so it can be used as AAD in AEAD.
std::vector<std::byte> encode_app_header(const AppMessageHeader& h);

// ── File chunk payload ────────────────────────────────────────────────────────
// Phase 2.  Large files are split into chunks of ≤ kFileChunkMaxBytes.
//
// On-wire:
//   file_id   [16]
//   chunk_idx [4 BE]
//   total     [4 BE]  -- total chunk count (0 = unknown / streaming)
//   is_last   [1]     -- 1 if final chunk
//   data_len  [4 BE]
//   data      [data_len] -- AEAD-encrypted with the per-file key

struct FileChunkPayload {
    ev::core::FileId       file_id;
    uint32_t               chunk_idx{0};
    uint32_t               total_chunks{0}; // 0 = unknown
    bool                   is_last{false};
    std::vector<std::byte> data;            // ciphertext
};

ev::core::Result<std::vector<std::byte>> encode_file_chunk(const FileChunkPayload& c);
ev::core::Result<FileChunkPayload>        decode_file_chunk(std::span<const std::byte> bytes);

// ── File metadata  ────────────────────────────────────────────────────────────
// Sent before the first chunk; encrypted inside an AppPayload as plaintext type.
//
// On-wire (inside AEAD plaintext):
//   type_tag      [1] = 0x01 (file metadata)
//   file_id       [16]
//   file_key      [32] -- per-file AEAD key, encrypted with session key
//   total_chunks  [4 BE]
//   file_size     [8 BE]
//   name_len      [2 BE]
//   file_name     [name_len, UTF-8, max 255]
//   mime_len      [2 BE]
//   mime_type     [mime_len, ASCII, max 128]

struct FileMetadata {
    ev::core::FileId   file_id;
    ev::crypto::SecureBuffer<32> file_key; // per-file encryption key
    uint32_t           total_chunks{0};
    uint64_t           file_size{0};
    std::string        file_name;
    std::string        mime_type;
};

// ── Receipt payload ───────────────────────────────────────────────────────────
// Phase 2.  Delivery and read receipts.
//
// On-wire:
//   receipt_type  [1]  0x01=delivered, 0x02=read
//   message_id    [16]

enum class ReceiptType : uint8_t { Delivered = 0x01, Read = 0x02 };

struct ReceiptPayload {
    ReceiptType       receipt_type;
    ev::core::MessageId message_id;
};

ev::core::Result<std::vector<std::byte>> encode_receipt(const ReceiptPayload& r);
ev::core::Result<ReceiptPayload>          decode_receipt(std::span<const std::byte> bytes);

// ── Group message payload (Phase 3) ──────────────────────────────────────────
// Sent as a GroupMessage frame to all group members simultaneously.
//
// On-wire:
//   group_id        [16]
//   sender_sign_pub [32]  -- identifies the sender's Sender Key chain
//   message_number  [4 BE]
//   ct_len          [4 BE]
//   ciphertext      [ct_len]  -- AEAD with per-message key from sender chain
//   signature       [64]  -- Ed25519 sig(group_id||sender_pub||msg_num||ct)

struct GroupMessagePayload {
    ev::core::GroupId      group_id;
    ev::core::PublicKey    sender_sign_pub; // sender's Sender Key signing pub
    uint32_t               message_number{0};
    std::vector<std::byte> ciphertext;
    ev::core::Signature    signature;
};

// ── Group operation payload (Phase 3) ─────────────────────────────────────────
// Sent via pairwise DR AppMessage as inner type GroupOp.
// Carries group lifecycle events: create, invite, leave, kick.
//
// On-wire (inside AEAD plaintext, after GroupOp inner type byte):
//   op_type            [1]   GroupOpType enum
//   group_id           [16]
//   group_name_len     [2 BE]
//   group_name         [...]  (only in Create/Invite ops)
//   member_key         [32]   affected member signing pub (Invite/Kick/Leave)
//   chain_key          [32]   sender's current chain key (Invite only)
//   chain_key_counter  [4 BE] sender's current chain counter (Invite only)

enum class GroupOpType : uint8_t {
    Create = 0x01, // initiator creates group, shares with first invitee
    Invite = 0x02, // existing member invites another; includes sender chain key
    Leave  = 0x03, // member announces departure
    Kick   = 0x04, // admin removes a member (future: admin-only enforcement)
};

struct GroupOpPayload {
    GroupOpType         op;
    ev::core::GroupId   group_id;
    std::string         group_name;       // filled for Create and Invite ops
    ev::core::PublicKey member_key;       // signing pub of affected member
    std::array<uint8_t, 32> chain_key{}; // sender's chain key (Invite only)
    uint32_t            chain_counter{0}; // sender's chain counter (Invite only)
};

ev::core::Result<std::vector<std::byte>> encode_group_message(const GroupMessagePayload& g);
ev::core::Result<GroupMessagePayload>     decode_group_message(std::span<const std::byte> bytes);

ev::core::Result<std::vector<std::byte>> encode_group_op(const GroupOpPayload& g);
ev::core::Result<GroupOpPayload>          decode_group_op(std::span<const std::byte> bytes);

// ── Inner plaintext types ─────────────────────────────────────────────────────
// After AEAD decryption of AppPayload::ciphertext, the first byte is the type.

enum class InnerType : uint8_t {
    Text         = 0x00,
    FileMetadata = 0x01,
    Receipt      = 0x02,
    Typing       = 0x03, // Phase 2 typing indicator
    GroupOp      = 0x04, // Phase 3: group operation (sent via pairwise DR)
    DeviceLink   = 0x05, // Phase 3: device linking certificate
};

} // namespace ev::wire
