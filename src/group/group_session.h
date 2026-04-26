#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/crypto.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/crypto/types.h>
#include <ev/identity/identity.h>
#include <ev/wire/framing.h>

#include <array>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ev::group {

// ── Sender Keys model ─────────────────────────────────────────────────────────
//
// Each group member owns a "SenderKey": a (chain_key, Ed25519 signing keypair)
// pair.  On every message send:
//   mk      = HMAC-SHA256(chain_key, counter || 0x01)
//   new_ck  = HMAC-SHA256(chain_key, counter || 0x02)
//   ct      = XChaCha20-Poly1305(mk, plaintext, aad = group_id || msg_num)
//   sig     = Ed25519_sign(signing_sk, group_id || sender_pub || msg_num || ct)
//
// Members distribute their (chain_key, signing_pub, counter) to other members
// via pairwise DR sessions (encoded as GroupOp::Invite inner payloads).
// Each recipient advances the stored chain key for each message received.

// State for one remote member's sender key.
struct MemberState {
    ev::core::PublicKey      signing_pub;
    std::array<uint8_t, 32> chain_key{};  // current chain key
    uint32_t                 counter{0};   // next expected message number
};

// One group session for this device.
//
// Thread safety: not internally synchronised; callers must serialise.
class GroupSession {
public:
    // Create a brand-new group (generates group_id and signing keypair).
    static ev::core::Result<GroupSession> create(
        const std::string&              group_name,
        const ev::identity::Identity&   self);

    // Reconstruct from persisted state (e.g., loaded from SQLite).
    static ev::core::Result<GroupSession> from_state(
        const ev::core::GroupId&        group_id,
        const std::string&              group_name,
        ev::crypto::SecureBuffer<64>    own_sign_sk,
        ev::core::PublicKey             own_sign_pub,
        std::array<uint8_t, 32>         own_chain_key,
        uint32_t                        own_counter,
        std::vector<MemberState>        members);

    // Build a GroupOp::Create payload to send to the first invitee.
    ev::core::Result<ev::wire::GroupOpPayload> make_create_op(
        const ev::core::PublicKey& invitee_signing_pub) const;

    // Build a GroupOp::Invite payload to send to a new member via pairwise DR.
    ev::core::Result<ev::wire::GroupOpPayload> make_invite_op(
        const ev::core::PublicKey& invitee_signing_pub) const;

    // Build a GroupOp::Leave payload to broadcast.
    ev::wire::GroupOpPayload make_leave_op() const;

    // Process an incoming GroupOp (received via pairwise DR session).
    ev::core::Result<void> apply_op(const ev::wire::GroupOpPayload& op);

    // Encrypt a text message for the group.
    ev::core::Result<ev::wire::GroupMessagePayload> encrypt(
        const std::string& text) const;

    // Decrypt a group message.  Returns sender display key (signing pub) and text.
    ev::core::Result<std::pair<ev::core::PublicKey, std::string>> decrypt(
        const ev::wire::GroupMessagePayload& msg);

    // ── Accessors ─────────────────────────────────────────────────────────────

    const ev::core::GroupId&         group_id()    const { return group_id_; }
    const std::string&               group_name()  const { return group_name_; }
    const ev::core::PublicKey&       own_sign_pub() const { return own_sign_pub_; }
    const std::vector<MemberState>&  members()     const { return members_; }
    uint32_t                         own_counter() const { return own_counter_; }

    // Copy sensitive key material out for persistence (caller must immediately
    // encrypt the output; these bytes must not linger in memory unprotected).
    void copy_own_sign_sk(std::array<uint8_t, 64>& out) const;
    void copy_own_chain_key(std::array<uint8_t, 32>& out) const;

    // Move-only (SecureBuffer members).
    GroupSession(GroupSession&&)            = default;
    GroupSession& operator=(GroupSession&&) = default;
    GroupSession(const GroupSession&)            = delete;
    GroupSession& operator=(const GroupSession&) = delete;

private:
    explicit GroupSession() = default;

    ev::core::GroupId            group_id_;
    std::string                  group_name_;

    // Our own sending state.
    mutable ev::crypto::SecureBuffer<64> own_sign_sk_;
    ev::core::PublicKey                  own_sign_pub_;
    mutable std::array<uint8_t, 32>      own_chain_key_{};
    mutable uint32_t                     own_counter_{0};

    // Known member states (keyed by signing_pub.bytes).
    std::vector<MemberState> members_;

    MemberState* find_member(const ev::core::PublicKey& signing_pub);
};

} // namespace ev::group
