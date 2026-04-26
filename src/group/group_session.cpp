#include <cloak/group/group_session.h>
#include <cloak/crypto/crypto.h>

#include <algorithm>
#include <cstring>

namespace cloak::group {

using namespace cloak::core;
using namespace cloak::crypto;
using namespace cloak::wire;

namespace {

constexpr std::byte kChainByte{0x02};
constexpr std::byte kMsgByte{0x01};

// HMAC-SHA256 one-byte constant KDF step via Crypto facade.
// Accepts plain array<uint8_t,32> by copying into a temporary SecureBuffer
// so the copy is securely zeroed when the call returns.
Result<SecureBuffer<32>> hmac_step(
    const std::array<uint8_t, 32>& key, std::byte constant) {

    SecureBuffer<32> key_sb;
    std::memcpy(key_sb.data(), key.data(), 32);
    return Crypto::hmac_sha256(key_sb, std::span<const std::byte>(&constant, 1));
}

// Write a uint32 in big-endian byte order (replaces htonl, which requires winsock2.h).
static void write_be32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v >> 24);
    dst[1] = static_cast<uint8_t>(v >> 16);
    dst[2] = static_cast<uint8_t>(v >>  8);
    dst[3] = static_cast<uint8_t>(v);
}

// Derive a 24-byte AEAD nonce from public data: BLAKE2b-256(gid || msg_num_BE).
// Secrecy comes from the AEAD key; the nonce only needs to be unique per key,
// which group_id + counter guarantees without involving secret key material.
std::vector<std::byte> group_aead_nonce(const GroupId& gid, uint32_t msg_num) {
    std::array<uint8_t, 16 + 4> buf{};
    std::memcpy(buf.data(), gid.bytes.data(), 16);
    write_be32(buf.data() + 16, msg_num);

    auto hash = Crypto::blake2b_256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(buf.data()), buf.size()));

    std::vector<std::byte> nonce(24);
    if (hash) {
        for (size_t i = 0; i < 24; ++i)
            nonce[i] = static_cast<std::byte>((*hash)[i]);
    }
    return nonce;
}

// Build the signed bytes: group_id || sender_pub || msg_num_BE || ciphertext.
std::vector<std::byte> signed_body(
    const GroupId& gid,
    const PublicKey& sender_pub,
    uint32_t msg_num,
    const std::vector<std::byte>& ct) {

    std::vector<std::byte> body;
    body.reserve(16 + 32 + 4 + ct.size());
    body.insert(body.end(),
        reinterpret_cast<const std::byte*>(gid.bytes.data()),
        reinterpret_cast<const std::byte*>(gid.bytes.data()) + 16);
    body.insert(body.end(),
        reinterpret_cast<const std::byte*>(sender_pub.bytes.data()),
        reinterpret_cast<const std::byte*>(sender_pub.bytes.data()) + 32);
    uint8_t n_be[4];
    write_be32(n_be, msg_num);
    body.insert(body.end(),
        reinterpret_cast<const std::byte*>(n_be),
        reinterpret_cast<const std::byte*>(n_be) + 4);
    body.insert(body.end(), ct.begin(), ct.end());
    return body;
}

} // namespace

// ── Factory: create ───────────────────────────────────────────────────────────

Result<GroupSession> GroupSession::create(
    const std::string& group_name,
    const cloak::identity::Identity& /*self*/) {

    GroupSession gs;
    gs.group_name_ = group_name;

    // Random group ID.
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(
            reinterpret_cast<std::byte*>(gs.group_id_.bytes.data()), 16)));

    // Ed25519 signing keypair for our Sender Key.
    auto kp = Crypto::ed25519_keypair();
    if (!kp) return std::unexpected(kp.error());
    gs.own_sign_sk_  = std::move(kp->private_key);
    gs.own_sign_pub_ = kp->public_key;

    // Random chain key.
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(
            reinterpret_cast<std::byte*>(gs.own_chain_key_.data()), 32)));

    gs.own_counter_ = 0;
    return gs;
}

// ── Factory: from_state ───────────────────────────────────────────────────────

Result<GroupSession> GroupSession::from_state(
    const GroupId&          group_id,
    const std::string&      group_name,
    SecureBuffer<64>        own_sign_sk,
    PublicKey               own_sign_pub,
    std::array<uint8_t, 32> own_chain_key,
    uint32_t                own_counter,
    std::vector<MemberState> members) {

    GroupSession gs;
    gs.group_id_       = group_id;
    gs.group_name_     = group_name;
    gs.own_sign_sk_    = std::move(own_sign_sk);
    gs.own_sign_pub_   = own_sign_pub;
    gs.own_chain_key_  = own_chain_key;
    gs.own_counter_    = own_counter;
    gs.members_        = std::move(members);
    return gs;
}

// ── Op builders ───────────────────────────────────────────────────────────────

Result<GroupOpPayload> GroupSession::make_create_op(
    const PublicKey& invitee_signing_pub) const {

    GroupOpPayload op;
    op.op         = GroupOpType::Create;
    op.group_id   = group_id_;
    op.group_name = group_name_;
    op.member_key = invitee_signing_pub;
    std::memcpy(op.chain_key.data(), own_chain_key_.data(), 32);
    op.chain_counter = own_counter_;
    return op;
}

Result<GroupOpPayload> GroupSession::make_invite_op(
    const PublicKey& invitee_signing_pub) const {

    GroupOpPayload op;
    op.op         = GroupOpType::Invite;
    op.group_id   = group_id_;
    op.group_name = group_name_;
    op.member_key = invitee_signing_pub;
    std::memcpy(op.chain_key.data(), own_chain_key_.data(), 32);
    op.chain_counter = own_counter_;
    return op;
}

GroupOpPayload GroupSession::make_leave_op() const {
    GroupOpPayload op;
    op.op         = GroupOpType::Leave;
    op.group_id   = group_id_;
    op.group_name = group_name_;
    op.member_key = own_sign_pub_;
    return op;
}

// ── Apply incoming op ─────────────────────────────────────────────────────────

Result<void> GroupSession::apply_op(const GroupOpPayload& op) {
    if (op.group_id.bytes != group_id_.bytes) {
        return std::unexpected(Error::from(ErrorCode::InvalidArgument,
                                           "GroupOp for wrong group"));
    }

    switch (op.op) {
    case GroupOpType::Create:
    case GroupOpType::Invite: {
        // Register sender's chain key.
        auto* existing = find_member(op.member_key);
        if (existing) {
            std::memcpy(existing->chain_key.data(), op.chain_key.data(), 32);
            existing->counter = op.chain_counter;
        } else {
            MemberState ms;
            ms.signing_pub = op.member_key;
            std::memcpy(ms.chain_key.data(), op.chain_key.data(), 32);
            ms.counter = op.chain_counter;
            members_.push_back(std::move(ms));
        }
        if (!op.group_name.empty()) group_name_ = op.group_name;
        break;
    }
    case GroupOpType::Leave:
    case GroupOpType::Kick: {
        members_.erase(
            std::remove_if(members_.begin(), members_.end(),
                [&](const MemberState& ms) {
                    return ms.signing_pub.bytes == op.member_key.bytes;
                }),
            members_.end());
        break;
    }
    }
    return {};
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

Result<GroupMessagePayload> GroupSession::encrypt(
    const std::string& text) const {

    // Derive message key and advance chain.
    auto mk_res = hmac_step(own_chain_key_, kMsgByte);
    if (!mk_res) return std::unexpected(mk_res.error());

    auto new_ck_res = hmac_step(own_chain_key_, kChainByte);
    if (!new_ck_res) return std::unexpected(new_ck_res.error());

    const uint32_t msg_num = own_counter_;

    // AAD = group_id || sender_pub || msg_num_BE
    std::array<uint8_t, 16 + 32 + 4> aad_buf{};
    std::memcpy(aad_buf.data(),      group_id_.bytes.data(),     16);
    std::memcpy(aad_buf.data() + 16, own_sign_pub_.bytes.data(), 32);
    write_be32(aad_buf.data() + 48, msg_num);

    auto nonce = group_aead_nonce(group_id_, msg_num);

    auto ct = Crypto::aead_encrypt(
        *mk_res,
        std::span<const std::byte>(nonce),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(aad_buf.data()), aad_buf.size()),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(text.data()), text.size()));
    if (!ct) return std::unexpected(ct.error());

    // Sign.
    auto sig_body = signed_body(group_id_, own_sign_pub_, msg_num, *ct);
    auto sig_res  = Crypto::sign_detached(
        own_sign_sk_,
        std::span<const std::byte>(sig_body));
    if (!sig_res) return std::unexpected(sig_res.error());

    // Advance chain state (members are mutable for const encrypt).
    std::memcpy(own_chain_key_.data(), new_ck_res->data(), 32);
    ++own_counter_;

    GroupMessagePayload out;
    out.group_id        = group_id_;
    out.sender_sign_pub = own_sign_pub_;
    out.message_number  = msg_num;
    out.ciphertext      = std::move(*ct);
    out.signature       = *sig_res;
    return out;
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

Result<std::pair<PublicKey, std::string>> GroupSession::decrypt(
    const GroupMessagePayload& msg) {

    if (msg.group_id.bytes != group_id_.bytes) {
        return std::unexpected(Error::from(ErrorCode::InvalidArgument,
                                           "GroupMessage for wrong group"));
    }

    MemberState* ms = find_member(msg.sender_sign_pub);
    if (!ms) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Unknown group member sender key"));
    }

    // Verify signature first.
    auto sig_body = signed_body(msg.group_id, msg.sender_sign_pub,
                                msg.message_number, msg.ciphertext);
    auto vr = Crypto::verify_detached(
        msg.sender_sign_pub,
        std::span<const std::byte>(sig_body),
        msg.signature);
    if (!vr || !*vr) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Group message signature invalid"));
    }

    // Advance member chain key to reach msg.message_number.
    if (msg.message_number < ms->counter) {
        return std::unexpected(Error::from(ErrorCode::CounterMismatch,
                                           "Group message replay or out of order"));
    }
    while (ms->counter < msg.message_number) {
        auto new_ck = hmac_step(ms->chain_key, kChainByte);
        if (!new_ck) return std::unexpected(new_ck.error());
        std::memcpy(ms->chain_key.data(), new_ck->data(), 32);
        ++ms->counter;
    }

    // Derive message key at msg.message_number.
    auto mk_res = hmac_step(ms->chain_key, kMsgByte);
    if (!mk_res) return std::unexpected(mk_res.error());

    // Advance chain for next receive.
    auto new_ck_res = hmac_step(ms->chain_key, kChainByte);
    if (!new_ck_res) return std::unexpected(new_ck_res.error());
    std::memcpy(ms->chain_key.data(), new_ck_res->data(), 32);
    ++ms->counter;

    // AAD = group_id || sender_pub || msg_num_BE.
    std::array<uint8_t, 16 + 32 + 4> aad_buf{};
    std::memcpy(aad_buf.data(),      msg.group_id.bytes.data(),        16);
    std::memcpy(aad_buf.data() + 16, msg.sender_sign_pub.bytes.data(), 32);
    write_be32(aad_buf.data() + 48, msg.message_number);

    auto nonce = group_aead_nonce(msg.group_id, msg.message_number);

    auto pt = Crypto::aead_decrypt(
        *mk_res,
        std::span<const std::byte>(nonce),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(aad_buf.data()), aad_buf.size()),
        std::span<const std::byte>(msg.ciphertext));
    if (!pt) return std::unexpected(pt.error());

    return std::make_pair(
        msg.sender_sign_pub,
        std::string(reinterpret_cast<const char*>(pt->data()), pt->size()));
}

// ── Persistence helpers ───────────────────────────────────────────────────────

void GroupSession::copy_own_sign_sk(std::array<uint8_t, 64>& out) const {
    std::memcpy(out.data(), own_sign_sk_.data(), 64);
}

void GroupSession::copy_own_chain_key(std::array<uint8_t, 32>& out) const {
    std::memcpy(out.data(), own_chain_key_.data(), 32);
}

// ── find_member ───────────────────────────────────────────────────────────────

MemberState* GroupSession::find_member(const PublicKey& signing_pub) {
    for (auto& ms : members_) {
        if (ms.signing_pub.bytes == signing_pub.bytes) return &ms;
    }
    return nullptr;
}

} // namespace cloak::group
