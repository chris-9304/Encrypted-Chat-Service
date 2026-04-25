#include <ev/group/group_manager.h>
#include <cstring>
#include <span>

namespace ev::group {

using namespace ev::core;

Result<GroupId> GroupManager::create_group(
    const std::string& name, const ev::identity::Identity& self) {

    auto gs = GroupSession::create(name, self);
    if (!gs) return std::unexpected(gs.error());

    const GroupId gid = gs->group_id();
    std::lock_guard lock(mu_);
    groups_.emplace(gid, std::move(*gs));
    return gid;
}

Result<void> GroupManager::accept_invite(
    const ev::wire::GroupOpPayload& op,
    const PublicKey&                inviter_signing_pub) {

    std::lock_guard lock(mu_);

    auto it = groups_.find(op.group_id);
    if (it == groups_.end()) {
        // New group invitation — generate our own sender key and build state.
        auto kp = ev::crypto::Crypto::ed25519_keypair();
        if (!kp) return std::unexpected(kp.error());

        std::array<uint8_t, 32> ck{};
        auto ck_res = ev::crypto::Crypto::random_bytes(
            std::span<std::byte>(
                reinterpret_cast<std::byte*>(ck.data()), 32));
        if (!ck_res) return std::unexpected(ck_res.error());

        // Inviter's member state.
        MemberState inviter_ms;
        inviter_ms.signing_pub = inviter_signing_pub;
        std::memcpy(inviter_ms.chain_key.data(), op.chain_key.data(), 32);
        inviter_ms.counter = op.chain_counter;

        auto gs_res = GroupSession::from_state(
            op.group_id, op.group_name,
            std::move(kp->private_key), kp->public_key,
            ck, 0,
            {inviter_ms});
        if (!gs_res) return std::unexpected(gs_res.error());

        groups_.emplace(op.group_id, std::move(*gs_res));
        return {};
    }

    // Existing group — just update inviter's sender key.
    return it->second.apply_op(op);
}

Result<void> GroupManager::apply_op(const ev::wire::GroupOpPayload& op) {
    std::lock_guard lock(mu_);
    auto it = groups_.find(op.group_id);
    if (it == groups_.end()) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Group not found: cannot apply op"));
    }
    return it->second.apply_op(op);
}

Result<ev::wire::GroupMessagePayload> GroupManager::send(
    const GroupId& gid, const std::string& text) {

    std::lock_guard lock(mu_);
    auto it = groups_.find(gid);
    if (it == groups_.end()) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Group not found"));
    }
    return it->second.encrypt(text);
}

Result<std::pair<PublicKey, std::string>> GroupManager::recv(
    const ev::wire::GroupMessagePayload& msg) {

    std::lock_guard lock(mu_);
    auto it = groups_.find(msg.group_id);
    if (it == groups_.end()) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Group not found for incoming message"));
    }
    return it->second.decrypt(msg);
}

std::vector<std::pair<GroupId, std::string>> GroupManager::list_groups() const {
    std::lock_guard lock(mu_);
    std::vector<std::pair<GroupId, std::string>> result;
    result.reserve(groups_.size());
    for (const auto& [gid, gs] : groups_) {
        result.emplace_back(gid, gs.group_name());
    }
    return result;
}

Result<ev::wire::GroupOpPayload> GroupManager::leave(const GroupId& gid) {
    std::lock_guard lock(mu_);
    auto it = groups_.find(gid);
    if (it == groups_.end()) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Group not found"));
    }
    auto op = it->second.make_leave_op();
    groups_.erase(it);
    return op;
}

Result<ev::wire::GroupOpPayload> GroupManager::invite(
    const GroupId& gid, const PublicKey& invitee_signing_pub) {

    std::lock_guard lock(mu_);
    auto it = groups_.find(gid);
    if (it == groups_.end()) {
        return std::unexpected(Error::from(ErrorCode::PeerNotFound,
                                           "Group not found"));
    }
    return it->second.make_invite_op(invitee_signing_pub);
}

} // namespace ev::group
