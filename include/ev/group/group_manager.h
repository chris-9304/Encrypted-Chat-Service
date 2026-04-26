#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/group/group_session.h>
#include <ev/group/group_types.h>
#include <ev/identity/identity.h>

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ev::group {

// Thread-safe manager for all group sessions this device participates in.
class GroupManager {
public:
    // Create a new group; returns the GroupId.
    ev::core::Result<ev::core::GroupId> create_group(
        const std::string&              name,
        const ev::identity::Identity&   self);

    // Accept a group invitation (apply a Create/Invite GroupOp).
    ev::core::Result<void> accept_invite(
        const ev::wire::GroupOpPayload& op,
        const ev::core::PublicKey&      inviter_signing_pub);

    // Apply any GroupOp (leave / kick / invite from an existing member).
    ev::core::Result<void> apply_op(
        const ev::wire::GroupOpPayload& op);

    // Encrypt a text message to a group.
    ev::core::Result<ev::wire::GroupMessagePayload> send(
        const ev::core::GroupId& gid,
        const std::string&       text);

    // Decrypt an incoming group message.
    ev::core::Result<std::pair<ev::core::PublicKey, std::string>> recv(
        const ev::wire::GroupMessagePayload& msg);

    // List all groups this device belongs to.
    std::vector<std::pair<ev::core::GroupId, std::string>> list_groups() const;

    // Build a leave op and remove the group locally.
    ev::core::Result<ev::wire::GroupOpPayload> leave(
        const ev::core::GroupId& gid);

    // Build an invite op for a new member (called by existing members).
    ev::core::Result<ev::wire::GroupOpPayload> invite(
        const ev::core::GroupId&       gid,
        const ev::core::PublicKey&     invitee_signing_pub);

    // Restore a GroupSession loaded from persistent storage.
    ev::core::Result<void> restore(GroupSession&& gs);

    // Return a snapshot of a group's state for persistence.
    // Returns nullopt if the group is not found.
    std::optional<ev::store::GroupSessionRecord> snapshot(   // NOLINT: ev::store defined in group_types.h
        const ev::core::GroupId& gid) const;

private:
    mutable std::mutex                                         mu_;
    std::map<ev::core::GroupId, GroupSession>                  groups_;
};

} // namespace ev::group
