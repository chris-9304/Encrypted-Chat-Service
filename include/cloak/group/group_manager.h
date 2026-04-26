#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/group/group_session.h>
#include <cloak/group/group_types.h>
#include <cloak/identity/identity.h>

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace cloak::group {

// Thread-safe manager for all group sessions this device participates in.
class GroupManager {
public:
    // Create a new group; returns the GroupId.
    cloak::core::Result<cloak::core::GroupId> create_group(
        const std::string&              name,
        const cloak::identity::Identity&   self);

    // Accept a group invitation (apply a Create/Invite GroupOp).
    cloak::core::Result<void> accept_invite(
        const cloak::wire::GroupOpPayload& op,
        const cloak::core::PublicKey&      inviter_signing_pub);

    // Apply any GroupOp (leave / kick / invite from an existing member).
    cloak::core::Result<void> apply_op(
        const cloak::wire::GroupOpPayload& op);

    // Encrypt a text message to a group.
    cloak::core::Result<cloak::wire::GroupMessagePayload> send(
        const cloak::core::GroupId& gid,
        const std::string&       text);

    // Decrypt an incoming group message.
    cloak::core::Result<std::pair<cloak::core::PublicKey, std::string>> recv(
        const cloak::wire::GroupMessagePayload& msg);

    // List all groups this device belongs to.
    std::vector<std::pair<cloak::core::GroupId, std::string>> list_groups() const;

    // Build a leave op and remove the group locally.
    cloak::core::Result<cloak::wire::GroupOpPayload> leave(
        const cloak::core::GroupId& gid);

    // Build an invite op for a new member (called by existing members).
    cloak::core::Result<cloak::wire::GroupOpPayload> invite(
        const cloak::core::GroupId&       gid,
        const cloak::core::PublicKey&     invitee_signing_pub);

    // Restore a GroupSession loaded from persistent storage.
    cloak::core::Result<void> restore(GroupSession&& gs);

    // Return a snapshot of a group's state for persistence.
    // Returns nullopt if the group is not found.
    std::optional<cloak::store::GroupSessionRecord> snapshot(   // NOLINT: cloak::store defined in group_types.h
        const cloak::core::GroupId& gid) const;

private:
    mutable std::mutex                                         mu_;
    std::map<cloak::core::GroupId, GroupSession>                  groups_;
};

} // namespace cloak::group
