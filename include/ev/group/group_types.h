#pragma once

#include <ev/core/types.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ev::store {

// Persisted state for one remote member's sender key within a group.
struct GroupMemberRecord {
    ev::core::GroupId       group_id;
    std::array<uint8_t, 32> signing_pub{};
    std::array<uint8_t, 32> chain_key{};  // stored AEAD-encrypted by MessageStore
    uint32_t                counter{0};
};

// Full persisted state for one group session on this device.
struct GroupSessionRecord {
    ev::core::GroupId       group_id;
    std::string             group_name;
    std::array<uint8_t, 64> own_sign_sk{};    // AEAD-encrypted by MessageStore
    std::array<uint8_t, 32> own_sign_pub{};
    std::array<uint8_t, 32> own_chain_key{};  // AEAD-encrypted by MessageStore
    uint32_t                own_counter{0};
    std::vector<GroupMemberRecord> members;
};

} // namespace ev::store
