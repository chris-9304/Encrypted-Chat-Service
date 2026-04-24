#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <ev/core/types.h>

namespace ev::wire {

// Decrypted application message, as stored in MessageStore.
struct Message {
    ev::core::MessageId id;
    ev::core::PeerId    from;
    ev::core::Timestamp timestamp;
    std::string         body;       // UTF-8 plaintext
};

} // namespace ev::wire
