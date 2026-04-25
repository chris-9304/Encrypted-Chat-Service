#pragma once

#include <ev/core/types.h>
#include <cstdint>
#include <string>

namespace ev::wire {

// Decrypted, stored application message.  The on-wire ciphertext is never kept
// in this struct — only plaintext after successful AEAD decryption.
struct Message {
    ev::core::MessageId id;
    ev::core::PeerId    from;
    ev::core::Timestamp timestamp;
    std::string         body;        // UTF-8 plaintext
    bool                is_delivered{false};
    bool                is_read{false};
    int64_t             expires_at_ms{0}; // 0 = never, Phase 2 disappearing messages
};

} // namespace ev::wire
