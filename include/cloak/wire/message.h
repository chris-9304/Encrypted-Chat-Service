#pragma once

#include <cloak/core/types.h>
#include <cstdint>
#include <string>

namespace cloak::wire {

// Decrypted, stored application message.  The on-wire ciphertext is never kept
// in this struct — only plaintext after successful AEAD decryption.
struct Message {
    cloak::core::MessageId id;
    cloak::core::PeerId    from;        // sender signing-pub (as PeerId bytes)
    cloak::core::PeerId    to;          // recipient signing-pub (as PeerId bytes)
    cloak::core::Timestamp timestamp;
    std::string         body;        // UTF-8 plaintext
    bool                is_delivered{false};
    bool                is_read{false};
    int64_t             expires_at_ms{0}; // 0 = never, Phase 2 disappearing messages
};

} // namespace cloak::wire
