#pragma once

#include <ev/core/types.h>
#include <string>
#include <variant>

namespace ev::wire {

struct TextMessage {
    std::string text;
};

// Phase 2: struct FileMessage { ... };

using MessageVariant = std::variant<TextMessage>;

struct Message {
    ev::core::MessageId id;
    ev::core::PeerId sender_id;
    ev::core::Timestamp timestamp;
    MessageVariant payload;
};

} // namespace ev::wire
