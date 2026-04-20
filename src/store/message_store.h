#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/wire/message.h>
#include <ev/crypto/secure_buffer.h>

namespace ev::store {

class MessageStore {
public:
    static ev::core::Result<MessageStore> open(const ev::core::Path& path, const ev::crypto::SecureBuffer<32>& db_key);

    ev::core::Result<void> save_message(const ev::wire::Message& message);
    ev::core::Result<std::vector<ev::wire::Message>> get_messages_for_peer(const ev::core::PeerId& peer, const ev::core::Timestamp& since) const;

private:
    MessageStore() = default;
    
    // Deferred to Phase 2 (SQLite disabled for Demo REPL)
};

} // namespace ev::store
