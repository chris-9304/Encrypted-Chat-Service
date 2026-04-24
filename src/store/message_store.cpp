#include "message_store.h"
#include <vector>

namespace ev::store {

ev::core::Result<MessageStore> MessageStore::open(const ev::core::Path&, const ev::crypto::SecureBuffer<32>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> MessageStore::save_message(const ev::wire::Message&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<std::vector<ev::wire::Message>> MessageStore::get_messages_for_peer(const ev::core::PeerId&, const ev::core::Timestamp&) const {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::store
