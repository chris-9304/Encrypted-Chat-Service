#include "chat_application.h"

namespace ev::app {

ChatApplication::ChatApplication() {
    // M1.1 skeleton
}

ChatApplication::~ChatApplication() {
    // M1.1 skeleton
}

ev::core::Result<void> ChatApplication::initialize() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> ChatApplication::run() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

void ChatApplication::shutdown() {
    // M1.1 skeleton
}

} // namespace ev::app
