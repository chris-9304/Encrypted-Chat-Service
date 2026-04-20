#include "session_manager.h"

namespace ev::session {

ev::core::Result<void> SessionManager::add_session(Session&&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> SessionManager::remove_session(const ev::core::SessionId&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::session
