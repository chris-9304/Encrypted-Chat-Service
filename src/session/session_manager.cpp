#include <ev/session/session_manager.h>

namespace ev::session {

ev::core::Result<void> SessionManager::add_session(Session&& s) {
    std::lock_guard lock(mu_);
    sessions_.push_back(std::make_unique<Session>(std::move(s)));
    return {};
}

ev::core::Result<void> SessionManager::remove_session(
    const ev::core::SessionId& /*id*/) {
    // Phase 2: implement indexed removal by session ID.
    return {};
}

} // namespace ev::session
