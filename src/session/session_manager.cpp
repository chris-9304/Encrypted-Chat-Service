#include <ev/session/session_manager.h>
#include <algorithm>

namespace ev::session {

ev::core::Result<ev::core::SessionId> SessionManager::add_session(Session&& s) {
    std::lock_guard lock(mu_);
    const ev::core::SessionId id{next_id_++};
    sessions_.emplace_back(id, std::make_unique<Session>(std::move(s)));
    return id;
}

ev::core::Result<void> SessionManager::remove_session(
    const ev::core::SessionId& id) {

    std::lock_guard lock(mu_);
    auto it = std::find_if(sessions_.begin(), sessions_.end(),
                           [&](const auto& p) { return p.first.id == id.id; });
    if (it == sessions_.end()) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::PeerNotFound,
            "No session with id " + std::to_string(id.id)));
    }
    sessions_.erase(it);
    return {};
}

ev::core::Result<void> SessionManager::remove_by_peer_key(
    const ev::core::PublicKey& signing_pub) {

    std::lock_guard lock(mu_);
    auto it = std::find_if(sessions_.begin(), sessions_.end(),
                           [&](const auto& p) {
                               return p.second->peer_signing_key().bytes ==
                                      signing_pub.bytes;
                           });
    if (it == sessions_.end()) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::PeerNotFound,
            "No session for given peer signing key"));
    }
    sessions_.erase(it);
    return {};
}

} // namespace ev::session
