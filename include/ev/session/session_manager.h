#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/session/session.h>
#include <memory>
#include <mutex>
#include <vector>

namespace ev::session {

// Manages the set of live sessions.  Thread-safe via an internal mutex.
class SessionManager {
public:
    SessionManager() = default;

    // Non-copyable, non-movable.
    SessionManager(const SessionManager&)            = delete;
    SessionManager& operator=(const SessionManager&) = delete;
    SessionManager(SessionManager&&)                 = delete;
    SessionManager& operator=(SessionManager&&)      = delete;

    // Add a session; returns its assigned SessionId.
    ev::core::Result<ev::core::SessionId> add_session(Session&& s);

    // Remove session by ID.  Returns PeerNotFound if no such session.
    ev::core::Result<void> remove_session(const ev::core::SessionId& id);

    // Remove session by peer signing key.  Returns PeerNotFound if not found.
    ev::core::Result<void> remove_by_peer_key(const ev::core::PublicKey& signing_pub);

    // Iterate over live sessions (calls f with each session and its ID).
    template <typename F>
    void for_each(F&& f) {
        std::lock_guard lock(mu_);
        for (auto& [id, s] : sessions_) {
            f(id, *s);
        }
    }

    size_t count() const {
        std::lock_guard lock(mu_);
        return sessions_.size();
    }

private:
    mutable std::mutex mu_;
    std::vector<std::pair<ev::core::SessionId, std::unique_ptr<Session>>> sessions_;
    uint64_t next_id_{1};
};

} // namespace ev::session
