#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/session/session.h>
#include <memory>
#include <mutex>
#include <vector>

namespace ev::session {

// Manages the set of live sessions.  Thread-safe via an internal mutex.
// Phase 2: adds per-session strands (Asio) for concurrent sessions.
class SessionManager {
public:
    SessionManager() = default;

    // Non-copyable, non-movable.
    SessionManager(const SessionManager&)            = delete;
    SessionManager& operator=(const SessionManager&) = delete;
    SessionManager(SessionManager&&)                 = delete;
    SessionManager& operator=(SessionManager&&)      = delete;

    ev::core::Result<void> add_session(Session&& s);
    ev::core::Result<void> remove_session(const ev::core::SessionId& id);

    // Iterate over live sessions (calls f with each; stops on error).
    template <typename F>
    void for_each(F&& f) {
        std::lock_guard lock(mu_);
        for (auto& s : sessions_) {
            f(*s);
        }
    }

    size_t count() const {
        std::lock_guard lock(mu_);
        return sessions_.size();
    }

private:
    mutable std::mutex                        mu_;
    std::vector<std::unique_ptr<Session>>     sessions_;
};

} // namespace ev::session
