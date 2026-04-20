#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include "session.h"
#include <vector>

namespace ev::session {

class SessionManager {
public:
    SessionManager() = default;

    ev::core::Result<void> add_session(Session&& session);
    ev::core::Result<void> remove_session(const ev::core::SessionId& id);

private:
    // TODO(M1.x): Session persistence queue spanning across Asio strands
};

} // namespace ev::session
