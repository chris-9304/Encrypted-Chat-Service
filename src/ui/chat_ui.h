#pragma once

#include <ev/core/error.h>
#include <ev/identity/identity.h>
#include <ev/identity/peer_directory.h>
#include <ev/session/session_manager.h>
#include <ev/store/message_store.h>

namespace ev::ui {

class ChatUi {
public:
    ChatUi(
        const ev::identity::Identity& identity,
        ev::identity::PeerDirectory& directory,
        ev::session::SessionManager& session_manager,
        ev::store::MessageStore& store
    );

    ev::core::Result<void> run_main_loop();
    void request_shutdown();

private:
    // Deferred to Phase 2 (FTXUI disabled for Demo REPL)
};

} // namespace ev::ui
