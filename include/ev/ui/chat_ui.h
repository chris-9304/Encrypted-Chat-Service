#pragma once

#include <ev/core/error.h>

namespace ev::ui {

// FTXUI-based terminal interface.
// Phase 2: full split-pane UI (peer list, conversation, input, status bar).
// Phase 1: stubbed; application uses the ChatApplication REPL loop.
class ChatUi {
public:
    ChatUi() = default;

    ev::core::Result<void> run_main_loop();
    void request_shutdown();
};

} // namespace ev::ui
