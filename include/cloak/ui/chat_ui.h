#pragma once

#include <cloak/core/error.h>

namespace cloak::ui {

// FTXUI-based terminal interface.
// Phase 2: full split-pane UI (peer list, conversation, input, status bar).
// Phase 1: stubbed; application uses the ChatApplication REPL loop.
class ChatUi {
public:
    ChatUi() = default;

    cloak::core::Result<void> run_main_loop();
    void request_shutdown();
};

} // namespace cloak::ui
