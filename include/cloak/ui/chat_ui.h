#pragma once

#include <cloak/core/error.h>

#include <atomic>

// Forward declaration — avoids pulling all of chat_application.h into UI headers.
namespace cloak::app { class ChatApplication; }

namespace cloak::ui {

// Full FTXUI terminal UI.
// Owns the main-thread event loop; ChatApplication runs its threads in the background.
// Passphrase / identity unlock happens in main() before this is constructed.
class ChatUi {
public:
    explicit ChatUi(cloak::app::ChatApplication& app);

    // Blocks until the user closes the window (Ctrl-C or the Quit button).
    cloak::core::Result<void> run_main_loop();

    // Safe to call from any thread — posts a shutdown event to the FTXUI loop.
    void request_shutdown();

private:
    cloak::app::ChatApplication& app_;
    std::atomic<bool>            shutdown_{false};
};

} // namespace cloak::ui
