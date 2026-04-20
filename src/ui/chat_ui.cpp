#include "chat_ui.h"

namespace ev::ui {

ChatUi::ChatUi(
    const ev::identity::Identity&,
    ev::identity::PeerDirectory&,
    ev::session::SessionManager&,
    ev::store::MessageStore&
) {
    // M1.1 skeleton
}

ev::core::Result<void> ChatUi::run_main_loop() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

void ChatUi::request_shutdown() {
    // M1.1 skeleton
}

} // namespace ev::ui
