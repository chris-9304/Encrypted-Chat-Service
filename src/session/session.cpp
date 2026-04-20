#include "session.h"

namespace ev::session {

ev::core::Result<Session> Session::create_initiator(std::unique_ptr<ev::transport::Transport>) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<Session> Session::create_responder(std::unique_ptr<ev::transport::Transport>) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> Session::send_message(const ev::wire::Message&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<ev::wire::Message> Session::receive_message() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::session
