#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/wire/message.h>
#include <ev/transport/transport.h>
#include <memory>

namespace ev::session {

class Session {
public:
    static ev::core::Result<Session> create_initiator(std::unique_ptr<ev::transport::Transport> transport);
    static ev::core::Result<Session> create_responder(std::unique_ptr<ev::transport::Transport> transport);

    ev::core::Result<void> send_message(const ev::wire::Message& message);
    ev::core::Result<ev::wire::Message> receive_message();

private:
    Session() = default;
    
    // TODO(M1.x): Active noise tracking states and current chain keys
};

} // namespace ev::session
