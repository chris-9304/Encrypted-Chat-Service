#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/identity/identity.h>
#include <ev/transport/transport.h>
#include <memory>
#include <string>

namespace ev::session {

enum class SessionState {
    Unconnected,
    HandshakeSent,
    HandshakeReceived,
    Established,
    Closed
};

class Session {
public:
    static ev::core::Result<Session> initiate(
        const ev::identity::Identity& self, const std::string& display_name,
        std::unique_ptr<ev::transport::Transport> transport);
        
    static ev::core::Result<Session> accept(
        const ev::identity::Identity& self, const std::string& display_name,
        std::unique_ptr<ev::transport::Transport> transport);

    Session(Session&&) = default;
    Session& operator=(Session&&) = default;
    ~Session(); // Securely destroys session_key

    ev::core::Result<void> send_text(const std::string& body);
    ev::core::Result<std::string> recv_text();

    const std::string& peer_display_name() const;
    std::string peer_fingerprint() const;
    bool is_established() const;

private:
    Session(std::unique_ptr<ev::transport::Transport> t, uint32_t dir_send, uint32_t dir_recv);

    ev::core::Result<void> do_handshake_initiator(const ev::identity::Identity& self, const std::string& my_name);
    ev::core::Result<void> do_handshake_responder(const ev::identity::Identity& self, const std::string& my_name);

    ev::core::Result<void> derive_keys(const ev::core::PublicKey& self_kx_pub, const ev::core::PublicKey& peer_kx_pub, const ev::crypto::SharedSecret& shared_secret);
    
    std::unique_ptr<ev::transport::Transport> transport_;
    SessionState state_{SessionState::Unconnected};
    ev::crypto::SecureBuffer<32> session_key_;
    
    uint64_t send_counter_{0};
    uint64_t recv_counter_{0};
    uint32_t direction_send_;
    uint32_t direction_recv_;

    std::string peer_display_name_;
    ev::core::PublicKey peer_signing_pk_;
    
    ev::core::Nonce build_nonce(uint32_t direction, uint64_t counter) const;
};

} // namespace ev::session
