#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/crypto/types.h>
#include <ev/identity/identity.h>
#include <ev/transport/transport.h>
#include <ev/wire/framing.h>
#include <map>
#include <memory>
#include <string>
#include <tuple>

namespace ev::session {

enum class SessionState : uint8_t {
    Unconnected,
    HandshakeSent,
    HandshakeReceived,
    Established,
    Closed,
};

// Double Ratchet skipped-message-key cache entry.
// Key: (sender DR pub key bytes, message number in that chain).
struct SkippedKeyId {
    std::array<uint8_t, 32> dh_pub;
    uint32_t                n;
    bool operator<(const SkippedKeyId& o) const noexcept {
        if (dh_pub != o.dh_pub) return dh_pub < o.dh_pub;
        return n < o.n;
    }
};

// Maximum number of skipped message keys to cache.
constexpr int kMaxSkip = 500;

// One live, authenticated, Double-Ratchet encrypted conversation with one peer.
//
// Handshake (Phase 2):
//   Both peers exchange X25519 pub, Ed25519 pub, Ed25519 sig over X25519, a
//   DR ephemeral key, and a sig over the DR key.  The shared secret from X25519
//   becomes the Double Ratchet root key.  The DR ephemeral keys initialize the
//   first ratchet step.
//
// Double Ratchet (Signal protocol):
//   KDF_RK  = HKDF-SHA256(rk, dh_out) → (new_rk, new_ck)
//   KDF_CK  = HMAC-SHA256 with key=ck, constant messages
//   AEAD    = XChaCha20-Poly1305
//   Nonce   = first 24 bytes of HKDF(mk, info="EV_MK_NONCE")
//
// Thread safety: not internally thread-safe.  SessionManager serialises access.
class Session {
public:
    // Factory: initiates or accepts the connection and performs the handshake.
    static ev::core::Result<Session> initiate(
        const ev::identity::Identity&            self,
        const std::string&                        display_name,
        std::unique_ptr<ev::transport::Transport> transport);

    static ev::core::Result<Session> accept(
        const ev::identity::Identity&            self,
        const std::string&                        display_name,
        std::unique_ptr<ev::transport::Transport> transport);

    // Move-only (SecureBuffer members).
    Session(Session&&)            = default;
    Session& operator=(Session&&) = default;
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    ~Session(); // SecureZeroMemory on all key material

    // ── Messaging ─────────────────────────────────────────────────────────────

    // Encrypt and send a UTF-8 text message (InnerType::Text).
    ev::core::Result<void> send_text(const std::string& body);

    // Encrypt and send a typed inner payload.  Use this for non-text inner
    // types (GroupOp, GroupMessage, DeviceLink, Receipt, etc.).
    ev::core::Result<void> send_inner(ev::wire::InnerType type,
                                      std::span<const std::byte> payload);

    // Receive and decrypt one DR message.
    // Returns (InnerType, payload_bytes) — the type byte is NOT included in the payload.
    // Blocks until data arrives or an error occurs.
    ev::core::Result<std::pair<ev::wire::InnerType, std::vector<std::byte>>>
        recv_message();

    // Convenience wrapper: calls recv_message(), asserts InnerType::Text.
    ev::core::Result<std::string> recv_text();

    // ── Phase 2 ───────────────────────────────────────────────────────────────

    // Send a receipt (delivered / read acknowledgement).
    ev::core::Result<void> send_receipt(ev::wire::ReceiptType type,
                                        const ev::core::MessageId& mid);

    // ── Session info ──────────────────────────────────────────────────────────

    const std::string&         peer_display_name() const;
    std::string                peer_fingerprint() const;
    const ev::core::PublicKey& peer_signing_key() const;
    bool                       is_established() const;

private:
    Session(std::unique_ptr<ev::transport::Transport> t, bool is_initiator);

    // Handshake helpers.
    ev::core::Result<void> do_handshake_initiator(
        const ev::identity::Identity& self, const std::string& my_name);
    ev::core::Result<void> do_handshake_responder(
        const ev::identity::Identity& self, const std::string& my_name);

    // Double Ratchet initialisation after handshake.
    ev::core::Result<void> dr_init_initiator(
        const ev::crypto::SharedSecret& sk,
        const ev::core::PublicKey&      peer_dr_pub);
    ev::core::Result<void> dr_init_responder(
        const ev::crypto::SharedSecret& sk,
        const ev::core::PublicKey&      peer_dr_pub,
        ev::crypto::SecureBuffer<32>    own_dr_priv,
        const ev::core::PublicKey&      own_dr_pub);

    // Double Ratchet step functions.
    ev::core::Result<std::pair<ev::wire::AppMessageHeader, std::vector<std::byte>>>
        dr_encrypt(std::span<const std::byte> plaintext);

    ev::core::Result<std::vector<std::byte>>
        dr_decrypt(const ev::wire::AppPayload& payload);

    ev::core::Result<void> dr_ratchet(const ev::core::PublicKey& peer_dr_pub);

    ev::core::Result<std::pair<ev::crypto::SecureBuffer<32>, ev::crypto::SecureBuffer<32>>>
        kdf_rk(const ev::crypto::SecureBuffer<32>& rk,
                std::span<const std::byte>           dh_output);

    ev::core::Result<std::pair<ev::crypto::SecureBuffer<32>, ev::crypto::SecureBuffer<32>>>
        kdf_ck(const ev::crypto::SecureBuffer<32>& ck);

    ev::core::Result<std::vector<std::byte>> dr_nonce_from_mk(
        const ev::crypto::SecureBuffer<32>& mk);

    ev::core::Result<void> dr_skip_message_keys(uint32_t until);

    // Low-level frame I/O.
    ev::core::Result<void>       send_frame(const ev::wire::Frame& f);
    ev::core::Result<ev::wire::Frame> recv_frame();

    // ── State ─────────────────────────────────────────────────────────────────

    std::unique_ptr<ev::transport::Transport> transport_;
    SessionState                              state_{SessionState::Unconnected};
    bool                                      is_initiator_{false};

    // Peer identity (set during handshake).
    std::string         peer_display_name_;
    ev::core::PublicKey peer_signing_pk_;
    ev::core::PublicKey peer_dr_pub_;  // peer's current DR ratchet key

    // ── Double Ratchet state ──────────────────────────────────────────────────

    ev::crypto::SecureBuffer<32> dr_rk_;   // root key
    ev::crypto::SecureBuffer<32> dr_cks_;  // sending chain key
    ev::crypto::SecureBuffer<32> dr_ckr_;  // receiving chain key

    ev::crypto::SecureBuffer<32> dr_dhs_priv_; // our current DR priv key
    ev::core::PublicKey          dr_dhs_pub_;  // our current DR pub key

    uint32_t dr_ns_{0};   // sending message counter
    uint32_t dr_nr_{0};   // receiving message counter
    uint32_t dr_pn_{0};   // previous chain length

    bool dr_ckr_valid_{false}; // CKr is valid (false for initiator until first receive)
    bool dr_cks_valid_{false}; // CKs is valid (false for responder until first send)

    // Skipped message keys: (DR-pub, msg-num) → message key.
    std::map<SkippedKeyId, ev::crypto::SecureBuffer<32>> dr_mkskipped_;
};

} // namespace ev::session
