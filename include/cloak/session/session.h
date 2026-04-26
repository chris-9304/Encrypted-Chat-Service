#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/crypto/secure_buffer.h>
#include <cloak/crypto/types.h>
#include <cloak/identity/identity.h>
#include <cloak/transport/transport.h>
#include <cloak/wire/framing.h>
#include <map>
#include <memory>
#include <string>
#include <tuple>

namespace cloak::session {

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
//   Nonce   = first 24 bytes of HKDF(mk, info="CLOAK_MK_NONCE")
//
// Thread safety: not internally thread-safe.  SessionManager serialises access.
class Session {
public:
    // Factory: initiates or accepts the connection and performs the handshake.
    static cloak::core::Result<Session> initiate(
        const cloak::identity::Identity&            self,
        const std::string&                        display_name,
        std::unique_ptr<cloak::transport::Transport> transport);

    static cloak::core::Result<Session> accept(
        const cloak::identity::Identity&            self,
        const std::string&                        display_name,
        std::unique_ptr<cloak::transport::Transport> transport);

    // Move-only (SecureBuffer members).
    Session(Session&&)            = default;
    Session& operator=(Session&&) = default;
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    ~Session(); // SecureZeroMemory on all key material

    // ── Messaging ─────────────────────────────────────────────────────────────

    // Encrypt and send a UTF-8 text message (InnerType::Text).
    cloak::core::Result<void> send_text(const std::string& body);

    // Encrypt and send a typed inner payload.  Use this for non-text inner
    // types (GroupOp, GroupMessage, DeviceLink, Receipt, etc.).
    cloak::core::Result<void> send_inner(cloak::wire::InnerType type,
                                      std::span<const std::byte> payload);

    // Receive and decrypt one DR message.
    // Returns (InnerType, payload_bytes) — the type byte is NOT included in the payload.
    // Blocks until data arrives or an error occurs.
    cloak::core::Result<std::pair<cloak::wire::InnerType, std::vector<std::byte>>>
        recv_message();

    // Convenience wrapper: calls recv_message(), asserts InnerType::Text.
    cloak::core::Result<std::string> recv_text();

    // ── Phase 2 ───────────────────────────────────────────────────────────────

    // Send a receipt (delivered / read acknowledgement).
    cloak::core::Result<void> send_receipt(cloak::wire::ReceiptType type,
                                        const cloak::core::MessageId& mid);

    // ── Session info ──────────────────────────────────────────────────────────

    const std::string&         peer_display_name() const;
    std::string                peer_fingerprint() const;
    const cloak::core::PublicKey& peer_signing_key() const;
    bool                       is_established() const;

private:
    Session(std::unique_ptr<cloak::transport::Transport> t, bool is_initiator);

    // Handshake helpers.
    cloak::core::Result<void> do_handshake_initiator(
        const cloak::identity::Identity& self, const std::string& my_name);
    cloak::core::Result<void> do_handshake_responder(
        const cloak::identity::Identity& self, const std::string& my_name);

    // Double Ratchet initialisation after handshake.
    cloak::core::Result<void> dr_init_initiator(
        const cloak::crypto::SharedSecret& sk,
        const cloak::core::PublicKey&      peer_dr_pub);
    cloak::core::Result<void> dr_init_responder(
        const cloak::crypto::SharedSecret& sk,
        const cloak::core::PublicKey&      peer_dr_pub,
        cloak::crypto::SecureBuffer<32>    own_dr_priv,
        const cloak::core::PublicKey&      own_dr_pub);

    // Double Ratchet step functions.
    cloak::core::Result<std::pair<cloak::wire::AppMessageHeader, std::vector<std::byte>>>
        dr_encrypt(std::span<const std::byte> plaintext);

    cloak::core::Result<std::vector<std::byte>>
        dr_decrypt(const cloak::wire::AppPayload& payload);

    cloak::core::Result<void> dr_ratchet(const cloak::core::PublicKey& peer_dr_pub);

    cloak::core::Result<std::pair<cloak::crypto::SecureBuffer<32>, cloak::crypto::SecureBuffer<32>>>
        kdf_rk(const cloak::crypto::SecureBuffer<32>& rk,
                std::span<const std::byte>           dh_output);

    cloak::core::Result<std::pair<cloak::crypto::SecureBuffer<32>, cloak::crypto::SecureBuffer<32>>>
        kdf_ck(const cloak::crypto::SecureBuffer<32>& ck);

    cloak::core::Result<std::vector<std::byte>> dr_nonce_from_mk(
        const cloak::crypto::SecureBuffer<32>& mk);

    cloak::core::Result<void> dr_skip_message_keys(uint32_t until);

    // Low-level frame I/O.
    cloak::core::Result<void>       send_frame(const cloak::wire::Frame& f);
    cloak::core::Result<cloak::wire::Frame> recv_frame();

    // ── State ─────────────────────────────────────────────────────────────────

    std::unique_ptr<cloak::transport::Transport> transport_;
    SessionState                              state_{SessionState::Unconnected};
    bool                                      is_initiator_{false};

    // Peer identity (set during handshake).
    std::string         peer_display_name_;
    cloak::core::PublicKey peer_signing_pk_;
    cloak::core::PublicKey peer_dr_pub_;  // peer's current DR ratchet key

    // ── Double Ratchet state ──────────────────────────────────────────────────

    cloak::crypto::SecureBuffer<32> dr_rk_;   // root key
    cloak::crypto::SecureBuffer<32> dr_cks_;  // sending chain key
    cloak::crypto::SecureBuffer<32> dr_ckr_;  // receiving chain key

    cloak::crypto::SecureBuffer<32> dr_dhs_priv_; // our current DR priv key
    cloak::core::PublicKey          dr_dhs_pub_;  // our current DR pub key

    uint32_t dr_ns_{0};   // sending message counter
    uint32_t dr_nr_{0};   // receiving message counter
    uint32_t dr_pn_{0};   // previous chain length

    bool dr_ckr_valid_{false}; // CKr is valid (false for initiator until first receive)
    bool dr_cks_valid_{false}; // CKs is valid (false for responder until first send)

    // Skipped message keys: (DR-pub, msg-num) → message key.
    std::map<SkippedKeyId, cloak::crypto::SecureBuffer<32>> dr_mkskipped_;
};

} // namespace cloak::session
