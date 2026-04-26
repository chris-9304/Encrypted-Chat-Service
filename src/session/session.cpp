#include <cloak/session/session.h>
#include <cloak/crypto/crypto.h>
#include <cloak/wire/framing.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <array>
#include <cstring>

namespace cloak::session {

using namespace cloak::core;
using namespace cloak::crypto;
using namespace cloak::wire;

// ── KDF info constants ────────────────────────────────────────────────────────

// Copy bytes between SecureBuffers (copy-ctor is deleted; use memcpy instead).
static void sb_copy(SecureBuffer<32>& dst, const SecureBuffer<32>& src) {
    std::memcpy(dst.data(), src.data(), 32);
}

namespace {

constexpr std::string_view kInfoSk    = "Cloak_SessionKey_v2";
constexpr std::string_view kInfoRkCk  = "Cloak_DR_RK_CK_v2";
constexpr std::string_view kInfoNonce = "Cloak_DR_MK_NONCE_v2";

inline std::span<const std::byte> as_bytes(std::string_view s) {
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(s.data()), s.size());
}

// HMAC-SHA256 byte constants used in KDF_CK.
constexpr std::byte kCkMsg{0x02};
constexpr std::byte kMkMsg{0x01};

} // namespace

// ── Constructor / Destructor ──────────────────────────────────────────────────

Session::Session(std::unique_ptr<cloak::transport::Transport> t, bool is_initiator)
    : transport_(std::move(t)), is_initiator_(is_initiator) {}

Session::~Session() {
    // SecureBuffer members zero themselves on destruction.
    // Close transport if still open.
    if (transport_ && transport_->is_open()) {
        static_cast<void>(transport_->close());
    }
}

// ── Factory methods ───────────────────────────────────────────────────────────

Result<Session> Session::initiate(
    const cloak::identity::Identity&            self,
    const std::string&                        display_name,
    std::unique_ptr<cloak::transport::Transport> transport) {

    Session s(std::move(transport), /*is_initiator=*/true);
    auto res = s.do_handshake_initiator(self, display_name);
    if (!res) return std::unexpected(res.error());
    return s;
}

Result<Session> Session::accept(
    const cloak::identity::Identity&            self,
    const std::string&                        display_name,
    std::unique_ptr<cloak::transport::Transport> transport) {

    Session s(std::move(transport), /*is_initiator=*/false);
    auto res = s.do_handshake_responder(self, display_name);
    if (!res) return std::unexpected(res.error());
    return s;
}

// ── Handshake ─────────────────────────────────────────────────────────────────

Result<void> Session::do_handshake_initiator(
    const cloak::identity::Identity& self, const std::string& my_name) {

    // Generate our DR ephemeral key pair.
    auto dr_kp_res = Crypto::kx_keypair();
    if (!dr_kp_res) return std::unexpected(dr_kp_res.error());
    auto& dr_kp = *dr_kp_res;

    // Sign the DR public key.
    auto sig_kx = self.sign(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(self.kx_public().bytes.data()),
            32));
    if (!sig_kx) return std::unexpected(sig_kx.error());

    auto sig_dr = self.sign(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(dr_kp.public_key.bytes.data()),
            32));
    if (!sig_dr) return std::unexpected(sig_dr.error());

    HandshakePayload out_hs{
        .x25519_pub      = self.kx_public(),
        .ed25519_pub     = self.signing_public(),
        .sig_over_x25519 = *sig_kx,
        .dr_pub          = dr_kp.public_key,
        .sig_over_dr     = *sig_dr,
        .display_name    = my_name,
    };

    auto enc = encode_handshake(out_hs);
    if (!enc) return std::unexpected(enc.error());

    Frame f{MessageType::Handshake, std::move(*enc)};
    if (auto sr = send_frame(f); !sr) return std::unexpected(sr.error());

    state_ = SessionState::HandshakeSent;

    // Receive peer's handshake.
    auto peer_frame = recv_frame();
    if (!peer_frame) return std::unexpected(peer_frame.error());
    if (peer_frame->type != MessageType::Handshake) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Expected Handshake frame"));
    }

    auto peer_hs = decode_handshake(peer_frame->payload);
    if (!peer_hs) return std::unexpected(peer_hs.error());

    // Verify peer's signature over their X25519 key.
    auto vx = Crypto::verify_detached(
        peer_hs->ed25519_pub,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(peer_hs->x25519_pub.bytes.data()),
            32),
        peer_hs->sig_over_x25519);
    if (!vx || !*vx) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Peer X25519 signature invalid"));
    }

    // Verify peer's signature over their DR key.
    auto vdr = Crypto::verify_detached(
        peer_hs->ed25519_pub,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(peer_hs->dr_pub.bytes.data()),
            32),
        peer_hs->sig_over_dr);
    if (!vdr || !*vdr) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Peer DR key signature invalid"));
    }

    // Compute shared X25519 secret → session root.
    auto ss = self.agree(peer_hs->x25519_pub);
    if (!ss) return std::unexpected(ss.error());

    peer_display_name_ = peer_hs->display_name;
    peer_signing_pk_   = peer_hs->ed25519_pub;
    peer_dr_pub_       = peer_hs->dr_pub;

    // Derive SK (shared key) via HKDF over the DH output.
    auto sk = Crypto::hkdf_sha256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(ss->secret.data()), 32),
        {},
        as_bytes(kInfoSk));
    if (!sk) return std::unexpected(sk.error());

    // Wrap in SharedSecret for dr_init_initiator.
    cloak::crypto::SharedSecret sk_ss;
    sb_copy(sk_ss.secret, *sk);

    // Initialise Double Ratchet as initiator.
    // Store DR key pair first so dr_dhs_priv_ is available during lazy init.
    dr_dhs_priv_ = std::move(dr_kp.private_key);
    dr_dhs_pub_  = dr_kp.public_key;

    auto dr_res = dr_init_initiator(sk_ss, peer_hs->dr_pub);
    if (!dr_res) return std::unexpected(dr_res.error());

    state_ = SessionState::Established;
    return {};
}

Result<void> Session::do_handshake_responder(
    const cloak::identity::Identity& self, const std::string& my_name) {

    // Receive initiator's handshake first.
    auto peer_frame = recv_frame();
    if (!peer_frame) return std::unexpected(peer_frame.error());
    if (peer_frame->type != MessageType::Handshake) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Expected Handshake frame"));
    }

    auto peer_hs = decode_handshake(peer_frame->payload);
    if (!peer_hs) return std::unexpected(peer_hs.error());

    // Verify signatures.
    auto vx = Crypto::verify_detached(
        peer_hs->ed25519_pub,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(peer_hs->x25519_pub.bytes.data()),
            32),
        peer_hs->sig_over_x25519);
    if (!vx || !*vx) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Peer X25519 signature invalid"));
    }

    auto vdr = Crypto::verify_detached(
        peer_hs->ed25519_pub,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(peer_hs->dr_pub.bytes.data()),
            32),
        peer_hs->sig_over_dr);
    if (!vdr || !*vdr) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Peer DR key signature invalid"));
    }

    state_ = SessionState::HandshakeReceived;

    // Generate our own DR ephemeral key pair.
    auto dr_kp_res = Crypto::kx_keypair();
    if (!dr_kp_res) return std::unexpected(dr_kp_res.error());
    auto& dr_kp = *dr_kp_res;

    // Sign our keys.
    auto sig_kx = self.sign(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(self.kx_public().bytes.data()),
            32));
    if (!sig_kx) return std::unexpected(sig_kx.error());

    auto sig_dr = self.sign(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(dr_kp.public_key.bytes.data()),
            32));
    if (!sig_dr) return std::unexpected(sig_dr.error());

    // Send our handshake.
    HandshakePayload out_hs{
        .x25519_pub      = self.kx_public(),
        .ed25519_pub     = self.signing_public(),
        .sig_over_x25519 = *sig_kx,
        .dr_pub          = dr_kp.public_key,
        .sig_over_dr     = *sig_dr,
        .display_name    = my_name,
    };

    auto enc = encode_handshake(out_hs);
    if (!enc) return std::unexpected(enc.error());

    Frame f{MessageType::Handshake, std::move(*enc)};
    if (auto sr = send_frame(f); !sr) return std::unexpected(sr.error());

    // Compute shared secret and derive SK.
    auto ss = self.agree(peer_hs->x25519_pub);
    if (!ss) return std::unexpected(ss.error());

    peer_display_name_ = peer_hs->display_name;
    peer_signing_pk_   = peer_hs->ed25519_pub;
    peer_dr_pub_       = peer_hs->dr_pub;

    auto sk = Crypto::hkdf_sha256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(ss->secret.data()), 32),
        {},
        as_bytes(kInfoSk));
    if (!sk) return std::unexpected(sk.error());

    // Wrap in SharedSecret for dr_init_responder.
    cloak::crypto::SharedSecret sk_ss;
    sb_copy(sk_ss.secret, *sk);

    // Initialise Double Ratchet as responder.
    auto dr_res = dr_init_responder(sk_ss, peer_hs->dr_pub,
                                    std::move(dr_kp.private_key),
                                    dr_kp.public_key);
    if (!dr_res) return std::unexpected(dr_res.error());

    state_ = SessionState::Established;
    return {};
}

// ── Double Ratchet initialisation ─────────────────────────────────────────────

Result<void> Session::dr_init_initiator(
    const cloak::crypto::SharedSecret& sk, const PublicKey& peer_dr_pub) {

    // Alice (initiator) per Signal spec:
    // RK = SK; CKs set lazily on first encrypt (Signal-spec lazy init).
    sb_copy(dr_rk_, sk.secret);
    peer_dr_pub_  = peer_dr_pub;
    dr_cks_valid_ = false;
    dr_ckr_valid_ = false;
    dr_ns_ = 0; dr_nr_ = 0; dr_pn_ = 0;

    return {};
}

Result<void> Session::dr_init_responder(
    const cloak::crypto::SharedSecret& sk,
    const PublicKey&                 /*peer_dr_pub_hint*/,
    SecureBuffer<32>                 own_dr_priv,
    const PublicKey&                 own_dr_pub) {

    // Signal-spec responder initialization:
    //   DHs = own DR keypair (our "signed prekey" equivalent)
    //   DHr = None (set when first message received)
    //   RK  = SK
    //   CKs = CKr = None
    //
    // On first recv(), dr_decrypt() will call dr_ratchet(peer_dr_pub) which:
    //   1. Sets DHr = peer_dr_pub (Alice's DR key from the header)
    //   2. Computes (RK, CKr) = KDF_RK(SK, DH(own_DR_priv, Alice_DR_pub))
    //      which equals Alice's CKs (ECDH symmetry) ✓
    //   3. Generates new DHs for the reply
    //   4. Computes (RK, CKs) = KDF_RK(RK, DH(new_DHs, Alice_DR_pub))

    dr_dhs_priv_ = std::move(own_dr_priv);
    dr_dhs_pub_  = own_dr_pub;
    // Explicitly zero peer_dr_pub_ so DHRatchet fires on first receive,
    // even if do_handshake_responder pre-set it from the handshake payload.
    peer_dr_pub_ = cloak::core::PublicKey{};
    dr_ns_ = 0; dr_nr_ = 0; dr_pn_ = 0;

    sb_copy(dr_rk_, sk.secret); // RK = SK

    dr_cks_valid_ = false;
    dr_ckr_valid_ = false;

    return {};
}

// ── Double Ratchet KDFs ───────────────────────────────────────────────────────

Result<std::pair<SecureBuffer<32>, SecureBuffer<32>>>
Session::kdf_rk(const SecureBuffer<32>& rk,
                std::span<const std::byte> dh_output) {

    // KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info="...")
    // → 64 bytes split into (new_rk, new_ck)
    return Crypto::hkdf_sha256_64(
        dh_output,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(rk.data()), 32),
        as_bytes(kInfoRkCk));
}

Result<std::pair<SecureBuffer<32>, SecureBuffer<32>>>
Session::kdf_ck(const SecureBuffer<32>& ck) {

    // KDF_CK(ck) = HMAC-SHA256(key=ck, msg=0x01) → mk
    //              HMAC-SHA256(key=ck, msg=0x02) → new_ck
    auto mk  = Crypto::hmac_sha256(ck, std::span<const std::byte>(&kMkMsg, 1));
    if (!mk) return std::unexpected(mk.error());

    auto nck = Crypto::hmac_sha256(ck, std::span<const std::byte>(&kCkMsg, 1));
    if (!nck) return std::unexpected(nck.error());

    return std::make_pair(std::move(*mk), std::move(*nck));
}

Result<std::vector<std::byte>> Session::dr_nonce_from_mk(
    const SecureBuffer<32>& mk) {

    // Derive 24-byte nonce from the message key to ensure uniqueness.
    auto nonce_key = Crypto::hkdf_sha256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(mk.data()), 32),
        {},
        as_bytes(kInfoNonce));
    if (!nonce_key) return std::unexpected(nonce_key.error());

    std::vector<std::byte> nonce(24);
    std::memcpy(nonce.data(), nonce_key->data(), 24);
    return nonce;
}

// ── DHRatchet step ────────────────────────────────────────────────────────────

Result<void> Session::dr_ratchet(const PublicKey& peer_dr_pub) {
    // Signal DHRatchet:
    //   PN = Ns
    //   Ns = 0, Nr = 0
    //   DHr = peer_dr_pub
    //   RK, CKr = KDF_RK(RK, DH(DHs, DHr))
    //   DHs = generate new DH keypair
    //   RK, CKs = KDF_RK(RK, DH(new_DHs, DHr))

    dr_pn_      = dr_ns_;
    dr_ns_      = 0;
    dr_nr_      = 0;
    peer_dr_pub_ = peer_dr_pub;

    // Step 1: DH(current DHs, new DHr) → receive chain
    {
        auto dh1 = Crypto::kx_agree(dr_dhs_priv_, peer_dr_pub_);
        if (!dh1) return std::unexpected(
            Error::from(ErrorCode::CryptoError, "DHRatchet: step1 DH failed"));
        auto res = kdf_rk(dr_rk_,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(dh1->secret.data()), 32));
        if (!res) return std::unexpected(res.error());
        dr_rk_        = std::move(res->first);
        dr_ckr_       = std::move(res->second);
        dr_ckr_valid_ = true;
    }

    // Step 2: Generate new DHs, DH(new DHs, DHr) → send chain
    {
        auto new_kp = Crypto::kx_keypair();
        if (!new_kp) return std::unexpected(new_kp.error());

        auto dh2 = Crypto::kx_agree(new_kp->private_key, peer_dr_pub_);
        if (!dh2) return std::unexpected(
            Error::from(ErrorCode::CryptoError, "DHRatchet: step2 DH failed"));
        auto res = kdf_rk(dr_rk_,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(dh2->secret.data()), 32));
        if (!res) return std::unexpected(res.error());
        dr_rk_        = std::move(res->first);
        dr_cks_       = std::move(res->second);
        dr_cks_valid_ = true;
        dr_dhs_priv_  = std::move(new_kp->private_key);
        dr_dhs_pub_   = new_kp->public_key;
    }

    return {};
}

// ── Skip message keys ─────────────────────────────────────────────────────────

Result<void> Session::dr_skip_message_keys(uint32_t until) {
    // If no receive chain yet, only acceptable if there's nothing to skip.
    if (!dr_ckr_valid_) {
        if (until <= dr_nr_) return {};
        return std::unexpected(Error::from(ErrorCode::NotEstablished,
                                           "DR: no receive chain yet"));
    }
    if (until < dr_nr_) {
        return std::unexpected(Error::from(ErrorCode::CounterMismatch,
                                           "DR: skip target below current counter"));
    }
    if (until - dr_nr_ > static_cast<uint32_t>(kMaxSkip)) {
        return std::unexpected(Error::from(ErrorCode::CounterMismatch,
                                           "DR: too many skipped messages"));
    }

    // Guard against unbounded map growth across multiple ratchet epochs.
    if (dr_mkskipped_.size() + (until - dr_nr_) > static_cast<size_t>(kMaxSkip) * 5) {
        return std::unexpected(Error::from(ErrorCode::CounterMismatch,
                                           "DR: skipped-key cache full"));
    }

    while (dr_nr_ < until) {
        auto ck_res = kdf_ck(dr_ckr_);
        if (!ck_res) return std::unexpected(ck_res.error());
        SkippedKeyId key{peer_dr_pub_.bytes, dr_nr_};
        dr_mkskipped_.emplace(key, std::move(ck_res->first));
        dr_ckr_ = std::move(ck_res->second);
        dr_nr_++;
    }
    return {};
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

Result<std::pair<AppMessageHeader, std::vector<std::byte>>>
Session::dr_encrypt(std::span<const std::byte> plaintext) {

    // Initiator: first send triggers a DHRatchet (lazy init of CKs).
    if (!dr_cks_valid_) {
        if (!dr_ckr_valid_ && is_initiator_) {
            // Initiator's very first send: perform ratchet with peer_dr_pub_.
            // dr_dhs_priv_ is already set (from do_handshake_initiator).
            auto dh = Crypto::kx_agree(dr_dhs_priv_, peer_dr_pub_);
            if (!dh) return std::unexpected(
                Error::from(ErrorCode::CryptoError, "DR first send: DH failed"));
            auto res = kdf_rk(dr_rk_,
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(dh->secret.data()), 32));
            if (!res) return std::unexpected(res.error());
            dr_rk_        = std::move(res->first);
            dr_cks_       = std::move(res->second);
            dr_cks_valid_ = true;
        } else {
            return std::unexpected(Error::from(ErrorCode::NotEstablished,
                                               "DR: send chain not initialised"));
        }
    }

    auto ck_res = kdf_ck(dr_cks_);
    if (!ck_res) return std::unexpected(ck_res.error());
    auto mk     = std::move(ck_res->first);
    dr_cks_     = std::move(ck_res->second);

    AppMessageHeader hdr;
    hdr.dh_pub = dr_dhs_pub_;
    hdr.pn     = dr_pn_;
    hdr.n      = dr_ns_;
    dr_ns_++;

    // AEAD: encrypt plaintext with MK; AAD = serialised header.
    auto aad      = encode_app_header(hdr);
    auto nonce_r  = dr_nonce_from_mk(mk);
    if (!nonce_r) return std::unexpected(nonce_r.error());

    auto ct = Crypto::aead_encrypt(
        mk,
        std::span<const std::byte>(*nonce_r),
        std::span<const std::byte>(aad),
        plaintext);
    if (!ct) return std::unexpected(ct.error());

    return std::make_pair(hdr, std::move(*ct));
}

Result<std::vector<std::byte>>
Session::dr_decrypt(const AppPayload& payload) {
    const auto& hdr = payload.header;

    // Check skipped-key cache.
    SkippedKeyId key{hdr.dh_pub.bytes, hdr.n};
    auto it = dr_mkskipped_.find(key);
    if (it != dr_mkskipped_.end()) {
        auto mk = std::move(it->second);
        dr_mkskipped_.erase(it);

        auto aad      = encode_app_header(hdr);
        auto nonce_r  = dr_nonce_from_mk(mk);
        if (!nonce_r) return std::unexpected(nonce_r.error());
        return Crypto::aead_decrypt(
            mk,
            std::span<const std::byte>(*nonce_r),
            std::span<const std::byte>(aad),
            std::span<const std::byte>(payload.ciphertext));
    }

    // New DH ratchet key from peer?
    if (!Crypto::constant_time_equal(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(peer_dr_pub_.bytes.data()), 32),
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(hdr.dh_pub.bytes.data()), 32))) {

        // Skip messages in the current receive chain.
        if (auto sr = dr_skip_message_keys(hdr.pn); !sr) {
            return std::unexpected(sr.error());
        }
        // Advance the ratchet.
        if (auto rr = dr_ratchet(hdr.dh_pub); !rr) {
            return std::unexpected(rr.error());
        }
    }

    // Skip messages in the new receive chain.
    if (auto sr = dr_skip_message_keys(hdr.n); !sr) {
        return std::unexpected(sr.error());
    }

    auto ck_res2 = kdf_ck(dr_ckr_);
    if (!ck_res2) return std::unexpected(ck_res2.error());
    auto mk2    = std::move(ck_res2->first);
    dr_ckr_     = std::move(ck_res2->second);
    dr_nr_++;

    auto aad       = encode_app_header(hdr);
    auto nonce_res = dr_nonce_from_mk(mk2);
    if (!nonce_res) return std::unexpected(nonce_res.error());
    auto& nonce = *nonce_res;

    auto pt = Crypto::aead_decrypt(
        mk2,
        std::span<const std::byte>(nonce),
        std::span<const std::byte>(aad),
        std::span<const std::byte>(payload.ciphertext));
    if (!pt) {
        state_ = SessionState::Closed;
        return std::unexpected(pt.error());
    }
    return *pt;
}

// ── Public messaging API ──────────────────────────────────────────────────────

Result<void> Session::send_inner(InnerType type,
                                  std::span<const std::byte> payload) {
    if (state_ != SessionState::Established) {
        return std::unexpected(Error::from(ErrorCode::NotEstablished,
                                           "Session not established"));
    }
    std::vector<std::byte> inner;
    inner.reserve(1 + payload.size());
    inner.push_back(static_cast<std::byte>(type));
    inner.insert(inner.end(), payload.begin(), payload.end());

    auto enc_res = dr_encrypt(std::span<const std::byte>(inner));
    if (!enc_res) return std::unexpected(enc_res.error());

    AppPayload p{enc_res->first, std::move(enc_res->second)};
    auto encoded = encode_app(p);
    if (!encoded) return std::unexpected(encoded.error());

    Frame f{MessageType::AppMessage, std::move(*encoded)};
    if (auto sr = send_frame(f); !sr) {
        state_ = SessionState::Closed;
        return std::unexpected(sr.error());
    }
    return {};
}

Result<void> Session::send_text(const std::string& body) {
    return send_inner(InnerType::Text,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(body.data()), body.size()));
}

Result<std::pair<InnerType, std::vector<std::byte>>> Session::recv_message() {
    if (state_ != SessionState::Established) {
        return std::unexpected(Error::from(ErrorCode::NotEstablished,
                                           "Session not established"));
    }

    auto frame = recv_frame();
    if (!frame) {
        state_ = SessionState::Closed;
        return std::unexpected(frame.error());
    }
    if (frame->type != MessageType::AppMessage) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Expected AppMessage frame"));
    }

    auto app = decode_app(frame->payload);
    if (!app) return std::unexpected(app.error());

    auto inner = dr_decrypt(*app);
    if (!inner) return std::unexpected(inner.error());

    if (inner->empty()) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Empty inner payload"));
    }

    const auto inner_type = static_cast<InnerType>((*inner)[0]);
    std::vector<std::byte> body(inner->begin() + 1, inner->end());
    return std::make_pair(inner_type, std::move(body));
}

Result<std::string> Session::recv_text() {
    auto msg = recv_message();
    if (!msg) return std::unexpected(msg.error());

    if (msg->first != InnerType::Text) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Expected Text inner type, got " +
                                           std::to_string(static_cast<uint8_t>(msg->first))));
    }
    return std::string(
        reinterpret_cast<const char*>(msg->second.data()),
        msg->second.size());
}

Result<void> Session::send_receipt(ReceiptType type, const MessageId& mid) {
    std::vector<std::byte> payload;
    payload.push_back(static_cast<std::byte>(type));
    payload.insert(payload.end(),
                   reinterpret_cast<const std::byte*>(mid.bytes.data()),
                   reinterpret_cast<const std::byte*>(mid.bytes.data()) + 16);
    return send_inner(InnerType::Receipt,
                      std::span<const std::byte>(payload));
}

// ── Frame I/O ─────────────────────────────────────────────────────────────────

Result<void> Session::send_frame(const Frame& f) {
    auto enc = encode(f);
    if (!enc) return std::unexpected(enc.error());
    return transport_->send(std::span<const std::byte>(*enc));
}

Result<Frame> Session::recv_frame() {
    // Read 4-byte length prefix.
    auto head = transport_->receive(4);
    if (!head) return std::unexpected(head.error());

    uint32_t len_be{};
    std::memcpy(&len_be, head->data(), 4);
    const uint32_t len = ntohl(len_be);

    if (len == 0 || len > kMaxFrameBodySize) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
                                           "Invalid frame length"));
    }

    auto body = transport_->receive(len);
    if (!body) return std::unexpected(body.error());

    std::vector<std::byte> full(4 + len);
    std::memcpy(full.data(),     head->data(), 4);
    std::memcpy(full.data() + 4, body->data(), len);

    return decode(std::span<const std::byte>(full));
}

// ── Session info ──────────────────────────────────────────────────────────────

const std::string& Session::peer_display_name() const {
    return peer_display_name_;
}

std::string Session::peer_fingerprint() const {
    auto hash_res = Crypto::blake2b_256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(peer_signing_pk_.bytes.data()),
            32));
    if (!hash_res) return "(error)";

    const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string b32;
    uint32_t    buf      = 0;
    int         bits_left = 0;

    for (uint8_t byte : *hash_res) {
        buf = (buf << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            b32.push_back(alpha[(buf >> bits_left) & 0x1F]);
        }
        if (b32.size() >= 12) break;
    }
    while (b32.size() < 12) b32.push_back('A');

    return b32.substr(0,4) + "-" + b32.substr(4,4) + "-" + b32.substr(8,4);
}

const PublicKey& Session::peer_signing_key() const {
    return peer_signing_pk_;
}

bool Session::is_established() const {
    return state_ == SessionState::Established;
}

} // namespace cloak::session
