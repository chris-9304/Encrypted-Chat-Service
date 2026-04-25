#include <ev/crypto/crypto.h>
#include <sodium.h>
#include <cstring>
#include <mutex>

namespace ev::crypto {

namespace {
    std::once_flag g_sodium_init_flag;
    bool           g_sodium_init_failed = false;
}

ev::core::Result<void> Crypto::initialize() {
    std::call_once(g_sodium_init_flag, [] {
        if (sodium_init() < 0) {
            g_sodium_init_failed = true;
        }
    });
    if (g_sodium_init_failed) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "libsodium init failed"));
    }
    return {};
}

// ── Key generation ────────────────────────────────────────────────────────────

ev::core::Result<KeyPair> Crypto::kx_keypair() {
    KeyPair kp;
    if (crypto_kx_keypair(kp.public_key.bytes.data(),
                          kp.private_key.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "kx_keypair failed"));
    }
    return kp;
}

ev::core::Result<Ed25519KeyPair> Crypto::ed25519_keypair() {
    Ed25519KeyPair kp;
    if (crypto_sign_keypair(kp.public_key.bytes.data(),
                            kp.private_key.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "ed25519_keypair failed"));
    }
    return kp;
}

// ── Key agreement ─────────────────────────────────────────────────────────────

ev::core::Result<SharedSecret> Crypto::kx_agree(
    const SecureBuffer<32>& sk, const ev::core::PublicKey& peer_pk) {

    SharedSecret ss;
    if (crypto_scalarmult(ss.secret.data(),
                          sk.data(),
                          peer_pk.bytes.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "X25519 scalarmult failed"));
    }
    // Reject low-order points (all-zero output is always unsafe).
    if (sodium_is_zero(ss.secret.data(), 32)) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "X25519: low-order point rejected"));
    }
    return ss;
}

// ── Signing ───────────────────────────────────────────────────────────────────

ev::core::Result<ev::core::Signature> Crypto::sign_detached(
    const SecureBuffer<64>& sk, std::span<const std::byte> msg) {

    ev::core::Signature sig;
    unsigned long long  sig_len = 0;
    if (crypto_sign_detached(
            sig.bytes.data(), &sig_len,
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            sk.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "Ed25519 sign failed"));
    }
    return sig;
}

ev::core::Result<bool> Crypto::verify_detached(
    const ev::core::PublicKey& pk,
    std::span<const std::byte>  msg,
    const ev::core::Signature&  sig) {

    int rc = crypto_sign_verify_detached(
        sig.bytes.data(),
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
        pk.bytes.data());
    return rc == 0;
}

// ── AEAD ──────────────────────────────────────────────────────────────────────

ev::core::Result<std::vector<std::byte>> Crypto::aead_encrypt(
    const SecureBuffer<32>&    key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> aad,
    std::span<const std::byte> plaintext) {

    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::InvalidArgument,
                                  "AEAD nonce must be 24 bytes"));
    }

    std::vector<std::byte> ct(
        plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(ct.data()), &ct_len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(),
            aad.empty() ? nullptr
                        : reinterpret_cast<const unsigned char*>(aad.data()),
            aad.size(),
            nullptr,
            reinterpret_cast<const unsigned char*>(nonce.data()),
            key.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "AEAD encrypt failed"));
    }
    ct.resize(ct_len);
    return ct;
}

ev::core::Result<std::vector<std::byte>> Crypto::aead_decrypt(
    const SecureBuffer<32>&    key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> aad,
    std::span<const std::byte> ciphertext) {

    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::InvalidArgument,
                                  "AEAD nonce must be 24 bytes"));
    }
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::DecryptionFailed,
                                  "AEAD ciphertext too short"));
    }

    std::vector<std::byte> pt(
        ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &pt_len,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            ciphertext.size(),
            aad.empty() ? nullptr
                        : reinterpret_cast<const unsigned char*>(aad.data()),
            aad.size(),
            reinterpret_cast<const unsigned char*>(nonce.data()),
            key.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::DecryptionFailed,
                                  "AEAD MAC verification failed"));
    }
    pt.resize(pt_len);
    return pt;
}

// ── Key derivation ────────────────────────────────────────────────────────────

ev::core::Result<SecureBuffer<32>> Crypto::hkdf_sha256(
    std::span<const std::byte> ikm,
    std::span<const std::byte> salt,
    std::span<const std::byte> info) {

    SecureBuffer<32> prk;
    if (crypto_kdf_hkdf_sha256_extract(
            prk.data(),
            salt.empty() ? nullptr
                         : reinterpret_cast<const unsigned char*>(salt.data()),
            salt.size(),
            reinterpret_cast<const unsigned char*>(ikm.data()),
            ikm.size()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "HKDF-SHA256 extract failed"));
    }

    SecureBuffer<32> okm;
    if (crypto_kdf_hkdf_sha256_expand(
            okm.data(), okm.size(),
            reinterpret_cast<const char*>(info.data()), info.size(),
            prk.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "HKDF-SHA256 expand failed"));
    }
    return okm;
}

ev::core::Result<std::pair<SecureBuffer<32>, SecureBuffer<32>>>
Crypto::hkdf_sha256_64(
    std::span<const std::byte> ikm,
    std::span<const std::byte> salt,
    std::span<const std::byte> info) {

    SecureBuffer<32> prk;
    if (crypto_kdf_hkdf_sha256_extract(
            prk.data(),
            salt.empty() ? nullptr
                         : reinterpret_cast<const unsigned char*>(salt.data()),
            salt.size(),
            reinterpret_cast<const unsigned char*>(ikm.data()),
            ikm.size()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "HKDF-SHA256 extract (64) failed"));
    }

    // Expand 64 bytes then split.
    std::array<uint8_t, 64> okm_raw{};
    if (crypto_kdf_hkdf_sha256_expand(
            okm_raw.data(), okm_raw.size(),
            reinterpret_cast<const char*>(info.data()), info.size(),
            prk.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "HKDF-SHA256 expand (64) failed"));
    }

    SecureBuffer<32> out1, out2;
    std::memcpy(out1.data(), okm_raw.data(),      32);
    std::memcpy(out2.data(), okm_raw.data() + 32, 32);
    sodium_memzero(okm_raw.data(), okm_raw.size());

    return std::make_pair(std::move(out1), std::move(out2));
}

ev::core::Result<SecureBuffer<32>> Crypto::hmac_sha256(
    const SecureBuffer<32>&    key,
    std::span<const std::byte> msg) {

    SecureBuffer<32> out;
    if (crypto_auth_hmacsha256(
            out.data(),
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            key.data()) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "HMAC-SHA256 failed"));
    }
    return out;
}

ev::core::Result<SecureBuffer<32>> Crypto::argon2id_derive(
    std::span<const std::byte> passphrase,
    std::span<const std::byte> salt,
    uint64_t ops_limit,
    size_t   mem_limit) {

    if (salt.size() != crypto_pwhash_SALTBYTES) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::InvalidArgument,
                                  "Argon2id salt must be 16 bytes"));
    }

    SecureBuffer<32> key;
    if (crypto_pwhash(
            key.data(), key.size(),
            reinterpret_cast<const char*>(passphrase.data()),
            passphrase.size(),
            reinterpret_cast<const unsigned char*>(salt.data()),
            ops_limit, mem_limit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "Argon2id key derivation failed (out of memory?)"));
    }
    return key;
}

ev::core::Result<std::vector<std::byte>> Crypto::argon2id_salt() {
    std::vector<std::byte> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

bool Crypto::constant_time_equal(
    std::span<const std::byte> a, std::span<const std::byte> b) {

    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

ev::core::Result<void> Crypto::random_bytes(std::span<std::byte> out) {
    randombytes_buf(out.data(), out.size());
    return {};
}

ev::core::Result<std::array<uint8_t, 32>> Crypto::blake2b_256(
    std::span<const std::byte> msg) {

    std::array<uint8_t, 32> out{};
    if (crypto_generichash_blake2b(
            out.data(), out.size(),
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            nullptr, 0) != 0) {
        return std::unexpected(
            ev::core::Error::from(ev::core::ErrorCode::CryptoError,
                                  "BLAKE2b-256 failed"));
    }
    return out;
}

} // namespace ev::crypto
