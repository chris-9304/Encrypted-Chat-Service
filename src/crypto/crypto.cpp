#include "crypto.h"
#include <sodium.h>
#include <mutex>
#include <memory>
#include <cstring>

namespace ev::crypto {

std::once_flag sodium_init_flag;

ev::core::Result<void> Crypto::initialize() {
    bool init_failure = false;
    std::call_once(sodium_init_flag, [&init_failure]() {
        if (sodium_init() < 0) {
            init_failure = true;
        }
    });

    if (init_failure) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "Libsodium init failed", std::nullopt});
    }
    return {};
}

ev::core::Result<KeyPair> Crypto::kx_keypair() {
    KeyPair kp;
    if (crypto_kx_keypair(kp.public_key.bytes.data(), kp.private_key.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "kx_keypair failed", std::nullopt});
    }
    return kp;
}

ev::core::Result<SharedSecret> Crypto::kx_agree(const SecureBuffer<32>& sk, const ev::core::PublicKey& peer_pk) {
    SharedSecret shared;
    if (crypto_scalarmult(shared.secret.data(), sk.data(), peer_pk.bytes.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "kx_agree failed", std::nullopt});
    }
    if (sodium_is_zero(shared.secret.data(), shared.secret.size())) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "kx_agree Low-order point", std::nullopt});
    }
    return shared;
}

ev::core::Result<Ed25519KeyPair> Crypto::ed25519_keypair() {
    Ed25519KeyPair kp;
    if (crypto_sign_keypair(kp.public_key.bytes.data(), kp.private_key.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "ed25519_keypair failed", std::nullopt});
    }
    return kp;
}

ev::core::Result<ev::core::Signature> Crypto::sign_detached(const SecureBuffer<64>& sk, std::span<const std::byte> msg) {
    ev::core::Signature sig;
    unsigned long long sig_len;
    if (crypto_sign_detached(sig.bytes.data(), &sig_len, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "sign_detached failed", std::nullopt});
    }
    return sig;
}

ev::core::Result<bool> Crypto::verify_detached(const ev::core::PublicKey& pk, std::span<const std::byte> msg, const ev::core::Signature& sig) {
    if (crypto_sign_verify_detached(sig.bytes.data(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), pk.bytes.data()) != 0) {
        return false;
    }
    return true;
}

ev::core::Result<std::vector<std::byte>> Crypto::aead_encrypt(
    const SecureBuffer<32>& key, std::span<const std::byte> nonce,
    std::span<const std::byte> aad, std::span<const std::byte> plaintext) {
    
    std::vector<std::byte> ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<uint8_t*>(ct.data()), &ct_len,
            reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
            aad.empty() ? nullptr : reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
            nullptr, reinterpret_cast<const uint8_t*>(nonce.data()), key.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "AEAD encrypt failed", std::nullopt});
    }
    ct.resize(ct_len);
    return ct;
}

ev::core::Result<std::vector<std::byte>> Crypto::aead_decrypt(
    const SecureBuffer<32>& key, std::span<const std::byte> nonce,
    std::span<const std::byte> aad, std::span<const std::byte> ciphertext) {
    
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "AEAD ciphertext too short", std::nullopt});
    }
    
    std::vector<std::byte> pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<uint8_t*>(pt.data()), &pt_len,
            nullptr,
            reinterpret_cast<const uint8_t*>(ciphertext.data()), ciphertext.size(),
            aad.empty() ? nullptr : reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
            reinterpret_cast<const uint8_t*>(nonce.data()), key.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "AEAD decrypt MAC failed", std::nullopt});
    }
    pt.resize(pt_len);
    return pt;
}

ev::core::Result<SecureBuffer<32>> Crypto::hkdf_sha256(
    std::span<const std::byte> ikm, std::span<const std::byte> salt,
    std::span<const std::byte> info) {
    
    SecureBuffer<32> prk;
    if (crypto_kdf_hkdf_sha256_extract(
            prk.data(),
            salt.empty() ? nullptr : reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const uint8_t*>(ikm.data()), ikm.size()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "HKDF extract failed", std::nullopt});
    }
    
    SecureBuffer<32> okm;
    if (crypto_kdf_hkdf_sha256_expand(
            okm.data(), okm.size(),
            reinterpret_cast<const char*>(info.data()), info.size(),
            prk.data()) != 0) {
        return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "HKDF expand failed", std::nullopt});
    }
    
    return okm;
}

bool Crypto::constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

ev::core::Result<void> Crypto::random_bytes(std::span<std::byte> out) {
    randombytes_buf(out.data(), out.size());
    return {};
}

} // namespace ev::crypto
