#include "crypto.h"
#include <ev/core/log.h>

namespace ev::crypto {

ev::core::Result<void> Crypto::initialize() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<KeyPair> Crypto::kx_keypair() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<SharedSecret> Crypto::kx_agree(const SecureBuffer<32>&, const ev::core::PublicKey&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<KeyPair> Crypto::ed25519_keypair() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<ev::core::Signature> Crypto::sign_detached(const SecureBuffer<32>&, const std::vector<uint8_t>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<bool> Crypto::verify_detached(const ev::core::PublicKey&, const std::vector<uint8_t>&, const ev::core::Signature&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<AeadCiphertext> Crypto::aead_encrypt(const SecureBuffer<32>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, const ev::core::Nonce&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<std::vector<uint8_t>> Crypto::aead_decrypt(const SecureBuffer<32>&, const AeadCiphertext&, const std::vector<uint8_t>&, const ev::core::Nonce&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<std::vector<uint8_t>> Crypto::hkdf(const SecureBuffer<32>&, const SecureBuffer<32>&, const std::vector<uint8_t>&, size_t) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

ev::core::Result<SecureBuffer<32>> Crypto::argon2id_derive(const std::string&, const std::vector<uint8_t>&, size_t) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

bool Crypto::constant_time_equal(const uint8_t*, const uint8_t*, size_t) {
    return false; // M1.2 skeleton
}

ev::core::Result<void> Crypto::random_bytes(std::span<uint8_t>) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.2 skeleton", std::nullopt});
}

} // namespace ev::crypto
