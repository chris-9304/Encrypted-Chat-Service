#include "crypto.h"

namespace ev::crypto {

ev::core::Result<KeyPair> Crypto::kx_keypair() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<ev::core::Signature> Crypto::sign_detached(const SecureBuffer<32>&, const std::vector<uint8_t>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<AeadCiphertext> Crypto::aead_encrypt(const SecureBuffer<32>&, const ev::core::Nonce&, const std::vector<uint8_t>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<SharedSecret> Crypto::hkdf(const SecureBuffer<32>&, const SecureBuffer<32>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<SecureBuffer<32>> Crypto::argon2id_derive(const std::string&, const std::vector<uint8_t>&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

bool Crypto::constant_time_equal(const uint8_t*, const uint8_t*, size_t) {
    return false; // M1.1 skeleton
}

} // namespace ev::crypto
