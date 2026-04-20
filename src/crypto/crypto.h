#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include "types.h"
#include <string>
#include <vector>

namespace ev::crypto {

class Crypto {
public:
    static ev::core::Result<void> initialize();

    static ev::core::Result<KeyPair> kx_keypair();
    static ev::core::Result<SharedSecret> kx_agree(const SecureBuffer<32>& secret_key, const ev::core::PublicKey& peer_public_key);

    static ev::core::Result<KeyPair> ed25519_keypair();
    static ev::core::Result<ev::core::Signature> sign_detached(const SecureBuffer<32>& secret_key, const std::vector<uint8_t>& message);
    static ev::core::Result<bool> verify_detached(const ev::core::PublicKey& public_key, const std::vector<uint8_t>& message, const ev::core::Signature& signature);

    static ev::core::Result<AeadCiphertext> aead_encrypt(const SecureBuffer<32>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad, const ev::core::Nonce& nonce);
    static ev::core::Result<std::vector<uint8_t>> aead_decrypt(const SecureBuffer<32>& key, const AeadCiphertext& ciphertext, const std::vector<uint8_t>& aad, const ev::core::Nonce& nonce);

    static ev::core::Result<std::vector<uint8_t>> hkdf(const SecureBuffer<32>& ikm, const SecureBuffer<32>& salt, const std::vector<uint8_t>& info, size_t out_len);
    
    static ev::core::Result<SecureBuffer<32>> argon2id_derive(const std::string& passphrase, const std::vector<uint8_t>& salt, size_t out_len);

    static bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);
    static ev::core::Result<void> random_bytes(std::span<uint8_t> buf);
};

} // namespace ev::crypto
