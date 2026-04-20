#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include "types.h"

namespace ev::crypto {

class Crypto {
public:
    static ev::core::Result<KeyPair> kx_keypair();
    static ev::core::Result<ev::core::Signature> sign_detached(const SecureBuffer<32>& secret_key, const std::vector<uint8_t>& message);
    static ev::core::Result<AeadCiphertext> aead_encrypt(const SecureBuffer<32>& key, const ev::core::Nonce& nonce, const std::vector<uint8_t>& plaintext);
    static ev::core::Result<SharedSecret> hkdf(const SecureBuffer<32>& salt, const SecureBuffer<32>& ikm);
    static ev::core::Result<SecureBuffer<32>> argon2id_derive(const std::string& passphrase, const std::vector<uint8_t>& salt);
    static bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);
};

} // namespace ev::crypto
