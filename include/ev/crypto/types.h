#pragma once

#include <ev/crypto/secure_buffer.h>
#include <ev/core/types.h>

namespace ev::crypto {

// X25519 key-exchange keypair.
struct KeyPair {
    ev::core::PublicKey public_key;
    SecureBuffer<32>    private_key;
};

// Ed25519 signing keypair.
struct Ed25519KeyPair {
    ev::core::PublicKey public_key;
    SecureBuffer<64>    private_key; // libsodium: seed(32) + pk(32)
};

// Result of X25519 DH — always 32 bytes.
struct SharedSecret {
    SecureBuffer<32> secret;
};

// AEAD ciphertext with authentication tag appended.
struct AeadCiphertext {
    std::vector<std::byte> bytes; // ciphertext + 16-byte Poly1305 tag
};

} // namespace ev::crypto
