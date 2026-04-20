#pragma once

#include "secure_buffer.h"
#include <ev/core/types.h>
#include <vector>

namespace ev::crypto {

struct KeyPair {
    SecureBuffer<32> private_key;
    ev::core::PublicKey public_key;
};

struct Ed25519KeyPair {
    SecureBuffer<64> private_key;
    ev::core::PublicKey public_key;
};

struct SharedSecret {
    SecureBuffer<32> secret;
};

struct AeadCiphertext {
    std::vector<uint8_t> payload; // Used in M1.1, now obsolete but keeping for structure if needed
};

} // namespace ev::crypto
