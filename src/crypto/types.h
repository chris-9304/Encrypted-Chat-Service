#pragma once

#include "secure_buffer.h"

namespace ev::crypto {

struct KeyPair {
    SecureBuffer<32> private_key;
    SecureBuffer<32> public_key;
};

struct SharedSecret {
    SecureBuffer<32> secret;
};

struct AeadCiphertext {
    std::vector<uint8_t> payload;
};

} // namespace ev::crypto
