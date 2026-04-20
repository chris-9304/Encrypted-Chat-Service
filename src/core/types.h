#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace ev::core {

struct PeerId {
    std::array<uint8_t, 32> bytes;
};

struct SessionId {
    uint64_t id;
};

struct MessageId {
    std::array<uint8_t, 16> bytes;
};

struct PublicKey {
    std::array<uint8_t, 32> bytes;
};

struct Nonce {
    std::array<uint8_t, 24> bytes;
};

struct Signature {
    std::array<uint8_t, 64> bytes;
};

struct SafetyNumber {
    std::string value;
};

struct Timestamp {
    uint64_t unix_epoch_ms;
};

struct Endpoint {
    std::string address;
    uint16_t port;
};

struct Path {
    std::string generic_string;
};

} // namespace ev::core
