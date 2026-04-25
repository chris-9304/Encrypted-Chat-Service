#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace ev::core {

// ── Fixed-size byte-array wrappers ──────────────────────────────────────────

struct PeerId {
    std::array<uint8_t, 32> bytes{};
    bool operator==(const PeerId&) const = default;
};

struct SessionId {
    uint64_t id{0};
    bool operator==(const SessionId&) const = default;
};

struct MessageId {
    std::array<uint8_t, 16> bytes{};
    bool operator==(const MessageId&) const = default;
};

struct FileId {
    std::array<uint8_t, 16> bytes{};
    bool operator==(const FileId&) const = default;
};

// 32-byte public key (Ed25519 or X25519).
struct PublicKey {
    std::array<uint8_t, 32> bytes{};
    bool operator==(const PublicKey&) const = default;
};

// 24-byte nonce for XChaCha20-Poly1305.
struct Nonce {
    std::array<uint8_t, 24> bytes{};
};

// Ed25519 detached signature (64 bytes).
struct Signature {
    std::array<uint8_t, 64> bytes{};
};

// Safety number: 60-digit decimal derived from both parties' signing keys.
struct SafetyNumber {
    std::string digits; // exactly 60 decimal chars
};

// Wall-clock timestamp (ms since epoch, UTC).
using Timestamp = std::chrono::time_point<std::chrono::system_clock,
                                          std::chrono::milliseconds>;

// Network endpoint.
struct Endpoint {
    std::string address;
    uint16_t    port{0};
};

// Filesystem path alias.
using Path = std::filesystem::path;

// ── TOFU trust model ────────────────────────────────────────────────────────

enum class TrustStatus : uint8_t {
    Unknown  = 0, // never seen before
    Tofu     = 1, // first contact; key stored, not yet verified
    Verified = 2, // user confirmed safety number out-of-band
    Changed  = 3, // key changed since last contact — ALERT required
};

} // namespace ev::core
