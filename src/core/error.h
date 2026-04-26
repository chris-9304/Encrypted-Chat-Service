#pragma once

#include <expected>
#include <memory>
#include <optional>
#include <string>

namespace ev::core {

enum class ErrorCode : uint32_t {
    Success              = 0,
    NotImplemented       = 1,
    CryptoError          = 2,
    AuthenticationFailed = 3,
    DecryptionFailed     = 4,
    CounterMismatch      = 5,
    FramingError         = 6,
    TransportError       = 7,
    StorageError         = 8,
    InvalidArgument      = 9,
    PeerNotFound         = 10,
    IdentityChanged      = 11, // TOFU alert: peer key changed
    NotEstablished       = 12,
    IoError              = 13,
};

// Error is copyable so std::expected<T, Error> satisfies C++ requirements.
// cause uses shared_ptr to allow copying without deep allocation.
struct Error {
    ErrorCode                             code{ErrorCode::Success};
    std::string                           message;
    std::shared_ptr<Error>                cause; // nullable

    static Error from(ErrorCode c, std::string msg) {
        return Error{c, std::move(msg), nullptr};
    }
};

template <typename T>
using Result = std::expected<T, Error>;

} // namespace ev::core
