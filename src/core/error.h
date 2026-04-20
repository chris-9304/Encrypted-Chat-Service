#pragma once

#include <string>
#include <expected>
#include <memory>
#include <optional>

namespace ev::core {

enum class ErrorCode {
    Success = 0,
    NotImplemented,
    // TODO(M1.x): Add more error codes as needed
};

struct Error {
    ErrorCode code;
    std::string message;
    std::optional<std::unique_ptr<Error>> cause;
};

template <typename T>
using Result = std::expected<T, Error>;

} // namespace ev::core
