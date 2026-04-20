#pragma once

#include <spdlog/spdlog.h>
#include <string>

namespace ev::core {

// A trivial secure-logging wrapper. Will not emit sensitive strings.
template <typename T>
inline void log_sensitive(const std::string& msg, const T&) {
    spdlog::info("{} <redacted>", msg);
}

// Overload for just sensitive markers without variables
inline void log_sensitive(const std::string& msg) {
    spdlog::info("{} <redacted>", msg);
}

} // namespace ev::core
