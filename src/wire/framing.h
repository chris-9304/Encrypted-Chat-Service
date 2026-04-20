#pragma once

#include <ev/core/error.h>
#include <vector>
#include <cstdint>
#include <span>

namespace ev::wire {

class Framing {
public:
    static ev::core::Result<std::vector<uint8_t>> frame_payload(std::span<const uint8_t> payload);
    static ev::core::Result<std::vector<uint8_t>> unframe_payload(std::span<const uint8_t> buffer, size_t& bytes_consumed);
};

} // namespace ev::wire
