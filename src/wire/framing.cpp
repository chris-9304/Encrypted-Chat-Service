#include "framing.h"

namespace ev::wire {

ev::core::Result<std::vector<uint8_t>> Framing::frame_payload(std::span<const uint8_t>) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<std::vector<uint8_t>> Framing::unframe_payload(std::span<const uint8_t>, size_t&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::wire
