#pragma once

#include <ev/core/error.h>
#include <cstdint>
#include <span>
#include <vector>

namespace ev::transport {

class Transport {
public:
    virtual ~Transport() = default;

    virtual ev::core::Result<void> send(std::span<const uint8_t> data) = 0;
    virtual ev::core::Result<std::vector<uint8_t>> receive() = 0;
    virtual ev::core::Result<void> close() = 0;

    // Default implementations for generic interfaces
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    Transport(Transport&&) = delete;
    Transport& operator=(Transport&&) = delete;

protected:
    Transport() = default;
};

} // namespace ev::transport
