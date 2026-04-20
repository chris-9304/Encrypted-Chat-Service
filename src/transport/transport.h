#pragma once

#include <ev/core/error.h>
#include <cstdint>
#include <span>
#include <vector>

namespace ev::transport {

class Transport {
public:
    virtual ~Transport() = default;

    virtual ev::core::Result<void> send(std::span<const std::byte> data) = 0;
    virtual ev::core::Result<std::vector<std::byte>> receive(size_t exact_bytes) = 0;
    virtual ev::core::Result<void> close() = 0;
    virtual bool is_open() const = 0;

    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    Transport(Transport&&) = delete;
    Transport& operator=(Transport&&) = delete;

protected:
    Transport() = default;
};

} // namespace ev::transport
