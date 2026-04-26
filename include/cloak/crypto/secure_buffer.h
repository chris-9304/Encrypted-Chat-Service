#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace cloak::crypto {

// Owning, fixed-size buffer for secret key material.
// - VirtualLock on construction (best-effort, requires PROCESS_VM_OPERATION).
// - SecureZeroMemory on destruction.
// - Move-only: never copied, never logged, never serialized unencrypted.
template <size_t N>
class SecureBuffer {
public:
    SecureBuffer() {
        VirtualLock(buf_.data(), N);
    }

    ~SecureBuffer() {
        SecureZeroMemory(buf_.data(), N);
        VirtualUnlock(buf_.data(), N);
    }

    // Move-only.
    SecureBuffer(SecureBuffer&& o) noexcept : buf_(o.buf_) {
        SecureZeroMemory(o.buf_.data(), N);
    }
    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            SecureZeroMemory(buf_.data(), N);
            buf_ = o.buf_;
            SecureZeroMemory(o.buf_.data(), N);
        }
        return *this;
    }
    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    uint8_t*       data() noexcept       { return buf_.data(); }
    const uint8_t* data() const noexcept { return buf_.data(); }
    static constexpr size_t size() noexcept { return N; }

    uint8_t&       operator[](size_t i)       { return buf_[i]; }
    const uint8_t& operator[](size_t i) const { return buf_[i]; }

    auto begin()       { return buf_.begin(); }
    auto end()         { return buf_.end(); }
    auto begin() const { return buf_.begin(); }
    auto end()   const { return buf_.end(); }

private:
    std::array<uint8_t, N> buf_{};
};

} // namespace cloak::crypto
