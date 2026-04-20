#pragma once

#include <vector>
#include <stdexcept>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <memoryapi.h>

namespace ev::crypto {

template <size_t N>
class SecureBuffer {
public:
    SecureBuffer() {
        if (!VirtualLock(data_, N)) {
            // Memory locking failure is exceptional
            throw std::runtime_error("VirtualLock failed");
        }
    }

    ~SecureBuffer() {
        SecureZeroMemory(data_, N);
        VirtualUnlock(data_, N);
    }

    // Move-only, non-copyable requirements
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept {
        // Move construction safely swaps data implicitly or copies and zero-clears the old buffer
        // In a true RAII locked buffer array, we copy the bytes and zero the old one.
        if (this != &other) {
            VirtualLock(data_, N);
            std::copy(std::begin(other.data_), std::end(other.data_), std::begin(data_));
            SecureZeroMemory(other.data_, N);
        }
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            std::copy(std::begin(other.data_), std::end(other.data_), std::begin(data_));
            SecureZeroMemory(other.data_, N);
        }
        return *this;
    }

    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    constexpr size_t size() const { return N; }

private:
    uint8_t data_[N];
};

} // namespace ev::crypto
