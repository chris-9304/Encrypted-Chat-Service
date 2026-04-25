#include <ev/transport/mailbox_transport.h>
#include <algorithm>
#include <chrono>
#include <cstring>

namespace ev::transport {

using Clock = std::chrono::system_clock;

// ── Mailbox API ───────────────────────────────────────────────────────────────

ev::core::Result<void> LanMailboxTransport::enqueue(MailboxEnvelope env) {
    std::lock_guard lock(mu_);

    const size_t msg_bytes = env.ciphertext.size();
    if (queue_bytes_ + msg_bytes > kMaxQueueBytes) {
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::StorageError,
            "Mailbox queue full for recipient"));
    }

    queue_bytes_ += msg_bytes;
    queue_.push_back(std::move(env));
    return {};
}

ev::core::Result<std::vector<MailboxEnvelope>> LanMailboxTransport::drain(
    const ev::core::PublicKey& recipient_signing_key) {

    std::lock_guard lock(mu_);

    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    std::vector<MailboxEnvelope> result;
    std::vector<MailboxEnvelope> remaining;

    for (auto& env : queue_) {
        const bool for_recipient =
            env.recipient_signing_key.bytes == recipient_signing_key.bytes;
        const bool expired =
            env.expires_at_ms > 0 && env.expires_at_ms <= now_ms;

        if (for_recipient && !expired) {
            queue_bytes_ -= env.ciphertext.size();
            result.push_back(std::move(env));
        } else if (!for_recipient && !expired) {
            remaining.push_back(std::move(env));
        } else {
            // expired — discard
            queue_bytes_ -= env.ciphertext.size();
        }
    }
    queue_ = std::move(remaining);
    return result;
}

uint64_t LanMailboxTransport::purge_expired() {
    std::lock_guard lock(mu_);

    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    uint64_t purged = 0;
    auto it = std::remove_if(queue_.begin(), queue_.end(),
        [&](const MailboxEnvelope& env) {
            if (env.expires_at_ms > 0 && env.expires_at_ms <= now_ms) {
                queue_bytes_ -= env.ciphertext.size();
                ++purged;
                return true;
            }
            return false;
        });
    queue_.erase(it, queue_.end());
    return purged;
}

// ── Transport interface ───────────────────────────────────────────────────────

void LanMailboxTransport::seed_receive_buffer(std::vector<std::byte> data) {
    std::lock_guard lock(mu_);
    rx_buf_ = std::move(data);
    rx_pos_ = 0;
}

ev::core::Result<void> LanMailboxTransport::send(std::span<const std::byte> /*data*/) {
    // In the mailbox replay path the "send" direction is unused; callers
    // never call send() on this transport type.
    return {};
}

ev::core::Result<std::vector<std::byte>> LanMailboxTransport::receive(
    size_t exact_bytes) {

    std::lock_guard lock(mu_);

    if (rx_pos_ + exact_bytes > rx_buf_.size()) {
        open_ = false;
        return std::unexpected(ev::core::Error::from(
            ev::core::ErrorCode::TransportError,
            "Mailbox receive buffer exhausted"));
    }

    std::vector<std::byte> out(
        rx_buf_.begin() + static_cast<ptrdiff_t>(rx_pos_),
        rx_buf_.begin() + static_cast<ptrdiff_t>(rx_pos_ + exact_bytes));
    rx_pos_ += exact_bytes;
    return out;
}

ev::core::Result<void> LanMailboxTransport::close() {
    open_ = false;
    return {};
}

bool LanMailboxTransport::is_open() const {
    return open_.load(std::memory_order_relaxed);
}

} // namespace ev::transport
