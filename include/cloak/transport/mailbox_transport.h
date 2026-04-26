#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/transport/transport.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <queue>
#include <vector>

namespace cloak::transport {

// A pending message held by the mailbox on behalf of an offline peer.
struct MailboxEnvelope {
    cloak::core::PublicKey  recipient_signing_key; // who the message is for
    std::vector<std::byte> ciphertext;           // AEAD-sealed by sender (E2E)
    std::chrono::system_clock::time_point queued_at;
    int64_t                expires_at_ms{0};     // 0 = no expiry
};

// LanMailboxTransport — store-and-forward transport for offline LAN delivery.
//
// A trusted peer on the LAN ("mailbox peer") accepts encrypted messages on
// behalf of offline recipients.  The sender encrypts for the recipient (E2E);
// the mailbox never sees plaintext.  When the recipient comes online they
// connect to the mailbox peer and drain their queue.
//
// Phase 2 implementation is in-memory only.  Phase 3 will persist the queue
// to the mailbox peer's MessageStore so it survives restarts.
//
// Security properties:
// - All stored ciphertext is encrypted by the sender for the recipient;
//   the mailbox peer cannot decrypt it.
// - Queued messages are bounded: kMaxQueueBytes per recipient, kMaxAge per
//   message.  Expired messages are purged before each drain.
// - The mailbox peer authenticates recipients via their signing key.

class LanMailboxTransport final : public Transport {
public:
    static constexpr size_t  kMaxQueueBytes   = 64 * 1024 * 1024; // 64 MiB
    static constexpr int64_t kMaxAgeMs        = 7 * 24 * 3600 * 1000LL; // 7 days

    LanMailboxTransport() = default;
    ~LanMailboxTransport() override = default;

    // ── Mailbox API (called by the mailbox peer) ──────────────────────────────

    // Enqueue a message for an offline recipient.
    cloak::core::Result<void> enqueue(MailboxEnvelope env);

    // Drain all queued messages for a recipient (called when they reconnect).
    cloak::core::Result<std::vector<MailboxEnvelope>> drain(
        const cloak::core::PublicKey& recipient_signing_key);

    // Purge expired messages.  Returns count deleted.
    uint64_t purge_expired();

    // ── Transport interface (for direct peer-to-peer when both online) ─────────
    // When the recipient comes online the mailbox flushes their queue via a
    // virtual byte stream that replays the stored frames.

    cloak::core::Result<void> send(std::span<const std::byte> data) override;
    cloak::core::Result<std::vector<std::byte>> receive(size_t exact_bytes) override;
    cloak::core::Result<void> close() override;
    bool is_open() const override;

    // Seed the internal receive buffer (used by the drain path to replay frames).
    void seed_receive_buffer(std::vector<std::byte> data);

private:
    mutable std::mutex                              mu_;
    std::vector<MailboxEnvelope>                    queue_;
    size_t                                          queue_bytes_{0};

    // Virtual receive buffer (for the drain / replay path).
    std::vector<std::byte>                          rx_buf_;
    size_t                                          rx_pos_{0};
    std::atomic<bool>                               open_{true};
};

} // namespace cloak::transport
