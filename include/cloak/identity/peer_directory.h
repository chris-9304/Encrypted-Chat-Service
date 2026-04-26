#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace cloak::identity {

// Persistent record for one known peer.
struct PeerRecord {
    cloak::core::PublicKey    signing_public_key;
    cloak::core::PublicKey    kx_public_key;
    cloak::core::Endpoint     last_seen_endpoint;
    std::string            display_name;
    std::string            fingerprint;          // base32(SHA256(signing_pk))
    cloak::core::TrustStatus  trust{cloak::core::TrustStatus::Unknown};
};

// In-memory peer directory with TOFU trust tracking.
// Persisted to/from MessageStore SQLite tables via save_peers() / load_peers().
class PeerDirectory {
public:
    PeerDirectory() = default;

    // Non-copyable, non-movable (owns mutex).
    PeerDirectory(const PeerDirectory&)            = delete;
    PeerDirectory& operator=(const PeerDirectory&) = delete;
    PeerDirectory(PeerDirectory&&)                 = delete;
    PeerDirectory& operator=(PeerDirectory&&)      = delete;

    // Insert or update a record.
    // TOFU logic:
    //   - Unknown → Tofu on first insert.
    //   - Tofu/Verified: if signing_public_key CHANGED → trust = Changed.
    //   - Changed state is preserved until explicitly upgraded by the user.
    // Returns IdentityChanged error when a key change is detected so the
    // caller can alert the user loudly.
    cloak::core::Result<void> upsert(const PeerRecord& record);

    // List all known peers.
    cloak::core::Result<std::vector<PeerRecord>> all() const;

    // Find by fingerprint (base32(SHA256(signing_pk))).
    cloak::core::Result<PeerRecord> find_by_fingerprint(const std::string& fp) const;

    // Find by signing public key bytes.
    cloak::core::Result<PeerRecord> find_by_signing_key(
        const cloak::core::PublicKey& key) const;

    // Upgrade a peer's trust to Verified (user confirmed safety number).
    cloak::core::Result<void> mark_verified(const std::string& fingerprint);

    // Acknowledge a key change (trust goes back to Tofu; alert is cleared).
    cloak::core::Result<void> acknowledge_key_change(const std::string& fingerprint);

private:
    mutable std::mutex      mu_;
    std::vector<PeerRecord> records_;
};

} // namespace cloak::identity
