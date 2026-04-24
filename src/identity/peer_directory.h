#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <string>
#include <vector>
#include <mutex>

namespace ev::identity {

struct PeerRecord {
    ev::core::PublicKey signing_public_key;
    ev::core::Endpoint  last_seen_endpoint;
    std::string         display_name;
    std::string         fingerprint;
};

// Phase 1 seam — Phase 2 will persist records to SQLite via MessageStore.
class PeerDirectory {
public:
    PeerDirectory() = default;

    // Non-copyable, non-movable (owns mutex).
    PeerDirectory(const PeerDirectory&)            = delete;
    PeerDirectory& operator=(const PeerDirectory&) = delete;
    PeerDirectory(PeerDirectory&&)                 = delete;
    PeerDirectory& operator=(PeerDirectory&&)      = delete;

    ev::core::Result<void>                    upsert(const PeerRecord& record);
    ev::core::Result<std::vector<PeerRecord>> all() const;
    ev::core::Result<PeerRecord>              find_by_fingerprint(const std::string& fp) const;

private:
    mutable std::mutex       mu_;
    std::vector<PeerRecord>  records_;
};

} // namespace ev::identity
