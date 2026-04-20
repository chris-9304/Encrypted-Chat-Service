#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <vector>
#include <string>

namespace ev::identity {

enum class TrustStatus {
    Unknown,
    Tofu,
    Verified,
    Changed
};

struct PeerRecord {
    ev::core::PeerId id;
    std::string display_name;
    ev::core::PublicKey signing_public_key;
    TrustStatus trust_status;
};

class PeerDirectory {
public:
    PeerDirectory() = default;

    ev::core::Result<void> add_or_update_peer(const PeerRecord& record);
    ev::core::Result<PeerRecord> get_peer(const ev::core::PeerId& id) const;
    ev::core::Result<std::vector<PeerRecord>> list_peers() const;
    ev::core::Result<void> set_trust_status(const ev::core::PeerId& id, TrustStatus status);

private:
    // TODO(M1.x): Peer database / storage layer integration
};

} // namespace ev::identity
