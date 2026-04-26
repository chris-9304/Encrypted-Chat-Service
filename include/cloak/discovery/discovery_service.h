#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <string>
#include <vector>

namespace cloak::discovery {

// Information this peer broadcasts on the network.
struct LocalAdvertisement {
    std::string         display_name;
    uint16_t            port{0};
    cloak::core::PublicKey signing_pub; // base32 in TXT record so peers know who this is
};

// A peer found via discovery.
struct DiscoveredPeer {
    std::string         display_name;
    cloak::core::Endpoint  endpoint;
    cloak::core::PublicKey signing_pub;
};

// Abstract discovery service.  Phase 1: LoopbackDiscoveryService.
// Phase 2+: MdnsDiscoveryService, InviteCodeDiscovery, RelayDiscovery.
class DiscoveryService {
public:
    virtual ~DiscoveryService() = default;

    virtual cloak::core::Result<void> start_advertising(
        const LocalAdvertisement& adv) = 0;

    virtual cloak::core::Result<void> stop_advertising() = 0;

    virtual cloak::core::Result<std::vector<DiscoveredPeer>>
        get_discovered_peers() const = 0;
};

} // namespace cloak::discovery
