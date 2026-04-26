#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <string>
#include <vector>

namespace ev::discovery {

// Information this peer broadcasts on the network.
struct LocalAdvertisement {
    std::string         display_name;
    uint16_t            port{0};
    ev::core::PublicKey signing_pub; // base32 in TXT record so peers know who this is
};

// A peer found via discovery.
struct DiscoveredPeer {
    std::string         display_name;
    ev::core::Endpoint  endpoint;
    ev::core::PublicKey signing_pub;
};

// Abstract discovery service.  Phase 1: LoopbackDiscoveryService.
// Phase 2+: MdnsDiscoveryService, InviteCodeDiscovery, RelayDiscovery.
class DiscoveryService {
public:
    virtual ~DiscoveryService() = default;

    virtual ev::core::Result<void> start_advertising(
        const LocalAdvertisement& adv) = 0;

    virtual ev::core::Result<void> stop_advertising() = 0;

    virtual ev::core::Result<std::vector<DiscoveredPeer>>
        get_discovered_peers() const = 0;
};

} // namespace ev::discovery
