#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <vector>

namespace ev::discovery {

struct LocalAdvertisement {
    ev::core::PublicKey signing_public_key;
    uint16_t port;
};

struct DiscoveredPeer {
    ev::core::PublicKey signing_public_key;
    ev::core::Endpoint endpoint;
};

class DiscoveryService {
public:
    virtual ~DiscoveryService() = default;

    virtual ev::core::Result<void> start_advertising(const LocalAdvertisement& adv) = 0;
    virtual ev::core::Result<void> stop_advertising() = 0;
    virtual ev::core::Result<std::vector<DiscoveredPeer>> get_discovered_peers() const = 0;

    DiscoveryService(const DiscoveryService&) = delete;
    DiscoveryService& operator=(const DiscoveryService&) = delete;
    DiscoveryService(DiscoveryService&&) = delete;
    DiscoveryService& operator=(DiscoveryService&&) = delete;

protected:
    DiscoveryService() = default;
};

} // namespace ev::discovery
