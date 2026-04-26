#include <ev/discovery/loopback_discovery.h>

namespace ev::discovery {

LoopbackDiscoveryService::~LoopbackDiscoveryService() {
    static_cast<void>(stop_advertising());
}

ev::core::Result<void> LoopbackDiscoveryService::start_advertising(
    const LocalAdvertisement& adv) {
    std::lock_guard lock(mu_);
    adv_         = adv;
    advertising_ = true;
    return {};
}

ev::core::Result<void> LoopbackDiscoveryService::stop_advertising() {
    std::lock_guard lock(mu_);
    advertising_ = false;
    adv_.reset();
    return {};
}

// Returns empty: loopback discovery doesn't scan the network.
// Peers must be connected explicitly via --connect <host:port>.
ev::core::Result<std::vector<DiscoveredPeer>>
LoopbackDiscoveryService::get_discovered_peers() const {
    return std::vector<DiscoveredPeer>{};
}

} // namespace ev::discovery
