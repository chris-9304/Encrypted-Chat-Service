#pragma once

#include "discovery_service.h"

namespace ev::discovery {

class MdnsDiscoveryService final : public DiscoveryService {
public:
    MdnsDiscoveryService() = default;
    ~MdnsDiscoveryService() override = default;

    ev::core::Result<void> start_advertising(const LocalAdvertisement& adv) override;
    ev::core::Result<void> stop_advertising() override;
    ev::core::Result<std::vector<DiscoveredPeer>> get_discovered_peers() const override;

private:
    // TODO(M1.x): Win32 DNS registry hooks
};

} // namespace ev::discovery
