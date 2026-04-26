#pragma once

#include <cloak/discovery/discovery_service.h>
#include <atomic>
#include <mutex>
#include <optional>

namespace cloak::discovery {

// Loopback discovery — for local testing and single-machine demos.
// Does not send any network traffic.  Peers must connect explicitly via --connect.
class LoopbackDiscoveryService final : public DiscoveryService {
public:
    ~LoopbackDiscoveryService() override;

    cloak::core::Result<void> start_advertising(const LocalAdvertisement& adv) override;
    cloak::core::Result<void> stop_advertising() override;
    cloak::core::Result<std::vector<DiscoveredPeer>> get_discovered_peers() const override;

private:
    mutable std::mutex                mu_;
    std::optional<LocalAdvertisement> adv_;
    std::atomic<bool>                 advertising_{false};
};

} // namespace cloak::discovery
