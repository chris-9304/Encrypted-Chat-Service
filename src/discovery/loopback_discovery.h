#pragma once

#include <ev/discovery/discovery_service.h>
#include <atomic>
#include <mutex>
#include <optional>

namespace ev::discovery {

// Loopback discovery — for local testing and single-machine demos.
// Does not send any network traffic.  Peers must connect explicitly via --connect.
class LoopbackDiscoveryService final : public DiscoveryService {
public:
    ~LoopbackDiscoveryService() override;

    ev::core::Result<void> start_advertising(const LocalAdvertisement& adv) override;
    ev::core::Result<void> stop_advertising() override;
    ev::core::Result<std::vector<DiscoveredPeer>> get_discovered_peers() const override;

private:
    mutable std::mutex                mu_;
    std::optional<LocalAdvertisement> adv_;
    std::atomic<bool>                 advertising_{false};
};

} // namespace ev::discovery
