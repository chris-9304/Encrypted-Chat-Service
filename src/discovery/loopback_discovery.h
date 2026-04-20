#pragma once

#include "discovery_service.h"
#include <mutex>

namespace ev::discovery {

class LoopbackDiscoveryService final : public DiscoveryService {
public:
    LoopbackDiscoveryService() = default;
    ~LoopbackDiscoveryService() override;

    ev::core::Result<void> start_advertising(const LocalAdvertisement& adv) override;
    ev::core::Result<void> stop_advertising() override;
    ev::core::Result<std::vector<DiscoveredPeer>> get_discovered_peers() const override;

private:
    std::mutex mu_;
    bool advertising_{false};
    LocalAdvertisement adv_;
    
    // In a real loopback UDP broadcaster, we'd use Boost.Asio. 
    // To strictly pass demo, simulated file-based or port-scanning works.
    // For pure port scanning, we can just return empty and let manual connections work,
    // or actually scan 13370-13380.
    // Actually, scanning ports to find peers is reliable.
};

} // namespace ev::discovery
