#include "mdns_discovery_win32.h"

namespace ev::discovery {

ev::core::Result<void> MdnsDiscoveryService::start_advertising(const LocalAdvertisement&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> MdnsDiscoveryService::stop_advertising() {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<std::vector<DiscoveredPeer>> MdnsDiscoveryService::get_discovered_peers() const {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::discovery
