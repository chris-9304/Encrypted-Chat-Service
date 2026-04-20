#include "peer_directory.h"

namespace ev::identity {

ev::core::Result<void> PeerDirectory::add_or_update_peer(const PeerRecord&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<PeerRecord> PeerDirectory::get_peer(const ev::core::PeerId&) const {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<std::vector<PeerRecord>> PeerDirectory::list_peers() const {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> PeerDirectory::set_trust_status(const ev::core::PeerId&, TrustStatus) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

} // namespace ev::identity
