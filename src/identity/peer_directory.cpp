#include "peer_directory.h"
#include <algorithm>

namespace ev::identity {

ev::core::Result<void> PeerDirectory::upsert(const PeerRecord& record) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& r : records_) {
        if (r.fingerprint == record.fingerprint) {
            r = record;
            return {};
        }
    }
    records_.push_back(record);
    return {};
}

ev::core::Result<std::vector<PeerRecord>> PeerDirectory::all() const {
    std::lock_guard<std::mutex> lock(mu_);
    return records_;
}

ev::core::Result<PeerRecord> PeerDirectory::find_by_fingerprint(const std::string& fp) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = std::find_if(records_.begin(), records_.end(),
                           [&fp](const PeerRecord& r) { return r.fingerprint == fp; });
    if (it == records_.end()) {
        return std::unexpected(ev::core::Error{
            ev::core::ErrorCode::StorageError,
            "Peer not found: " + fp,
            std::nullopt
        });
    }
    return *it;
}

} // namespace ev::identity
