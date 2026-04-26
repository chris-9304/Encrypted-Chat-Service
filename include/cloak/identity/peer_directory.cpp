#include <cloak/identity/peer_directory.h>
#include <algorithm>

namespace cloak::identity {

using namespace cloak::core;

// TOFU upsert.
// - First contact → TrustStatus::Tofu.
// - Repeat contact, same key → update metadata, preserve trust.
// - Repeat contact, CHANGED key → TrustStatus::Changed, return IdentityChanged error.
Result<void> PeerDirectory::upsert(const PeerRecord& record) {
    std::lock_guard lock(mu_);

    auto it = std::find_if(records_.begin(), records_.end(),
                           [&](const PeerRecord& r) {
                               return r.fingerprint == record.fingerprint;
                           });

    if (it == records_.end()) {
        // New peer.
        PeerRecord r     = record;
        if (r.trust == TrustStatus::Unknown) r.trust = TrustStatus::Tofu;
        records_.push_back(std::move(r));
        return {};
    }

    // Existing peer — check if signing key changed.
    if (it->signing_public_key.bytes != record.signing_public_key.bytes) {
        it->signing_public_key  = record.signing_public_key;
        it->kx_public_key       = record.kx_public_key;
        it->last_seen_endpoint  = record.last_seen_endpoint;
        it->display_name        = record.display_name;
        it->trust               = TrustStatus::Changed;

        return std::unexpected(
            Error::from(ErrorCode::IdentityChanged,
                        "Peer " + record.display_name +
                        " signing key changed — VERIFY safety number!"));
    }

    // Key unchanged — update mutable fields.
    it->kx_public_key      = record.kx_public_key;
    it->last_seen_endpoint = record.last_seen_endpoint;
    it->display_name       = record.display_name;
    // Preserve existing trust level.
    return {};
}

Result<std::vector<PeerRecord>> PeerDirectory::all() const {
    std::lock_guard lock(mu_);
    return records_;
}

Result<PeerRecord> PeerDirectory::find_by_fingerprint(
    const std::string& fp) const {

    std::lock_guard lock(mu_);
    auto it = std::find_if(records_.begin(), records_.end(),
                           [&](const PeerRecord& r) {
                               return r.fingerprint == fp;
                           });
    if (it == records_.end()) {
        return std::unexpected(
            Error::from(ErrorCode::PeerNotFound,
                        "Peer not found: " + fp));
    }
    return *it;
}

Result<PeerRecord> PeerDirectory::find_by_signing_key(
    const PublicKey& key) const {

    std::lock_guard lock(mu_);
    auto it = std::find_if(records_.begin(), records_.end(),
                           [&](const PeerRecord& r) {
                               return r.signing_public_key.bytes == key.bytes;
                           });
    if (it == records_.end()) {
        return std::unexpected(
            Error::from(ErrorCode::PeerNotFound,
                        "Peer not found by signing key"));
    }
    return *it;
}

Result<void> PeerDirectory::mark_verified(const std::string& fingerprint) {
    std::lock_guard lock(mu_);
    auto it = std::find_if(records_.begin(), records_.end(),
                           [&](const PeerRecord& r) {
                               return r.fingerprint == fingerprint;
                           });
    if (it == records_.end()) {
        return std::unexpected(
            Error::from(ErrorCode::PeerNotFound,
                        "Peer not found: " + fingerprint));
    }
    it->trust = TrustStatus::Verified;
    return {};
}

Result<void> PeerDirectory::acknowledge_key_change(
    const std::string& fingerprint) {

    std::lock_guard lock(mu_);
    auto it = std::find_if(records_.begin(), records_.end(),
                           [&](const PeerRecord& r) {
                               return r.fingerprint == fingerprint;
                           });
    if (it == records_.end()) {
        return std::unexpected(
            Error::from(ErrorCode::PeerNotFound,
                        "Peer not found: " + fingerprint));
    }
    it->trust = TrustStatus::Tofu;
    return {};
}

} // namespace cloak::identity
