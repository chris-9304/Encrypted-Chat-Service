#include <ev/identity/device_registry.h>
#include <ev/crypto/crypto.h>
#include <cstring>
#include <span>
#include <stdexcept>

namespace ev::identity {

using namespace ev::core;
using namespace ev::crypto;

namespace {

// Build the message signed by the primary: device_pub || primary_pub.
std::vector<std::byte> cert_signed_body(const PublicKey& device_pub,
                                         const PublicKey& primary_pub) {
    std::vector<std::byte> body(64);
    std::memcpy(body.data(),      device_pub.bytes.data(),  32);
    std::memcpy(body.data() + 32, primary_pub.bytes.data(), 32);
    return body;
}

} // namespace

// ── init ──────────────────────────────────────────────────────────────────────

void DeviceRegistry::init_as_primary(const Identity& /*self*/,
                                      const std::string& name) {
    std::lock_guard lock(mu_);
    device_name_ = name;
    role_        = DeviceRole::Primary;
    own_cert_.reset();
}

Result<void> DeviceRegistry::init_as_secondary(DeviceCert cert) {
    if (!verify_cert(cert)) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Device cert signature invalid"));
    }
    std::lock_guard lock(mu_);
    device_name_ = cert.device_name;
    role_        = DeviceRole::Secondary;
    own_cert_    = std::move(cert);
    return {};
}

// ── issue_cert ────────────────────────────────────────────────────────────────

Result<DeviceCert> DeviceRegistry::issue_cert(
    const Identity&    self,
    const PublicKey&   secondary_signing_pub,
    const std::string& secondary_device_name) const {

    std::lock_guard lock(mu_);
    if (role_ != DeviceRole::Primary) {
        return std::unexpected(Error::from(ErrorCode::InvalidArgument,
                                           "Only primary device can issue certs"));
    }
    if (secondary_device_name.size() > 64) {
        return std::unexpected(Error::from(ErrorCode::InvalidArgument,
                                           "Device name exceeds 64 characters"));
    }

    auto body = cert_signed_body(secondary_signing_pub, self.signing_public());
    auto sig  = self.sign(std::span<const std::byte>(body));
    if (!sig) return std::unexpected(sig.error());

    DeviceCert cert;
    cert.device_pub   = secondary_signing_pub;
    cert.primary_pub  = self.signing_public();
    cert.primary_sig  = *sig;
    cert.device_name  = secondary_device_name;
    return cert;
}

// ── verify_cert ───────────────────────────────────────────────────────────────

bool DeviceRegistry::verify_cert(const DeviceCert& cert) {
    auto body = cert_signed_body(cert.device_pub, cert.primary_pub);
    auto res  = Crypto::verify_detached(
        cert.primary_pub,
        std::span<const std::byte>(body),
        cert.primary_sig);
    return res && *res;
}

// ── register_peer_device ─────────────────────────────────────────────────────

Result<void> DeviceRegistry::register_peer_device(const DeviceCert& cert) {
    if (!verify_cert(cert)) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                           "Peer device cert signature invalid"));
    }

    LinkedDevice ld;
    ld.device_signing_pub  = cert.device_pub;
    ld.primary_signing_pub = cert.primary_pub;
    ld.device_name         = cert.device_name;
    ld.role                = DeviceRole::Secondary;
    ld.is_self             = false;

    std::lock_guard lock(mu_);
    auto& list = peer_devices_[cert.primary_pub.bytes];

    // Avoid duplicates.
    for (const auto& existing : list) {
        if (existing.device_signing_pub.bytes == cert.device_pub.bytes) return {};
    }
    list.push_back(std::move(ld));
    return {};
}

// ── accessors ─────────────────────────────────────────────────────────────────

bool DeviceRegistry::is_secondary() const {
    std::lock_guard lock(mu_);
    return role_ == DeviceRole::Secondary;
}

const std::optional<DeviceCert>& DeviceRegistry::own_cert() const {
    std::lock_guard lock(mu_);
    return own_cert_;
}

std::optional<PublicKey> DeviceRegistry::primary_signing_key() const {
    std::lock_guard lock(mu_);
    if (role_ != DeviceRole::Secondary || !own_cert_) return std::nullopt;
    return own_cert_->primary_pub;
}

std::vector<LinkedDevice> DeviceRegistry::devices_for_primary(
    const PublicKey& primary_pub) const {

    std::lock_guard lock(mu_);
    auto it = peer_devices_.find(primary_pub.bytes);
    if (it == peer_devices_.end()) return {};
    return it->second;
}

const std::string& DeviceRegistry::device_name() const {
    std::lock_guard lock(mu_);
    return device_name_;
}

} // namespace ev::identity
