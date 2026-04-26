#pragma once

#include <ev/core/error.h>
#include <ev/identity/device_link.h>
#include <ev/identity/identity.h>

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ev::identity {

// Tracks multi-device relationships for this identity.
//
// Primary device flow:
//   1. User runs `/link-device <secondary_pub_hex>` on the primary.
//   2. DeviceRegistry::issue_cert() signs the secondary's pub key.
//   3. The cert is sent to the secondary via any channel (QR code / paste).
//   4. Secondary calls install_own_cert() to store it.
//   5. During handshake, secondary includes the cert as a DeviceLink inner payload.
//   6. Peers call verify_cert() to check the primary signature.
//
// Thread safety: all public methods are mutex-protected.
class DeviceRegistry {
public:
    // Initialize for a PRIMARY device (no cert needed).
    void init_as_primary(const Identity& self, const std::string& device_name);

    // Initialize for a SECONDARY device (cert must have been issued by primary).
    ev::core::Result<void> init_as_secondary(DeviceCert cert);

    // Primary: issue a cert for a secondary device.
    ev::core::Result<DeviceCert> issue_cert(
        const Identity&          self,
        const ev::core::PublicKey& secondary_signing_pub,
        const std::string&         secondary_device_name) const;

    // Verify that a cert was legitimately issued (signature check only).
    static bool verify_cert(const DeviceCert& cert);

    // Register a cert for a known peer's secondary device.
    ev::core::Result<void> register_peer_device(const DeviceCert& cert);

    // Returns true if this instance is a secondary device.
    bool is_secondary() const;

    // Returns a copy of this device's cert (only valid for secondary devices).
    std::optional<DeviceCert> own_cert() const;

    // Returns the primary signing key this device is linked to (secondary only).
    std::optional<ev::core::PublicKey> primary_signing_key() const;

    // Returns all known secondary devices for a given primary signing key.
    std::vector<LinkedDevice> devices_for_primary(
        const ev::core::PublicKey& primary_pub) const;

    // Human-readable device name for this instance.
    const std::string& device_name() const;

private:
    mutable std::mutex mu_;
    std::string        device_name_;
    DeviceRole         role_{DeviceRole::Primary};
    std::optional<DeviceCert> own_cert_; // only set if secondary

    // peer primary_pub → list of their known secondary devices
    std::map<std::array<uint8_t, 32>, std::vector<LinkedDevice>> peer_devices_;
};

} // namespace ev::identity
