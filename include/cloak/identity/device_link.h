#pragma once

#include <cloak/core/types.h>
#include <array>
#include <string>

namespace cloak::identity {

// A device is uniquely identified by its Ed25519 signing public key.
// The primary device signs secondary device certificates so peers can
// verify that a secondary device is legitimately linked to the primary.

enum class DeviceRole : uint8_t {
    Primary   = 0, // first/main device; can authorize secondaries
    Secondary = 1, // linked device; presents a cert signed by primary
};

// A device certificate is created by the PRIMARY device and given to the
// secondary.  Peers receive it during the handshake's DeviceLink inner
// payload and verify the primary_signature.
//
// On-wire (inside AEAD inner payload, after DeviceLink byte):
//   device_pub        [32]   secondary device's signing public key
//   primary_pub       [32]   primary device's signing public key
//   primary_signature [64]   Ed25519_sign(primary_sk, device_pub || primary_pub)
//   device_name_len   [2 BE]
//   device_name       [...]  human-readable device name, max 64 chars
struct DeviceCert {
    cloak::core::PublicKey device_pub;    // secondary's signing key
    cloak::core::PublicKey primary_pub;   // primary's signing key (identity root)
    cloak::core::Signature primary_sig;   // signed by primary over (device_pub || primary_pub)
    std::string         device_name;   // "Alice's Phone", max 64 chars
};

// Information we keep about a known linked device (ours or a peer's).
struct LinkedDevice {
    cloak::core::PublicKey device_signing_pub;
    cloak::core::PublicKey primary_signing_pub;
    std::string         device_name;
    DeviceRole          role{DeviceRole::Secondary};
    bool                is_self{false};  // true if this is one of our own devices
};

} // namespace cloak::identity
