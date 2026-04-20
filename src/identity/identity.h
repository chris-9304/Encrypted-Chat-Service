#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/types.h>
#include <string>

namespace ev::identity {

class Identity {
public:
    static ev::core::Result<Identity> generate(const std::string& passphrase);
    static ev::core::Result<Identity> load(const ev::core::Path& path, const std::string& passphrase);
    ev::core::Result<void> save(const ev::core::Path& path) const;

    const ev::core::PublicKey& signing_public_key() const;
    const ev::core::PublicKey& agreement_public_key() const;
    ev::core::SafetyNumber safety_number(const ev::core::PublicKey& peer_key) const;

private:
    Identity() = default;
    
    // TODO(M1.x): private state holding actual keys (ev::crypto::KeyPair)
};

} // namespace ev::identity
