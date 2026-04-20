#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/types.h>
#include <ev/crypto/secure_buffer.h>
#include <span>
#include <string>

namespace ev::identity {

class Identity {
public:
    static ev::core::Result<Identity> generate();

    const ev::core::PublicKey& signing_public() const;
    const ev::core::PublicKey& kx_public() const;
    std::string fingerprint() const;

    ev::core::Result<ev::core::Signature> sign(std::span<const std::byte> msg) const;
    ev::core::Result<ev::crypto::SharedSecret> agree(const ev::core::PublicKey& peer_kx_pub) const;

private:
    ev::crypto::SecureBuffer<64> signing_sk_;
    ev::crypto::SecureBuffer<32> kx_sk_;
    ev::core::PublicKey signing_pk_;
    ev::core::PublicKey kx_pk_;

    Identity(ev::crypto::SecureBuffer<64> s_sk, ev::core::PublicKey s_pk, 
             ev::crypto::SecureBuffer<32> k_sk, ev::core::PublicKey k_pk);
};

} // namespace ev::identity
