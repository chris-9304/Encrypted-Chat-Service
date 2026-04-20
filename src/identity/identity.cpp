#include "identity.h"
#include <ev/crypto/crypto.h>
#include <sodium.h>

namespace ev::identity {

Identity::Identity(ev::crypto::SecureBuffer<64> s_sk, ev::core::PublicKey s_pk, 
                   ev::crypto::SecureBuffer<32> k_sk, ev::core::PublicKey k_pk)
    : signing_sk_(std::move(s_sk)), signing_pk_(s_pk),
      kx_sk_(std::move(k_sk)), kx_pk_(k_pk) {}

ev::core::Result<Identity> Identity::generate() {
    auto sign_kp = ev::crypto::Crypto::ed25519_keypair();
    if (!sign_kp.has_value()) return std::unexpected(sign_kp.error());

    auto kx_kp = ev::crypto::Crypto::kx_keypair();
    if (!kx_kp.has_value()) return std::unexpected(kx_kp.error());

    return Identity(std::move(sign_kp->private_key), sign_kp->public_key,
                    std::move(kx_kp->private_key), kx_kp->public_key);
}

const ev::core::PublicKey& Identity::signing_public() const { return signing_pk_; }
const ev::core::PublicKey& Identity::kx_public() const { return kx_pk_; }

ev::core::Result<ev::core::Signature> Identity::sign(std::span<const std::byte> msg) const {
    return ev::crypto::Crypto::sign_detached(signing_sk_, msg);
}

ev::core::Result<ev::crypto::SharedSecret> Identity::agree(const ev::core::PublicKey& peer_kx_pub) const {
    return ev::crypto::Crypto::kx_agree(kx_sk_, peer_kx_pub);
}

std::string Identity::fingerprint() const {
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, signing_pk_.bytes.data(), signing_pk_.bytes.size());

    // Simple Base32 encoding (RFC4648)
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string b32;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    for (size_t i = 0; i < sizeof(hash); ++i) {
        buffer = (buffer << 8) | hash[i];
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            b32.push_back(alphabet[(buffer >> bits_left) & 0x1F]);
        }
        if (b32.size() >= 12) break; // We need 12 chars + 2 dashes = 14 total or similar, let's just grab 12 chars
    }

    // Format: XXXX-XXXX-XXXX
    std::string fp;
    fp += b32.substr(0, 4) + "-" + b32.substr(4, 4) + "-" + b32.substr(8, 4);
    return fp;
}

} // namespace ev::identity
