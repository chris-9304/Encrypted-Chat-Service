#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/crypto/types.h>
#include <span>
#include <string>

namespace ev::identity {

// Long-term cryptographic identity for one installed instance.
// Ed25519 signing keypair + X25519 key-agreement keypair.
// Persisted to disk encrypted with Argon2id(passphrase) + XChaCha20-Poly1305.
class Identity {
public:
    // Generate a fresh random identity (keypairs).
    static ev::core::Result<Identity> generate();

    // Persist to an encrypted file.  Derives an encryption key from passphrase
    // via Argon2id; stores salt + ciphertext.  Overwrites existing file.
    ev::core::Result<void> save(const ev::core::Path& path,
                                std::span<const std::byte> passphrase) const;

    // Load from an encrypted file.  Derives key from passphrase; returns
    // AuthenticationFailed if passphrase is wrong or file is corrupt.
    static ev::core::Result<Identity> load(const ev::core::Path& path,
                                           std::span<const std::byte> passphrase);

    // True if the file exists and looks like a valid identity blob.
    static bool exists(const ev::core::Path& path);

    const ev::core::PublicKey& signing_public() const;
    const ev::core::PublicKey& kx_public() const;

    // 12-char base32 fingerprint of the signing public key (XX XX XX format).
    std::string fingerprint() const;

    // 60-digit safety number computed from both parties' signing public keys.
    // Deterministic and symmetric: safety_number(a,b) == safety_number(b,a).
    static ev::core::SafetyNumber safety_number(const ev::core::PublicKey& a,
                                                const ev::core::PublicKey& b);

    ev::core::Result<ev::core::Signature> sign(std::span<const std::byte> msg) const;

    ev::core::Result<ev::crypto::SharedSecret> agree(
        const ev::core::PublicKey& peer_kx_pub) const;

    // Move-only (holds SecureBuffer members).
    Identity(Identity&&)            = default;
    Identity& operator=(Identity&&) = default;
    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;

private:
    ev::crypto::SecureBuffer<64> signing_sk_;
    ev::crypto::SecureBuffer<32> kx_sk_;
    ev::core::PublicKey          signing_pk_;
    ev::core::PublicKey          kx_pk_;

    Identity(ev::crypto::SecureBuffer<64> s_sk, ev::core::PublicKey s_pk,
             ev::crypto::SecureBuffer<32> k_sk, ev::core::PublicKey k_pk);
};

} // namespace ev::identity
