#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/crypto/secure_buffer.h>
#include <cloak/crypto/types.h>
#include <span>
#include <string>

namespace cloak::identity {

// Long-term cryptographic identity for one installed instance.
// Ed25519 signing keypair + X25519 key-agreement keypair.
// Persisted to disk encrypted with Argon2id(passphrase) + XChaCha20-Poly1305.
class Identity {
public:
    // Generate a fresh random identity (keypairs).
    static cloak::core::Result<Identity> generate();

    // Persist to an encrypted file.  Derives an encryption key from passphrase
    // via Argon2id; stores salt + ciphertext.  Overwrites existing file.
    cloak::core::Result<void> save(const cloak::core::Path& path,
                                std::span<const std::byte> passphrase) const;

    // Load from an encrypted file.  Derives key from passphrase; returns
    // AuthenticationFailed if passphrase is wrong or file is corrupt.
    static cloak::core::Result<Identity> load(const cloak::core::Path& path,
                                           std::span<const std::byte> passphrase);

    // True if the file exists and looks like a valid identity blob.
    static bool exists(const cloak::core::Path& path);

    const cloak::core::PublicKey& signing_public() const;
    const cloak::core::PublicKey& kx_public() const;

    // 12-char base32 fingerprint of the signing public key (XX XX XX format).
    std::string fingerprint() const;

    // 60-digit safety number computed from both parties' signing public keys.
    // Deterministic and symmetric: safety_number(a,b) == safety_number(b,a).
    static cloak::core::SafetyNumber safety_number(const cloak::core::PublicKey& a,
                                                const cloak::core::PublicKey& b);

    cloak::core::Result<cloak::core::Signature> sign(std::span<const std::byte> msg) const;

    cloak::core::Result<cloak::crypto::SharedSecret> agree(
        const cloak::core::PublicKey& peer_kx_pub) const;

    // Move-only (holds SecureBuffer members).
    Identity(Identity&&)            = default;
    Identity& operator=(Identity&&) = default;
    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;

private:
    cloak::crypto::SecureBuffer<64> signing_sk_;
    cloak::crypto::SecureBuffer<32> kx_sk_;
    cloak::core::PublicKey          signing_pk_;
    cloak::core::PublicKey          kx_pk_;

    Identity(cloak::crypto::SecureBuffer<64> s_sk, cloak::core::PublicKey s_pk,
             cloak::crypto::SecureBuffer<32> k_sk, cloak::core::PublicKey k_pk);
};

} // namespace cloak::identity
