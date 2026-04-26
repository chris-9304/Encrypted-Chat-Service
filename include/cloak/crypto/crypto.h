#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/crypto/secure_buffer.h>
#include <cloak/crypto/types.h>
#include <cstddef>
#include <span>
#include <vector>

namespace cloak::crypto {

// Static facade over libsodium.  Every other class calls ONLY this.
// sodium_init() is called exactly once via initialize().
// All methods are thread-safe after initialize().
class Crypto {
public:
    // Must be called once before any other crypto operation.
    static cloak::core::Result<void> initialize();

    // ── Key generation ────────────────────────────────────────────────────────

    // X25519 key-exchange keypair.
    static cloak::core::Result<KeyPair> kx_keypair();

    // Ed25519 signing keypair.
    static cloak::core::Result<Ed25519KeyPair> ed25519_keypair();

    // ── Key agreement ─────────────────────────────────────────────────────────

    // X25519 scalar multiplication.  Rejects low-order points.
    static cloak::core::Result<SharedSecret> kx_agree(
        const SecureBuffer<32>& sk, const cloak::core::PublicKey& peer_pk);

    // ── Signing ───────────────────────────────────────────────────────────────

    static cloak::core::Result<cloak::core::Signature> sign_detached(
        const SecureBuffer<64>& sk, std::span<const std::byte> msg);

    static cloak::core::Result<bool> verify_detached(
        const cloak::core::PublicKey& pk,
        std::span<const std::byte>  msg,
        const cloak::core::Signature&  sig);

    // ── AEAD (XChaCha20-Poly1305) ─────────────────────────────────────────────

    // Nonce must be exactly 24 bytes.  Returns ciphertext + 16-byte tag.
    static cloak::core::Result<std::vector<std::byte>> aead_encrypt(
        const SecureBuffer<32>&    key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> aad,
        std::span<const std::byte> plaintext);

    // Returns plaintext on success; DecryptionFailed on MAC mismatch.
    static cloak::core::Result<std::vector<std::byte>> aead_decrypt(
        const SecureBuffer<32>&    key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> aad,
        std::span<const std::byte> ciphertext);

    // ── Key derivation ────────────────────────────────────────────────────────

    // HKDF-SHA256: arbitrary-length salt and info, 32-byte output.
    static cloak::core::Result<SecureBuffer<32>> hkdf_sha256(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info);

    // HKDF-SHA256 producing 64 bytes (for split root-key + chain-key).
    static cloak::core::Result<std::pair<SecureBuffer<32>, SecureBuffer<32>>> hkdf_sha256_64(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info);

    // HMAC-SHA256: used in Double Ratchet chain KDF.
    static cloak::core::Result<SecureBuffer<32>> hmac_sha256(
        const SecureBuffer<32>&    key,
        std::span<const std::byte> msg);

    // Argon2id key derivation from a passphrase (for identity at-rest protection).
    // ops_limit and mem_limit are libsodium constants (e.g. crypto_pwhash_OPSLIMIT_INTERACTIVE).
    static cloak::core::Result<SecureBuffer<32>> argon2id_derive(
        std::span<const std::byte> passphrase,
        std::span<const std::byte> salt,       // must be crypto_pwhash_SALTBYTES (16)
        uint64_t ops_limit,
        size_t   mem_limit);

    // Generate a random Argon2id salt.
    static cloak::core::Result<std::vector<std::byte>> argon2id_salt();

    // ── Utilities ────────────────────────────────────────────────────────────

    // Constant-time comparison — never returns early.
    static bool constant_time_equal(
        std::span<const std::byte> a, std::span<const std::byte> b);

    // Fill span with cryptographically secure random bytes.
    static cloak::core::Result<void> random_bytes(std::span<std::byte> out);

    // Blake2b-256 hash.
    static cloak::core::Result<std::array<uint8_t, 32>> blake2b_256(
        std::span<const std::byte> msg);
};

} // namespace cloak::crypto
