#include <cloak/identity/identity.h>
#include <cloak/crypto/crypto.h>
#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace cloak::identity {

using namespace cloak::core;
using namespace cloak::crypto;

// ── File format ───────────────────────────────────────────────────────────────
// identity.bin:
//   magic    [4]  = "EVIDv2"[0..3] = {0x45,0x56,0x49,0x32}
//   argon_salt [16]               -- random Argon2id salt
//   nonce    [24]                 -- XChaCha20-Poly1305 nonce
//   ct       [?]                  -- AEAD( plaintext, key=Argon2id(passphrase) )
//
// Plaintext layout inside AEAD:
//   sign_sk  [64]   -- Ed25519 signing secret key
//   sign_pk  [32]   -- Ed25519 signing public key
//   kx_sk    [32]   -- X25519 key-agreement secret key
//   kx_pk    [32]   -- X25519 key-agreement public key

static constexpr std::array<uint8_t, 4> kMagic = {0x45, 0x56, 0x49, 0x32};
static constexpr size_t kPlainLen = 64 + 32 + 32 + 32; // 160 bytes

// Argon2id params: use interactive for now; production should use sensitive.
static constexpr uint64_t kArgonOps  = crypto_pwhash_OPSLIMIT_INTERACTIVE;
static constexpr size_t   kArgonMem  = crypto_pwhash_MEMLIMIT_INTERACTIVE;

// ── Constructor ───────────────────────────────────────────────────────────────

Identity::Identity(SecureBuffer<64> s_sk, PublicKey s_pk,
                   SecureBuffer<32> k_sk, PublicKey k_pk)
    : signing_sk_(std::move(s_sk)), signing_pk_(s_pk),
      kx_sk_(std::move(k_sk)), kx_pk_(k_pk) {}

// ── Generate ──────────────────────────────────────────────────────────────────

Result<Identity> Identity::generate() {
    auto sign_kp = Crypto::ed25519_keypair();
    if (!sign_kp) return std::unexpected(sign_kp.error());

    auto kx_kp = Crypto::kx_keypair();
    if (!kx_kp) return std::unexpected(kx_kp.error());

    return Identity(
        std::move(sign_kp->private_key), sign_kp->public_key,
        std::move(kx_kp->private_key),  kx_kp->public_key);
}

// ── Save ──────────────────────────────────────────────────────────────────────

Result<void> Identity::save(const cloak::core::Path& path,
                             std::span<const std::byte> passphrase) const {
    // Build 160-byte plaintext.
    std::array<uint8_t, kPlainLen> plain{};
    std::memcpy(plain.data(),        signing_sk_.data(), 64);
    std::memcpy(plain.data() + 64,   signing_pk_.bytes.data(), 32);
    std::memcpy(plain.data() + 96,   kx_sk_.data(), 32);
    std::memcpy(plain.data() + 128,  kx_pk_.bytes.data(), 32);

    // Generate Argon2id salt.
    auto salt_res = Crypto::argon2id_salt();
    if (!salt_res) return std::unexpected(salt_res.error());
    const auto& salt = *salt_res;

    // Derive file encryption key.
    auto key_res = Crypto::argon2id_derive(passphrase, salt,
                                            kArgonOps, kArgonMem);
    if (!key_res) {
        sodium_memzero(plain.data(), plain.size());
        return std::unexpected(key_res.error());
    }

    // Generate random nonce.
    std::vector<std::byte> nonce(24);
    static_cast<void>(Crypto::random_bytes(std::span<std::byte>(nonce)));

    // Encrypt.
    auto ct_res = Crypto::aead_encrypt(
        *key_res,
        std::span<const std::byte>(nonce),
        {},
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(plain.data()), kPlainLen));

    sodium_memzero(plain.data(), plain.size());

    if (!ct_res) return std::unexpected(ct_res.error());

    // Write file.
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        return std::unexpected(Error::from(ErrorCode::IoError,
                                            "Cannot open identity file for writing"));
    }

    f.write(reinterpret_cast<const char*>(kMagic.data()), 4);
    f.write(reinterpret_cast<const char*>(salt.data()), 16);
    f.write(reinterpret_cast<const char*>(nonce.data()), 24);
    f.write(reinterpret_cast<const char*>(ct_res->data()),
            static_cast<std::streamsize>(ct_res->size()));

    if (!f.good()) {
        return std::unexpected(Error::from(ErrorCode::IoError,
                                            "Write error on identity file"));
    }
    return {};
}

// ── Load ──────────────────────────────────────────────────────────────────────

Result<Identity> Identity::load(const cloak::core::Path& path,
                                 std::span<const std::byte> passphrase) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        return std::unexpected(Error::from(ErrorCode::IoError,
                                            "Cannot open identity file"));
    }

    const auto file_size = static_cast<size_t>(f.tellg());
    f.seekg(0);

    constexpr size_t kMinFile = 4 + 16 + 24 + kPlainLen + 16; // magic+salt+nonce+ct+tag
    if (file_size < kMinFile) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                            "Identity file too short"));
    }

    std::vector<uint8_t> buf(file_size);
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(file_size));
    if (!f.good()) {
        return std::unexpected(Error::from(ErrorCode::IoError,
                                            "Read error on identity file"));
    }

    // Check magic.
    if (std::memcmp(buf.data(), kMagic.data(), 4) != 0) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                            "Identity file magic mismatch"));
    }

    // Extract salt, nonce, ciphertext.
    const auto* salt_ptr  = reinterpret_cast<const std::byte*>(buf.data() + 4);
    const auto* nonce_ptr = reinterpret_cast<const std::byte*>(buf.data() + 20);
    const auto* ct_ptr    = reinterpret_cast<const std::byte*>(buf.data() + 44);
    const size_t ct_len   = file_size - 44;

    // Derive key.
    auto key_res = Crypto::argon2id_derive(
        passphrase,
        std::span<const std::byte>(salt_ptr, 16),
        kArgonOps, kArgonMem);
    if (!key_res) return std::unexpected(key_res.error());

    // Decrypt.
    auto pt_res = Crypto::aead_decrypt(
        *key_res,
        std::span<const std::byte>(nonce_ptr, 24),
        {},
        std::span<const std::byte>(ct_ptr, ct_len));

    if (!pt_res) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                            "Identity file decryption failed (wrong passphrase?)"));
    }

    if (pt_res->size() != kPlainLen) {
        return std::unexpected(Error::from(ErrorCode::AuthenticationFailed,
                                            "Identity plaintext unexpected length"));
    }

    // Reconstruct keypairs.
    SecureBuffer<64> sign_sk;
    SecureBuffer<32> kx_sk;
    PublicKey        sign_pk, kx_pk;

    std::memcpy(sign_sk.data(),      pt_res->data(),       64);
    std::memcpy(sign_pk.bytes.data(),pt_res->data() + 64,  32);
    std::memcpy(kx_sk.data(),        pt_res->data() + 96,  32);
    std::memcpy(kx_pk.bytes.data(),  pt_res->data() + 128, 32);

    sodium_memzero(pt_res->data(), pt_res->size());

    return Identity(std::move(sign_sk), sign_pk,
                    std::move(kx_sk),   kx_pk);
}

bool Identity::exists(const cloak::core::Path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f || !f.good()) return false;
    std::array<uint8_t, 4> magic{};
    f.read(reinterpret_cast<char*>(magic.data()), 4);
    return f.good() && magic == kMagic;
}

// ── Accessors ─────────────────────────────────────────────────────────────────

const PublicKey& Identity::signing_public() const { return signing_pk_; }
const PublicKey& Identity::kx_public()      const { return kx_pk_; }

std::string Identity::fingerprint() const {
    auto hash_res = Crypto::blake2b_256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(signing_pk_.bytes.data()), 32));
    if (!hash_res) return "(crypto-error)";

    const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string b32;
    uint32_t buf = 0; int bits = 0;
    for (uint8_t byte : *hash_res) {
        buf = (buf << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            b32.push_back(alpha[(buf >> bits) & 0x1F]);
        }
        if (b32.size() >= 12) break;
    }
    while (b32.size() < 12) b32.push_back('A');
    return b32.substr(0,4) + "-" + b32.substr(4,4) + "-" + b32.substr(8,4);
}

// 60-digit safety number: Signal-style.
// Compute 5 groups of 12 digits from BLAKE2b(sort(pk_a, pk_b)).
cloak::core::SafetyNumber Identity::safety_number(const PublicKey& a,
                                                const PublicKey& b) {
    // Sort deterministically: smaller key goes first.
    const PublicKey& first  = (a.bytes < b.bytes) ? a : b;
    const PublicKey& second = (a.bytes < b.bytes) ? b : a;

    std::array<uint8_t, 64> combined{};
    std::memcpy(combined.data(),      first.bytes.data(),  32);
    std::memcpy(combined.data() + 32, second.bytes.data(), 32);

    auto hash_res = Crypto::blake2b_256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(combined.data()), 64));
    sodium_memzero(combined.data(), combined.size());

    if (!hash_res) return SafetyNumber{"(error)"};

    // Build 60-digit string: 2 decimal digits per byte, 30 bytes = 60 digits.
    // Each byte is reduced mod 100 so the output is always exactly 2 digits.
    // Grouped in blocks of 10 digits (5 bytes) separated by spaces.
    SafetyNumber sn;
    sn.digits.reserve(66); // 60 digits + 5 spaces
    for (size_t i = 0; i < 30; ++i) {
        if (i > 0 && i % 5 == 0) sn.digits += ' ';
        char buf[3];
        snprintf(buf, sizeof(buf), "%02u",
                 static_cast<unsigned>((*hash_res)[i]) % 100u);
        sn.digits += buf;
    }
    return sn;
}

// ── Crypto operations ─────────────────────────────────────────────────────────

Result<Signature> Identity::sign(std::span<const std::byte> msg) const {
    return Crypto::sign_detached(signing_sk_, msg);
}

Result<SharedSecret> Identity::agree(const PublicKey& peer_kx_pub) const {
    return Crypto::kx_agree(kx_sk_, peer_kx_pub);
}

} // namespace cloak::identity
