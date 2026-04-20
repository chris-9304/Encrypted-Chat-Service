#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include "types.h"
#include <vector>
#include <span>
#include <cstddef>

namespace ev::crypto {

class Crypto {
public:
    static ev::core::Result<void> initialize();

    static ev::core::Result<KeyPair> kx_keypair();
    static ev::core::Result<SharedSecret> kx_agree(const SecureBuffer<32>& sk, const ev::core::PublicKey& peer_pk);

    static ev::core::Result<Ed25519KeyPair> ed25519_keypair();
    static ev::core::Result<ev::core::Signature> sign_detached(const SecureBuffer<64>& sk, std::span<const std::byte> msg);
    static ev::core::Result<bool> verify_detached(const ev::core::PublicKey& pk, std::span<const std::byte> msg, const ev::core::Signature& sig);

    static ev::core::Result<std::vector<std::byte>> aead_encrypt(
        const SecureBuffer<32>& key, std::span<const std::byte> nonce,
        std::span<const std::byte> aad, std::span<const std::byte> plaintext);
    static ev::core::Result<std::vector<std::byte>> aead_decrypt(
        const SecureBuffer<32>& key, std::span<const std::byte> nonce,
        std::span<const std::byte> aad, std::span<const std::byte> ciphertext);

    static ev::core::Result<SecureBuffer<32>> hkdf_sha256(
        std::span<const std::byte> ikm, std::span<const std::byte> salt,
        std::span<const std::byte> info);

    static bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b);
    static ev::core::Result<void> random_bytes(std::span<std::byte> out);
};

} // namespace ev::crypto
