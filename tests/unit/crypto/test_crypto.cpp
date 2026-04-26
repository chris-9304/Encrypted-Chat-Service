#include <catch2/catch_test_macros.hpp>
#include <ev/crypto/crypto.h>
#include <cstring>
#include <span>

using namespace ev::crypto;
using namespace ev::core;

TEST_CASE("Crypto AEAD round-trip", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());

    SecureBuffer<32> key;
    std::vector<std::byte> nonce(24);
    REQUIRE(Crypto::random_bytes(std::span<std::byte>(nonce)).has_value());

    std::vector<std::byte> pt  = {std::byte{'A'}, std::byte{'B'}, std::byte{'C'}};
    std::vector<std::byte> aad = {std::byte{'X'}};

    auto ct_res = Crypto::aead_encrypt(key, std::span<const std::byte>(nonce),
                                        std::span<const std::byte>(aad),
                                        std::span<const std::byte>(pt));
    REQUIRE(ct_res.has_value());

    auto dec_res = Crypto::aead_decrypt(key, std::span<const std::byte>(nonce),
                                         std::span<const std::byte>(aad),
                                         std::span<const std::byte>(*ct_res));
    REQUIRE(dec_res.has_value());
    REQUIRE(*dec_res == pt);

    (*ct_res)[0] ^= std::byte{0x01};
    auto bad_res = Crypto::aead_decrypt(key, std::span<const std::byte>(nonce),
                                         std::span<const std::byte>(aad),
                                         std::span<const std::byte>(*ct_res));
    REQUIRE_FALSE(bad_res.has_value());
}

TEST_CASE("Crypto X25519 ECDH symmetry (core DR property)", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());

    // Alice's DR keypair
    auto alice_kp = Crypto::kx_keypair();
    REQUIRE(alice_kp.has_value());

    // Bob's DR keypair
    auto bob_kp = Crypto::kx_keypair();
    REQUIRE(bob_kp.has_value());

    // DH(Alice_priv, Bob_pub) == DH(Bob_priv, Alice_pub)
    auto alice_shared = Crypto::kx_agree(alice_kp->private_key, bob_kp->public_key);
    REQUIRE(alice_shared.has_value());
    auto bob_shared = Crypto::kx_agree(bob_kp->private_key, alice_kp->public_key);
    REQUIRE(bob_shared.has_value());

    REQUIRE(std::memcmp(alice_shared->secret.data(), bob_shared->secret.data(), 32) == 0);
}

TEST_CASE("Crypto HKDF-SHA256 deterministic", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());

    std::vector<std::byte> ikm  = {std::byte{0x01}, std::byte{0x02}};
    std::vector<std::byte> salt = {std::byte{0xAA}};
    std::vector<std::byte> info = {std::byte{'E'}, std::byte{'V'}};

    auto k1 = Crypto::hkdf_sha256(std::span<const std::byte>(ikm),
                                   std::span<const std::byte>(salt),
                                   std::span<const std::byte>(info));
    auto k2 = Crypto::hkdf_sha256(std::span<const std::byte>(ikm),
                                   std::span<const std::byte>(salt),
                                   std::span<const std::byte>(info));
    REQUIRE(k1.has_value());
    REQUIRE(k2.has_value());
    REQUIRE(std::memcmp(k1->data(), k2->data(), 32) == 0);
}

TEST_CASE("Crypto DR KDF_RK symmetry: Alice CKs == Bob CKr", "[crypto]") {
    // Validates the core Double-Ratchet property before any session overhead.
    REQUIRE(Crypto::initialize().has_value());

    // Simulate session key (SK).
    SecureBuffer<32> SK;
    REQUIRE(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(SK.data()), 32)).has_value());

    // Each party generates a DR ephemeral keypair.
    auto alice_dr = Crypto::kx_keypair(); REQUIRE(alice_dr.has_value());
    auto bob_dr   = Crypto::kx_keypair(); REQUIRE(bob_dr.has_value());

    // DH(Alice_DR, Bob_DR) — must be symmetric.
    auto alice_dh = Crypto::kx_agree(alice_dr->private_key, bob_dr->public_key);
    REQUIRE(alice_dh.has_value());
    auto bob_dh = Crypto::kx_agree(bob_dr->private_key, alice_dr->public_key);
    REQUIRE(bob_dh.has_value());
    REQUIRE(std::memcmp(alice_dh->secret.data(), bob_dh->secret.data(), 32) == 0);

    // KDF_RK(SK, DH_output) -> (new_RK, CK)
    // Alice computes CKs, Bob computes CKr — must match.
    constexpr std::string_view kInfo = "EncryptiV_DR_RK_CK_v2";
    auto span_info = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(kInfo.data()), kInfo.size());
    auto span_dh = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(alice_dh->secret.data()), 32);
    auto span_sk = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(SK.data()), 32);

    auto alice_pair = Crypto::hkdf_sha256_64(span_dh, span_sk, span_info);
    REQUIRE(alice_pair.has_value());
    auto& CKs_alice = alice_pair->second; // bytes 32-63

    auto bob_span_dh = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(bob_dh->secret.data()), 32);
    auto bob_pair = Crypto::hkdf_sha256_64(bob_span_dh, span_sk, span_info);
    REQUIRE(bob_pair.has_value());
    auto& CKr_bob = bob_pair->second; // bytes 32-63

    REQUIRE(std::memcmp(CKs_alice.data(), CKr_bob.data(), 32) == 0);

    // KDF_CK(CK) -> (mk, new_ck): Alice mk == Bob mk.
    const std::byte kMkMsg{0x01};
    auto mk_alice = Crypto::hmac_sha256(CKs_alice,
        std::span<const std::byte>(&kMkMsg, 1));
    REQUIRE(mk_alice.has_value());
    auto mk_bob   = Crypto::hmac_sha256(CKr_bob,
        std::span<const std::byte>(&kMkMsg, 1));
    REQUIRE(mk_bob.has_value());
    REQUIRE(std::memcmp(mk_alice->data(), mk_bob->data(), 32) == 0);
}

TEST_CASE("Crypto X25519 low-order point rejection", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());
    SecureBuffer<32> sk;
    PublicKey pk{};
    auto res = Crypto::kx_agree(sk, pk);
    REQUIRE_FALSE(res.has_value());
}

TEST_CASE("Crypto Ed25519 sign/verify", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());
    auto kp = Crypto::ed25519_keypair();
    REQUIRE(kp.has_value());

    std::vector<std::byte> msg = {std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}};
    auto sig = Crypto::sign_detached(kp->private_key, std::span<const std::byte>(msg));
    REQUIRE(sig.has_value());

    auto ok = Crypto::verify_detached(kp->public_key, std::span<const std::byte>(msg), *sig);
    REQUIRE(ok.has_value());
    REQUIRE(*ok == true);

    msg[0] ^= std::byte{0x01};
    auto bad = Crypto::verify_detached(kp->public_key, std::span<const std::byte>(msg), *sig);
    REQUIRE(bad.has_value());
    REQUIRE(*bad == false);
}
