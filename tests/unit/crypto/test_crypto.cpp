#include <catch2/catch_test_macros.hpp>
#include <ev/crypto/crypto.h>
#include <cstring>

using namespace ev::crypto;
using namespace ev::core;

TEST_CASE("Crypto AEAD", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());
    
    SecureBuffer<32> key;
    std::vector<std::byte> nonce(24);
    Crypto::random_bytes(std::span<std::byte>(nonce));
    
    std::vector<std::byte> pt = {std::byte{'A'}, std::byte{'B'}, std::byte{'C'}};
    std::vector<std::byte> aad = {std::byte{'X'}};
    
    auto ct = Crypto::aead_encrypt(key, std::span<const std::byte>(nonce), std::span<const std::byte>(aad), std::span<const std::byte>(pt)).value();
    
    auto dec = Crypto::aead_decrypt(key, std::span<const std::byte>(nonce), std::span<const std::byte>(aad), std::span<const std::byte>(ct));
    REQUIRE(dec.has_value());
    REQUIRE(dec.value() == pt);
    
    // Tampering test - single bit flip
    ct[0] ^= std::byte{0x01};
    auto bad_dec = Crypto::aead_decrypt(key, std::span<const std::byte>(nonce), std::span<const std::byte>(aad), std::span<const std::byte>(ct));
    REQUIRE_FALSE(bad_dec.has_value());
}

TEST_CASE("Crypto KX Low order points", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());
    SecureBuffer<32> sk;
    PublicKey pk;
    memset(pk.bytes.data(), 0, 32); 
    auto res = Crypto::kx_agree(sk, pk);
    REQUIRE_FALSE(res.has_value());
}

TEST_CASE("Crypto signatures", "[crypto]") {
    REQUIRE(Crypto::initialize().has_value());
    auto kp = Crypto::ed25519_keypair().value();
    std::vector<std::byte> m = {std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}};
    
    auto sig = Crypto::sign_detached(kp.private_key, std::span<const std::byte>(m)).value();
    
    REQUIRE(Crypto::verify_detached(kp.public_key, std::span<const std::byte>(m), sig).value() == true);
    
    m[0] ^= std::byte{0x01}; // tamper
    REQUIRE(Crypto::verify_detached(kp.public_key, std::span<const std::byte>(m), sig).value() == false);
}
