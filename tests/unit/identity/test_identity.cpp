#include <catch2/catch_test_macros.hpp>
#include <ev/identity/identity.h>
#include <ev/crypto/crypto.h>
#include <cstring>

using namespace ev::identity;

TEST_CASE("Identity fingerprint and key agreement", "[identity]") {
    REQUIRE(ev::crypto::Crypto::initialize().has_value());

    auto id1_res = Identity::generate();
    REQUIRE(id1_res.has_value());
    auto id2_res = Identity::generate();
    REQUIRE(id2_res.has_value());

    auto& id1 = *id1_res;
    auto& id2 = *id2_res;

    REQUIRE(id1.fingerprint() != id2.fingerprint());
    REQUIRE(id1.fingerprint().length() == 14); // XXXX-XXXX-XXXX

    auto shared1 = id1.agree(id2.kx_public());
    REQUIRE(shared1.has_value());
    auto shared2 = id2.agree(id1.kx_public());
    REQUIRE(shared2.has_value());

    REQUIRE(shared1->secret.size() == 32);
    REQUIRE(std::memcmp(shared1->secret.data(), shared2->secret.data(), 32) == 0);
}

TEST_CASE("Identity signing verification", "[identity]") {
    REQUIRE(ev::crypto::Crypto::initialize().has_value());

    auto id_res = Identity::generate();
    REQUIRE(id_res.has_value());
    auto& id = *id_res;

    std::vector<std::byte> msg = {std::byte{0xDE}, std::byte{0xAD}};
    auto sig = id.sign(std::span<const std::byte>(msg));
    REQUIRE(sig.has_value());

    auto ok = ev::crypto::Crypto::verify_detached(
        id.signing_public(),
        std::span<const std::byte>(msg),
        *sig);
    REQUIRE(ok.has_value());
    REQUIRE(*ok == true);
}

TEST_CASE("Identity safety number symmetry", "[identity]") {
    REQUIRE(ev::crypto::Crypto::initialize().has_value());

    auto a = Identity::generate().value();
    auto b = Identity::generate().value();

    auto sn_ab = Identity::safety_number(a.signing_public(), b.signing_public());
    auto sn_ba = Identity::safety_number(b.signing_public(), a.signing_public());

    REQUIRE(sn_ab.digits == sn_ba.digits);
    REQUIRE(!sn_ab.digits.empty());
}
