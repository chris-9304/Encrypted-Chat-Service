#include <catch2/catch_test_macros.hpp>
#include <ev/identity/identity.h>
#include <ev/crypto/crypto.h>
#include <cstring>
#include <filesystem>
#include <string>

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

TEST_CASE("Identity safety number format: exactly 60 digits + 5 spaces", "[identity]") {
    REQUIRE(ev::crypto::Crypto::initialize().has_value());

    auto a = Identity::generate().value();
    auto b = Identity::generate().value();

    auto sn = Identity::safety_number(a.signing_public(), b.signing_public());

    // Total length: 60 digit chars + 5 space separators = 65.
    REQUIRE(sn.digits.size() == 65u);

    // Every char must be a decimal digit or a space.
    size_t spaces = 0;
    size_t digits = 0;
    for (char c : sn.digits) {
        if (c == ' ') { ++spaces; continue; }
        REQUIRE(c >= '0');
        REQUIRE(c <= '9');
        ++digits;
    }
    CHECK(digits == 60u);
    CHECK(spaces == 5u);

    // Each two-digit group must be 00-99 (not 100+ which would indicate the bug).
    // Remove spaces and walk in pairs.
    std::string only_digits;
    for (char c : sn.digits) if (c != ' ') only_digits += c;
    REQUIRE(only_digits.size() == 60u);
    for (size_t i = 0; i < 60; i += 2) {
        int val = (only_digits[i] - '0') * 10 + (only_digits[i+1] - '0');
        REQUIRE(val >= 0);
        REQUIRE(val <= 99);
    }
}

TEST_CASE("Identity save and load round-trip", "[identity]") {
    REQUIRE(ev::crypto::Crypto::initialize().has_value());

    const auto tmp = std::filesystem::temp_directory_path() / "ev_test_identity.bin";
    std::filesystem::remove(tmp);

    auto id = Identity::generate().value();
    const auto orig_fp = id.fingerprint();

    const std::string passphrase = "test-pass-phrase";
    REQUIRE(id.save(tmp,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(passphrase.data()),
            passphrase.size())).has_value());

    REQUIRE(Identity::exists(tmp));

    auto loaded = Identity::load(tmp,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(passphrase.data()),
            passphrase.size()));
    REQUIRE(loaded.has_value());
    CHECK(loaded->fingerprint() == orig_fp);

    // Wrong passphrase must fail.
    const std::string bad = "wrong-passphrase";
    auto bad_load = Identity::load(tmp,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(bad.data()), bad.size()));
    REQUIRE_FALSE(bad_load.has_value());

    std::filesystem::remove(tmp);
}
