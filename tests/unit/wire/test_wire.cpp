#include <catch2/catch_test_macros.hpp>
#include <ev/wire/framing.h>
#include <algorithm>
#include <random>

using namespace ev::wire;
using namespace ev::core;

TEST_CASE("Wire framing round-trip", "[wire]") {
    Frame f{MessageType::AppMessage, {std::byte{1}, std::byte{2}, std::byte{3}}};
    auto encoded = encode(f);
    REQUIRE(encoded.has_value());
    REQUIRE(encoded->size() == 4 + 1 + 3);

    auto decoded = decode(std::span<const std::byte>(*encoded));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->type == MessageType::AppMessage);
    REQUIRE(decoded->payload.size() == 3);

    auto trunc = decode(std::span<const std::byte>(encoded->data(), encoded->size() - 1));
    REQUIRE_FALSE(trunc.has_value());
}

TEST_CASE("Wire handshake payload Phase-2 format", "[wire]") {
    HandshakePayload p;
    p.display_name = "Alice";
    auto encoded = encode_handshake(p);
    REQUIRE(encoded.has_value());
    // x25519(32) + ed25519(32) + sig_x25519(64) + dr_pub(32) + sig_dr(64) + version(1) + name_len(2) + "Alice"(5)
    REQUIRE(encoded->size() == 32 + 32 + 64 + 32 + 64 + 1 + 2 + 5);

    auto decoded = decode_handshake(std::span<const std::byte>(*encoded));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->display_name == "Alice");
}

TEST_CASE("Wire AppMessage payload round-trip", "[wire]") {
    AppPayload p;
    p.header.pn  = 3;
    p.header.n   = 7;
    p.ciphertext = {std::byte{0xAB}, std::byte{0xCD}};

    auto enc = encode_app(p);
    REQUIRE(enc.has_value());

    auto dec = decode_app(std::span<const std::byte>(*enc));
    REQUIRE(dec.has_value());
    REQUIRE(dec->header.pn == 3);
    REQUIRE(dec->header.n  == 7);
    REQUIRE(dec->ciphertext == p.ciphertext);
}

TEST_CASE("Wire fuzzer-lite: random bytes must not crash", "[wire]") {
    std::mt19937 rng(0xDEADBEEF);
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    std::vector<std::byte> buf(1024);
    std::generate(buf.begin(), buf.end(),
                  [&]{ return std::byte{static_cast<uint8_t>(dist(rng))}; });

    for (int i = 0; i < 500; ++i) {
        const size_t off = rng() % (buf.size() - 100);
        const size_t len = (rng() % 99) + 1;
        static_cast<void>(decode(std::span<const std::byte>(buf.data() + off, len)));
        static_cast<void>(decode_handshake(std::span<const std::byte>(buf.data() + off, len)));
        static_cast<void>(decode_app(std::span<const std::byte>(buf.data() + off, len)));
    }
    SUCCEED("No crash on random input");
}
