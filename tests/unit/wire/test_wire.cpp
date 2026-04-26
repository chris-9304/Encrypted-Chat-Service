#include <catch2/catch_test_macros.hpp>
#include <cloak/wire/framing.h>
#include <algorithm>
#include <random>

using namespace cloak::wire;
using namespace cloak::core;

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
    // Version field stored and correct.
    REQUIRE(decoded->version == kWireVersion);
}

TEST_CASE("Wire handshake version: peer version > ours is rejected", "[wire]") {
    HandshakePayload p;
    p.display_name = "Future";
    p.version = kWireVersion + 1; // too new

    auto encoded = encode_handshake(p);
    REQUIRE(encoded.has_value());

    auto decoded = decode_handshake(std::span<const std::byte>(*encoded));
    REQUIRE_FALSE(decoded.has_value()); // must reject
}

TEST_CASE("Wire handshake version: older peer version is accepted", "[wire]") {
    HandshakePayload p;
    p.display_name = "Old";
    p.version = kWireVersion - 1; // older peer, we can still talk

    auto encoded = encode_handshake(p);
    REQUIRE(encoded.has_value());

    auto decoded = decode_handshake(std::span<const std::byte>(*encoded));
    REQUIRE(decoded.has_value()); // older versions are accepted
    CHECK(decoded->version == kWireVersion - 1);
}

TEST_CASE("Wire GroupMessage round-trip", "[wire][group]") {
    cloak::wire::GroupMessagePayload g;
    g.group_id.bytes.fill(0x01);
    g.sender_sign_pub.bytes.fill(0x02);
    g.message_number = 99;
    g.ciphertext     = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    g.signature.bytes.fill(0x03);

    auto enc = cloak::wire::encode_group_message(g);
    REQUIRE(enc.has_value());

    auto dec = cloak::wire::decode_group_message(std::span<const std::byte>(*enc));
    REQUIRE(dec.has_value());
    CHECK(dec->group_id.bytes    == g.group_id.bytes);
    CHECK(dec->message_number    == 99u);
    CHECK(dec->ciphertext        == g.ciphertext);
    CHECK(dec->signature.bytes   == g.signature.bytes);
}

TEST_CASE("Wire GroupOp round-trip", "[wire][group]") {
    cloak::wire::GroupOpPayload op;
    op.op           = cloak::wire::GroupOpType::Leave;
    op.group_id.bytes.fill(0x55);
    op.group_name   = "TestGroup";
    op.member_key.bytes.fill(0x66);
    op.chain_key.fill(0x77);
    op.chain_counter = 7;

    auto enc = cloak::wire::encode_group_op(op);
    REQUIRE(enc.has_value());

    auto dec = cloak::wire::decode_group_op(std::span<const std::byte>(*enc));
    REQUIRE(dec.has_value());
    CHECK(dec->op           == cloak::wire::GroupOpType::Leave);
    CHECK(dec->group_name   == "TestGroup");
    CHECK(dec->chain_counter == 7u);
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
