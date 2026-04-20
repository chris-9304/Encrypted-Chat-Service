#include <catch2/catch_test_macros.hpp>
#include <ev/wire/framing.h>
#include <sodium.h>

using namespace ev::wire;
using namespace ev::core;

TEST_CASE("Wire framing roundtrips", "[wire]") {
    Frame f{MessageType::AppMessage, {std::byte{1}, std::byte{2}, std::byte{3}}};
    auto encoded = encode(f).value();
    
    REQUIRE(encoded.size() == 4 + 1 + 3);
    
    auto decoded = decode(std::span<const std::byte>(encoded)).value();
    REQUIRE(decoded.type == MessageType::AppMessage);
    REQUIRE(decoded.payload.size() == 3);
    
    // Truncation
    auto trunc = decode(std::span<const std::byte>(encoded.data(), encoded.size() - 1));
    REQUIRE_FALSE(trunc.has_value());
}

TEST_CASE("Wire handshake payload format", "[wire]") {
    HandshakePayload p;
    p.display_name = "Alice";
    auto encoded = encode_handshake(p).value();
    
    REQUIRE(encoded.size() == 32 + 32 + 64 + 2 + 5);
    
    auto decoded = decode_handshake(std::span<const std::byte>(encoded)).value();
    REQUIRE(decoded.display_name == "Alice");
}

TEST_CASE("Wire fuzzer lite bounds checks", "[wire]") {
    std::vector<std::byte> rand(1024);
    randombytes_buf(rand.data(), rand.size());
    
    // Decoding random buffers should not crash, often fail gracefully
    for(int i = 0; i < 1000; i++) {
        size_t off = randombytes_uniform(rand.size() - 100);
        size_t len = randombytes_uniform(100);
        decode(std::span<const std::byte>(rand.data() + off, len));
        decode_handshake(std::span<const std::byte>(rand.data() + off, len));
        decode_app(std::span<const std::byte>(rand.data() + off, len));
    }
    SUCCEED("Did not crash");
}
