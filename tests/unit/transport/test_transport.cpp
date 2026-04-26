#include <catch2/catch_test_macros.hpp>
#include <cloak/transport/tcp_transport.h>
#include <chrono>
#include <thread>
#include <vector>

using namespace cloak::transport;

TEST_CASE("Transport loopback byte-stream round-trip", "[transport]") {
    constexpr uint16_t kPort = 30155;

    std::thread server_thread([]() {
        auto accept_res = TcpTransport::accept_from(kPort);
        if (!accept_res) return;
        auto& srv = *accept_res;

        for (int i = 0; i < 10; ++i) {
            auto data = srv->receive(5);
            if (data) {
                static_cast<void>(srv->send(*data)); // Echo
            }
        }
        static_cast<void>(srv->close());
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto cli_res = TcpTransport::connect({"127.0.0.1", kPort});
    if (!cli_res) {
        server_thread.join();
        SKIP("TCP connect failed (port may be in use)");
    }

    auto& cli = *cli_res;
    for (int i = 0; i < 10; ++i) {
        std::vector<std::byte> out = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{static_cast<uint8_t>(i)}
        };
        REQUIRE(cli->send(out).has_value());
        auto in = cli->receive(5);
        REQUIRE(in.has_value());
        REQUIRE(*in == out);
    }

    static_cast<void>(cli->close());
    server_thread.join();
}
