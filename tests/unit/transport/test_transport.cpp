#include <catch2/catch_test_macros.hpp>
#include <ev/transport/tcp_transport.h>
#include <thread>
#include <vector>
#include <chrono>

using namespace ev::transport;

TEST_CASE("Transport Loopback Verification", "[transport]") {
    std::thread server_thread([]() {
        auto accept_res = TcpTransport::accept_from(30155);
        if (accept_res.has_value()) {
            auto srv = std::move(accept_res.value());
            for(int i = 0; i < 10; ++i) {
                auto data = srv->receive(5);
                if (data.has_value()) {
                    srv->send(data.value()); // Echo
                }
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto cli_res = TcpTransport::connect({"127.0.0.1", 30155});
    REQUIRE(cli_res.has_value());
    auto cli = std::move(cli_res.value());
    
    for(int i = 0; i < 10; ++i) {
        std::vector<std::byte> out = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{static_cast<uint8_t>(i)}};
        REQUIRE(cli->send(out).has_value());
        auto in = cli->receive(5).value();
        REQUIRE(in == out);
    }
    
    cli->close();
    server_thread.join();
}
