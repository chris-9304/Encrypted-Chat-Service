#include <catch2/catch_test_macros.hpp>
#include <ev/session/session.h>
#include <ev/identity/identity.h>
#include <ev/transport/tcp_transport.h>
#include <ev/crypto/crypto.h>
#include <thread>
#include <chrono>

using namespace ev::session;
using namespace ev::identity;
using namespace ev::transport;
using namespace ev::crypto;

TEST_CASE("Session e2e encryption", "[session]") {
    Crypto::initialize();
    auto alice = Identity::generate().value();
    auto bob = Identity::generate().value();

    std::thread server_thread([&bob]() {
        auto accept_res = TcpTransport::accept_from(30156); // specific port for test
        if (accept_res.has_value()) {
            auto s = Session::accept(bob, "Bob", std::move(accept_res.value())).value();
            for(int i=0; i<5; i++) {
                auto msg = s.recv_text();
                if (msg.has_value() && msg.value() == "Hello Bob") {
                    s.send_text("Hello Alice").value();
                }
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto cli_res = TcpTransport::connect({"127.0.0.1", 30156});
    if (cli_res.has_value()) {
        auto s = Session::initiate(alice, "Alice", std::move(cli_res.value())).value();
        REQUIRE(s.is_established());
        REQUIRE(s.peer_display_name() == "Bob");

        for(int i=0; i<5; i++) {
            s.send_text("Hello Bob");
            auto msg = s.recv_text();
            REQUIRE(msg.has_value());
            REQUIRE(msg.value() == "Hello Alice");
        }
    }
    
    server_thread.join();
}
