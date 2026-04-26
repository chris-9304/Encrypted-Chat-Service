#include <catch2/catch_test_macros.hpp>
#include <ev/session/session.h>
#include <ev/identity/identity.h>
#include <ev/transport/tcp_transport.h>
#include <ev/crypto/crypto.h>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace ev::session;
using namespace ev::identity;
using namespace ev::transport;
using namespace ev::crypto;

// RAII thread guard: joins or detaches on destruction.
struct JoinGuard {
    std::thread& t;
    ~JoinGuard() {
        if (t.joinable()) t.detach();
    }
};

TEST_CASE("Session e2e Double-Ratchet encryption over loopback", "[session]") {
    REQUIRE(Crypto::initialize().has_value());

    auto alice_res = Identity::generate();
    REQUIRE(alice_res.has_value());
    auto bob_res = Identity::generate();
    REQUIRE(bob_res.has_value());

    auto& alice = *alice_res;
    auto& bob   = *bob_res;

    constexpr uint16_t kPort   = 30156;
    constexpr int      kRounds = 5;

    std::atomic<bool>  server_done{false};
    std::string        server_error;

    std::thread server_thread([&]() {
        auto accept_res = TcpTransport::accept_from(kPort);
        if (!accept_res) { server_error = "accept: " + accept_res.error().message; server_done = true; return; }

        auto s_res = Session::accept(bob, "Bob", std::move(*accept_res));
        if (!s_res) { server_error = "handshake: " + s_res.error().message; server_done = true; return; }
        auto& s = *s_res;

        for (int i = 0; i < kRounds; ++i) {
            auto msg = s.recv_text();
            if (!msg) { server_error = "recv[" + std::to_string(i) + "]: " + msg.error().message; break; }
            auto sr  = s.send_text("Hello Alice");
            if (!sr)  { server_error = "send[" + std::to_string(i) + "]: " + sr.error().message;  break; }
        }
        server_done = true;
    });

    JoinGuard guard{server_thread};  // detach on scope exit if not joined

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto cli_res = TcpTransport::connect({"127.0.0.1", kPort});
    if (!cli_res) {
        SKIP("TCP connect failed: " + cli_res.error().message);
    }

    auto s_res = Session::initiate(alice, "Alice", std::move(*cli_res));
    REQUIRE(s_res.has_value());
    auto& s = *s_res;

    CHECK(s.is_established());
    CHECK(s.peer_display_name() == "Bob");

    std::string client_error;
    for (int i = 0; i < kRounds && client_error.empty(); ++i) {
        auto send_res = s.send_text("Hello Bob");
        if (!send_res) { client_error = "send[" + std::to_string(i) + "]: " + send_res.error().message; break; }

        auto msg = s.recv_text();
        if (!msg) { client_error = "recv[" + std::to_string(i) + "]: " + msg.error().message; break; }
        if (*msg != "Hello Alice") { client_error = "round " + std::to_string(i) + " body mismatch: got '" + *msg + "'"; break; }
    }

    // Wait for server to finish (with timeout).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!server_done && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (server_thread.joinable()) server_thread.join();

    std::string combined;
    if (!server_error.empty()) combined += "Server: " + server_error + "  ";
    if (!client_error.empty()) combined += "Client: " + client_error;
    if (!combined.empty()) FAIL(combined);
    SUCCEED("All " + std::to_string(kRounds) + " rounds passed");
}
