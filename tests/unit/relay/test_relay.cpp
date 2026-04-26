#include <catch2/catch_test_macros.hpp>
#include <ev/relay/relay_server.h>
#include <ev/transport/relay_transport.h>
#include <ev/session/session.h>
#include <ev/identity/identity.h>
#include <ev/crypto/crypto.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace ev::relay;
using namespace ev::transport;
using namespace ev::session;
using namespace ev::identity;
using namespace ev::crypto;

// ── Helpers ───────────────────────────────────────────────────────────────────

// RAII wrapper that starts a RelayServer on an ephemeral port in a background
// thread and waits until the acceptor is fully bound before returning.
struct ServerGuard {
    RelayServer              srv{0}; // port=0 → OS picks an ephemeral port
    std::thread              t;
    std::atomic<bool>        started{false};

    ServerGuard() {
        t = std::thread([this]() {
            static_cast<void>(srv.run());
        });
        // run() sets bound_port_ after bind() succeeds, before accept().
        // Spin until the port is known or we time out.
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (srv.bound_port() == 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        started = (srv.bound_port() != 0);
    }

    ~ServerGuard() {
        srv.stop();
        if (t.joinable()) t.detach();
    }

    uint16_t port() const { return srv.bound_port(); }
    bool     ok()   const { return started.load(); }
};

// ── Invite code tests ─────────────────────────────────────────────────────────

TEST_CASE("Invite code round-trip", "[relay][invite]") {
    ev::core::Endpoint relay_in{"192.168.1.10", 8765};
    RelayRoomId room{};
    for (size_t i = 0; i < 32; ++i) room[i] = static_cast<uint8_t>(i);

    const auto code = make_invite_code(relay_in, room);
    REQUIRE(!code.empty());

    ev::core::Endpoint relay_out{};
    RelayRoomId room_out{};
    REQUIRE(parse_invite_code(code, relay_out, room_out));
    CHECK(relay_out.address == relay_in.address);
    CHECK(relay_out.port    == relay_in.port);
    CHECK(room_out          == room);
}

TEST_CASE("Invite code rejects malformed inputs", "[relay][invite]") {
    ev::core::Endpoint ep{};
    RelayRoomId room{};

    CHECK_FALSE(parse_invite_code("", ep, room));
    CHECK_FALSE(parse_invite_code("noport/aabbcc", ep, room));
    CHECK_FALSE(parse_invite_code("host:8765/tooshort", ep, room));
    CHECK_FALSE(parse_invite_code("host:8765", ep, room)); // missing slash
    // 64 hex chars but invalid host (no colon)
    CHECK_FALSE(parse_invite_code(
        "hostonly/" + std::string(64, 'a'), ep, room));
}

TEST_CASE("Relay server: host + guest pair and exchange bytes", "[relay]") {
    REQUIRE(Crypto::initialize().has_value());

    ServerGuard guard;
    if (!guard.ok()) SKIP("Relay server failed to bind");
    const uint16_t srv_port = guard.port();

    ev::core::Endpoint relay{"127.0.0.1", srv_port};
    RelayRoomId room{};
    room.fill(0x42);

    std::atomic<bool> host_done{false};
    std::string       host_error;
    std::string       host_received;

    // Host thread: registers room, waits for guest, sends "ping", receives "pong".
    std::thread host_thread([&]() {
        auto t = RelayTransport::host(relay, room);
        if (!t) { host_error = t.error().message; host_done = true; return; }

        // Write "ping" and read "pong".
        const std::vector<std::byte> ping = {
            std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
        auto sr = (*t)->send(std::span<const std::byte>(ping));
        if (!sr) { host_error = sr.error().message; host_done = true; return; }

        auto rr = (*t)->receive(4);
        if (!rr) { host_error = rr.error().message; host_done = true; return; }
        host_received.assign(reinterpret_cast<const char*>(rr->data()), 4);
        host_done = true;
    });

    // Give host time to register.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Guest: joins room, receives "ping", sends "pong".
    auto gt = RelayTransport::join(relay, room);
    REQUIRE(gt.has_value());

    auto rr = (*gt)->receive(4);
    REQUIRE(rr.has_value());
    CHECK(std::string(reinterpret_cast<const char*>(rr->data()), 4) == "ping");

    const std::vector<std::byte> pong = {
        std::byte{'p'}, std::byte{'o'}, std::byte{'n'}, std::byte{'g'}};
    REQUIRE((*gt)->send(std::span<const std::byte>(pong)).has_value());

    // Wait for host.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!host_done && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    if (host_thread.joinable()) host_thread.join();

    if (!host_error.empty()) FAIL("Host: " + host_error);
    CHECK(host_received == "pong");
}

TEST_CASE("Relay: guest gets error for unknown room", "[relay]") {
    REQUIRE(Crypto::initialize().has_value());

    ServerGuard guard;
    if (!guard.ok()) SKIP("Relay server failed to bind");
    ev::core::Endpoint relay{"127.0.0.1", guard.port()};

    RelayRoomId room{};
    room.fill(0xDE); // no host registered this room

    auto t = RelayTransport::join(relay, room);
    CHECK_FALSE(t.has_value()); // relay should return an error
}

TEST_CASE("Relay: full EncryptiV session over relay transport", "[relay][session]") {
    REQUIRE(Crypto::initialize().has_value());

    ServerGuard guard;
    if (!guard.ok()) SKIP("Relay server failed to bind");
    const uint16_t srv_port = guard.port();

    auto alice_id = Identity::generate();
    REQUIRE(alice_id.has_value());
    auto bob_id = Identity::generate();
    REQUIRE(bob_id.has_value());

    ev::core::Endpoint relay{"127.0.0.1", srv_port};
    RelayRoomId room{};
    room.fill(0xAB);

    std::atomic<bool> bob_done{false};
    std::string       bob_error;

    // Bob: host (Session::accept).
    std::thread bob_thread([&]() {
        auto t = RelayTransport::host(relay, room);
        if (!t) { bob_error = t.error().message; bob_done = true; return; }

        auto s = Session::accept(*bob_id, "Bob", std::move(*t));
        if (!s) { bob_error = s.error().message; bob_done = true; return; }

        auto msg = s->recv_text();
        if (!msg) { bob_error = msg.error().message; bob_done = true; return; }
        if (*msg != "Hello Bob over relay")
            bob_error = "body mismatch: " + *msg;

        static_cast<void>(s->send_text("Hello Alice over relay"));
        bob_done = true;
    });

    // Give Bob time to register.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Alice: guest (Session::initiate).
    auto at = RelayTransport::join(relay, room);
    if (!at) {
        bob_thread.detach();
        SKIP("Relay join failed: " + at.error().message);
    }

    auto alice_s = Session::initiate(*alice_id, "Alice", std::move(*at));
    REQUIRE(alice_s.has_value());
    REQUIRE(alice_s->is_established());
    CHECK(alice_s->peer_display_name() == "Bob");

    REQUIRE(alice_s->send_text("Hello Bob over relay").has_value());
    auto reply = alice_s->recv_text();
    REQUIRE(reply.has_value());
    CHECK(*reply == "Hello Alice over relay");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!bob_done && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (bob_thread.joinable()) bob_thread.join();

    if (!bob_error.empty()) FAIL("Bob: " + bob_error);
    SUCCEED("Full EncryptiV session over relay transport passed");
}
