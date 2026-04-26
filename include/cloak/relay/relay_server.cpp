#include <cloak/relay/relay_server.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <boost/asio.hpp>
#include <array>
#include <condition_variable>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace cloak::relay {

using namespace cloak::core;
namespace asio = boost::asio;

// ── Protocol constants (must match relay_transport.cpp) ───────────────────────

static constexpr uint8_t kMagic[4]        = {0x43, 0x4C, 0x4B, 0x31}; // "CLK1"
static constexpr uint8_t kRoleHost        = 0x01;
static constexpr uint8_t kRoleJoin        = 0x02;
static constexpr uint8_t kStatusWaiting   = 0x00;
static constexpr uint8_t kStatusInitiator = 0x01;
static constexpr uint8_t kStatusResponder = 0x02;
static constexpr uint8_t kStatusError     = 0xFF;

using RoomId = std::array<uint8_t, 32>;
using SharedSocket = std::shared_ptr<asio::ip::tcp::socket>;

// ── Helpers ───────────────────────────────────────────────────────────────────

static void send_status(asio::ip::tcp::socket& sock, uint8_t status) {
    boost::system::error_code ec;
    asio::write(sock, asio::buffer(&status, 1), ec);
}

static void send_error(asio::ip::tcp::socket& sock, const std::string& msg) {
    boost::system::error_code ec;
    const uint16_t len = static_cast<uint16_t>(
        std::min(msg.size(), static_cast<size_t>(65535)));
    std::vector<uint8_t> buf;
    buf.reserve(3 + len);
    buf.push_back(kStatusError);
    buf.push_back(static_cast<uint8_t>(len >> 8));
    buf.push_back(static_cast<uint8_t>(len & 0xFF));
    buf.insert(buf.end(), msg.begin(), msg.begin() + len);
    asio::write(sock, asio::buffer(buf), ec);
}

// ── Forwarding ────────────────────────────────────────────────────────────────

// Read from `src` and write to `dst` until one side closes.
// Sets `done` on any error so the other forwarder thread also exits.
static void forward_loop(SharedSocket src, SharedSocket dst,
                         std::shared_ptr<std::atomic<bool>> done) {
    std::vector<uint8_t> buf(65536);
    while (!done->load()) {
        boost::system::error_code ec;
        const size_t n = src->read_some(asio::buffer(buf), ec);
        if (ec || n == 0) break;
        asio::write(*dst, asio::buffer(buf.data(), n), ec);
        if (ec) break;
    }
    done->store(true);
    // Shut down both directions so the other forwarder unblocks.
    boost::system::error_code ec;
    src->shutdown(asio::ip::tcp::socket::shutdown_receive, ec);
    dst->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
}

// Pipe `a` ↔ `b` using two threads; blocks until both sides close.
static void pipe_sockets(SharedSocket a, SharedSocket b) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread t([=]() { forward_loop(b, a, done); });
    forward_loop(a, b, done);
    if (t.joinable()) t.join();
}

// ── Room registry ─────────────────────────────────────────────────────────────

struct WaitingRoom {
    SharedSocket           host_socket;     // owned shared_ptr; host thread blocks below
    std::mutex             mu;
    std::condition_variable cv;
    SharedSocket           guest_socket;    // set by the guest handler thread
    bool                   guest_arrived{false};
    bool                   cancelled{false}; // host disconnected before guest
};

static std::mutex                                  g_rooms_mu;
static std::map<RoomId, std::shared_ptr<WaitingRoom>> g_rooms;

// ── Host handler ──────────────────────────────────────────────────────────────

static void handle_host(SharedSocket host_sock, const RoomId& room) {
    auto entry = std::make_shared<WaitingRoom>();
    entry->host_socket = host_sock;

    {
        std::lock_guard lg(g_rooms_mu);
        if (g_rooms.count(room)) {
            send_error(*host_sock, "room already has a host");
            return;
        }
        g_rooms[room] = entry;
    }

    // Acknowledge: tell host we are waiting for a guest.
    send_status(*host_sock, kStatusWaiting);

    // Block until a guest arrives or the host disconnects.
    {
        std::unique_lock lk(entry->mu);
        entry->cv.wait(lk, [&]{ return entry->guest_arrived || entry->cancelled; });
    }

    // Always clean up the room registry.
    {
        std::lock_guard lg(g_rooms_mu);
        g_rooms.erase(room);
    }

    if (entry->cancelled || !entry->guest_socket) return;

    // Tell host it is the Cloak responder (Session::accept side).
    boost::system::error_code ec;
    send_status(*host_sock, kStatusResponder);
    // Check that the write succeeded (host may have disconnected while waiting).
    if (ec) return;

    pipe_sockets(host_sock, entry->guest_socket);
}

// ── Guest handler ─────────────────────────────────────────────────────────────

// Guest handler runs briefly: finds the room, hands off its socket, and returns.
// The host thread takes over the guest socket and drives all I/O.
static void handle_guest(SharedSocket guest_sock, const RoomId& room) {
    std::shared_ptr<WaitingRoom> entry;
    {
        std::lock_guard lg(g_rooms_mu);
        auto it = g_rooms.find(room);
        if (it == g_rooms.end()) {
            send_error(*guest_sock, "room not found — host may not be ready yet");
            return;
        }
        entry = it->second;
    }

    // Tell guest it is the Cloak initiator (Session::initiate side).
    send_status(*guest_sock, kStatusInitiator);

    // Hand guest socket to the host entry and signal the waiting host thread.
    // From this point forward the host thread owns all I/O on guest_sock.
    {
        std::lock_guard lk(entry->mu);
        entry->guest_socket  = std::move(guest_sock);
        entry->guest_arrived = true;
    }
    entry->cv.notify_one();
    // This thread now exits; the host thread drives the forwarding.
}

// ── Client dispatcher ─────────────────────────────────────────────────────────

static void handle_client(asio::ip::tcp::socket raw_sock) {
    // Wrap in shared_ptr so it can be safely handed off between threads.
    auto sock = std::make_shared<asio::ip::tcp::socket>(std::move(raw_sock));

    boost::system::error_code ec;
    std::array<uint8_t, 37> hs{};
    asio::read(*sock, asio::buffer(hs), ec);
    if (ec) return;

    if (std::memcmp(hs.data(), kMagic, 4) != 0) {
        send_error(*sock, "bad magic — expected CLK1");
        return;
    }

    const uint8_t role = hs[4];
    RoomId room;
    std::memcpy(room.data(), hs.data() + 5, 32);

    if (role == kRoleHost)       handle_host(std::move(sock), room);
    else if (role == kRoleJoin)  handle_guest(std::move(sock), room);
    else                         send_error(*sock, "unknown role byte");
}

// ── RelayServer ───────────────────────────────────────────────────────────────

RelayServer::RelayServer(uint16_t port) : port_(port) {}
RelayServer::~RelayServer() { stop(); }

Result<void> RelayServer::run() {
    try {
        asio::io_context io;
        asio::ip::tcp::acceptor acceptor(
            io,
            asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port_));
        acceptor.set_option(asio::socket_base::reuse_address(true));

        bound_port_ = acceptor.local_endpoint().port();
        running_    = true;

        while (running_) {
            boost::system::error_code ec;
            asio::ip::tcp::socket sock(io);
            acceptor.accept(sock, ec);
            if (ec) {
                if (!running_) break;
                continue; // transient accept error — keep listening
            }
            sock.set_option(asio::ip::tcp::no_delay(true));
            // Each client gets its own detached thread; max concurrency is
            // bounded by OS limits and is sufficient for development use.
            std::thread(handle_client, std::move(sock)).detach();
        }
    } catch (const boost::system::system_error& e) {
        return std::unexpected(Error::from(ErrorCode::TransportError,
            std::string("RelayServer: ") + e.what()));
    }
    return {};
}

void RelayServer::stop() {
    running_ = false;
}

} // namespace cloak::relay
