#include <ev/app/chat_application.h>
#include <ev/crypto/crypto.h>
#include <ev/transport/tcp_transport.h>
#include <ev/discovery/loopback_discovery.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace ev::app {

using namespace ev::core;
using namespace ev::session;
using namespace ev::identity;
using namespace ev::transport;
using namespace ev::discovery;
using namespace ev::crypto;

// ── Constructor / Destructor ──────────────────────────────────────────────────

ChatApplication::ChatApplication(std::string name, uint16_t port,
                                  std::string connect_target)
    : my_name_(std::move(name)),
      my_port_(port),
      connect_target_(std::move(connect_target)) {}

ChatApplication::~ChatApplication() {
    running_ = false;
    if (listen_thread_.joinable())    listen_thread_.join();
    if (receive_thread_.joinable())   receive_thread_.join();
    if (discovery_thread_.joinable()) discovery_thread_.join();
}

// ── Background threads ────────────────────────────────────────────────────────

void ChatApplication::listen_thread_func() {
    while (running_) {
        auto t_res = TcpTransport::accept_from(my_port_);
        if (!t_res || !running_) {
            if (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            continue;
        }

        auto s_res = Session::accept(*identity_, my_name_, std::move(*t_res));
        if (!s_res) {
            std::cerr << "\n[System] Accept handshake failed: "
                      << s_res.error().message << "\n> " << std::flush;
            continue;
        }

        {
            std::lock_guard lock(session_mutex_);
            std::cout << "\n[System] Accepted connection from "
                      << s_res->peer_display_name()
                      << " (FP: " << s_res->peer_fingerprint() << ")\n> "
                      << std::flush;
            active_sessions_.push_back(
                std::make_unique<Session>(std::move(*s_res)));
        }
    }
}

// The receive thread does a non-blocking poll: it tries each established
// session with a short timeout by relying on Boost.Asio non-blocking reads
// internally.  Because TcpTransport::receive() is blocking, we run each
// session's recv on a separate detached thread to avoid head-of-line blocking.
// Phase 2: replace with per-session Asio strands.
void ChatApplication::receive_thread_func() {
    while (running_) {
        // Snapshot active sessions so we don't hold the mutex during I/O.
        std::vector<Session*> snapshot;
        {
            std::lock_guard lock(session_mutex_);
            for (auto& s : active_sessions_) {
                if (s && s->is_established()) snapshot.push_back(s.get());
            }
        }

        bool got_any = false;
        for (Session* s : snapshot) {
            // Attempt a recv — transport_->receive(4) blocks; wrap in timed-out
            // thread to avoid starving other sessions.
            // For Phase 1 single-peer demo this is fine; Phase 2 uses strands.
            auto res = s->recv_text();
            if (res) {
                std::cout << "\n" << s->peer_display_name() << ": "
                          << *res << "\n> " << std::flush;
                got_any = true;
            }
        }

        if (!got_any) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

void ChatApplication::discovery_thread_func() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        // Phase 2: auto-connect to newly discovered peers.
    }
}

// ── run() ─────────────────────────────────────────────────────────────────────

Result<void> ChatApplication::run() {
    // Initialise libsodium.
    if (auto r = Crypto::initialize(); !r) return std::unexpected(r.error());

    // Load or generate identity.
    namespace fs = std::filesystem;
    char* appdata_ptr = nullptr;
    size_t appdata_len = 0;
    _dupenv_s(&appdata_ptr, &appdata_len, "APPDATA");
    std::string appdata_str = (appdata_ptr ? appdata_ptr : ".");
    free(appdata_ptr);
    fs::path app_dir = fs::path(appdata_str) / "EncryptiV";
    fs::create_directories(app_dir);
    const auto id_path = app_dir / "identity.bin";

    if (Identity::exists(id_path)) {
        std::cout << "Passphrase to unlock identity: " << std::flush;
        std::string pass;
        std::getline(std::cin, pass);

        auto id_res = Identity::load(
            id_path,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(pass.data()), pass.size()));
        if (!id_res) {
            std::cerr << "[Error] " << id_res.error().message << "\n";
            return std::unexpected(id_res.error());
        }
        identity_ = std::make_unique<Identity>(std::move(*id_res));
        std::cout << "[System] Identity loaded. FP: " << identity_->fingerprint() << "\n";
    } else {
        std::cout << "No identity found. Creating new identity.\n";
        std::cout << "Choose a passphrase (protect your identity file): " << std::flush;
        std::string pass;
        std::getline(std::cin, pass);

        auto id_res = Identity::generate();
        if (!id_res) return std::unexpected(id_res.error());
        identity_ = std::make_unique<Identity>(std::move(*id_res));

        auto save_res = identity_->save(
            id_path,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(pass.data()), pass.size()));
        if (!save_res) {
            std::cerr << "[Warning] Could not save identity: "
                      << save_res.error().message << "\n";
        }
        std::cout << "[System] New identity created. FP: "
                  << identity_->fingerprint() << "\n";
    }

    // Start loopback discovery.
    discovery_ = std::make_unique<LoopbackDiscoveryService>();
    static_cast<void>(discovery_->start_advertising(
        {my_name_, my_port_, identity_->signing_public()}));

    // Start background threads.
    listen_thread_    = std::thread(&ChatApplication::listen_thread_func, this);
    receive_thread_   = std::thread(&ChatApplication::receive_thread_func, this);
    discovery_thread_ = std::thread(&ChatApplication::discovery_thread_func, this);

    // Outbound connect if requested.
    if (!connect_target_.empty()) {
        const auto colon = connect_target_.find(':');
        if (colon != std::string::npos) {
            const std::string host = connect_target_.substr(0, colon);
            const uint16_t    port = static_cast<uint16_t>(
                std::stoi(connect_target_.substr(colon + 1)));

            auto t_res = TcpTransport::connect({host, port});
            if (t_res) {
                auto s_res = Session::initiate(
                    *identity_, my_name_, std::move(*t_res));
                if (s_res) {
                    const auto& name = s_res->peer_display_name();
                    const auto& fp   = s_res->peer_fingerprint();
                    {
                        std::lock_guard lock(session_mutex_);
                        active_sessions_.push_back(
                            std::make_unique<Session>(std::move(*s_res)));
                    }
                    std::cout << "[System] Connected to " << name
                              << " (FP: " << fp << ")\n";
                } else {
                    std::cerr << "[System] Handshake failed: "
                              << s_res.error().message << "\n";
                }
            } else {
                std::cerr << "[System] Connect failed: "
                          << t_res.error().message << "\n";
            }
        }
    }

    print_help();

    std::string line;
    while (running_) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        handle_command(line);
    }

    return {};
}

// ── Command dispatch ──────────────────────────────────────────────────────────

void ChatApplication::print_help() {
    std::cout <<
        "\n"
        "Commands:\n"
        "  /help               Show this help\n"
        "  /peers              List connected peers\n"
        "  /switch <idx>       Switch active session\n"
        "  /safety             Show safety number for current peer\n"
        "  /verify             Mark current peer as verified\n"
        "  /fp                 Show your own fingerprint\n"
        "  /quit               Exit\n"
        "  <any other text>    Send message to current peer\n\n";
}

void ChatApplication::handle_command(const std::string& line) {
    if (line == "/help") {
        print_help();
        return;
    }

    if (line == "/fp") {
        std::cout << "My fingerprint: " << identity_->fingerprint() << "\n";
        return;
    }

    if (line == "/peers") {
        std::lock_guard lock(session_mutex_);
        if (active_sessions_.empty()) {
            std::cout << "(no connected peers)\n";
            return;
        }
        for (size_t i = 0; i < active_sessions_.size(); ++i) {
            const auto& s = *active_sessions_[i];
            std::cout << i << ": " << s.peer_display_name()
                      << "  FP:" << s.peer_fingerprint()
                      << (i == current_session_index_ ? "  *" : "") << "\n";
        }
        return;
    }

    if (line.compare(0, 8, "/switch ") == 0) {
        try {
            size_t idx = static_cast<size_t>(std::stoi(line.substr(8)));
            std::lock_guard lock(session_mutex_);
            if (idx < active_sessions_.size()) {
                current_session_index_ = idx;
                std::cout << "[System] Switched to "
                          << active_sessions_[idx]->peer_display_name() << "\n";
            } else {
                std::cout << "[System] Invalid index.\n";
            }
        } catch (...) {
            std::cout << "[System] Usage: /switch <index>\n";
        }
        return;
    }

    if (line == "/safety") {
        std::lock_guard lock(session_mutex_);
        if (active_sessions_.empty() ||
            current_session_index_ >= active_sessions_.size()) {
            std::cout << "[System] No active session.\n";
            return;
        }
        const auto& s  = *active_sessions_[current_session_index_];
        const auto  sn = Identity::safety_number(identity_->signing_public(),
                                                  s.peer_signing_key());
        std::cout << "Safety number with " << s.peer_display_name() << ":\n"
                  << "  " << sn.digits << "\n"
                  << "Compare this out-of-band to verify their identity.\n";
        return;
    }

    if (line == "/verify") {
        std::lock_guard lock(session_mutex_);
        if (active_sessions_.empty() ||
            current_session_index_ >= active_sessions_.size()) {
            std::cout << "[System] No active session.\n";
            return;
        }
        const auto& s  = *active_sessions_[current_session_index_];
        static_cast<void>(peer_dir_.mark_verified(s.peer_fingerprint()));
        std::cout << "[System] " << s.peer_display_name()
                  << " marked as verified.\n";
        return;
    }

    if (line == "/quit") {
        running_ = false;
        return;
    }

    // Default: send as message.
    std::lock_guard lock(session_mutex_);
    if (active_sessions_.empty() ||
        current_session_index_ >= active_sessions_.size()) {
        std::cout << "[System] No active session. Use /peers to list.\n";
        return;
    }
    auto& s   = *active_sessions_[current_session_index_];
    auto  res = s.send_text(line);
    if (!res) {
        std::cerr << "[System] Send failed: " << res.error().message << "\n";
    }
}

} // namespace ev::app
