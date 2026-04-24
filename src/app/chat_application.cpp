#include "chat_application.h"
#include <ev/crypto/crypto.h>
#include <ev/transport/tcp_transport.h>
#include <ev/discovery/loopback_discovery.h>
#include <iostream>
#include <chrono>

namespace ev::app {

using namespace ev::core;
using namespace ev::session;
using namespace ev::identity;
using namespace ev::transport;
using namespace ev::discovery;
using namespace ev::crypto;

ChatApplication::ChatApplication(std::string name, uint16_t port, std::string connect_target)
    : my_name_(std::move(name)), my_port_(port), connect_target_(std::move(connect_target)) {}

ChatApplication::~ChatApplication() {
    running_ = false;
    if (listen_thread_.joinable()) listen_thread_.join();
    if (receive_thread_.joinable()) receive_thread_.join();
    if (discovery_thread_.joinable()) discovery_thread_.join();
}

void ChatApplication::listen_thread_func() {
    while (running_) {
        auto t_res = TcpTransport::accept_from(my_port_);
        if (t_res.has_value() && running_) {
            auto s_res = Session::accept(*identity_, my_name_, std::move(t_res.value()));
            if (s_res.has_value()) {
                std::lock_guard<std::mutex> lock(session_mutex_);
                active_sessions_.push_back(std::make_unique<Session>(std::move(s_res.value())));
                std::cout << "\n[System] Accepted connection from " << active_sessions_.back()->peer_display_name() 
                          << " (FP: " << active_sessions_.back()->peer_fingerprint() << ")\n> " << std::flush;
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

void ChatApplication::receive_thread_func() {
    while (running_) {
        std::string msg;
        std::string peer_name;
        bool got_msg = false;

        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            for (auto& s : active_sessions_) {
                if (s->is_established()) {
                    auto res = s->recv_text();
                    if (res.has_value()) {
                        msg = std::move(res.value());
                        peer_name = s->peer_display_name();
                        got_msg = true;
                        break;
                    }
                }
            }
        }
        
        if (got_msg) {
            std::cout << "\n" << peer_name << ": " << msg << "\n> " << std::flush;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // tight loop protection
        }
    }
}

void ChatApplication::discovery_thread_func() {
     while(running_) {
         std::this_thread::sleep_for(std::chrono::seconds(2));
         auto peers = discovery_->get_discovered_peers();
         // If a peer is discovered, we would auto-connect here.
         // For demo reliability we rely heavily on --connect.
     }
}

ev::core::Result<void> ChatApplication::run() {
    Crypto::initialize();
    auto id_res = Identity::generate();
    if (!id_res.has_value()) return std::unexpected(Error{ErrorCode::CryptoError, "Identity generation failed", std::nullopt});
    identity_ = std::make_unique<Identity>(std::move(id_res.value()));

    // FIXME(M1.5): protect peer_dir_ with session_mutex_ when MessageStore is wired in

    std::cout << "Identity Generated. FP: " << identity_->fingerprint() << "\n";
    
    discovery_ = std::make_unique<LoopbackDiscoveryService>();

    listen_thread_ = std::thread(&ChatApplication::listen_thread_func, this);
    receive_thread_ = std::thread(&ChatApplication::receive_thread_func, this);
    discovery_thread_ = std::thread(&ChatApplication::discovery_thread_func, this);

    if (!connect_target_.empty()) {
        size_t colon = connect_target_.find(':');
        if (colon != std::string::npos) {
            std::string host = connect_target_.substr(0, colon);
            uint16_t port = std::stoi(connect_target_.substr(colon + 1));
            auto t_res = TcpTransport::connect({host, port});
            if (t_res.has_value()) {
                auto s_res = Session::initiate(*identity_, my_name_, std::move(t_res.value()));
                if (s_res.has_value()) {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    active_sessions_.push_back(std::make_unique<Session>(std::move(s_res.value())));
                    std::cout << "[System] Connected to " << active_sessions_.back()->peer_display_name() << "\n";
                }
            } else {
                std::cout << "[System] Failed to connect to " << connect_target_ << "\n";
            }
        }
    }

    std::cout << "\nType /peers to list. /switch <id> to switch. Anything else to send.\n";
    
    std::string line;
    while (running_) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        
        if (line.empty()) continue;
        
        if (line == "/peers") {
            std::lock_guard<std::mutex> lock(session_mutex_);
            for (size_t i = 0; i < active_sessions_.size(); ++i) {
                std::cout << i << ": " << active_sessions_[i]->peer_display_name() 
                          << " (" << active_sessions_[i]->peer_fingerprint() << ")"
                          << (i == current_session_index_ ? " *" : "") << "\n";
            }
        } else if (line.compare(0, 8, "/switch ") == 0) {
            size_t idx = std::stoi(line.substr(8));
            std::lock_guard<std::mutex> lock(session_mutex_);
            if (idx < active_sessions_.size()) {
                current_session_index_ = idx;
                std::cout << "[System] Switched to " << active_sessions_[idx]->peer_display_name() << "\n";
            }
        } else {
            std::lock_guard<std::mutex> lock(session_mutex_);
            if (!active_sessions_.empty() && current_session_index_ < active_sessions_.size()) {
                active_sessions_[current_session_index_]->send_text(line);
            } else {
                std::cout << "[System] No active sessions.\n";
            }
        }
    }

    return {};
}

} // namespace ev::app
