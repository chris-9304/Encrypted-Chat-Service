#pragma once

#include <ev/core/error.h>
#include <ev/discovery/discovery_service.h>
#include <ev/identity/identity.h>
#include <ev/identity/peer_directory.h>
#include <ev/session/session.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ev::app {

class ChatApplication {
public:
    ChatApplication(std::string name, uint16_t port, std::string connect_target);
    ~ChatApplication();

    ev::core::Result<void> run();

private:
    void listen_thread_func();
    void receive_thread_func();
    void discovery_thread_func();
    void handle_command(const std::string& line);
    void print_help();

    std::string my_name_;
    uint16_t    my_port_;
    std::string connect_target_;

    std::unique_ptr<ev::identity::Identity>        identity_;
    ev::identity::PeerDirectory                    peer_dir_;
    std::unique_ptr<ev::discovery::DiscoveryService> discovery_;

    mutable std::mutex                                  session_mutex_;
    std::vector<std::unique_ptr<ev::session::Session>>  active_sessions_;
    size_t                                              current_session_index_{0};

    std::atomic<bool> running_{true};
    std::thread       listen_thread_;
    std::thread       receive_thread_;
    std::thread       discovery_thread_;
};

} // namespace ev::app
