#pragma once

#include <ev/core/error.h>
#include <ev/identity/identity.h>
#include <ev/session/session.h>
#include <ev/discovery/discovery_service.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

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

    std::string my_name_;
    uint16_t my_port_;
    std::string connect_target_;

    std::unique_ptr<ev::identity::Identity> identity_;
    std::unique_ptr<ev::discovery::DiscoveryService> discovery_;
    
    std::mutex session_mutex_;
    std::vector<std::unique_ptr<ev::session::Session>> active_sessions_;
    size_t current_session_index_{0};

    std::atomic<bool> running_{true};
    std::thread listen_thread_;
    std::thread receive_thread_;
    std::thread discovery_thread_;
};

} // namespace ev::app
