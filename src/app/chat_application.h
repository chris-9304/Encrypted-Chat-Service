#pragma once

#include <ev/core/error.h>
#include <ev/discovery/discovery_service.h>
#include <ev/group/group_manager.h>
#include <ev/identity/device_registry.h>
#include <ev/identity/identity.h>
#include <ev/identity/peer_directory.h>
#include <ev/session/session.h>
#include <ev/store/message_store.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <cstring>

namespace ev::app {

// One live session plus its dedicated receive thread.
// dead is heap-allocated so SessionEntry is movable despite std::atomic.
struct SessionEntry {
    std::unique_ptr<ev::session::Session>   session;
    std::thread                             recv_thread;
    std::shared_ptr<std::atomic<bool>>      dead{std::make_shared<std::atomic<bool>>(false)};

    explicit SessionEntry(std::unique_ptr<ev::session::Session> s)
        : session(std::move(s)) {}

    // Move-only.
    SessionEntry(SessionEntry&&)            = default;
    SessionEntry& operator=(SessionEntry&&) = default;
    SessionEntry(const SessionEntry&)       = delete;
    SessionEntry& operator=(const SessionEntry&) = delete;
};

class ChatApplication {
public:
    ChatApplication(std::string name, uint16_t port, std::string connect_target);
    ~ChatApplication();

    ev::core::Result<void> run();

private:
    // Background thread functions.
    void listen_thread_func();
    void discovery_thread_func();
    void cleanup_thread_func();

    // Per-session receive thread (one per SessionEntry).
    void session_recv_func(SessionEntry* entry);
    void session_recv_func_impl(std::shared_ptr<std::atomic<bool>> dead_flag,
                                ev::session::Session* session_ptr);

    // Spawn a receive thread for a newly added session.
    void start_recv_thread(SessionEntry& entry);

    // Add a session (takes lock internally).
    void add_session(std::unique_ptr<ev::session::Session> s);

    // Command handlers.
    void handle_command(const std::string& line);
    void print_help() const;
    void cmd_peers();
    void cmd_switch(const std::string& args);
    void cmd_safety();
    void cmd_verify();
    void cmd_send_file(const std::string& path);
    void cmd_history();
    void cmd_group_create(const std::string& name);
    void cmd_group_list();
    void cmd_group_switch(const std::string& args);
    void cmd_group_msg(const std::string& text);
    void cmd_group_invite(const std::string& args);
    void cmd_group_leave();
    void cmd_devices();
    void cmd_link_device(const std::string& pub_hex);
    void cmd_install_cert(const std::string& cert_hex);

    // State.
    std::string my_name_;
    uint16_t    my_port_;
    std::string connect_target_;

    std::unique_ptr<ev::identity::Identity>           identity_;
    ev::identity::PeerDirectory                       peer_dir_;
    ev::identity::DeviceRegistry                      device_registry_;
    std::unique_ptr<ev::discovery::DiscoveryService>  discovery_;
    std::optional<ev::store::MessageStore>            store_;
    ev::group::GroupManager                           group_mgr_;

    // Active pairwise sessions.
    mutable std::mutex           session_mutex_;
    std::vector<SessionEntry>    sessions_;      // guarded by session_mutex_
    size_t                       current_session_idx_{0};

    // Active group selection.
    std::optional<ev::core::GroupId> current_group_;

    std::atomic<bool> running_{true};
    std::thread       listen_thread_;
    std::thread       discovery_thread_;
    std::thread       cleanup_thread_;

    // Message queue for background threads to post display output.
    mutable std::mutex              print_mutex_;
};

} // namespace ev::app
