#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/discovery/discovery_service.h>
#include <cloak/group/group_manager.h>
#include <cloak/identity/device_registry.h>
#include <cloak/identity/identity.h>
#include <cloak/identity/peer_directory.h>
#include <cloak/session/session.h>
#include <cloak/store/message_store.h>
#include <cloak/transport/relay_transport.h>

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <cstring>

namespace cloak::app {

// Offline message queue entry.
struct QueuedMessage {
    std::string text;
};

// One live session plus its dedicated receive thread.
// dead is heap-allocated so SessionEntry is movable despite std::atomic.
struct SessionEntry {
    std::unique_ptr<cloak::session::Session>  session;
    std::thread                               recv_thread;
    std::shared_ptr<std::atomic<bool>>        dead{std::make_shared<std::atomic<bool>>(false)};

    explicit SessionEntry(std::unique_ptr<cloak::session::Session> s)
        : session(std::move(s)) {}

    SessionEntry(SessionEntry&&)            = default;
    SessionEntry& operator=(SessionEntry&&) = default;
    SessionEntry(const SessionEntry&)       = delete;
    SessionEntry& operator=(const SessionEntry&) = delete;
};

class ChatApplication {
public:
    ChatApplication(std::string name, uint16_t port, std::string connect_target,
                    std::optional<cloak::core::Endpoint> relay_endpoint = std::nullopt);
    ~ChatApplication();

    cloak::core::Result<void> run();

private:
    // Background thread functions.
    void listen_thread_func();
    void discovery_thread_func();
    void cleanup_thread_func();

    // Per-session receive thread — drains offline queue then enters recv loop.
    void session_recv_func_impl(std::shared_ptr<std::atomic<bool>> dead_flag,
                                cloak::session::Session* session_ptr);

    // Spawn a receive thread for a newly added session.
    void start_recv_thread(SessionEntry& entry);

    // Add a session (takes session_mutex_ internally).
    void add_session(std::unique_ptr<cloak::session::Session> s);

    // Queue a text message for later delivery to the named peer.
    // Call while holding session_mutex_ (queue_mutex_ is taken inside).
    void queue_for_peer(const std::string& fingerprint,
                        const std::string& peer_name,
                        const std::string& text);

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

    // Phase 4: relay / invite commands.
    void cmd_make_invite();
    void cmd_connect_invite(const std::string& code);

    // ── State ─────────────────────────────────────────────────────────────────
    std::string my_name_;
    uint16_t    my_port_;
    std::string connect_target_;
    std::optional<cloak::core::Endpoint> relay_endpoint_;

    std::unique_ptr<cloak::identity::Identity>           identity_;
    cloak::identity::PeerDirectory                       peer_dir_;
    cloak::identity::DeviceRegistry                      device_registry_;
    std::unique_ptr<cloak::discovery::DiscoveryService>  discovery_;
    std::optional<cloak::store::MessageStore>            store_;
    cloak::group::GroupManager                           group_mgr_;

    // Active pairwise sessions.
    mutable std::mutex        session_mutex_;
    std::vector<SessionEntry> sessions_;
    size_t                    current_session_idx_{0};

    // Active group selection.
    std::optional<cloak::core::GroupId> current_group_;

    // ── Offline message queue ─────────────────────────────────────────────────
    // Lock order rule: always take session_mutex_ before queue_mutex_.
    mutable std::mutex                               queue_mutex_;
    std::map<std::string, std::deque<QueuedMessage>> message_queue_; // key = peer fingerprint

    std::atomic<bool> running_{true};
    std::thread       listen_thread_;
    std::thread       discovery_thread_;
    std::thread       cleanup_thread_;

    mutable std::mutex print_mutex_;
};

} // namespace cloak::app
