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
#include <functional>
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

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    // Unlocks identity, opens DB, starts background threads, then returns.
    // The caller (main) then runs the FTXUI loop on the main thread.
    cloak::core::Result<void> run();
    void shutdown();  // Signal all threads to stop.

    // ── Callback types (called from background threads) ────────────────────────
    using MessageCallback    = std::function<void(std::string from, std::string text,
                                                   bool is_mine)>;
    using PeerChangeCallback = std::function<void()>;
    using SystemCallback     = std::function<void(std::string msg)>;

    void set_message_callback(MessageCallback cb);
    void set_peer_change_callback(PeerChangeCallback cb);
    void set_system_callback(SystemCallback cb);

    // ── Peer snapshot ─────────────────────────────────────────────────────────
    struct PeerInfo {
        size_t      index;
        std::string name;
        std::string fingerprint;
        bool        online;
        size_t      queued_count;
        bool        verified;
    };
    std::vector<PeerInfo> get_peers() const;
    void                  switch_peer(size_t idx);
    size_t                current_peer_idx() const;

    // ── Message actions ───────────────────────────────────────────────────────
    cloak::core::Result<void> send_text_to_current(const std::string& text);

    // ── Invite / connect ──────────────────────────────────────────────────────
    // Generates the invite code locally (fast) and launches the relay host in
    // background.  Peer connection fires the peer-change callback.
    cloak::core::Result<std::string> make_invite_code();
    cloak::core::Result<void>        connect_invite(const std::string& code);
    cloak::core::Result<void>        connect_to(const std::string& host, uint16_t port);

    // ── Identity info ─────────────────────────────────────────────────────────
    std::string my_name()        const;
    std::string my_fingerprint() const;

    // ── Message history ───────────────────────────────────────────────────────
    struct MessageEntry {
        std::string sender;
        std::string text;
        std::string time_str;
        bool        is_mine;
    };
    // Returns in-memory messages accumulated during this session.
    std::vector<MessageEntry> get_message_snapshot() const;

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

    // ── Callbacks ─────────────────────────────────────────────────────────────
    mutable std::mutex  cb_mutex_;
    MessageCallback     msg_cb_;
    PeerChangeCallback  peer_cb_;
    SystemCallback      sys_cb_;

    // Helpers that fire callbacks (take cb_mutex_ internally).
    void fire_message(std::string from, std::string text, bool is_mine);
    void fire_peer_change();
    void fire_system(std::string msg);

    // ── In-memory message log (appended by recv threads) ──────────────────────
    mutable std::mutex          log_mutex_;
    std::vector<MessageEntry>   message_log_;

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
