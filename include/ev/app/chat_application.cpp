#include <ev/app/chat_application.h>
#include <ev/crypto/crypto.h>
#include <ev/transfer/file_transfer.h>
#include <ev/transport/tcp_transport.h>
#include <ev/discovery/loopback_discovery.h>
#include <ev/wire/framing.h>

#include <sodium.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

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
    if (discovery_thread_.joinable()) discovery_thread_.join();
    if (cleanup_thread_.joinable())   cleanup_thread_.join();

    std::lock_guard lock(session_mutex_);
    for (auto& entry : sessions_) {
        entry.dead->store(true);
        if (entry.recv_thread.joinable()) entry.recv_thread.join();
    }
}

// ── add_session / start_recv_thread ──────────────────────────────────────────

void ChatApplication::add_session(std::unique_ptr<Session> s) {
    std::lock_guard lock(session_mutex_);
    sessions_.emplace_back(std::move(s));
    start_recv_thread(sessions_.back());
}

void ChatApplication::start_recv_thread(SessionEntry& entry) {
    // Capture shared_ptr so the dead flag outlives SessionEntry erasure.
    auto dead_flag = entry.dead;
    auto* session_ptr = entry.session.get();
    entry.recv_thread = std::thread(
        [this, dead_flag, session_ptr]() {
            session_recv_func_impl(dead_flag, session_ptr);
        });
}

// ── Per-session receive thread ────────────────────────────────────────────────

void ChatApplication::session_recv_func(SessionEntry* /*entry*/) {
    // Kept for ABI; real implementation below.
}

void ChatApplication::session_recv_func_impl(
    std::shared_ptr<std::atomic<bool>> dead_flag,
    ev::session::Session*              session_ptr) {

    while (!dead_flag->load() && running_) {
        auto res = session_ptr->recv_text();
        if (!res) {
            dead_flag->store(true);
            const std::string name = session_ptr->peer_display_name();
            std::lock_guard plock(print_mutex_);
            std::cout << "\n[System] " << name << " disconnected.\n> "
                      << std::flush;
            return;
        }

        const std::string& body = *res;
        const std::string  name = session_ptr->peer_display_name();

        // Check inner type byte for group ops.
        if (!body.empty()) {
            const auto type_byte = static_cast<uint8_t>(
                static_cast<unsigned char>(body[0]));
            if (type_byte == static_cast<uint8_t>(ev::wire::InnerType::GroupOp) &&
                body.size() >= 2) {
                auto op_res = ev::wire::decode_group_op(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte*>(body.data() + 1),
                        body.size() - 1));
                if (op_res) {
                    const auto& peer_pub = session_ptr->peer_signing_key();
                    if (op_res->op == ev::wire::GroupOpType::Create ||
                        op_res->op == ev::wire::GroupOpType::Invite) {
                        const auto accept_r =
                            group_mgr_.accept_invite(*op_res, peer_pub);
                        std::lock_guard plock(print_mutex_);
                        if (accept_r) {
                            std::cout << "\n[Group] Joined group '"
                                      << op_res->group_name << "'\n> " << std::flush;
                        }
                    } else {
                        static_cast<void>(group_mgr_.apply_op(*op_res));
                    }
                }
                continue;
            }
        }

        // Display and persist plain text.
        {
            std::lock_guard plock(print_mutex_);
            std::cout << "\n" << name << ": " << body << "\n> " << std::flush;
        }

        if (store_) {
            ev::wire::Message msg;
            static_cast<void>(Crypto::random_bytes(
                std::span<std::byte>(
                    reinterpret_cast<std::byte*>(msg.id.bytes.data()), 16)));
            std::memcpy(msg.from.bytes.data(),
                        session_ptr->peer_signing_key().bytes.data(), 32);
            msg.timestamp = std::chrono::time_point_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now());
            msg.body         = body;
            msg.is_delivered = true;
            msg.is_read      = false;
            msg.expires_at_ms = 0;
            static_cast<void>(store_->save_message(msg));
        }
    }
}

// ── Background: listen ────────────────────────────────────────────────────────

void ChatApplication::listen_thread_func() {
    while (running_) {
        auto t_res = TcpTransport::accept_from(my_port_);
        if (!t_res || !running_) {
            if (running_)
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        auto s_res = Session::accept(*identity_, my_name_, std::move(*t_res));
        if (!s_res) {
            std::lock_guard plock(print_mutex_);
            std::cerr << "\n[System] Accept handshake failed: "
                      << s_res.error().message << "\n> " << std::flush;
            continue;
        }

        const auto name = s_res->peer_display_name();
        const auto fp   = s_res->peer_fingerprint();

        add_session(std::make_unique<Session>(std::move(*s_res)));

        std::lock_guard plock(print_mutex_);
        std::cout << "\n[System] Accepted connection from " << name
                  << " (FP: " << fp << ")\n> " << std::flush;
    }
}

// ── Background: cleanup dead sessions ────────────────────────────────────────

void ChatApplication::cleanup_thread_func() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::lock_guard lock(session_mutex_);
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (it->dead->load()) {
                if (it->recv_thread.joinable()) it->recv_thread.join();
                const size_t idx = static_cast<size_t>(
                    std::distance(sessions_.begin(), it));
                if (current_session_idx_ > 0 && idx <= current_session_idx_)
                    --current_session_idx_;
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// ── Background: discovery ─────────────────────────────────────────────────────

void ChatApplication::discovery_thread_func() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        // Phase 3: mDNS peer discovery and auto-connect.
    }
}

// ── run() ─────────────────────────────────────────────────────────────────────

Result<void> ChatApplication::run() {
    if (auto r = Crypto::initialize(); !r) return std::unexpected(r.error());

    namespace fs = std::filesystem;
    char* appdata_ptr = nullptr;
    size_t appdata_len = 0;
    _dupenv_s(&appdata_ptr, &appdata_len, "APPDATA");
    std::string appdata_str = (appdata_ptr ? appdata_ptr : ".");
    free(appdata_ptr);

    const fs::path app_dir = fs::path(appdata_str) / "EncryptiV";
    fs::create_directories(app_dir);
    const auto id_path = app_dir / "identity.bin";

    std::string pass;

    if (Identity::exists(id_path)) {
        std::cout << "Passphrase to unlock identity: " << std::flush;
        std::getline(std::cin, pass);

        auto id_res = Identity::load(
            id_path,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(pass.data()), pass.size()));

        // Zero passphrase immediately after use.
        sodium_memzero(pass.data(), pass.size());
        pass.clear();

        if (!id_res) {
            std::cerr << "[Error] " << id_res.error().message << "\n";
            return std::unexpected(id_res.error());
        }
        identity_ = std::make_unique<Identity>(std::move(*id_res));
        std::cout << "[System] Identity loaded. FP: " << identity_->fingerprint() << "\n";
    } else {
        std::cout << "No identity found. Creating new identity.\n";
        std::cout << "Choose a passphrase (protect your identity file): " << std::flush;
        std::getline(std::cin, pass);

        auto id_res = Identity::generate();
        if (!id_res) {
            sodium_memzero(pass.data(), pass.size());
            return std::unexpected(id_res.error());
        }
        identity_ = std::make_unique<Identity>(std::move(*id_res));

        auto save_res = identity_->save(
            id_path,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(pass.data()), pass.size()));

        // Zero passphrase immediately after use.
        sodium_memzero(pass.data(), pass.size());
        pass.clear();

        if (!save_res) {
            std::cerr << "[Warning] Could not save identity: "
                      << save_res.error().message << "\n";
        }
        std::cout << "[System] New identity created. FP: "
                  << identity_->fingerprint() << "\n";
    }

    // Guard against silent all-zero keypair.
    {
        bool all_zero = true;
        for (auto b : identity_->signing_public().bytes) {
            if (b != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            return std::unexpected(Error::from(ErrorCode::CryptoError,
                "Identity keypair generation failed (all-zero key)"));
        }
    }

    // Open message store. DB key is derived from signing public key via HKDF so
    // we don't need the passphrase a second time.
    {
        constexpr std::string_view kDbInfo = "EncryptiV_DB_Key_v1";
        auto db_key_res = Crypto::hkdf_sha256(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(
                    identity_->signing_public().bytes.data()), 32),
            {},
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(kDbInfo.data()), kDbInfo.size()));
        if (db_key_res) {
            const auto db_path = app_dir / "messages.db";
            auto store_res = ev::store::MessageStore::open(db_path, *db_key_res);
            if (store_res) {
                store_ = std::move(*store_res);
                static_cast<void>(store_->load_peers(peer_dir_));
            } else {
                std::cerr << "[Warning] Message store unavailable: "
                          << store_res.error().message << "\n";
            }
        }
    }

    device_registry_.init_as_primary(*identity_, my_name_);

    discovery_ = std::make_unique<LoopbackDiscoveryService>();
    static_cast<void>(discovery_->start_advertising(
        {my_name_, my_port_, identity_->signing_public()}));

    listen_thread_    = std::thread(&ChatApplication::listen_thread_func, this);
    discovery_thread_ = std::thread(&ChatApplication::discovery_thread_func, this);
    cleanup_thread_   = std::thread(&ChatApplication::cleanup_thread_func, this);

    // Outbound connect if requested.
    if (!connect_target_.empty()) {
        const auto colon = connect_target_.find(':');
        if (colon != std::string::npos) {
            const std::string host = connect_target_.substr(0, colon);
            const uint16_t    port = static_cast<uint16_t>(
                std::stoi(connect_target_.substr(colon + 1)));

            auto t_res = TcpTransport::connect({host, port});
            if (t_res) {
                auto s_res = Session::initiate(*identity_, my_name_, std::move(*t_res));
                if (s_res) {
                    const auto name = s_res->peer_display_name();
                    const auto fp   = s_res->peer_fingerprint();
                    add_session(std::make_unique<Session>(std::move(*s_res)));
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

    if (store_) static_cast<void>(store_->save_peers(peer_dir_));

    return {};
}

// ── Command dispatch ──────────────────────────────────────────────────────────

void ChatApplication::print_help() const {
    std::cout <<
        "\nCommands:\n"
        "  /help                  This help\n"
        "  /fp                    Show your fingerprint\n"
        "  /peers                 List connected peers\n"
        "  /switch <idx>          Switch active pairwise session\n"
        "  /safety                Safety number for current peer\n"
        "  /verify                Mark current peer as verified\n"
        "  /send <path>           Send a file to current peer\n"
        "  /history               Show recent message history\n"
        "\nGroup commands (Phase 3):\n"
        "  /group-create <name>   Create a new group\n"
        "  /groups                List your groups\n"
        "  /group-switch <idx>    Switch active group\n"
        "  /group-invite [<idx>]  Invite current (or indexed) peer to active group\n"
        "  /group-msg <text>      Send encrypted message to active group\n"
        "  /group-leave           Leave active group\n"
        "\nMulti-device commands (Phase 3):\n"
        "  /devices               List known linked devices for current peer\n"
        "  /link-device <pubhex>  Issue a device cert (primary only)\n"
        "  /install-cert <hex>    Install cert making this a secondary device\n"
        "\n  <any other text>       Send pairwise message to current peer\n\n";
}

void ChatApplication::handle_command(const std::string& line) {
    if (line == "/help") { print_help(); return; }
    if (line == "/fp") {
        std::cout << "My fingerprint: " << identity_->fingerprint() << "\n";
        return;
    }
    if (line == "/peers")        { cmd_peers(); return; }
    if (line == "/safety")       { cmd_safety(); return; }
    if (line == "/verify")       { cmd_verify(); return; }
    if (line == "/history")      { cmd_history(); return; }
    if (line == "/groups")       { cmd_group_list(); return; }
    if (line == "/group-leave")  { cmd_group_leave(); return; }
    if (line == "/devices")      { cmd_devices(); return; }
    if (line == "/quit") { running_ = false; return; }

    auto starts_with = [&](std::string_view prefix) {
        return line.compare(0, prefix.size(), prefix) == 0;
    };
    auto arg_of = [&](std::string_view prefix) -> std::string {
        return (line.size() > prefix.size()) ? line.substr(prefix.size()) : "";
    };

    if (starts_with("/switch "))       { cmd_switch(arg_of("/switch ")); return; }
    if (starts_with("/send "))         { cmd_send_file(arg_of("/send ")); return; }
    if (starts_with("/group-create ")) { cmd_group_create(arg_of("/group-create ")); return; }
    if (starts_with("/group-switch ")) { cmd_group_switch(arg_of("/group-switch ")); return; }
    if (starts_with("/group-invite"))  { cmd_group_invite(arg_of("/group-invite")); return; }
    if (starts_with("/group-msg "))    { cmd_group_msg(arg_of("/group-msg ")); return; }
    if (starts_with("/link-device "))  { cmd_link_device(arg_of("/link-device ")); return; }
    if (starts_with("/install-cert ")) { cmd_install_cert(arg_of("/install-cert ")); return; }

    // Default: send pairwise text to current session.
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session. Use /peers.\n";
        return;
    }
    auto& s   = *sessions_[current_session_idx_].session;
    auto  res = s.send_text(line);
    if (!res) {
        std::cerr << "[System] Send failed: " << res.error().message << "\n";
        sessions_[current_session_idx_].dead->load() = true;
        return;
    }

    if (store_) {
        ev::wire::Message msg;
        static_cast<void>(Crypto::random_bytes(
            std::span<std::byte>(
                reinterpret_cast<std::byte*>(msg.id.bytes.data()), 16)));
        std::memcpy(msg.from.bytes.data(),
                    identity_->signing_public().bytes.data(), 32);
        msg.timestamp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
        msg.body         = line;
        msg.is_delivered = false;
        msg.is_read      = true;
        msg.expires_at_ms = 0;
        static_cast<void>(store_->save_message(msg));
    }
}

// ── Command implementations ───────────────────────────────────────────────────

void ChatApplication::cmd_peers() {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty()) { std::cout << "(no connected peers)\n"; return; }
    for (size_t i = 0; i < sessions_.size(); ++i) {
        const auto& e = sessions_[i];
        if (e.dead) {
            std::cout << i << ": [disconnected]\n";
        } else {
            std::cout << i << ": " << e.session->peer_display_name()
                      << "  FP:" << e.session->peer_fingerprint()
                      << (i == current_session_idx_ ? "  *" : "") << "\n";
        }
    }
}

void ChatApplication::cmd_switch(const std::string& args) {
    try {
        const size_t idx = static_cast<size_t>(std::stoi(args));
        std::lock_guard lock(session_mutex_);
        if (idx < sessions_.size() && !sessions_[idx].dead->load()) {
            current_session_idx_ = idx;
            std::cout << "[System] Switched to "
                      << sessions_[idx].session->peer_display_name() << "\n";
        } else {
            std::cout << "[System] Invalid index.\n";
        }
    } catch (...) {
        std::cout << "[System] Usage: /switch <index>\n";
    }
}

void ChatApplication::cmd_safety() {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    const auto& s  = *sessions_[current_session_idx_].session;
    const auto  sn = Identity::safety_number(identity_->signing_public(),
                                              s.peer_signing_key());
    std::cout << "Safety number with " << s.peer_display_name() << ":\n"
              << "  " << sn.digits << "\n"
              << "Compare out-of-band to verify identity.\n";
}

void ChatApplication::cmd_verify() {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    const auto& s = *sessions_[current_session_idx_].session;
    static_cast<void>(peer_dir_.mark_verified(s.peer_fingerprint()));
    std::cout << "[System] " << s.peer_display_name() << " marked as verified.\n";
}

void ChatApplication::cmd_send_file(const std::string& path) {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    auto& s = *sessions_[current_session_idx_].session;
    std::cout << "[System] Sending " << path << " ...\n";
    auto fid_res = ev::transfer::send_file(
        s, ev::core::Path(path), "application/octet-stream",
        [](uint64_t sent, uint64_t total) {
            std::cout << "\r  " << sent << "/" << total << " bytes" << std::flush;
        });
    if (!fid_res) {
        std::cerr << "\n[System] File send failed: " << fid_res.error().message << "\n";
    } else {
        std::cout << "\n[System] File sent successfully.\n";
    }
}

void ChatApplication::cmd_history() {
    if (!store_) {
        std::cout << "[System] Message store not available.\n"; return;
    }
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    const auto& s = *sessions_[current_session_idx_].session;
    ev::core::PeerId peer_id;
    std::memcpy(peer_id.bytes.data(), s.peer_signing_key().bytes.data(), 32);

    auto msgs = store_->get_messages_for_peer(peer_id, ev::core::Timestamp{});
    if (!msgs) {
        std::cerr << "[System] History error: " << msgs.error().message << "\n"; return;
    }
    if (msgs->empty()) { std::cout << "(no message history)\n"; return; }

    std::cout << "--- History with " << s.peer_display_name() << " ---\n";
    for (const auto& m : *msgs) {
        const auto ms  = m.timestamp.time_since_epoch().count();
        const std::time_t t = static_cast<std::time_t>(ms / 1000);
        char tbuf[20];
        std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", std::localtime(&t));
        std::cout << "[" << tbuf << "] " << m.body << "\n";
    }
    std::cout << "--- End ---\n";
}

void ChatApplication::cmd_group_create(const std::string& name) {
    if (name.empty()) { std::cout << "[System] Usage: /group-create <name>\n"; return; }
    auto gid_res = group_mgr_.create_group(name, *identity_);
    if (!gid_res) {
        std::cerr << "[System] Create group failed: " << gid_res.error().message << "\n";
        return;
    }
    current_group_ = *gid_res;
    std::cout << "[System] Group '" << name << "' created and selected.\n";
}

void ChatApplication::cmd_group_list() {
    const auto groups = group_mgr_.list_groups();
    if (groups.empty()) { std::cout << "(no groups)\n"; return; }
    size_t i = 0;
    for (const auto& [gid, gname] : groups) {
        const bool active = current_group_ && current_group_->bytes == gid.bytes;
        std::cout << i++ << ": " << gname << (active ? "  *" : "") << "\n";
    }
}

void ChatApplication::cmd_group_switch(const std::string& args) {
    try {
        const size_t idx = static_cast<size_t>(std::stoi(args));
        const auto groups = group_mgr_.list_groups();
        if (idx >= groups.size()) { std::cout << "[System] Invalid index.\n"; return; }
        current_group_ = groups[idx].first;
        std::cout << "[System] Active group: " << groups[idx].second << "\n";
    } catch (...) {
        std::cout << "[System] Usage: /group-switch <index>\n";
    }
}

void ChatApplication::cmd_group_msg(const std::string& text) {
    if (!current_group_) {
        std::cout << "[System] No active group. Use /group-create or /group-switch.\n";
        return;
    }
    auto payload_res = group_mgr_.send(*current_group_, text);
    if (!payload_res) {
        std::cerr << "[System] Group encrypt failed: " << payload_res.error().message << "\n";
        return;
    }
    auto enc_res = ev::wire::encode_group_message(*payload_res);
    if (!enc_res) return;

    const std::string frame_str(
        reinterpret_cast<const char*>(enc_res->data()), enc_res->size());

    std::lock_guard lock(session_mutex_);
    int cnt = 0;
    for (auto& entry : sessions_) {
        if (!entry.dead->load() && entry.session->is_established()) {
            static_cast<void>(entry.session->send_text(frame_str));
            ++cnt;
        }
    }
    std::cout << "[Group] Sent to " << cnt << " peer(s).\n";
}

void ChatApplication::cmd_group_invite(const std::string& args) {
    if (!current_group_) {
        std::cout << "[System] No active group.\n"; return;
    }
    std::lock_guard lock(session_mutex_);

    size_t target_idx = current_session_idx_;
    if (!args.empty()) {
        try { target_idx = static_cast<size_t>(std::stoi(args)); }
        catch (...) {}
    }
    if (target_idx >= sessions_.size() || sessions_[target_idx].dead->load()) {
        std::cout << "[System] Invalid session index.\n"; return;
    }

    const auto& peer_pub = sessions_[target_idx].session->peer_signing_key();
    auto op_res = group_mgr_.invite(*current_group_, peer_pub);
    if (!op_res) {
        std::cerr << "[System] Invite failed: " << op_res.error().message << "\n"; return;
    }

    auto enc_res = ev::wire::encode_group_op(*op_res);
    if (!enc_res) return;

    std::string payload;
    payload.push_back(static_cast<char>(ev::wire::InnerType::GroupOp));
    payload.append(reinterpret_cast<const char*>(enc_res->data()), enc_res->size());

    auto& s = *sessions_[target_idx].session;
    if (auto sr = s.send_text(payload); !sr) {
        std::cerr << "[System] Send invite failed: " << sr.error().message << "\n"; return;
    }
    std::cout << "[System] Invited "
              << sessions_[target_idx].session->peer_display_name() << " to group.\n";
}

void ChatApplication::cmd_group_leave() {
    if (!current_group_) { std::cout << "[System] No active group.\n"; return; }

    auto op_res = group_mgr_.leave(*current_group_);
    current_group_.reset();
    if (!op_res) return;

    auto enc_res = ev::wire::encode_group_op(*op_res);
    if (!enc_res) return;

    std::string payload;
    payload.push_back(static_cast<char>(ev::wire::InnerType::GroupOp));
    payload.append(reinterpret_cast<const char*>(enc_res->data()), enc_res->size());

    std::lock_guard lock(session_mutex_);
    for (auto& entry : sessions_) {
        if (!entry.dead->load() && entry.session->is_established())
            static_cast<void>(entry.session->send_text(payload));
    }
    std::cout << "[System] Left group.\n";
}

void ChatApplication::cmd_devices() {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    const auto& peer_pub = sessions_[current_session_idx_].session->peer_signing_key();
    const auto  devices  = device_registry_.devices_for_primary(peer_pub);
    if (devices.empty()) { std::cout << "(no known linked devices)\n"; return; }
    std::cout << "Linked devices for "
              << sessions_[current_session_idx_].session->peer_display_name() << ":\n";
    for (const auto& d : devices)
        std::cout << "  [" << d.device_name << "]\n";
}

void ChatApplication::cmd_link_device(const std::string& pub_hex) {
    if (pub_hex.size() != 64) {
        std::cout << "[System] Usage: /link-device <64-hex signing pub>\n"; return;
    }
    ev::core::PublicKey secondary_pub;
    for (size_t i = 0; i < 32; ++i) {
        secondary_pub.bytes[i] = static_cast<uint8_t>(
            std::stoi(pub_hex.substr(i * 2, 2), nullptr, 16));
    }
    std::cout << "Device name for secondary: " << std::flush;
    std::string device_name;
    std::getline(std::cin, device_name);

    auto cert_res = device_registry_.issue_cert(*identity_, secondary_pub, device_name);
    if (!cert_res) {
        std::cerr << "[System] issue_cert failed: " << cert_res.error().message << "\n";
        return;
    }

    // Encode cert as hex for out-of-band transfer.
    std::ostringstream hex;
    auto push_hex = [&](const uint8_t* d, size_t n) {
        for (size_t i = 0; i < n; ++i)
            hex << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(d[i]);
    };
    push_hex(cert_res->device_pub.bytes.data(),  32);
    push_hex(cert_res->primary_pub.bytes.data(), 32);
    push_hex(cert_res->primary_sig.bytes.data(), 64);
    const auto nlen = static_cast<uint16_t>(cert_res->device_name.size());
    hex << std::hex << std::setw(4) << std::setfill('0') << nlen;
    push_hex(reinterpret_cast<const uint8_t*>(cert_res->device_name.data()),
             cert_res->device_name.size());

    std::cout << "[System] Device cert (give to secondary device):\n"
              << hex.str() << "\n";
}

void ChatApplication::cmd_install_cert(const std::string& cert_hex) {
    if (cert_hex.size() < (32 + 32 + 64 + 2) * 2) {
        std::cout << "[System] Usage: /install-cert <hex>\n"; return;
    }
    auto hb = [&](size_t i) -> uint8_t {
        return static_cast<uint8_t>(
            std::stoi(cert_hex.substr(i * 2, 2), nullptr, 16));
    };

    ev::identity::DeviceCert cert;
    for (size_t i = 0; i < 32; ++i) cert.device_pub.bytes[i]  = hb(i);
    for (size_t i = 0; i < 32; ++i) cert.primary_pub.bytes[i] = hb(32 + i);
    for (size_t i = 0; i < 64; ++i) cert.primary_sig.bytes[i] = hb(64 + i);

    const size_t   name_off = 32 + 32 + 64;
    const uint16_t name_len = static_cast<uint16_t>(
        (hb(name_off) << 8) | hb(name_off + 1));
    if (cert_hex.size() < (name_off + 2 + name_len) * 2) {
        std::cout << "[System] Cert hex truncated.\n"; return;
    }
    cert.device_name.resize(name_len);
    for (size_t i = 0; i < name_len; ++i)
        cert.device_name[i] = static_cast<char>(hb(name_off + 2 + i));

    auto res = device_registry_.init_as_secondary(std::move(cert));
    if (!res) {
        std::cerr << "[System] install_cert failed: " << res.error().message << "\n";
        return;
    }
    std::cout << "[System] Cert installed. This is now a secondary device.\n";
}

} // namespace ev::app
