#include <cloak/app/chat_application.h>
#include <cloak/crypto/crypto.h>
#include <cloak/transfer/file_transfer.h>
#include <cloak/transport/tcp_transport.h>
#include <cloak/transport/relay_transport.h>
#include <cloak/discovery/loopback_discovery.h>
#include <cloak/wire/framing.h>

#include <sodium.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace cloak::app {

using namespace cloak::core;
using namespace cloak::session;
using namespace cloak::identity;
using namespace cloak::transport;
using namespace cloak::discovery;
using namespace cloak::crypto;

// ── Constructor / Destructor ──────────────────────────────────────────────────

ChatApplication::ChatApplication(std::string name, uint16_t port,
                                  std::string connect_target,
                                  std::optional<cloak::core::Endpoint> relay_endpoint)
    : my_name_(std::move(name)),
      my_port_(port),
      connect_target_(std::move(connect_target)),
      relay_endpoint_(std::move(relay_endpoint)) {}

ChatApplication::~ChatApplication() {
    running_ = false;

    // Signal all recv threads to stop before joining background threads.
    // Without this, recv threads may block in recv_message() while cleanup_thread
    // is being joined — which can deadlock if cleanup tries to join a recv thread
    // that is itself waiting on running_ to change.
    {
        std::lock_guard lock(session_mutex_);
        for (auto& entry : sessions_)
            entry.dead->store(true);
    }

    if (listen_thread_.joinable())    listen_thread_.join();
    if (discovery_thread_.joinable()) discovery_thread_.join();
    if (cleanup_thread_.joinable())   cleanup_thread_.join();

    std::lock_guard lock(session_mutex_);
    for (auto& entry : sessions_) {
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
    auto dead_flag   = entry.dead;
    auto* session_ptr = entry.session.get();
    entry.recv_thread = std::thread(
        [this, dead_flag, session_ptr]() {
            session_recv_func_impl(dead_flag, session_ptr);
        });
}

// ── Offline queue helper ──────────────────────────────────────────────────────

void ChatApplication::queue_for_peer(const std::string& fingerprint,
                                      const std::string& peer_name,
                                      const std::string& text) {
    // Caller already holds session_mutex_; we take queue_mutex_ here.
    // Lock order: session_mutex_ → queue_mutex_ (never reversed elsewhere).
    std::lock_guard qlock(queue_mutex_);
    message_queue_[fingerprint].push_back({text});
    std::cout << "[Queue] Message saved for " << peer_name
              << " — will deliver when they reconnect.\n";
}

// ── Per-session receive thread ────────────────────────────────────────────────

void ChatApplication::session_recv_func(SessionEntry* /*entry*/) {}

void ChatApplication::session_recv_func_impl(
    std::shared_ptr<std::atomic<bool>> dead_flag,
    cloak::session::Session*           session_ptr) {

    // ── Drain offline queue for this peer ─────────────────────────────────
    {
        const std::string fp = session_ptr->peer_fingerprint();
        std::lock_guard qlock(queue_mutex_);
        auto it = message_queue_.find(fp);
        if (it != message_queue_.end() && !it->second.empty()) {
            {
                std::lock_guard plock(print_mutex_);
                std::cout << "\n[Queue] Delivering " << it->second.size()
                          << " offline message(s) to "
                          << session_ptr->peer_display_name() << "...\n> " << std::flush;
            }
            while (!it->second.empty()) {
                if (dead_flag->load()) break;
                const std::string& text = it->second.front().text;
                auto r = session_ptr->send_text(text);
                if (!r) { dead_flag->store(true); break; }
                {
                    std::lock_guard plock(print_mutex_);
                    std::cout << "\n[Queue] >> " << text << "\n> " << std::flush;
                }
                it->second.pop_front();
            }
            if (it->second.empty())
                message_queue_.erase(it);
        }
    }

    // ── Main receive loop ──────────────────────────────────────────────────
    while (!dead_flag->load() && running_) {
        auto res = session_ptr->recv_message();
        if (!res) {
            dead_flag->store(true);
            const std::string name = session_ptr->peer_display_name();
            std::lock_guard plock(print_mutex_);
            std::cout << "\n[System] " << name << " disconnected.\n> " << std::flush;
            return;
        }

        const auto [inner_type, body] = std::move(*res);
        const std::string name        = session_ptr->peer_display_name();

        switch (inner_type) {

        case cloak::wire::InnerType::Text: {
            const std::string text(
                reinterpret_cast<const char*>(body.data()), body.size());
            {
                std::lock_guard plock(print_mutex_);
                std::cout << "\n" << name << ": " << text << "\n> " << std::flush;
            }
            if (store_) {
                cloak::wire::Message msg;
                static_cast<void>(Crypto::random_bytes(
                    std::span<std::byte>(
                        reinterpret_cast<std::byte*>(msg.id.bytes.data()), 16)));
                std::memcpy(msg.from.bytes.data(),
                            session_ptr->peer_signing_key().bytes.data(), 32);
                std::memcpy(msg.to.bytes.data(),
                            identity_->signing_public().bytes.data(), 32);
                msg.timestamp = std::chrono::time_point_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now());
                msg.body          = text;
                msg.is_delivered  = true;
                msg.is_read       = false;
                msg.expires_at_ms = 0;
                static_cast<void>(store_->save_message(msg));
            }
            break;
        }

        case cloak::wire::InnerType::Receipt: {
            if (body.size() < 17) break;
            const auto rtype = static_cast<cloak::wire::ReceiptType>(body[0]);
            cloak::core::MessageId mid;
            std::memcpy(mid.bytes.data(),
                        reinterpret_cast<const std::byte*>(body.data()) + 1, 16);
            if (store_) {
                if (rtype == cloak::wire::ReceiptType::Delivered)
                    static_cast<void>(store_->mark_delivered(mid));
                else
                    static_cast<void>(store_->mark_read(mid));
            }
            break;
        }

        case cloak::wire::InnerType::GroupOp: {
            auto op_res = cloak::wire::decode_group_op(
                std::span<const std::byte>(body));
            if (!op_res) break;
            const auto& peer_pub = session_ptr->peer_signing_key();
            if (op_res->op == cloak::wire::GroupOpType::Create ||
                op_res->op == cloak::wire::GroupOpType::Invite) {
                const auto accept_r =
                    group_mgr_.accept_invite(*op_res, peer_pub);
                if (accept_r && store_) {
                    auto snap = group_mgr_.snapshot(op_res->group_id);
                    if (snap) static_cast<void>(store_->save_group(*snap));
                }
                std::lock_guard plock(print_mutex_);
                if (accept_r)
                    std::cout << "\n[Group] Joined group '"
                              << op_res->group_name << "'\n> " << std::flush;
            } else {
                static_cast<void>(group_mgr_.apply_op(*op_res));
                if (op_res->op == cloak::wire::GroupOpType::Leave) {
                    std::lock_guard plock(print_mutex_);
                    std::cout << "\n[Group] " << name << " left the group.\n> "
                              << std::flush;
                }
            }
            break;
        }

        case cloak::wire::InnerType::GroupMessage: {
            auto gmp = cloak::wire::decode_group_message(
                std::span<const std::byte>(body));
            if (!gmp) break;
            auto decrypted = group_mgr_.recv(*gmp);
            if (!decrypted) break;
            const auto& [sender_pub, text] = *decrypted;
            auto peer_rec = peer_dir_.find_by_signing_key(sender_pub);
            const std::string sender =
                peer_rec ? peer_rec->display_name : "[group member]";
            // Look up the group name by scanning the group list.
            std::string group_label = "group";
            for (const auto& [gid, gname] : group_mgr_.list_groups()) {
                if (gid.bytes == gmp->group_id.bytes) { group_label = gname; break; }
            }
            std::lock_guard plock(print_mutex_);
            std::cout << "\n[" << group_label << "] "
                      << sender << ": " << text << "\n> " << std::flush;
            break;
        }

        case cloak::wire::InnerType::DeviceLink: {
            // DeviceCert format: device_pub[32] | primary_pub[32] | sig[64]
            //                     | name_len[2 BE] | name[name_len]
            constexpr size_t kMinCert = 32 + 32 + 64 + 2;
            if (body.size() < kMinCert) break;

            cloak::identity::DeviceCert cert;
            size_t off = 0;
            std::memcpy(cert.device_pub.bytes.data(),
                        reinterpret_cast<const uint8_t*>(body.data()), 32); off += 32;
            std::memcpy(cert.primary_pub.bytes.data(),
                        reinterpret_cast<const uint8_t*>(body.data()) + off, 32); off += 32;
            std::memcpy(cert.primary_sig.bytes.data(),
                        reinterpret_cast<const uint8_t*>(body.data()) + off, 64); off += 64;
            const uint16_t nlen =
                (static_cast<uint16_t>(
                    static_cast<uint8_t>(body[off])) << 8) |
                 static_cast<uint8_t>(body[off + 1]);
            off += 2;
            if (off + nlen > body.size()) break;
            cert.device_name.assign(
                reinterpret_cast<const char*>(body.data()) + off, nlen);

            static_cast<void>(device_registry_.register_peer_device(cert));
            {
                std::lock_guard plock(print_mutex_);
                std::cout << "\n[Devices] Registered device '"
                          << cert.device_name << "' for " << name << "\n> "
                          << std::flush;
            }
            break;
        }

        case cloak::wire::InnerType::FileMetadata:
        case cloak::wire::InnerType::Typing:
        default:
            // Silently ignore unhandled inner types to stay robust.
            break;
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

        const auto& peer_pub = s_res->peer_signing_key();
        const auto  peer_fp  = s_res->peer_fingerprint();
        const auto  peer_name = s_res->peer_display_name();

        // If the connecting device presents a DeviceCert in its handshake payload,
        // we will receive it as a DeviceLink inner message shortly after.  For now
        // we record the peer so TOFU kicks in.
        {
            PeerRecord pr;
            pr.signing_public_key  = peer_pub;
            pr.kx_public_key       = {};  // filled in via directory persistence
            pr.display_name        = peer_name;
            pr.fingerprint         = peer_fp;
            auto up = peer_dir_.upsert(pr);
            if (!up && up.error().code == ErrorCode::IdentityChanged) {
                std::lock_guard plock(print_mutex_);
                std::cout << "\n[SECURITY] Key change detected for " << peer_name
                          << "!  Safety number changed — verify before trusting!\n> "
                          << std::flush;
            }
        }

        add_session(std::make_unique<Session>(std::move(*s_res)));

        std::lock_guard plock(print_mutex_);
        std::cout << "\n[System] Accepted connection from " << peer_name
                  << " (FP: " << peer_fp << ")\n> " << std::flush;
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
                const size_t idx =
                    static_cast<size_t>(std::distance(sessions_.begin(), it));
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
        auto peers_res = discovery_->get_discovered_peers();
        if (!peers_res) continue;
        for (const auto& dp : *peers_res) {
            // Auto-connect to newly discovered peers not yet in our session list.
            bool already_connected = false;
            {
                std::lock_guard lock(session_mutex_);
                for (const auto& e : sessions_) {
                    if (!e.dead->load() &&
                        e.session->peer_signing_key().bytes == dp.signing_pub.bytes) {
                        already_connected = true;
                        break;
                    }
                }
            }
            if (already_connected) continue;

            auto t_res = TcpTransport::connect(dp.endpoint);
            if (!t_res) continue;

            auto s_res = Session::initiate(*identity_, my_name_, std::move(*t_res));
            if (!s_res) continue;

            const auto fp   = s_res->peer_fingerprint();
            const auto pname = s_res->peer_display_name();
            add_session(std::make_unique<Session>(std::move(*s_res)));
            std::lock_guard plock(print_mutex_);
            std::cout << "\n[Discovery] Auto-connected to " << pname
                      << " (FP: " << fp << ")\n> " << std::flush;
        }
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

    const fs::path app_dir = fs::path(appdata_str) / "Cloak";
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
        sodium_memzero(pass.data(), pass.size());
        pass.clear();

        if (!save_res) {
            std::cerr << "[Warning] Could not save identity: "
                      << save_res.error().message << "\n";
        }
        std::cout << "[System] New identity created. FP: "
                  << identity_->fingerprint() << "\n";
    }

    // Guard against all-zero keypair (indicates a crypto failure).
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

    // Derive DB key from signing public key so we don't need passphrase twice.
    {
        constexpr std::string_view kDbInfo = "Cloak_DB_Key_v1";
        auto db_key_res = Crypto::hkdf_sha256(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(
                    identity_->signing_public().bytes.data()), 32),
            {},
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(kDbInfo.data()), kDbInfo.size()));
        if (db_key_res) {
            const auto db_path = app_dir / "messages.db";
            auto store_res = cloak::store::MessageStore::open(db_path, *db_key_res);
            if (store_res) {
                store_ = std::move(*store_res);
                static_cast<void>(store_->load_peers(peer_dir_));
                // Load persisted groups back into GroupManager.
                auto groups_res = store_->load_groups();
                if (groups_res) {
                    for (auto& rec : *groups_res) {
                        cloak::crypto::SecureBuffer<64> own_sk;
                        std::memcpy(own_sk.data(), rec.own_sign_sk.data(), 64);
                        cloak::core::PublicKey own_pk;
                        std::memcpy(own_pk.bytes.data(), rec.own_sign_pub.data(), 32);
                        std::array<uint8_t, 32> own_ck{};
                        std::memcpy(own_ck.data(), rec.own_chain_key.data(), 32);

                        std::vector<cloak::group::MemberState> members;
                        for (const auto& mr : rec.members) {
                            cloak::group::MemberState ms;
                            std::memcpy(ms.signing_pub.bytes.data(), mr.signing_pub.data(), 32);
                            ms.chain_key = mr.chain_key;
                            ms.counter   = mr.counter;
                            members.push_back(std::move(ms));
                        }

                        auto gs_res = cloak::group::GroupSession::from_state(
                            rec.group_id, rec.group_name,
                            std::move(own_sk), own_pk,
                            own_ck, rec.own_counter,
                            std::move(members));
                        if (gs_res)
                            static_cast<void>(group_mgr_.restore(std::move(*gs_res)));
                    }
                }
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

    // Outbound connect on startup if --connect was given.
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
                    const auto pname = s_res->peer_display_name();
                    const auto fp    = s_res->peer_fingerprint();

                    // If this device is secondary, send our cert so the peer can
                    // link us to our primary.
                    if (device_registry_.is_secondary()) {
                        auto cert = device_registry_.own_cert();
                        if (cert) {
                            std::vector<std::byte> cert_payload;
                            cert_payload.resize(32 + 32 + 64 + 2 +
                                                cert->device_name.size());
                            size_t off = 0;
                            std::memcpy(cert_payload.data() + off,
                                        cert->device_pub.bytes.data(), 32); off += 32;
                            std::memcpy(cert_payload.data() + off,
                                        cert->primary_pub.bytes.data(), 32); off += 32;
                            std::memcpy(cert_payload.data() + off,
                                        cert->primary_sig.bytes.data(), 64); off += 64;
                            const uint16_t nlen =
                                static_cast<uint16_t>(cert->device_name.size());
                            cert_payload[off]     = static_cast<std::byte>(nlen >> 8);
                            cert_payload[off + 1] = static_cast<std::byte>(nlen & 0xFF);
                            off += 2;
                            std::memcpy(cert_payload.data() + off,
                                        cert->device_name.data(),
                                        cert->device_name.size());
                            static_cast<void>(
                                s_res->send_inner(cloak::wire::InnerType::DeviceLink,
                                                  std::span<const std::byte>(cert_payload)));
                        }
                    }

                    add_session(std::make_unique<Session>(std::move(*s_res)));
                    std::cout << "[System] Connected to " << pname
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

    // Persist peers and groups on clean exit.
    if (store_) {
        static_cast<void>(store_->save_peers(peer_dir_));
        for (const auto& [gid, gname] : group_mgr_.list_groups()) {
            auto snap = group_mgr_.snapshot(gid);
            if (snap) static_cast<void>(store_->save_group(*snap));
        }
    }

    return {};
}

// ── Command dispatch ──────────────────────────────────────────────────────────

void ChatApplication::print_help() const {
    std::cout <<
        "\nCloak 0.4.0 — Commands:\n"
        "  /help                  This help\n"
        "  /fp                    Show your fingerprint\n"
        "  /peers                 List connected peers (shows queued message count)\n"
        "  /switch <idx>          Switch active pairwise session\n"
        "  /safety                Safety number for current peer\n"
        "  /verify                Mark current peer as verified\n"
        "  /send <path>           Send any file (image, video, document, etc.)\n"
        "  /history               Show full conversation history\n"
        "  /quit                  Exit cleanly\n"
        "\nGroup commands:\n"
        "  /group-create <name>   Create a new group\n"
        "  /groups                List your groups\n"
        "  /group-switch <idx>    Switch active group\n"
        "  /group-invite [<idx>]  Invite current (or indexed) peer to active group\n"
        "  /group-msg <text>      Send encrypted message to active group\n"
        "  /group-leave           Leave active group\n"
        "\nMulti-device commands:\n"
        "  /devices               List known linked devices for current peer\n"
        "  /link-device <pubhex>  Issue a device cert (primary only)\n"
        "  /install-cert <hex>    Install cert making this a secondary device\n"
        "\nInternet relay commands:\n"
        "  /make-invite           Generate an invite code via the configured relay\n"
        "  /connect-invite <code> Connect to a peer using an invite code\n"
        "\n  <any other text>       Send encrypted message to current peer.\n"
        "                         If the peer is offline, the message is queued\n"
        "                         and delivered automatically on reconnect.\n\n";
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

    if (starts_with("/switch "))         { cmd_switch(arg_of("/switch ")); return; }
    if (starts_with("/send "))           { cmd_send_file(arg_of("/send ")); return; }
    if (starts_with("/group-create "))   { cmd_group_create(arg_of("/group-create ")); return; }
    if (starts_with("/group-switch "))   { cmd_group_switch(arg_of("/group-switch ")); return; }
    if (starts_with("/group-invite"))    { cmd_group_invite(arg_of("/group-invite")); return; }
    if (starts_with("/group-msg "))      { cmd_group_msg(arg_of("/group-msg ")); return; }
    if (starts_with("/link-device "))    { cmd_link_device(arg_of("/link-device ")); return; }
    if (starts_with("/install-cert "))   { cmd_install_cert(arg_of("/install-cert ")); return; }
    if (line == "/make-invite")          { cmd_make_invite(); return; }
    if (starts_with("/connect-invite ")) { cmd_connect_invite(arg_of("/connect-invite ")); return; }

    // ── Default: send pairwise text to active session ────────────────────────
    std::lock_guard lock(session_mutex_);

    if (sessions_.empty()) {
        std::cout << "[System] Not connected. Use --connect, /make-invite, or"
                     " /connect-invite to reach a peer.\n";
        return;
    }

    // Session exists but is currently dead → queue for automatic retry.
    if (current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        const auto& e = sessions_[std::min(current_session_idx_,
                                           sessions_.size() - 1)];
        queue_for_peer(e.session->peer_fingerprint(),
                       e.session->peer_display_name(), line);
        return;
    }

    auto& s = *sessions_[current_session_idx_].session;
    auto  res = s.send_text(line);
    if (!res) {
        const std::string fp    = s.peer_fingerprint();
        const std::string pname = s.peer_display_name();
        std::cerr << "[System] Send failed: " << res.error().message << "\n";
        sessions_[current_session_idx_].dead->store(true);
        // Queue the failed message — prepend so it's first when peer reconnects.
        {
            std::lock_guard qlock(queue_mutex_);
            message_queue_[fp].push_front({line});
        }
        std::cout << "[Queue] Message queued for " << pname
                  << " — will retry on reconnect.\n";
        return;
    }

    if (store_) {
        cloak::wire::Message msg;
        static_cast<void>(Crypto::random_bytes(
            std::span<std::byte>(
                reinterpret_cast<std::byte*>(msg.id.bytes.data()), 16)));
        std::memcpy(msg.from.bytes.data(),
                    identity_->signing_public().bytes.data(), 32);
        std::memcpy(msg.to.bytes.data(),
                    s.peer_signing_key().bytes.data(), 32);
        msg.timestamp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
        msg.body          = line;
        msg.is_delivered  = false;
        msg.is_read       = true;
        msg.expires_at_ms = 0;
        static_cast<void>(store_->save_message(msg));
    }
}

// ── Command implementations ───────────────────────────────────────────────────

void ChatApplication::cmd_peers() {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty()) { std::cout << "(no connected peers)\n"; return; }
    for (size_t i = 0; i < sessions_.size(); ++i) {
        const auto& e  = sessions_[i];
        const auto  fp = e.session->peer_fingerprint();
        if (e.dead->load()) {
            // Show queued message count so user knows messages are waiting.
            std::string queue_str;
            {
                std::lock_guard qlock(queue_mutex_);
                auto it = message_queue_.find(fp);
                if (it != message_queue_.end() && !it->second.empty())
                    queue_str = " [" + std::to_string(it->second.size()) + " queued]";
            }
            std::cout << i << ": [offline] " << e.session->peer_display_name()
                      << queue_str << "\n";
        } else {
            auto rec = peer_dir_.find_by_fingerprint(fp);
            const std::string trust_str =
                rec ? (rec->trust == cloak::core::TrustStatus::Verified ? " [verified]" :
                       rec->trust == cloak::core::TrustStatus::Changed  ? " [KEY CHANGED]" :
                       "")
                    : "";
            std::cout << i << ": " << e.session->peer_display_name()
                      << "  FP:" << fp
                      << trust_str
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
            std::cout << "[System] Invalid session index.\n";
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
    const auto  fp = s.peer_fingerprint();
    static_cast<void>(peer_dir_.mark_verified(fp));
    std::cout << "[System] " << s.peer_display_name() << " marked as verified.\n";
}

void ChatApplication::cmd_send_file(const std::string& path) {
    std::lock_guard lock(session_mutex_);
    if (sessions_.empty() || current_session_idx_ >= sessions_.size() ||
        sessions_[current_session_idx_].dead->load()) {
        std::cout << "[System] No active session.\n"; return;
    }
    auto& s = *sessions_[current_session_idx_].session;

    // Detect MIME type from extension so the receiver can handle it correctly.
    namespace fs = std::filesystem;
    std::string mime = "application/octet-stream";
    {
        const auto ext = fs::path(path).extension().string();
        if      (ext == ".jpg"  || ext == ".jpeg") mime = "image/jpeg";
        else if (ext == ".png")                    mime = "image/png";
        else if (ext == ".gif")                    mime = "image/gif";
        else if (ext == ".webp")                   mime = "image/webp";
        else if (ext == ".mp4")                    mime = "video/mp4";
        else if (ext == ".mkv")                    mime = "video/x-matroska";
        else if (ext == ".mov")                    mime = "video/quicktime";
        else if (ext == ".avi")                    mime = "video/x-msvideo";
        else if (ext == ".mp3")                    mime = "audio/mpeg";
        else if (ext == ".wav")                    mime = "audio/wav";
        else if (ext == ".pdf")                    mime = "application/pdf";
        else if (ext == ".txt")                    mime = "text/plain";
        else if (ext == ".zip")                    mime = "application/zip";
        else if (ext == ".7z")                     mime = "application/x-7z-compressed";
    }

    std::cout << "[System] Sending " << path << " (" << mime << ")...\n";
    auto fid_res = cloak::transfer::send_file(
        s, cloak::core::Path(path), mime,
        [](uint64_t sent, uint64_t total) {
            const int pct = total > 0 ? static_cast<int>(sent * 100 / total) : 0;
            std::cout << "\r  " << sent << "/" << total << " bytes  ("
                      << pct << "%)  " << std::flush;
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
    cloak::core::PeerId peer_id;
    std::memcpy(peer_id.bytes.data(), s.peer_signing_key().bytes.data(), 32);
    cloak::core::PeerId my_id;
    std::memcpy(my_id.bytes.data(), identity_->signing_public().bytes.data(), 32);

    auto msgs = store_->get_conversation(my_id, peer_id, cloak::core::Timestamp{});
    if (!msgs) {
        std::cerr << "[System] History error: " << msgs.error().message << "\n"; return;
    }
    if (msgs->empty()) { std::cout << "(no message history)\n"; return; }

    std::cout << "--- History with " << s.peer_display_name() << " ---\n";
    for (const auto& m : *msgs) {
        const auto ms_count = m.timestamp.time_since_epoch().count();
        const std::time_t t = static_cast<std::time_t>(ms_count / 1000);
        char tbuf[20];
        std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", std::localtime(&t));
        const bool is_mine = m.from.bytes == my_id.bytes;
        const std::string dir = is_mine ? "me" : s.peer_display_name();
        std::cout << "[" << tbuf << "] " << dir << ": " << m.body
                  << (m.is_read ? "" : " (unread)") << "\n";
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
    if (store_) {
        auto snap = group_mgr_.snapshot(*gid_res);
        if (snap) static_cast<void>(store_->save_group(*snap));
    }
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
    auto enc_res = cloak::wire::encode_group_message(*payload_res);
    if (!enc_res) return;

    std::lock_guard lock(session_mutex_);
    int cnt = 0;
    for (auto& entry : sessions_) {
        if (!entry.dead->load() && entry.session->is_established()) {
            // Send as InnerType::GroupMessage so receiver can dispatch correctly.
            auto sr = entry.session->send_inner(
                cloak::wire::InnerType::GroupMessage,
                std::span<const std::byte>(*enc_res));
            if (sr) ++cnt;
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

    auto enc_res = cloak::wire::encode_group_op(*op_res);
    if (!enc_res) return;

    auto& s = *sessions_[target_idx].session;
    if (auto sr = s.send_inner(cloak::wire::InnerType::GroupOp,
                               std::span<const std::byte>(*enc_res)); !sr) {
        std::cerr << "[System] Send invite failed: " << sr.error().message << "\n"; return;
    }
    std::cout << "[System] Invited "
              << sessions_[target_idx].session->peer_display_name() << " to group.\n";
}

void ChatApplication::cmd_group_leave() {
    if (!current_group_) { std::cout << "[System] No active group.\n"; return; }

    const cloak::core::GroupId gid = *current_group_;
    auto op_res = group_mgr_.leave(gid);
    current_group_.reset();

    if (store_) static_cast<void>(store_->delete_group(gid));

    if (!op_res) return;

    auto enc_res = cloak::wire::encode_group_op(*op_res);
    if (!enc_res) return;

    std::lock_guard lock(session_mutex_);
    for (auto& entry : sessions_) {
        if (!entry.dead->load() && entry.session->is_established())
            static_cast<void>(entry.session->send_inner(
                cloak::wire::InnerType::GroupOp,
                std::span<const std::byte>(*enc_res)));
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
    cloak::core::PublicKey secondary_pub;
    for (size_t i = 0; i < 32; ++i) {
        secondary_pub.bytes[i] = static_cast<uint8_t>(
            std::stoi(pub_hex.substr(i * 2, 2), nullptr, 16));
    }
    std::cout << "Device name for secondary: " << std::flush;
    std::string device_name;
    std::getline(std::cin, device_name);
    if (device_name.empty()) device_name = "Unnamed device";

    auto cert_res = device_registry_.issue_cert(*identity_, secondary_pub, device_name);
    if (!cert_res) {
        std::cerr << "[System] issue_cert failed: " << cert_res.error().message << "\n";
        return;
    }

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

    std::cout << "[System] Device cert (paste on secondary device with /install-cert):\n"
              << hex.str() << "\n";
}

void ChatApplication::cmd_install_cert(const std::string& cert_hex) {
    constexpr size_t kMinHex = (32 + 32 + 64 + 2) * 2;
    if (cert_hex.size() < kMinHex) {
        std::cout << "[System] Usage: /install-cert <hex>\n"; return;
    }
    auto hb = [&](size_t i) -> uint8_t {
        return static_cast<uint8_t>(
            std::stoi(cert_hex.substr(i * 2, 2), nullptr, 16));
    };

    cloak::identity::DeviceCert cert;
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
    std::cout << "[System] Cert installed. This device is now secondary.\n"
              << "         Reconnect to a peer to advertise your device cert.\n";
}

// ── Phase 4: relay / invite ───────────────────────────────────────────────────

void ChatApplication::cmd_make_invite() {
    if (!relay_endpoint_) {
        std::cout << "[System] No relay configured. Start with --relay <host:port>\n";
        return;
    }

    // Derive room_id: BLAKE2b-256(sign_pub || random_16_bytes).
    cloak::transport::RelayRoomId room_id{};
    {
        std::array<std::byte, 32 + 16> seed{};
        std::memcpy(seed.data(),
                    identity_->signing_public().bytes.data(), 32);
        static_cast<void>(cloak::crypto::Crypto::random_bytes(
            std::span<std::byte>(seed.data() + 32, 16)));
        auto hash = cloak::crypto::Crypto::blake2b_256(
            std::span<const std::byte>(seed));
        if (!hash) {
            std::cerr << "[System] Failed to generate room ID.\n";
            return;
        }
        std::memcpy(room_id.data(), hash->data(), 32);
    }

    const std::string code =
        cloak::transport::make_invite_code(*relay_endpoint_, room_id);

    std::cout << "[Invite] Share this code with the peer you want to connect to:\n"
              << "  " << code << "\n"
              << "[Invite] Waiting for peer to connect (Ctrl+C to cancel)...\n"
              << std::flush;

    // Block in a background thread; the main REPL stays responsive on other commands.
    const cloak::core::Endpoint relay_ep = *relay_endpoint_;
    std::thread([this, relay_ep, room_id]() {
        auto t_res = cloak::transport::RelayTransport::host(relay_ep, room_id);
        if (!t_res) {
            std::lock_guard plock(print_mutex_);
            std::cerr << "\n[Invite] Relay host failed: "
                      << t_res.error().message << "\n> " << std::flush;
            return;
        }

        // Relay paired us as responder — accept the Cloak handshake.
        auto s_res = cloak::session::Session::accept(
            *identity_, my_name_, std::move(*t_res));
        if (!s_res) {
            std::lock_guard plock(print_mutex_);
            std::cerr << "\n[Invite] Handshake failed: "
                      << s_res.error().message << "\n> " << std::flush;
            return;
        }

        const auto peer_name = s_res->peer_display_name();
        const auto peer_fp   = s_res->peer_fingerprint();
        const auto& peer_pub = s_res->peer_signing_key();

        // TOFU check.
        {
            cloak::identity::PeerRecord pr;
            pr.signing_public_key = peer_pub;
            pr.display_name       = peer_name;
            pr.fingerprint        = peer_fp;
            auto up = peer_dir_.upsert(pr);
            if (!up && up.error().code == cloak::core::ErrorCode::IdentityChanged) {
                std::lock_guard plock(print_mutex_);
                std::cout << "\n[SECURITY] Key change detected for " << peer_name
                          << "! Verify before trusting.\n> " << std::flush;
            }
        }

        add_session(std::make_unique<cloak::session::Session>(std::move(*s_res)));
        {
            std::lock_guard plock(print_mutex_);
            std::cout << "\n[Invite] Connected to " << peer_name
                      << " via relay (FP: " << peer_fp << ")\n> " << std::flush;
        }
    }).detach();
}

void ChatApplication::cmd_connect_invite(const std::string& code) {
    if (code.empty()) {
        std::cout << "[System] Usage: /connect-invite <invite_code>\n";
        return;
    }

    cloak::core::Endpoint relay_ep;
    cloak::transport::RelayRoomId room_id{};
    if (!cloak::transport::parse_invite_code(code, relay_ep, room_id)) {
        std::cout << "[System] Invalid invite code format.\n"
                  << "  Expected: <relay_host>:<relay_port>/<64-hex-chars>\n";
        return;
    }

    std::cout << "[Invite] Connecting to relay at "
              << relay_ep.address << ":" << relay_ep.port << "...\n" << std::flush;

    auto t_res = cloak::transport::RelayTransport::join(relay_ep, room_id);
    if (!t_res) {
        std::cerr << "[Invite] Relay join failed: " << t_res.error().message << "\n";
        return;
    }

    // Relay paired us as initiator — drive the Cloak handshake.
    auto s_res = cloak::session::Session::initiate(
        *identity_, my_name_, std::move(*t_res));
    if (!s_res) {
        std::cerr << "[Invite] Handshake failed: " << s_res.error().message << "\n";
        return;
    }

    const auto peer_name = s_res->peer_display_name();
    const auto peer_fp   = s_res->peer_fingerprint();
    const auto& peer_pub = s_res->peer_signing_key();

    // TOFU check.
    {
        cloak::identity::PeerRecord pr;
        pr.signing_public_key = peer_pub;
        pr.display_name       = peer_name;
        pr.fingerprint        = peer_fp;
        auto up = peer_dir_.upsert(pr);
        if (!up && up.error().code == cloak::core::ErrorCode::IdentityChanged) {
            std::cout << "[SECURITY] Key change detected for " << peer_name
                      << "! Verify before trusting.\n";
        }
    }

    add_session(std::make_unique<cloak::session::Session>(std::move(*s_res)));
    std::cout << "[Invite] Connected to " << peer_name
              << " via relay (FP: " << peer_fp << ")\n";
}

} // namespace cloak::app
