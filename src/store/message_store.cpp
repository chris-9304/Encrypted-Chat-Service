#include <ev/store/message_store.h>
#include <ev/crypto/crypto.h>
#include <sqlite3.h>
#include <chrono>
#include <cstring>
#include <functional>

namespace ev::store {

using namespace ev::core;
using namespace ev::crypto;

// ── RAII sqlite3_stmt wrapper ─────────────────────────────────────────────────

struct Stmt {
    sqlite3_stmt* s{nullptr};
    ~Stmt() { if (s) sqlite3_finalize(s); }
    operator sqlite3_stmt*() { return s; }
};

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace {

Result<void> exec(sqlite3* db, const char* sql) {
    char* errmsg = nullptr;
    int   rc     = sqlite3_exec(db, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string msg(errmsg ? errmsg : "sqlite3_exec failed");
        sqlite3_free(errmsg);
        return std::unexpected(Error::from(ErrorCode::StorageError, msg));
    }
    return {};
}

Timestamp ms_to_ts(int64_t ms) {
    return Timestamp(std::chrono::milliseconds(ms));
}

int64_t ts_to_ms(const Timestamp& ts) {
    return ts.time_since_epoch().count();
}

} // namespace

// ── Constructor / Destructor ──────────────────────────────────────────────────

MessageStore::MessageStore(sqlite3* db, SecureBuffer<32> key)
    : db_(db), db_key_(std::move(key)) {}

MessageStore::~MessageStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── open() ────────────────────────────────────────────────────────────────────

Result<MessageStore> MessageStore::open(
    const Path& path, const SecureBuffer<32>& db_key) {

    sqlite3* db = nullptr;
    int rc = sqlite3_open(path.string().c_str(), &db);
    if (rc != SQLITE_OK) {
        const char* msg = db ? sqlite3_errmsg(db) : "sqlite3_open failed";
        if (db) sqlite3_close(db);
        return std::unexpected(Error::from(ErrorCode::StorageError, msg));
    }

    SecureBuffer<32> key_copy;
    std::memcpy(key_copy.data(), db_key.data(), 32);

    MessageStore store(db, std::move(key_copy));

    if (auto r = exec(db, "PRAGMA journal_mode=WAL;"); !r) return std::unexpected(r.error());
    if (auto r = exec(db, "PRAGMA foreign_keys=ON;");  !r) return std::unexpected(r.error());

    if (auto r = store.run_migrations(); !r) return std::unexpected(r.error());
    return store;
}

// ── Schema migrations ─────────────────────────────────────────────────────────

Result<void> MessageStore::run_migrations() {
    if (auto r = exec(db_, R"(
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
    )"); !r) return std::unexpected(r.error());

    int version = 0;
    {
        Stmt st;
        sqlite3_prepare_v2(db_,
            "SELECT version FROM schema_version LIMIT 1;", -1, &st.s, nullptr);
        if (sqlite3_step(st) == SQLITE_ROW)
            version = sqlite3_column_int(st, 0);
    }

    if (version < 1) {
        if (auto r = exec(db_, R"(
            CREATE TABLE IF NOT EXISTS messages (
                id           BLOB    PRIMARY KEY,
                from_peer    BLOB    NOT NULL,
                timestamp    INTEGER NOT NULL,
                body_ct      BLOB    NOT NULL,
                is_delivered INTEGER NOT NULL DEFAULT 0,
                is_read      INTEGER NOT NULL DEFAULT 0,
                expires_at   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_messages_from_peer
                ON messages(from_peer, timestamp);

            CREATE TABLE IF NOT EXISTS peers (
                fingerprint  TEXT    PRIMARY KEY,
                sign_pk      BLOB    NOT NULL,
                kx_pk        BLOB    NOT NULL,
                endpoint     TEXT    NOT NULL DEFAULT '',
                display_name TEXT    NOT NULL DEFAULT '',
                trust        INTEGER NOT NULL DEFAULT 0
            );

            INSERT OR IGNORE INTO schema_version(version) VALUES(0);
            UPDATE schema_version SET version = 1;
        )"); !r) return std::unexpected(r.error());
    }

    if (version < 2) {
        // Phase 3: group session persistence.
        if (auto r = exec(db_, R"(
            CREATE TABLE IF NOT EXISTS group_sessions (
                group_id        BLOB    PRIMARY KEY,
                group_name      TEXT    NOT NULL DEFAULT '',
                own_sign_sk_ct  BLOB    NOT NULL,
                own_sign_pub    BLOB    NOT NULL,
                own_chain_key_ct BLOB   NOT NULL,
                own_counter     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id        BLOB    NOT NULL,
                member_sign_pub BLOB    NOT NULL,
                chain_key_ct    BLOB    NOT NULL,
                counter         INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, member_sign_pub),
                FOREIGN KEY (group_id)
                    REFERENCES group_sessions(group_id) ON DELETE CASCADE
            );

            UPDATE schema_version SET version = 2;
        )"); !r) return std::unexpected(r.error());
    }

    if (version < 3) {
        // Phase 4: add to_peer column to messages for bidirectional history.
        if (auto r = exec(db_, R"(
            ALTER TABLE messages ADD COLUMN to_peer BLOB NOT NULL DEFAULT (zeroblob(32));
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
                ON messages(from_peer, to_peer, timestamp);
            UPDATE schema_version SET version = 3;
        )"); !r) return std::unexpected(r.error());
    }

    return {};
}

// ── Encryption helpers ────────────────────────────────────────────────────────
// Format: [24-byte nonce][ciphertext+16-byte tag]

Result<std::vector<std::byte>> MessageStore::encrypt_blob(
    std::span<const std::byte> plaintext) const {

    std::vector<std::byte> nonce(24);
    static_cast<void>(Crypto::random_bytes(std::span<std::byte>(nonce)));

    auto ct = Crypto::aead_encrypt(db_key_,
                                   std::span<const std::byte>(nonce),
                                   {},
                                   plaintext);
    if (!ct) return std::unexpected(ct.error());

    std::vector<std::byte> out;
    out.reserve(24 + ct->size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct->begin(), ct->end());
    return out;
}

Result<std::vector<std::byte>> MessageStore::decrypt_blob(
    std::span<const std::byte> blob) const {

    if (blob.size() < 24 + 16)
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            "Blob too short to decrypt"));
    return Crypto::aead_decrypt(db_key_, blob.subspan(0, 24), {}, blob.subspan(24));
}

Result<std::vector<std::byte>> MessageStore::encrypt_column(
    const std::string& plaintext) const {

    return encrypt_blob(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(plaintext.data()), plaintext.size()));
}

Result<std::string> MessageStore::decrypt_column(
    std::span<const std::byte> blob) const {

    auto pt = decrypt_blob(blob);
    if (!pt) return std::unexpected(pt.error());
    return std::string(reinterpret_cast<const char*>(pt->data()), pt->size());
}

// ── Messages ──────────────────────────────────────────────────────────────────

Result<void> MessageStore::save_message(const ev::wire::Message& message) {
    auto body_ct = encrypt_column(message.body);
    if (!body_ct) return std::unexpected(body_ct.error());

    std::lock_guard lock(mu_);

    Stmt st;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO messages"
        "(id, from_peer, to_peer, timestamp, body_ct, is_delivered, is_read, expires_at)"
        " VALUES(?,?,?,?,?,?,?,?);",
        -1, &st.s, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));

    sqlite3_bind_blob(st, 1, message.id.bytes.data(), 16, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, message.from.bytes.data(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, message.to.bytes.data(),   32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, ts_to_ms(message.timestamp));
    sqlite3_bind_blob(st, 5, body_ct->data(),
                      static_cast<int>(body_ct->size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, message.is_delivered ? 1 : 0);
    sqlite3_bind_int(st, 7, message.is_read      ? 1 : 0);
    sqlite3_bind_int64(st, 8, message.expires_at_ms);

    if (sqlite3_step(st) != SQLITE_DONE)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    return {};
}

namespace {

ev::wire::Message read_message_row(sqlite3_stmt* st,
    const std::function<ev::core::Result<std::string>(std::span<const std::byte>)>& decrypt) {
    ev::wire::Message m;
    std::memcpy(m.id.bytes.data(),   sqlite3_column_blob(st, 0), 16);
    std::memcpy(m.from.bytes.data(), sqlite3_column_blob(st, 1), 32);
    std::memcpy(m.to.bytes.data(),   sqlite3_column_blob(st, 2), 32);
    m.timestamp = Timestamp(std::chrono::milliseconds(sqlite3_column_int64(st, 3)));
    const auto* ct_data = static_cast<const std::byte*>(sqlite3_column_blob(st, 4));
    const int   ct_sz   = sqlite3_column_bytes(st, 4);
    if (ct_sz > 0 && ct_data != nullptr) {
        auto body = decrypt(std::span<const std::byte>(ct_data, ct_sz));
        if (body) m.body = std::move(*body);
    }
    m.is_delivered  = sqlite3_column_int(st, 5) != 0;
    m.is_read       = sqlite3_column_int(st, 6) != 0;
    m.expires_at_ms = sqlite3_column_int64(st, 7);
    return m;
}

} // namespace

Result<std::vector<ev::wire::Message>> MessageStore::get_messages_for_peer(
    const PeerId& peer, const Timestamp& since) const {

    std::lock_guard lock(mu_);

    Stmt st;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT id, from_peer, to_peer, timestamp, body_ct,"
        "       is_delivered, is_read, expires_at"
        " FROM messages WHERE from_peer = ? AND timestamp >= ?"
        " ORDER BY timestamp ASC;",
        -1, &st.s, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));

    sqlite3_bind_blob(st, 1, peer.bytes.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, ts_to_ms(since));

    auto dec = [this](std::span<const std::byte> b) { return decrypt_column(b); };
    std::vector<ev::wire::Message> msgs;
    while (sqlite3_step(st) == SQLITE_ROW) {
        auto m = read_message_row(st, dec);
        if (!m.body.empty())
            msgs.push_back(std::move(m));
    }
    return msgs;
}

Result<std::vector<ev::wire::Message>> MessageStore::get_conversation(
    const PeerId& my_id, const PeerId& peer_id, const Timestamp& since) const {

    std::lock_guard lock(mu_);

    Stmt st;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT id, from_peer, to_peer, timestamp, body_ct,"
        "       is_delivered, is_read, expires_at"
        " FROM messages"
        " WHERE timestamp >= ?"
        "   AND ((from_peer = ? AND to_peer = ?)"
        "     OR (from_peer = ? AND to_peer = ?))"
        " ORDER BY timestamp ASC;",
        -1, &st.s, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));

    sqlite3_bind_int64(st, 1, ts_to_ms(since));
    sqlite3_bind_blob(st, 2, peer_id.bytes.data(), 32, SQLITE_STATIC); // received: from=peer, to=me
    sqlite3_bind_blob(st, 3, my_id.bytes.data(),   32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, my_id.bytes.data(),   32, SQLITE_STATIC); // sent: from=me, to=peer
    sqlite3_bind_blob(st, 5, peer_id.bytes.data(), 32, SQLITE_STATIC);

    auto dec = [this](std::span<const std::byte> b) { return decrypt_column(b); };
    std::vector<ev::wire::Message> msgs;
    while (sqlite3_step(st) == SQLITE_ROW) {
        auto m = read_message_row(st, dec);
        if (!m.body.empty())
            msgs.push_back(std::move(m));
    }
    return msgs;
}

Result<void> MessageStore::mark_delivered(const MessageId& id) {
    std::lock_guard lock(mu_);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "UPDATE messages SET is_delivered=1 WHERE id=?;", -1, &st.s, nullptr);
    sqlite3_bind_blob(st, 1, id.bytes.data(), 16, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    return {};
}

Result<void> MessageStore::mark_read(const MessageId& id) {
    std::lock_guard lock(mu_);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "UPDATE messages SET is_read=1 WHERE id=?;", -1, &st.s, nullptr);
    sqlite3_bind_blob(st, 1, id.bytes.data(), 16, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    return {};
}

Result<uint64_t> MessageStore::purge_expired() {
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

    std::lock_guard lock(mu_);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "DELETE FROM messages WHERE expires_at > 0 AND expires_at <= ?;",
        -1, &st.s, nullptr);
    sqlite3_bind_int64(st, 1, now_ms);
    if (sqlite3_step(st) != SQLITE_DONE)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    return static_cast<uint64_t>(sqlite3_changes(db_));
}

// ── Peers ─────────────────────────────────────────────────────────────────────

Result<void> MessageStore::save_peers(
    const ev::identity::PeerDirectory& dir) {

    auto all_res = dir.all();
    if (!all_res) return std::unexpected(all_res.error());

    std::lock_guard lock(mu_);

    for (const auto& r : *all_res) {
        Stmt st;
        sqlite3_prepare_v2(db_,
            "INSERT OR REPLACE INTO peers"
            "(fingerprint, sign_pk, kx_pk, endpoint, display_name, trust)"
            " VALUES(?,?,?,?,?,?);",
            -1, &st.s, nullptr);

        const std::string ep = r.last_seen_endpoint.address + ":" +
                               std::to_string(r.last_seen_endpoint.port);
        sqlite3_bind_text(st, 1, r.fingerprint.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, r.signing_public_key.bytes.data(), 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, r.kx_public_key.bytes.data(),      32, SQLITE_STATIC);
        sqlite3_bind_text(st, 4, ep.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, r.display_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 6, static_cast<int>(r.trust));

        if (sqlite3_step(st) != SQLITE_DONE)
            return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    }
    return {};
}

Result<void> MessageStore::load_peers(
    ev::identity::PeerDirectory& dir) const {

    std::lock_guard lock(mu_);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "SELECT fingerprint, sign_pk, kx_pk, endpoint, display_name, trust"
        " FROM peers;",
        -1, &st.s, nullptr);

    while (sqlite3_step(st) == SQLITE_ROW) {
        ev::identity::PeerRecord r;
        r.fingerprint = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        std::memcpy(r.signing_public_key.bytes.data(), sqlite3_column_blob(st, 1), 32);
        std::memcpy(r.kx_public_key.bytes.data(),      sqlite3_column_blob(st, 2), 32);

        std::string ep = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
        const auto colon = ep.find(':');
        if (colon != std::string::npos) {
            r.last_seen_endpoint.address = ep.substr(0, colon);
            r.last_seen_endpoint.port =
                static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
        }

        r.display_name = reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
        r.trust = static_cast<ev::core::TrustStatus>(sqlite3_column_int(st, 5));

        static_cast<void>(dir.upsert(r)); // ignore IdentityChanged on load
    }
    return {};
}

// ── Groups (Phase 3) ──────────────────────────────────────────────────────────

Result<void> MessageStore::save_group(const GroupSessionRecord& rec) {
    // Encrypt sensitive key material.
    auto sk_ct = encrypt_blob(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(rec.own_sign_sk.data()), 64));
    if (!sk_ct) return std::unexpected(sk_ct.error());

    auto ck_ct = encrypt_blob(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(rec.own_chain_key.data()), 32));
    if (!ck_ct) return std::unexpected(ck_ct.error());

    std::lock_guard lock(mu_);

    // Upsert session row.
    {
        Stmt st;
        sqlite3_prepare_v2(db_,
            "INSERT OR REPLACE INTO group_sessions"
            "(group_id, group_name, own_sign_sk_ct, own_sign_pub, own_chain_key_ct, own_counter)"
            " VALUES(?,?,?,?,?,?);",
            -1, &st.s, nullptr);
        sqlite3_bind_blob(st, 1, rec.group_id.bytes.data(), 16, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, rec.group_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, sk_ct->data(), static_cast<int>(sk_ct->size()), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 4, rec.own_sign_pub.data(), 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 5, ck_ct->data(), static_cast<int>(ck_ct->size()), SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, static_cast<int>(rec.own_counter));
        if (sqlite3_step(st) != SQLITE_DONE)
            return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    }

    // Delete old members, re-insert all.
    {
        Stmt del;
        sqlite3_prepare_v2(db_,
            "DELETE FROM group_members WHERE group_id=?;", -1, &del.s, nullptr);
        sqlite3_bind_blob(del, 1, rec.group_id.bytes.data(), 16, SQLITE_STATIC);
        sqlite3_step(del);
    }

    for (const auto& m : rec.members) {
        auto mck_ct = encrypt_blob(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(m.chain_key.data()), 32));
        if (!mck_ct) return std::unexpected(mck_ct.error());

        Stmt st;
        sqlite3_prepare_v2(db_,
            "INSERT INTO group_members"
            "(group_id, member_sign_pub, chain_key_ct, counter)"
            " VALUES(?,?,?,?);",
            -1, &st.s, nullptr);
        sqlite3_bind_blob(st, 1, rec.group_id.bytes.data(), 16, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, m.signing_pub.data(), 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, mck_ct->data(), static_cast<int>(mck_ct->size()), SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, static_cast<int>(m.counter));
        if (sqlite3_step(st) != SQLITE_DONE)
            return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    }
    return {};
}

Result<std::vector<GroupSessionRecord>> MessageStore::load_groups() const {
    std::lock_guard lock(mu_);

    Stmt st;
    sqlite3_prepare_v2(db_,
        "SELECT group_id, group_name, own_sign_sk_ct, own_sign_pub,"
        "       own_chain_key_ct, own_counter"
        " FROM group_sessions;",
        -1, &st.s, nullptr);

    std::vector<GroupSessionRecord> result;

    while (sqlite3_step(st) == SQLITE_ROW) {
        GroupSessionRecord rec;

        std::memcpy(rec.group_id.bytes.data(), sqlite3_column_blob(st, 0), 16);
        rec.group_name = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));

        // Decrypt signing secret key.
        {
            const auto* d = static_cast<const std::byte*>(sqlite3_column_blob(st, 2));
            const int   n = sqlite3_column_bytes(st, 2);
            auto pt = decrypt_blob(std::span<const std::byte>(d, n));
            if (!pt || pt->size() != 64) continue; // skip corrupt
            std::memcpy(rec.own_sign_sk.data(), pt->data(), 64);
        }

        std::memcpy(rec.own_sign_pub.data(), sqlite3_column_blob(st, 3), 32);

        // Decrypt own chain key.
        {
            const auto* d = static_cast<const std::byte*>(sqlite3_column_blob(st, 4));
            const int   n = sqlite3_column_bytes(st, 4);
            auto pt = decrypt_blob(std::span<const std::byte>(d, n));
            if (!pt || pt->size() != 32) continue;
            std::memcpy(rec.own_chain_key.data(), pt->data(), 32);
        }

        rec.own_counter = static_cast<uint32_t>(sqlite3_column_int(st, 5));

        // Load members.
        {
            Stmt mst;
            sqlite3_prepare_v2(db_,
                "SELECT member_sign_pub, chain_key_ct, counter"
                " FROM group_members WHERE group_id=?;",
                -1, &mst.s, nullptr);
            sqlite3_bind_blob(mst, 1, rec.group_id.bytes.data(), 16, SQLITE_STATIC);

            while (sqlite3_step(mst) == SQLITE_ROW) {
                GroupMemberRecord mr;
                mr.group_id = rec.group_id;
                std::memcpy(mr.signing_pub.data(), sqlite3_column_blob(mst, 0), 32);

                const auto* d2 = static_cast<const std::byte*>(sqlite3_column_blob(mst, 1));
                const int   n2 = sqlite3_column_bytes(mst, 1);
                auto pt2 = decrypt_blob(std::span<const std::byte>(d2, n2));
                if (!pt2 || pt2->size() != 32) continue;
                std::memcpy(mr.chain_key.data(), pt2->data(), 32);

                mr.counter = static_cast<uint32_t>(sqlite3_column_int(mst, 2));
                rec.members.push_back(std::move(mr));
            }
        }

        result.push_back(std::move(rec));
    }
    return result;
}

Result<void> MessageStore::delete_group(const ev::core::GroupId& gid) {
    std::lock_guard lock(mu_);
    // Members are deleted via CASCADE.
    Stmt st;
    sqlite3_prepare_v2(db_,
        "DELETE FROM group_sessions WHERE group_id=?;", -1, &st.s, nullptr);
    sqlite3_bind_blob(st, 1, gid.bytes.data(), 16, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE)
        return std::unexpected(Error::from(ErrorCode::StorageError, sqlite3_errmsg(db_)));
    return {};
}

} // namespace ev::store
