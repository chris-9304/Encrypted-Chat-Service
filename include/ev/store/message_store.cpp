#include <ev/store/message_store.h>
#include <ev/crypto/crypto.h>
#include <sqlite3.h>
#include <cstring>
#include <chrono>
#include <mutex>

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

static std::mutex g_db_mutex; // coarse global lock (Phase 2: per-connection WAL)

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

    // Copy key — we need our own SecureBuffer.
    SecureBuffer<32> key_copy;
    std::memcpy(key_copy.data(), db_key.data(), 32);

    MessageStore store(db, std::move(key_copy));

    // WAL mode for better concurrency.
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
        if (sqlite3_step(st) == SQLITE_ROW) {
            version = sqlite3_column_int(st, 0);
        }
    }

    if (version < 1) {
        if (auto r = exec(db_, R"(
            CREATE TABLE IF NOT EXISTS messages (
                id          BLOB    PRIMARY KEY,  -- 16-byte MessageId
                from_peer   BLOB    NOT NULL,     -- 32-byte PeerId (signing key)
                timestamp   INTEGER NOT NULL,     -- ms since epoch
                body_ct     BLOB    NOT NULL,     -- AEAD-encrypted UTF-8 body
                is_delivered INTEGER NOT NULL DEFAULT 0,
                is_read     INTEGER NOT NULL DEFAULT 0,
                expires_at  INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_messages_from_peer
                ON messages(from_peer, timestamp);

            CREATE TABLE IF NOT EXISTS peers (
                fingerprint TEXT    PRIMARY KEY,
                sign_pk     BLOB    NOT NULL,
                kx_pk       BLOB    NOT NULL,
                endpoint    TEXT    NOT NULL DEFAULT '',
                display_name TEXT   NOT NULL DEFAULT '',
                trust       INTEGER NOT NULL DEFAULT 0
            );

            INSERT OR IGNORE INTO schema_version(version) VALUES(0);
            UPDATE schema_version SET version = 1;
        )"); !r) return std::unexpected(r.error());
    }

    return {};
}

// ── Column encryption ─────────────────────────────────────────────────────────
// Format: [24-byte nonce][ciphertext+tag]

Result<std::vector<std::byte>> MessageStore::encrypt_column(
    const std::string& plaintext) const {

    std::vector<std::byte> nonce(24);
    static_cast<void>(Crypto::random_bytes(std::span<std::byte>(nonce)));

    auto ct = Crypto::aead_encrypt(
        db_key_,
        std::span<const std::byte>(nonce),
        {},
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(plaintext.data()),
            plaintext.size()));
    if (!ct) return std::unexpected(ct.error());

    std::vector<std::byte> out;
    out.reserve(24 + ct->size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct->begin(), ct->end());
    return out;
}

Result<std::string> MessageStore::decrypt_column(
    std::span<const std::byte> blob) const {

    if (blob.size() < 24 + 16) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            "Column blob too short"));
    }

    auto pt = Crypto::aead_decrypt(
        db_key_,
        blob.subspan(0, 24),
        {},
        blob.subspan(24));
    if (!pt) return std::unexpected(pt.error());

    return std::string(reinterpret_cast<const char*>(pt->data()), pt->size());
}

// ── Messages ──────────────────────────────────────────────────────────────────

Result<void> MessageStore::save_message(const ev::wire::Message& message) {
    auto body_ct = encrypt_column(message.body);
    if (!body_ct) return std::unexpected(body_ct.error());

    std::lock_guard lock(g_db_mutex);

    Stmt st;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO messages"
        "(id, from_peer, timestamp, body_ct, is_delivered, is_read, expires_at)"
        " VALUES(?,?,?,?,?,?,?);",
        -1, &st.s, nullptr);
    if (rc != SQLITE_OK) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }

    sqlite3_bind_blob(st, 1, message.id.bytes.data(), 16, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, message.from.bytes.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, ts_to_ms(message.timestamp));
    sqlite3_bind_blob(st, 4, body_ct->data(),
                      static_cast<int>(body_ct->size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, message.is_delivered ? 1 : 0);
    sqlite3_bind_int(st, 6, message.is_read      ? 1 : 0);
    sqlite3_bind_int64(st, 7, message.expires_at_ms);

    if (sqlite3_step(st) != SQLITE_DONE) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }
    return {};
}

Result<std::vector<ev::wire::Message>> MessageStore::get_messages_for_peer(
    const PeerId& peer, const Timestamp& since) const {

    std::lock_guard lock(g_db_mutex);

    Stmt st;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT id, from_peer, timestamp, body_ct, is_delivered, is_read, expires_at"
        " FROM messages WHERE from_peer = ? AND timestamp >= ?"
        " ORDER BY timestamp ASC;",
        -1, &st.s, nullptr);
    if (rc != SQLITE_OK) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }

    sqlite3_bind_blob(st, 1, peer.bytes.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, ts_to_ms(since));

    std::vector<ev::wire::Message> msgs;
    while (sqlite3_step(st) == SQLITE_ROW) {
        ev::wire::Message m;

        std::memcpy(m.id.bytes.data(),
                    sqlite3_column_blob(st, 0), 16);
        std::memcpy(m.from.bytes.data(),
                    sqlite3_column_blob(st, 1), 32);
        m.timestamp = ms_to_ts(sqlite3_column_int64(st, 2));

        const auto* ct_data = static_cast<const std::byte*>(
            sqlite3_column_blob(st, 3));
        const int ct_sz = sqlite3_column_bytes(st, 3);

        auto body = decrypt_column(
            std::span<const std::byte>(ct_data, ct_sz));
        if (!body) continue; // skip corrupted rows

        m.body          = std::move(*body);
        m.is_delivered  = sqlite3_column_int(st, 4) != 0;
        m.is_read       = sqlite3_column_int(st, 5) != 0;
        m.expires_at_ms = sqlite3_column_int64(st, 6);
        msgs.push_back(std::move(m));
    }
    return msgs;
}

Result<void> MessageStore::mark_delivered(const MessageId& id) {
    std::lock_guard lock(g_db_mutex);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "UPDATE messages SET is_delivered=1 WHERE id=?;",
        -1, &st.s, nullptr);
    sqlite3_bind_blob(st, 1, id.bytes.data(), 16, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }
    return {};
}

Result<void> MessageStore::mark_read(const MessageId& id) {
    std::lock_guard lock(g_db_mutex);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "UPDATE messages SET is_read=1 WHERE id=?;",
        -1, &st.s, nullptr);
    sqlite3_bind_blob(st, 1, id.bytes.data(), 16, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }
    return {};
}

Result<uint64_t> MessageStore::purge_expired() {
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

    std::lock_guard lock(g_db_mutex);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "DELETE FROM messages WHERE expires_at > 0 AND expires_at <= ?;",
        -1, &st.s, nullptr);
    sqlite3_bind_int64(st, 1, now_ms);
    if (sqlite3_step(st) != SQLITE_DONE) {
        return std::unexpected(Error::from(ErrorCode::StorageError,
                                            sqlite3_errmsg(db_)));
    }
    return static_cast<uint64_t>(sqlite3_changes(db_));
}

// ── Peers ─────────────────────────────────────────────────────────────────────

Result<void> MessageStore::save_peers(
    const ev::identity::PeerDirectory& dir) {

    auto all_res = dir.all();
    if (!all_res) return std::unexpected(all_res.error());

    std::lock_guard lock(g_db_mutex);

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
        sqlite3_bind_blob(st, 3, r.kx_public_key.bytes.data(), 32, SQLITE_STATIC);
        sqlite3_bind_text(st, 4, ep.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, r.display_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 6, static_cast<int>(r.trust));

        if (sqlite3_step(st) != SQLITE_DONE) {
            return std::unexpected(Error::from(ErrorCode::StorageError,
                                                sqlite3_errmsg(db_)));
        }
    }
    return {};
}

Result<void> MessageStore::load_peers(
    ev::identity::PeerDirectory& dir) const {

    std::lock_guard lock(g_db_mutex);
    Stmt st;
    sqlite3_prepare_v2(db_,
        "SELECT fingerprint, sign_pk, kx_pk, endpoint, display_name, trust"
        " FROM peers;",
        -1, &st.s, nullptr);

    while (sqlite3_step(st) == SQLITE_ROW) {
        ev::identity::PeerRecord r;
        r.fingerprint = reinterpret_cast<const char*>(
            sqlite3_column_text(st, 0));
        std::memcpy(r.signing_public_key.bytes.data(),
                    sqlite3_column_blob(st, 1), 32);
        std::memcpy(r.kx_public_key.bytes.data(),
                    sqlite3_column_blob(st, 2), 32);

        std::string ep = reinterpret_cast<const char*>(
            sqlite3_column_text(st, 3));
        const auto colon = ep.find(':');
        if (colon != std::string::npos) {
            r.last_seen_endpoint.address = ep.substr(0, colon);
            r.last_seen_endpoint.port =
                static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
        }

        r.display_name = reinterpret_cast<const char*>(
            sqlite3_column_text(st, 4));
        r.trust = static_cast<ev::core::TrustStatus>(
            sqlite3_column_int(st, 5));

        static_cast<void>(dir.upsert(r)); // ignore IdentityChanged errors during load
    }
    return {};
}

} // namespace ev::store
