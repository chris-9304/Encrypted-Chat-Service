#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/identity/peer_directory.h>
#include <ev/wire/message.h>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

// Forward-declare sqlite3 so callers don't need to pull in sqlite3.h.
struct sqlite3;

namespace ev::store {

// Persistent message and peer storage backed by SQLite.
// Sensitive columns (message bodies, keys) are AEAD-encrypted with db_key.
// The db_key is derived from the user passphrase via Argon2id at startup
// and held in a SecureBuffer; it is never written to disk.
//
// Thread-safety: all public methods acquire an internal mutex.
class MessageStore {
public:
    // Open (or create) the database at path, decrypt with db_key.
    // Runs schema migrations.  Fails if db_key is wrong (AEAD rejection).
    static ev::core::Result<MessageStore> open(
        const ev::core::Path&                path,
        const ev::crypto::SecureBuffer<32>&  db_key);

    // Move-only (owns the sqlite3* handle).
    MessageStore(MessageStore&&)            = default;
    MessageStore& operator=(MessageStore&&) = default;
    MessageStore(const MessageStore&)            = delete;
    MessageStore& operator=(const MessageStore&) = delete;
    ~MessageStore();

    // ── Messages ─────────────────────────────────────────────────────────────

    // Persist a decrypted message.  Body is AEAD-encrypted in the DB column.
    ev::core::Result<void> save_message(const ev::wire::Message& message);

    // Retrieve messages for a peer since a given timestamp.
    ev::core::Result<std::vector<ev::wire::Message>> get_messages_for_peer(
        const ev::core::PeerId&   peer,
        const ev::core::Timestamp& since) const;

    // Mark a message delivered / read.
    ev::core::Result<void> mark_delivered(const ev::core::MessageId& id);
    ev::core::Result<void> mark_read(const ev::core::MessageId& id);

    // Delete expired messages (expires_at_ms ≤ now_ms, non-zero).
    ev::core::Result<uint64_t> purge_expired();

    // ── Peers ─────────────────────────────────────────────────────────────────

    // Persist all in-memory peer records from a PeerDirectory.
    ev::core::Result<void> save_peers(
        const ev::identity::PeerDirectory& dir);

    // Load peers from DB into a PeerDirectory.
    ev::core::Result<void> load_peers(
        ev::identity::PeerDirectory& dir) const;

private:
    explicit MessageStore(sqlite3* db, ev::crypto::SecureBuffer<32> key);

    ev::core::Result<void> run_migrations();

    // Encrypt a UTF-8 string for storage.  Uses a random nonce; prepends nonce.
    ev::core::Result<std::vector<std::byte>> encrypt_column(
        const std::string& plaintext) const;

    // Decrypt a column value.
    ev::core::Result<std::string> decrypt_column(
        std::span<const std::byte> ciphertext) const;

    sqlite3*                     db_{nullptr};
    ev::crypto::SecureBuffer<32> db_key_;
};

} // namespace ev::store
