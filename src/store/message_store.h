#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/group/group_types.h>
#include <ev/identity/peer_directory.h>
#include <ev/wire/message.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

// Forward-declare sqlite3 so callers don't need to pull in sqlite3.h.
struct sqlite3;

namespace ev::store {

// Persistent message, peer, and group storage backed by SQLite.
// Sensitive columns (message bodies, keys) are AEAD-encrypted with db_key.
// The db_key is derived from the user passphrase via Argon2id at startup
// and held in a SecureBuffer; it is never written to disk.
//
// Thread-safety: all public methods acquire an internal per-instance mutex.
class MessageStore {
public:
    // Open (or create) the database at path, decrypt with db_key.
    // Runs schema migrations.
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

    ev::core::Result<void> save_message(const ev::wire::Message& message);

    // Returns messages FROM peer (received messages).
    ev::core::Result<std::vector<ev::wire::Message>> get_messages_for_peer(
        const ev::core::PeerId&   peer,
        const ev::core::Timestamp& since) const;

    // Returns all messages in a conversation: sent by me to peer, or received from peer.
    ev::core::Result<std::vector<ev::wire::Message>> get_conversation(
        const ev::core::PeerId&    my_id,
        const ev::core::PeerId&    peer_id,
        const ev::core::Timestamp& since) const;

    ev::core::Result<void> mark_delivered(const ev::core::MessageId& id);
    ev::core::Result<void> mark_read(const ev::core::MessageId& id);

    // Delete expired messages (expires_at_ms ≤ now_ms, non-zero).
    ev::core::Result<uint64_t> purge_expired();

    // ── Peers ─────────────────────────────────────────────────────────────────

    ev::core::Result<void> save_peers(
        const ev::identity::PeerDirectory& dir);

    ev::core::Result<void> load_peers(
        ev::identity::PeerDirectory& dir) const;

    // ── Groups (Phase 3) ──────────────────────────────────────────────────────

    // Upsert one group session record (own keys + member list).
    ev::core::Result<void> save_group(const GroupSessionRecord& rec);

    // Load all group session records.
    ev::core::Result<std::vector<GroupSessionRecord>> load_groups() const;

    // Remove a group (leave / kick flow).
    ev::core::Result<void> delete_group(const ev::core::GroupId& gid);

private:
    explicit MessageStore(sqlite3* db, ev::crypto::SecureBuffer<32> key);

    ev::core::Result<void> run_migrations();

    // Encrypt binary data for storage. Format: [24-byte nonce][ciphertext+tag].
    ev::core::Result<std::vector<std::byte>> encrypt_blob(
        std::span<const std::byte> plaintext) const;

    // Decrypt a blob column value.
    ev::core::Result<std::vector<std::byte>> decrypt_blob(
        std::span<const std::byte> ciphertext) const;

    // Encrypt/decrypt a UTF-8 string column (convenience wrappers over blob helpers).
    ev::core::Result<std::vector<std::byte>> encrypt_column(
        const std::string& plaintext) const;

    ev::core::Result<std::string> decrypt_column(
        std::span<const std::byte> ciphertext) const;

    sqlite3*                     db_{nullptr};
    ev::crypto::SecureBuffer<32> db_key_;
    mutable std::mutex           mu_;
};

} // namespace ev::store
