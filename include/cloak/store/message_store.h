#pragma once

#include <cloak/core/error.h>
#include <cloak/core/types.h>
#include <cloak/crypto/secure_buffer.h>
#include <cloak/group/group_types.h>
#include <cloak/identity/peer_directory.h>
#include <cloak/wire/message.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

// Forward-declare sqlite3 so callers don't need to pull in sqlite3.h.
struct sqlite3;

namespace cloak::store {

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
    static cloak::core::Result<MessageStore> open(
        const cloak::core::Path&                path,
        const cloak::crypto::SecureBuffer<32>&  db_key);

    // Move-only (owns the sqlite3* handle).
    MessageStore(MessageStore&&)            = default;
    MessageStore& operator=(MessageStore&&) = default;
    MessageStore(const MessageStore&)            = delete;
    MessageStore& operator=(const MessageStore&) = delete;
    ~MessageStore();

    // ── Messages ─────────────────────────────────────────────────────────────

    cloak::core::Result<void> save_message(const cloak::wire::Message& message);

    // Returns messages FROM peer (received messages).
    cloak::core::Result<std::vector<cloak::wire::Message>> get_messages_for_peer(
        const cloak::core::PeerId&   peer,
        const cloak::core::Timestamp& since) const;

    // Returns all messages in a conversation: sent by me to peer, or received from peer.
    cloak::core::Result<std::vector<cloak::wire::Message>> get_conversation(
        const cloak::core::PeerId&    my_id,
        const cloak::core::PeerId&    peer_id,
        const cloak::core::Timestamp& since) const;

    cloak::core::Result<void> mark_delivered(const cloak::core::MessageId& id);
    cloak::core::Result<void> mark_read(const cloak::core::MessageId& id);

    // Delete expired messages (expires_at_ms ≤ now_ms, non-zero).
    cloak::core::Result<uint64_t> purge_expired();

    // ── Peers ─────────────────────────────────────────────────────────────────

    cloak::core::Result<void> save_peers(
        const cloak::identity::PeerDirectory& dir);

    cloak::core::Result<void> load_peers(
        cloak::identity::PeerDirectory& dir) const;

    // ── Groups (Phase 3) ──────────────────────────────────────────────────────

    // Upsert one group session record (own keys + member list).
    cloak::core::Result<void> save_group(const GroupSessionRecord& rec);

    // Load all group session records.
    cloak::core::Result<std::vector<GroupSessionRecord>> load_groups() const;

    // Remove a group (leave / kick flow).
    cloak::core::Result<void> delete_group(const cloak::core::GroupId& gid);

private:
    explicit MessageStore(sqlite3* db, cloak::crypto::SecureBuffer<32> key);

    cloak::core::Result<void> run_migrations();

    // Encrypt binary data for storage. Format: [24-byte nonce][ciphertext+tag].
    cloak::core::Result<std::vector<std::byte>> encrypt_blob(
        std::span<const std::byte> plaintext) const;

    // Decrypt a blob column value.
    cloak::core::Result<std::vector<std::byte>> decrypt_blob(
        std::span<const std::byte> ciphertext) const;

    // Encrypt/decrypt a UTF-8 string column (convenience wrappers over blob helpers).
    cloak::core::Result<std::vector<std::byte>> encrypt_column(
        const std::string& plaintext) const;

    cloak::core::Result<std::string> decrypt_column(
        std::span<const std::byte> ciphertext) const;

    sqlite3*                     db_{nullptr};
    cloak::crypto::SecureBuffer<32> db_key_;
    mutable std::mutex           mu_;
};

} // namespace cloak::store
