#pragma once

#include <ev/core/error.h>
#include <ev/core/types.h>
#include <ev/crypto/crypto.h>
#include <ev/crypto/secure_buffer.h>
#include <ev/session/session.h>
#include <ev/wire/framing.h>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace ev::transfer {

// Progress callback: (bytes_done, total_bytes).
using ProgressCallback = std::function<void(uint64_t, uint64_t)>;

// Send a file over an established session using the Phase 2 chunked protocol.
//
// Security:
// - A random 32-byte per-file key is generated via Crypto::random_bytes.
// - Each chunk is AEAD-sealed (XChaCha20-Poly1305) with the per-file key and a
//   counter-based nonce.  The per-file key is itself sealed inside an
//   AppPayload using the Double Ratchet session key.
// - The receiver stores only ciphertext on disk until explicitly saved.
//
// Wire flow:
//   1. Sender encrypts metadata (FileMetadata) as an InnerType::FileMetadata
//      AppPayload so the receiver learns the file name, MIME type, total size,
//      and the sealed per-file key.
//   2. Sender sends kFileChunkMaxBytes-sized FileChunkPayload frames for the
//      body.  Each chunk is AEAD-encrypted with the per-file key.
//   3. Receiver calls receive_file() which reassembles the ciphertext, then
//      decrypts into the destination path only after all chunks arrive.
//
// Thread safety: these are free functions; internal state is on the stack.

ev::core::Result<ev::core::FileId> send_file(
    ev::session::Session&       session,
    const ev::core::Path&       local_path,
    const std::string&           mime_type   = "application/octet-stream",
    const ProgressCallback&      on_progress = nullptr);

// Receive the next in-flight file from a session.
// Blocks until all chunks arrive or an error occurs.
ev::core::Result<ev::core::Path> receive_file(
    ev::session::Session&  session,
    const ev::core::Path&  save_dir,
    const ProgressCallback& on_progress = nullptr);

// Derive a nonce for a specific file chunk using HKDF.
// nonce = HKDF(file_key, info="EV_CHUNK_NONCE_" || chunk_idx)[:24]
ev::core::Result<std::vector<std::byte>> chunk_nonce(
    const ev::crypto::SecureBuffer<32>& file_key,
    uint32_t                             chunk_idx);

} // namespace ev::transfer
