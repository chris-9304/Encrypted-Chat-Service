#include <cloak/transfer/file_transfer.h>
#include <cloak/crypto/crypto.h>
#include <cloak/wire/framing.h>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace cloak::transfer {

using namespace cloak::core;
using namespace cloak::crypto;
using namespace cloak::wire;
using namespace cloak::session;

static constexpr std::string_view kChunkNonceInfo = "CLOAK_CHUNK_NONCE_v2";

// ── chunk_nonce ───────────────────────────────────────────────────────────────

Result<std::vector<std::byte>> chunk_nonce(
    const SecureBuffer<32>& file_key, uint32_t chunk_idx) {

    // info = kChunkNonceInfo || little-endian(chunk_idx)
    std::vector<std::byte> info(kChunkNonceInfo.size() + 4);
    std::memcpy(info.data(),
                kChunkNonceInfo.data(), kChunkNonceInfo.size());
    const uint32_t idx_le = chunk_idx; // little-endian on x86
    std::memcpy(info.data() + kChunkNonceInfo.size(), &idx_le, 4);

    auto key24 = Crypto::hkdf_sha256(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(file_key.data()), 32),
        {},
        std::span<const std::byte>(info));
    if (!key24) return std::unexpected(key24.error());

    std::vector<std::byte> nonce(24);
    std::memcpy(nonce.data(), key24->data(), 24);
    return nonce;
}

// ── send_file ─────────────────────────────────────────────────────────────────

Result<FileId> send_file(
    Session&                  session,
    const Path&               local_path,
    const std::string&         mime_type,
    const ProgressCallback&    on_progress) {

    // Open file.
    std::ifstream f(local_path, std::ios::binary | std::ios::ate);
    if (!f) {
        return std::unexpected(Error::from(ErrorCode::IoError,
            "Cannot open file for sending: " + local_path.string()));
    }
    const uint64_t file_size = static_cast<uint64_t>(f.tellg());
    f.seekg(0);

    // Generate per-file key and file ID.
    SecureBuffer<32> file_key;
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(file_key.data()), 32)));

    FileId fid;
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(fid.bytes.data()), 16)));

    const uint32_t chunk_size   = static_cast<uint32_t>(kFileChunkMaxBytes);
    const uint32_t total_chunks = file_size == 0 ? 0 :
        static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);

    // Build FileMetadata inner payload.
    // Layout: [type=0x01][file_id 16][file_key 32][total_chunks 4 BE]
    //         [file_size 8 BE][name_len 2 BE][name][mime_len 2 BE][mime]
    const std::string file_name = local_path.filename().string();
    std::vector<std::byte> meta;
    meta.push_back(static_cast<std::byte>(InnerType::FileMetadata));
    meta.insert(meta.end(),
        reinterpret_cast<const std::byte*>(fid.bytes.data()),
        reinterpret_cast<const std::byte*>(fid.bytes.data()) + 16);
    meta.insert(meta.end(),
        reinterpret_cast<const std::byte*>(file_key.data()),
        reinterpret_cast<const std::byte*>(file_key.data()) + 32);

    auto push32be = [&meta](uint32_t v) {
        const uint8_t b[4] = {
            uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v) };
        meta.insert(meta.end(),
            reinterpret_cast<const std::byte*>(b),
            reinterpret_cast<const std::byte*>(b) + 4);
    };
    auto push64be = [&meta](uint64_t v) {
        for (int i = 7; i >= 0; --i)
            meta.push_back(std::byte{uint8_t(v >> (8*i))});
    };
    auto push16be = [&meta](uint16_t v) {
        meta.push_back(std::byte{uint8_t(v >> 8)});
        meta.push_back(std::byte{uint8_t(v)});
    };

    push32be(total_chunks);
    push64be(file_size);
    push16be(static_cast<uint16_t>(file_name.size()));
    meta.insert(meta.end(),
        reinterpret_cast<const std::byte*>(file_name.data()),
        reinterpret_cast<const std::byte*>(file_name.data()) + file_name.size());
    push16be(static_cast<uint16_t>(mime_type.size()));
    meta.insert(meta.end(),
        reinterpret_cast<const std::byte*>(mime_type.data()),
        reinterpret_cast<const std::byte*>(mime_type.data()) + mime_type.size());

    // Send metadata via DR-encrypted AppPayload.
    if (auto r = session.send_text(
            std::string(reinterpret_cast<const char*>(meta.data()), meta.size()));
        !r) {
        return std::unexpected(r.error());
    }

    // Send chunks.
    std::vector<std::byte> chunk_plain(chunk_size);
    uint64_t bytes_sent = 0;

    for (uint32_t idx = 0; idx < total_chunks || (total_chunks == 0 && idx == 0); ++idx) {
        f.read(reinterpret_cast<char*>(chunk_plain.data()),
               static_cast<std::streamsize>(chunk_size));
        const auto read_bytes = static_cast<size_t>(f.gcount());
        if (read_bytes == 0) break;

        // Encrypt chunk with per-file key.
        auto nonce_res = chunk_nonce(file_key, idx);
        if (!nonce_res) return std::unexpected(nonce_res.error());

        auto ct_res = Crypto::aead_encrypt(
            file_key,
            std::span<const std::byte>(*nonce_res),
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(fid.bytes.data()), 16),
            std::span<const std::byte>(chunk_plain.data(), read_bytes));
        if (!ct_res) return std::unexpected(ct_res.error());

        FileChunkPayload cp;
        cp.file_id      = fid;
        cp.chunk_idx    = idx;
        cp.total_chunks = total_chunks;
        cp.is_last      = (f.peek() == EOF || idx == total_chunks - 1);
        cp.data         = std::move(*ct_res);

        auto enc = encode_file_chunk(cp);
        if (!enc) return std::unexpected(enc.error());

        Frame frame{MessageType::FileChunk, std::move(*enc)};
        // Send as raw frame — this bypasses DR (chunk is already AEAD encrypted
        // with the per-file key, and the per-file key was DR-protected in metadata).
        // For production, embed chunks inside AppPayload too; for Phase 2 this
        // sends them as FileChunk frames directly.
        auto enc_frame = encode(frame);
        if (!enc_frame) return std::unexpected(enc_frame.error());

        // Chunk frames are sent as raw bytes inside a DR-encrypted AppPayload via
        // send_text().  Each chunk is already AEAD-protected with the per-file key;
        // the outer DR session key provides an additional layer and forward secrecy.
        // The receiver decodes the embedded FileChunk frame from the raw body bytes.
        std::string raw(reinterpret_cast<const char*>(enc_frame->data()),
                        enc_frame->size());
        if (auto r = session.send_text(raw); !r) return std::unexpected(r.error());

        bytes_sent += read_bytes;
        if (on_progress) on_progress(bytes_sent, file_size);

        if (cp.is_last) break;
    }

    return fid;
}

// ── receive_file ──────────────────────────────────────────────────────────────

Result<Path> receive_file(
    Session&                session,
    const Path&             save_dir,
    const ProgressCallback& on_progress) {

    // Receive metadata message.
    auto meta_res = session.recv_text();
    if (!meta_res) return std::unexpected(meta_res.error());

    const auto& meta_raw = *meta_res;
    if (meta_raw.empty() ||
        static_cast<uint8_t>(meta_raw[0]) != static_cast<uint8_t>(InnerType::FileMetadata)) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
            "Expected FileMetadata inner payload"));
    }

    if (meta_raw.size() < 1 + 16 + 32 + 4 + 8 + 2) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
            "FileMetadata payload too short"));
    }

    const auto* data = reinterpret_cast<const uint8_t*>(meta_raw.data());
    size_t off = 1; // skip type byte

    FileId fid;
    std::memcpy(fid.bytes.data(), data + off, 16); off += 16;

    SecureBuffer<32> file_key;
    std::memcpy(file_key.data(), data + off, 32); off += 32;

    const uint32_t total_chunks =
        (uint32_t(data[off])<<24)|(uint32_t(data[off+1])<<16)|
        (uint32_t(data[off+2])<<8)|uint32_t(data[off+3]); off += 4;

    uint64_t file_size = 0;
    for (int i = 0; i < 8; ++i) file_size = (file_size << 8) | data[off + i];
    off += 8;

    const uint16_t name_len = (uint16_t(data[off]) << 8) | data[off+1]; off += 2;
    if (off + name_len > meta_raw.size()) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
            "FileMetadata name truncated"));
    }
    const std::string file_name_raw(reinterpret_cast<const char*>(data + off), name_len);
    off += name_len;

    // Sanitize: keep only the final filename component to prevent path traversal.
    const std::string file_name =
        std::filesystem::path(file_name_raw).filename().string();
    if (file_name.empty()) {
        return std::unexpected(Error::from(ErrorCode::FramingError,
            "FileMetadata file_name is empty after sanitization"));
    }

    // Receive chunks, decrypt, and write to temp file.
    const Path save_path = save_dir / file_name;
    std::ofstream out_file(save_path, std::ios::binary | std::ios::trunc);
    if (!out_file) {
        return std::unexpected(Error::from(ErrorCode::IoError,
            "Cannot create output file: " + save_path.string()));
    }

    uint64_t bytes_received = 0;
    for (uint32_t idx = 0; idx < total_chunks || total_chunks == 0; ++idx) {
        auto raw_res = session.recv_text();
        if (!raw_res) return std::unexpected(raw_res.error());

        // Decode the embedded FileChunk frame.
        auto frame_res = decode(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(raw_res->data()), raw_res->size()));
        if (!frame_res || frame_res->type != MessageType::FileChunk) {
            return std::unexpected(Error::from(ErrorCode::FramingError,
                "Expected FileChunk frame"));
        }

        auto chunk_res = decode_file_chunk(
            std::span<const std::byte>(frame_res->payload));
        if (!chunk_res) return std::unexpected(chunk_res.error());

        auto& cp = *chunk_res;
        if (cp.file_id.bytes != fid.bytes) {
            return std::unexpected(Error::from(ErrorCode::FramingError,
                "FileChunk file_id mismatch"));
        }

        // Decrypt chunk.
        auto nonce_res = chunk_nonce(file_key, cp.chunk_idx);
        if (!nonce_res) return std::unexpected(nonce_res.error());

        auto pt_res = Crypto::aead_decrypt(
            file_key,
            std::span<const std::byte>(*nonce_res),
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(fid.bytes.data()), 16),
            std::span<const std::byte>(cp.data));
        if (!pt_res) return std::unexpected(pt_res.error());

        out_file.write(reinterpret_cast<const char*>(pt_res->data()),
                       static_cast<std::streamsize>(pt_res->size()));

        bytes_received += pt_res->size();
        if (on_progress) on_progress(bytes_received, file_size);

        if (cp.is_last) break;
    }

    return save_path;
}

} // namespace cloak::transfer
