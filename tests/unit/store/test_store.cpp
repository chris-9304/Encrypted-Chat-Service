#include <catch2/catch_test_macros.hpp>
#include <cloak/store/message_store.h>
#include <cloak/crypto/crypto.h>
#include <cloak/identity/peer_directory.h>
#include <filesystem>
#include <cstring>

using namespace cloak::store;
using namespace cloak::core;
using namespace cloak::crypto;

namespace {

std::filesystem::path tmp_db(const char* suffix) {
    return std::filesystem::temp_directory_path() /
           (std::string("ev_test_") + suffix + ".db");
}

SecureBuffer<32> make_key() {
    SecureBuffer<32> k;
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(k.data()), 32)));
    return k;
}

// Build a minimal valid Message (from=sender, to=recipient).
cloak::wire::Message make_msg(const PeerId& from, const PeerId& to,
                           const std::string& body = "Hello") {
    cloak::wire::Message m;
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(m.id.bytes.data()), 16)));
    m.from      = from;
    m.to        = to;
    m.timestamp = std::chrono::time_point_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now());
    m.body      = body;
    return m;
}

} // namespace

TEST_CASE("MessageStore: open, save and retrieve messages", "[store]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("msg");
    std::filesystem::remove(path);

    auto key = make_key();
    auto store_res = MessageStore::open(path, key);
    REQUIRE(store_res.has_value());
    auto& store = *store_res;

    PeerId alice{}, bob{};
    alice.bytes.fill(0xAA);
    bob.bytes.fill(0xBB);

    auto m = make_msg(alice, bob, "Hello, world!");
    REQUIRE(store.save_message(m).has_value());

    // get_messages_for_peer returns messages FROM alice.
    auto msgs = store.get_messages_for_peer(alice, Timestamp{});
    REQUIRE(msgs.has_value());
    REQUIRE(msgs->size() == 1);
    CHECK((*msgs)[0].body == "Hello, world!");
    CHECK(!(*msgs)[0].is_delivered);

    REQUIRE(store.mark_delivered(m.id).has_value());
    auto msgs2 = store.get_messages_for_peer(alice, Timestamp{});
    REQUIRE(msgs2.has_value());
    CHECK((*msgs2)[0].is_delivered);

    std::filesystem::remove(path);
}

TEST_CASE("MessageStore: get_conversation returns both directions", "[store]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("conv");
    std::filesystem::remove(path);

    auto key = make_key();
    auto store = MessageStore::open(path, key);
    REQUIRE(store.has_value());

    PeerId alice{}, bob{}, carol{};
    alice.bytes.fill(0x01);
    bob.bytes.fill(0x02);
    carol.bytes.fill(0x03);

    // alice → bob
    REQUIRE(store->save_message(make_msg(alice, bob, "hi bob")).has_value());
    // bob → alice
    REQUIRE(store->save_message(make_msg(bob, alice, "hi alice")).has_value());
    // carol → alice (should NOT appear in alice↔bob conversation)
    REQUIRE(store->save_message(make_msg(carol, alice, "hi alice from carol")).has_value());

    auto conv = store->get_conversation(alice, bob, Timestamp{});
    REQUIRE(conv.has_value());
    REQUIRE(conv->size() == 2);
    // Both messages should be present.
    bool found_ab = false, found_ba = false;
    for (const auto& m : *conv) {
        if (m.body == "hi bob")   found_ab = true;
        if (m.body == "hi alice") found_ba = true;
    }
    CHECK(found_ab);
    CHECK(found_ba);

    std::filesystem::remove(path);
}

TEST_CASE("MessageStore: purge expired messages", "[store]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("purge");
    std::filesystem::remove(path);

    auto key = make_key();
    auto store = MessageStore::open(path, key);
    REQUIRE(store.has_value());

    PeerId from{}, to{};
    auto m = make_msg(from, to, "ephemeral");
    m.expires_at_ms = 1; // expired in the past

    REQUIRE(store->save_message(m).has_value());
    auto purged = store->purge_expired();
    REQUIRE(purged.has_value());
    REQUIRE(*purged == 1u);

    std::filesystem::remove(path);
}

TEST_CASE("MessageStore: peer persistence round-trip", "[store]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("peers");
    std::filesystem::remove(path);

    auto key = make_key();
    auto store = MessageStore::open(path, key);
    REQUIRE(store.has_value());

    cloak::identity::PeerDirectory dir1;
    cloak::identity::PeerRecord rec;
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(
            reinterpret_cast<std::byte*>(rec.signing_public_key.bytes.data()), 32)));
    rec.fingerprint  = "ABCD-EFGH-IJKL";
    rec.display_name = "TestPeer";
    rec.trust        = cloak::core::TrustStatus::Tofu;
    REQUIRE(dir1.upsert(rec).has_value());

    REQUIRE(store->save_peers(dir1).has_value());

    cloak::identity::PeerDirectory dir2;
    REQUIRE(store->load_peers(dir2).has_value());
    auto all = dir2.all();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 1);
    CHECK((*all)[0].display_name == "TestPeer");
    CHECK((*all)[0].trust == cloak::core::TrustStatus::Tofu);

    std::filesystem::remove(path);
}

TEST_CASE("MessageStore: group session persistence round-trip", "[store][group]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("groups");
    std::filesystem::remove(path);

    auto key = make_key();
    auto store = MessageStore::open(path, key);
    REQUIRE(store.has_value());

    GroupSessionRecord rec;
    rec.group_id.bytes.fill(0xAB);
    rec.group_name = "TestGroup";
    rec.own_sign_sk.fill(0x11);
    rec.own_sign_pub.fill(0x22);
    rec.own_chain_key.fill(0x33);
    rec.own_counter = 42;

    GroupMemberRecord mr;
    mr.group_id = rec.group_id;
    mr.signing_pub.fill(0x44);
    mr.chain_key.fill(0x55);
    mr.counter = 7;
    rec.members.push_back(mr);

    REQUIRE(store->save_group(rec).has_value());

    auto loaded = store->load_groups();
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->size() == 1);

    const auto& g = (*loaded)[0];
    CHECK(g.group_id.bytes == rec.group_id.bytes);
    CHECK(g.group_name     == "TestGroup");
    CHECK(g.own_sign_sk    == rec.own_sign_sk);
    CHECK(g.own_sign_pub   == rec.own_sign_pub);
    CHECK(g.own_chain_key  == rec.own_chain_key);
    CHECK(g.own_counter    == 42u);
    REQUIRE(g.members.size() == 1);
    CHECK(g.members[0].signing_pub == mr.signing_pub);
    CHECK(g.members[0].chain_key   == mr.chain_key);
    CHECK(g.members[0].counter     == 7u);

    REQUIRE(store->delete_group(rec.group_id).has_value());
    auto after_del = store->load_groups();
    REQUIRE(after_del.has_value());
    CHECK(after_del->empty());

    std::filesystem::remove(path);
}

TEST_CASE("MessageStore: wrong key rejects column decryption", "[store]") {
    REQUIRE(Crypto::initialize().has_value());

    const auto path = tmp_db("wrongkey");
    std::filesystem::remove(path);

    auto key1 = make_key();
    auto key2 = make_key();

    {
        auto store = MessageStore::open(path, key1);
        REQUIRE(store.has_value());
        PeerId from{}, to{};
        auto m = make_msg(from, to, "secret");
        REQUIRE(store->save_message(m).has_value());
    }

    // Reopen with a different key — decryption failures silently skip rows.
    auto store2 = MessageStore::open(path, key2);
    REQUIRE(store2.has_value());
    PeerId all_zeros;
    all_zeros.bytes.fill(0);
    auto msgs = store2->get_messages_for_peer(all_zeros, Timestamp{});
    REQUIRE(msgs.has_value());
    CHECK(msgs->empty());

    std::filesystem::remove(path);
}
