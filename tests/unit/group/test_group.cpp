#include <catch2/catch_test_macros.hpp>
#include <cloak/group/group_manager.h>
#include <cloak/group/group_session.h>
#include <cloak/identity/identity.h>
#include <cloak/crypto/crypto.h>

using namespace cloak::group;
using namespace cloak::identity;
using namespace cloak::crypto;
using namespace cloak::core;
using namespace cloak::wire;

// ── GroupSession unit tests ───────────────────────────────────────────────────

TEST_CASE("GroupSession create and encrypt/decrypt round-trip", "[group]") {
    REQUIRE(Crypto::initialize().has_value());

    auto alice_id = Identity::generate();
    REQUIRE(alice_id.has_value());
    auto bob_id = Identity::generate();
    REQUIRE(bob_id.has_value());

    // Alice creates the group.
    auto alice_gs = GroupSession::create("TestGroup", *alice_id);
    REQUIRE(alice_gs.has_value());

    // Build invite op for Bob.
    auto invite_op = alice_gs->make_invite_op(bob_id->signing_public());
    REQUIRE(invite_op.has_value());
    CHECK(invite_op->op == GroupOpType::Invite);
    CHECK(invite_op->group_name == "TestGroup");

    // Bob accepts the invite, creates his own GroupSession.
    std::array<uint8_t, 32> bob_ck{};
    static_cast<void>(Crypto::random_bytes(
        std::span<std::byte>(reinterpret_cast<std::byte*>(bob_ck.data()), 32)));

    auto bob_kp = Crypto::ed25519_keypair();
    REQUIRE(bob_kp.has_value());

    MemberState alice_ms;
    alice_ms.signing_pub = alice_gs->own_sign_pub();
    std::memcpy(alice_ms.chain_key.data(), invite_op->chain_key.data(), 32);
    alice_ms.counter = invite_op->chain_counter;

    auto bob_gs = GroupSession::from_state(
        alice_gs->group_id(), "TestGroup",
        std::move(bob_kp->private_key), bob_kp->public_key,
        bob_ck, 0, {alice_ms});
    REQUIRE(bob_gs.has_value());

    // Alice must know Bob's sender key to decrypt Bob's messages.
    // In production this flows via another invite; here we manually wire it.
    auto alice_invite_bob = bob_gs->make_invite_op(alice_gs->own_sign_pub());
    REQUIRE(alice_invite_bob.has_value());
    static_cast<void>(alice_gs->apply_op(*alice_invite_bob));

    // Alice sends a group message.
    auto payload = alice_gs->encrypt("Hello group!");
    REQUIRE(payload.has_value());
    CHECK(payload->group_id.bytes == alice_gs->group_id().bytes);
    CHECK(payload->message_number == 0);

    // Bob decrypts it.
    auto decrypted = bob_gs->decrypt(*payload);
    REQUIRE(decrypted.has_value());
    CHECK(decrypted->second == "Hello group!");
    CHECK(decrypted->first.bytes == alice_gs->own_sign_pub().bytes);

    // Alice sends a second message — counter advances.
    auto payload2 = alice_gs->encrypt("Second message");
    REQUIRE(payload2.has_value());
    CHECK(payload2->message_number == 1);

    auto decrypted2 = bob_gs->decrypt(*payload2);
    REQUIRE(decrypted2.has_value());
    CHECK(decrypted2->second == "Second message");
}

TEST_CASE("GroupSession signature verification rejects tampered ciphertext", "[group]") {
    REQUIRE(Crypto::initialize().has_value());

    auto alice_id = Identity::generate();
    REQUIRE(alice_id.has_value());
    auto bob_id = Identity::generate();
    REQUIRE(bob_id.has_value());

    auto alice_gs = GroupSession::create("SigTest", *alice_id);
    REQUIRE(alice_gs.has_value());

    auto invite = alice_gs->make_invite_op(bob_id->signing_public());
    REQUIRE(invite.has_value());

    auto bob_kp = Crypto::ed25519_keypair();
    REQUIRE(bob_kp.has_value());

    std::array<uint8_t, 32> bob_ck{};
    MemberState alice_ms;
    alice_ms.signing_pub = alice_gs->own_sign_pub();
    std::memcpy(alice_ms.chain_key.data(), invite->chain_key.data(), 32);
    alice_ms.counter = invite->chain_counter;

    auto bob_gs = GroupSession::from_state(
        alice_gs->group_id(), "SigTest",
        std::move(bob_kp->private_key), bob_kp->public_key,
        bob_ck, 0, {alice_ms});
    REQUIRE(bob_gs.has_value());

    auto payload = alice_gs->encrypt("tamper me");
    REQUIRE(payload.has_value());

    // Flip a byte in the ciphertext.
    payload->ciphertext[0] ^= std::byte{0xFF};

    auto result = bob_gs->decrypt(*payload);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("GroupSession wire encode/decode round-trip", "[group][wire]") {
    REQUIRE(Crypto::initialize().has_value());

    auto alice_id = Identity::generate();
    REQUIRE(alice_id.has_value());
    auto bob_id = Identity::generate();
    REQUIRE(bob_id.has_value());

    auto alice_gs = GroupSession::create("WireTest", *alice_id);
    REQUIRE(alice_gs.has_value());

    auto invite = alice_gs->make_invite_op(bob_id->signing_public());
    REQUIRE(invite.has_value());

    auto bob_kp = Crypto::ed25519_keypair();
    REQUIRE(bob_kp.has_value());

    std::array<uint8_t, 32> bob_ck{};
    MemberState alice_ms;
    alice_ms.signing_pub = alice_gs->own_sign_pub();
    std::memcpy(alice_ms.chain_key.data(), invite->chain_key.data(), 32);
    alice_ms.counter = invite->chain_counter;

    auto bob_gs = GroupSession::from_state(
        alice_gs->group_id(), "WireTest",
        std::move(bob_kp->private_key), bob_kp->public_key,
        bob_ck, 0, {alice_ms});
    REQUIRE(bob_gs.has_value());

    auto payload = alice_gs->encrypt("wire test");
    REQUIRE(payload.has_value());

    // Encode then decode.
    auto encoded = cloak::wire::encode_group_message(*payload);
    REQUIRE(encoded.has_value());

    auto decoded = cloak::wire::decode_group_message(
        std::span<const std::byte>(*encoded));
    REQUIRE(decoded.has_value());

    CHECK(decoded->group_id.bytes == payload->group_id.bytes);
    CHECK(decoded->sender_sign_pub.bytes == payload->sender_sign_pub.bytes);
    CHECK(decoded->message_number == payload->message_number);
    CHECK(decoded->ciphertext == payload->ciphertext);
    CHECK(decoded->signature.bytes == payload->signature.bytes);

    // Decrypt the decoded payload.
    auto decrypted = bob_gs->decrypt(*decoded);
    REQUIRE(decrypted.has_value());
    CHECK(decrypted->second == "wire test");
}

TEST_CASE("GroupOp wire encode/decode round-trip", "[group][wire]") {
    GroupOpPayload op;
    op.op         = GroupOpType::Invite;
    op.group_name = "InviteTest";
    op.member_key.bytes.fill(0xAB);
    op.chain_key.fill(0xCD);
    op.chain_counter = 42;
    op.group_id.bytes.fill(0x11);

    auto encoded = cloak::wire::encode_group_op(op);
    REQUIRE(encoded.has_value());

    auto decoded = cloak::wire::decode_group_op(
        std::span<const std::byte>(*encoded));
    REQUIRE(decoded.has_value());

    CHECK(decoded->op == GroupOpType::Invite);
    CHECK(decoded->group_name == "InviteTest");
    CHECK(decoded->chain_counter == 42);
    CHECK(decoded->chain_key == op.chain_key);
    CHECK(decoded->member_key.bytes == op.member_key.bytes);
}

// ── GroupManager integration test ─────────────────────────────────────────────

TEST_CASE("GroupManager create, invite, send, recv", "[group][manager]") {
    REQUIRE(Crypto::initialize().has_value());

    auto alice_id = Identity::generate();
    REQUIRE(alice_id.has_value());
    auto bob_id = Identity::generate();
    REQUIRE(bob_id.has_value());

    GroupManager alice_mgr;
    GroupManager bob_mgr;

    // Alice creates a group.
    auto gid_res = alice_mgr.create_group("MgrGroup", *alice_id);
    REQUIRE(gid_res.has_value());
    const GroupId gid = *gid_res;

    // Alice generates an invite op for Bob.
    auto invite_res = alice_mgr.invite(gid, bob_id->signing_public());
    REQUIRE(invite_res.has_value());

    // Bob accepts the invite.
    auto accept_res = bob_mgr.accept_invite(*invite_res,
                                             alice_id->signing_public());
    REQUIRE(accept_res.has_value());

    // Bob must share his sender key with Alice (via a second invite in reverse).
    // For the test we manually add Bob's sender key to Alice's group session.
    // In production this is done via an Invite GroupOp from Bob to Alice.
    // Here we skip that step and test only Alice→Bob direction.

    // Alice sends a group message.
    auto sent = alice_mgr.send(gid, "Hello from Alice");
    REQUIRE(sent.has_value());

    // Bob receives it.
    auto recvd = bob_mgr.recv(*sent);
    REQUIRE(recvd.has_value());
    CHECK(recvd->second == "Hello from Alice");

    // Groups list.
    const auto alice_groups = alice_mgr.list_groups();
    REQUIRE(alice_groups.size() == 1);
    CHECK(alice_groups[0].second == "MgrGroup");

    // Alice leaves.
    auto leave_res = alice_mgr.leave(gid);
    REQUIRE(leave_res.has_value());
    CHECK(leave_res->op == GroupOpType::Leave);
    CHECK(alice_mgr.list_groups().empty());
}
