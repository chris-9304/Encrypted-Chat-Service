#include <catch2/catch_test_macros.hpp>
#include <ev/identity/device_registry.h>
#include <ev/identity/identity.h>
#include <ev/crypto/crypto.h>

using namespace ev::identity;
using namespace ev::crypto;
using namespace ev::core;

TEST_CASE("DeviceRegistry: primary issues and secondary installs cert", "[identity][device]") {
    REQUIRE(Crypto::initialize().has_value());

    // Primary device.
    auto primary_id = Identity::generate();
    REQUIRE(primary_id.has_value());
    DeviceRegistry primary_reg;
    primary_reg.init_as_primary(*primary_id, "Alice's Desktop");
    REQUIRE_FALSE(primary_reg.is_secondary());

    // Secondary device has its own keypair.
    auto secondary_id = Identity::generate();
    REQUIRE(secondary_id.has_value());

    // Primary issues a cert for secondary.
    auto cert_res = primary_reg.issue_cert(
        *primary_id,
        secondary_id->signing_public(),
        "Alice's Phone");
    REQUIRE(cert_res.has_value());

    CHECK(cert_res->device_pub.bytes == secondary_id->signing_public().bytes);
    CHECK(cert_res->primary_pub.bytes == primary_id->signing_public().bytes);
    CHECK(cert_res->device_name == "Alice's Phone");

    // Verify the cert signature.
    REQUIRE(DeviceRegistry::verify_cert(*cert_res));

    // Secondary installs the cert.
    DeviceRegistry secondary_reg;
    auto install_res = secondary_reg.init_as_secondary(*cert_res);
    REQUIRE(install_res.has_value());
    REQUIRE(secondary_reg.is_secondary());
    REQUIRE(secondary_reg.primary_signing_key().has_value());
    CHECK(secondary_reg.primary_signing_key()->bytes ==
          primary_id->signing_public().bytes);
}

TEST_CASE("DeviceRegistry: tampered cert is rejected", "[identity][device]") {
    REQUIRE(Crypto::initialize().has_value());

    auto primary_id = Identity::generate();
    REQUIRE(primary_id.has_value());
    DeviceRegistry primary_reg;
    primary_reg.init_as_primary(*primary_id, "Bob's Desktop");

    auto secondary_id = Identity::generate();
    REQUIRE(secondary_id.has_value());

    auto cert_res = primary_reg.issue_cert(
        *primary_id, secondary_id->signing_public(), "Bob's Laptop");
    REQUIRE(cert_res.has_value());

    // Tamper with the signature.
    cert_res->primary_sig.bytes[0] ^= 0xFF;
    REQUIRE_FALSE(DeviceRegistry::verify_cert(*cert_res));

    DeviceRegistry secondary_reg;
    auto install_res = secondary_reg.init_as_secondary(*cert_res);
    REQUIRE_FALSE(install_res.has_value());
}

TEST_CASE("DeviceRegistry: register peer's secondary device", "[identity][device]") {
    REQUIRE(Crypto::initialize().has_value());

    auto peer_primary  = Identity::generate();
    REQUIRE(peer_primary.has_value());
    auto peer_secondary = Identity::generate();
    REQUIRE(peer_secondary.has_value());

    // Peer's primary issues cert.
    DeviceRegistry peer_primary_reg;
    peer_primary_reg.init_as_primary(*peer_primary, "Eve's Desktop");
    auto cert_res = peer_primary_reg.issue_cert(
        *peer_primary, peer_secondary->signing_public(), "Eve's Phone");
    REQUIRE(cert_res.has_value());

    // Our registry registers Eve's linked device.
    DeviceRegistry our_reg;
    auto our_id = Identity::generate();
    REQUIRE(our_id.has_value());
    our_reg.init_as_primary(*our_id, "Our Device");

    auto reg_res = our_reg.register_peer_device(*cert_res);
    REQUIRE(reg_res.has_value());

    const auto devices = our_reg.devices_for_primary(peer_primary->signing_public());
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].device_signing_pub.bytes ==
          peer_secondary->signing_public().bytes);
    CHECK(devices[0].device_name == "Eve's Phone");

    // Registering the same device again is idempotent.
    auto reg_res2 = our_reg.register_peer_device(*cert_res);
    REQUIRE(reg_res2.has_value());
    CHECK(our_reg.devices_for_primary(peer_primary->signing_public()).size() == 1);
}

TEST_CASE("DeviceRegistry: secondary cannot issue certs", "[identity][device]") {
    REQUIRE(Crypto::initialize().has_value());

    auto primary_id   = Identity::generate();
    REQUIRE(primary_id.has_value());
    auto secondary_id = Identity::generate();
    REQUIRE(secondary_id.has_value());

    DeviceRegistry primary_reg;
    primary_reg.init_as_primary(*primary_id, "Primary");
    auto cert = primary_reg.issue_cert(
        *primary_id, secondary_id->signing_public(), "Secondary");
    REQUIRE(cert.has_value());

    DeviceRegistry secondary_reg;
    REQUIRE(secondary_reg.init_as_secondary(*cert).has_value());

    // Secondary attempting to issue a cert should fail.
    auto another_id = Identity::generate();
    REQUIRE(another_id.has_value());
    auto bad = secondary_reg.issue_cert(
        *secondary_id, another_id->signing_public(), "Attacker");
    REQUIRE_FALSE(bad.has_value());
}
