#include <catch2/catch_test_macros.hpp>
#include <ev/discovery/loopback_discovery.h>

using namespace ev::discovery;

TEST_CASE("Loopback discovery bindings", "[discovery]") {
    LoopbackDiscoveryService svc;
    LocalAdvertisement adv;
    adv.port = 13370;
    adv.display_name = "Alice";
    REQUIRE(svc.start_advertising(adv).has_value());
    REQUIRE(svc.get_discovered_peers().has_value());
    REQUIRE(svc.stop_advertising().has_value());
}
