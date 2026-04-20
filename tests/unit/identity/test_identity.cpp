#include <catch2/catch_test_macros.hpp>
#include <ev/identity/identity.h>
#include <ev/crypto/crypto.h>

using namespace ev::identity;

TEST_CASE("Identity distinctiveness and properties", "[identity]") {
    ev::crypto::Crypto::initialize();
    
    auto id1 = Identity::generate().value();
    auto id2 = Identity::generate().value();
    
    REQUIRE(id1.fingerprint() != id2.fingerprint());
    REQUIRE(id1.fingerprint().length() == 14); // XXXX-XXXX-XXXX
    
    auto shared1 = id1.agree(id2.kx_public()).value();
    auto shared2 = id2.agree(id1.kx_public()).value();
    
    REQUIRE(shared1.secret.size() == 32);
    REQUIRE(memcmp(shared1.secret.data(), shared2.secret.data(), 32) == 0);
}
