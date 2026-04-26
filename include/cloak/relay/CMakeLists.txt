cloak_add_library(
    NAME relay
    SOURCES
        relay_server.cpp
    DEPS
        core
        Boost::boost
        ws2_32
)

# The auto-discovered test_relay exercises both RelayServer and RelayTransport,
# so it needs the extra libraries that aren't relay's own runtime deps.
if(TARGET test_relay)
    target_link_libraries(test_relay PRIVATE
        cloak::transport
        cloak::session
        cloak::identity
        cloak::crypto)
endif()

add_executable(cloak-relay relay_main.cpp)
target_link_libraries(cloak-relay PRIVATE cloak::relay Boost::program_options)
cloak_target_warnings(cloak-relay)
