ev_add_library(
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
        ev::transport
        ev::session
        ev::identity
        ev::crypto)
endif()

add_executable(ev-relay relay_main.cpp)
target_link_libraries(ev-relay PRIVATE ev::relay Boost::program_options)
ev_target_warnings(ev-relay)
