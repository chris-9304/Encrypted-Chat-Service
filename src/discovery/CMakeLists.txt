ev_add_library(
    NAME discovery
    SOURCES
        loopback_discovery.cpp
    DEPS
        core
        transport
)
