ev_add_library(
    NAME identity
    SOURCES
        identity.cpp
        peer_directory.cpp
        device_registry.cpp
    DEPS
        core
        crypto
        sodium
)
