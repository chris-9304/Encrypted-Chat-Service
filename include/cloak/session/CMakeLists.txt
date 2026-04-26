cloak_add_library(
    NAME session
    SOURCES
        session.cpp
        session_manager.cpp
    DEPS
        core
        crypto
        identity
        wire
        transport
        sodium
        ws2_32
)
