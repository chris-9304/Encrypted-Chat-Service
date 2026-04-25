ev_add_library(
    NAME group
    SOURCES
        group_session.cpp
        group_manager.cpp
    DEPS
        core
        crypto
        identity
        wire
)
