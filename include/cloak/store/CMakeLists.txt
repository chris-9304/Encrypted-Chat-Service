cloak_add_library(
    NAME store
    SOURCES
        message_store.cpp
    DEPS
        core
        crypto
        wire
        identity
        group
        unofficial::sqlite3::sqlite3
)
