ev_add_library(
    NAME store
    SOURCES
        message_store.cpp
    DEPS
        core
        crypto
        wire
        identity
        unofficial::sqlite3::sqlite3
)
