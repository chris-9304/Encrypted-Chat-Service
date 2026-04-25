ev_add_library(
    NAME transfer
    SOURCES
        file_transfer.cpp
    DEPS
        core
        crypto
        session
        wire
)
