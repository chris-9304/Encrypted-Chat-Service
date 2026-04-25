ev_add_library(
    NAME wire
    SOURCES
        framing.cpp
    DEPS
        core
        ws2_32
)
