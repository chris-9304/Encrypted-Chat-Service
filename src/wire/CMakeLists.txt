ev_add_library(
    NAME wire
    HEADERS 
        message.h
        framing.h
    SOURCES 
        framing.cpp
    DEPS 
        core
)
