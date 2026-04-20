ev_add_library(
    NAME store
    HEADERS 
        message_store.h
    SOURCES 
        message_store.cpp
    DEPS 
        core
        crypto
        wire
)
