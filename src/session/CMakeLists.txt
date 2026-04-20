ev_add_library(
    NAME session
    HEADERS 
        session.h
        session_manager.h
    SOURCES 
        session.cpp
        session_manager.cpp
    DEPS 
        core
        crypto
        wire
        transport
)
