ev_add_library(
    NAME identity
    HEADERS 
        identity.h
        peer_directory.h
    SOURCES 
        identity.cpp
        peer_directory.cpp
    DEPS 
        core
        crypto
)
