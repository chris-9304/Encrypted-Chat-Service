ev_add_library(
    NAME transport
    HEADERS 
        transport.h
        tcp_transport.h
    SOURCES 
        tcp_transport.cpp
    DEPS 
        core
)
