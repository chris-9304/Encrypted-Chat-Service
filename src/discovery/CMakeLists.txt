ev_add_library(
    NAME discovery
    HEADERS 
        discovery_service.h
        mdns_discovery_win32.h
    SOURCES 
        mdns_discovery_win32.cpp
    DEPS 
        core
)
