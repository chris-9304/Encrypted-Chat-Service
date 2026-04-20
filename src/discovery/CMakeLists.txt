ev_add_library(
    NAME discovery
    HEADERS 
        discovery_service.h
        mdns_discovery_win32.h
        loopback_discovery.h
    SOURCES 
        mdns_discovery_win32.cpp
        loopback_discovery.cpp
    DEPS 
        core
        transport
)
