cloak_add_library(
    NAME transport
    SOURCES
        tcp_transport.cpp
        mailbox_transport.cpp
        relay_transport.cpp
    DEPS
        core
        Boost::boost
        ws2_32
)
