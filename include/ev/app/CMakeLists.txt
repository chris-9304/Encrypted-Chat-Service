ev_add_library(
    NAME app_lib
    SOURCES
        chat_application.cpp
    DEPS
        core
        crypto
        identity
        wire
        store
        transport
        session
        discovery
        transfer
        group
        relay
)

add_executable(ev-chat main.cpp)
target_link_libraries(ev-chat PRIVATE ev::app_lib Boost::program_options)
ev_target_warnings(ev-chat)
