cloak_add_library(
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

add_executable(cloak main.cpp)
target_link_libraries(cloak PRIVATE
    cloak::app_lib
    cloak::ui
    Boost::program_options
)
cloak_target_warnings(cloak)
