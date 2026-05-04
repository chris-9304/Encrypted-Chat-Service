cloak_add_library(
    NAME ui
    SOURCES
        chat_ui.cpp
    DEPS
        core
        identity
        session
        store
        ftxui::screen
        ftxui::dom
        ftxui::component
)

# app_lib depends on ui (for callbacks), and ui includes app headers via the
# global include_directories set in the root CMakeLists.txt.
# No circular dependency: ui only #includes the chat_application.h header;
# it does NOT link against app_lib (app_lib -> ui, not ui -> app_lib).
