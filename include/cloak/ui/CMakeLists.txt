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
