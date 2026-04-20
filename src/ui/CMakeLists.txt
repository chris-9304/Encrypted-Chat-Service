ev_add_library(
    NAME ui
    HEADERS 
        chat_ui.h
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
