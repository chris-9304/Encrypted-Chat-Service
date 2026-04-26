cloak_add_library(
    NAME crypto
    SOURCES
        crypto.cpp
    DEPS
        core
        sodium
)
