ev_add_library(
    NAME crypto
    HEADERS 
        crypto.h
        secure_buffer.h
        types.h
    SOURCES 
        crypto.cpp
    DEPS 
        core
)
