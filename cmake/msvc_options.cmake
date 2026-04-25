macro(ev_apply_msvc_options)
    add_compile_options(/utf-8)
    # Target Windows 10 (0x0A00) for all code.
    add_compile_definitions(
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endmacro()
