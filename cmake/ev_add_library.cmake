function(ev_add_library)
    cmake_parse_arguments(ARG "" "NAME" "SOURCES;HEADERS;DEPS" ${ARGN})

    add_library(${ARG_NAME} STATIC ${ARG_SOURCES} ${ARG_HEADERS})
    add_library(ev::${ARG_NAME} ALIAS ${ARG_NAME})

    target_include_directories(${ARG_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    )

    if(ARG_DEPS)
        target_link_libraries(${ARG_NAME} PUBLIC ${ARG_DEPS})
    endif()

    ev_target_warnings(${ARG_NAME})
    
    # Unit tests wireup
    if(BUILD_TESTING AND EXISTS "${CMAKE_SOURCE_DIR}/tests/unit/${ARG_NAME}")
        set(TEST_NAME "test_${ARG_NAME}")
        # Find all cpp files under the tests/unit/<module>/ dir
        file(GLOB TEST_SOURCES "${CMAKE_SOURCE_DIR}/tests/unit/${ARG_NAME}/*.cpp")
        if (TEST_SOURCES)
            add_executable(${TEST_NAME} ${TEST_SOURCES})
            target_link_libraries(${TEST_NAME} PRIVATE ev::${ARG_NAME} Catch2::Catch2WithMain)
            ev_target_warnings(${TEST_NAME})
            add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
        endif()
    endif()
endfunction()
