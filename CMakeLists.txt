cmake_minimum_required(VERSION 3.25)

project(EncryptiV LANGUAGES CXX C)

# MSVC is set only after project() declares the languages.
if(NOT MSVC OR NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "EncryptiV targets MSVC on Windows exclusively. See WINDOWS_BUILD.md.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(warnings)
include(msvc_options)
include(ev_add_library)

# Make <ev/...> angle-bracket includes available to all targets in the tree.
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")

# Apply global options
ev_apply_msvc_options()

# Set up testing if this is not a subproject
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

# ── Dependencies (vcpkg manifest mode) ──────────────────────────────────────
find_package(unofficial-sodium CONFIG REQUIRED)
# Convenience alias: ev libraries link against "sodium"
if(NOT TARGET sodium)
    add_library(sodium ALIAS unofficial-sodium::sodium)
endif()
find_package(Boost           REQUIRED COMPONENTS program_options)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(spdlog          CONFIG REQUIRED)
find_package(fmt             CONFIG REQUIRED)
find_package(Catch2          CONFIG REQUIRED)
find_package(ftxui           CONFIG REQUIRED)
find_package(wil             CONFIG REQUIRED)
# protobuf: available but not yet used in Phase 2 (wire format is hand-rolled)
# find_package(protobuf CONFIG REQUIRED)

# Convenience alias: ev_add_library uses "unofficial::sqlite3::sqlite3".
# No alias needed — that IS the vcpkg target name.

# ── Source directories ────────────────────────────────────────────────────────
add_subdirectory(src/core)
add_subdirectory(src/crypto)
add_subdirectory(src/identity)
add_subdirectory(src/wire)
add_subdirectory(src/store)
add_subdirectory(src/transport)
add_subdirectory(src/session)
add_subdirectory(src/discovery)
add_subdirectory(src/transfer)
add_subdirectory(src/group)
add_subdirectory(src/relay)
add_subdirectory(src/ui)
add_subdirectory(src/app)

# Installer placeholder
add_custom_target(installer
    COMMAND ${CMAKE_COMMAND} -E echo "WiX MSI installer coming in M1.11"
)
