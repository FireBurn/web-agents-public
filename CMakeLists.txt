cmake_minimum_required(VERSION 3.12)
project(OpenAMWebAgent
    VERSION 5.0.0
    DESCRIPTION "OpenAM Web Policy Agents"
    LANGUAGES C)

# -----------------------------------------------------------------------------
# Project options
# -----------------------------------------------------------------------------

option(BUILD_TESTING       "Build the unit tests"                          ON)
option(BUILD_APACHE_MODULE "Build the Apache module (requires apxs + APR)" ON)

# Emit compile_commands.json for clangd / VSCode / etc.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "" FORCE)

# Default to Release if no build type was requested
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

# -----------------------------------------------------------------------------
# Version information baked into the binaries
# -----------------------------------------------------------------------------
#
# AGENT_VERSION can be overridden from the command line, e.g.:
#     cmake -B build -DAGENT_VERSION=5.0.1
# CI passes the git tag here so the binary matches the release.

if(NOT DEFINED AGENT_VERSION OR AGENT_VERSION STREQUAL "")
    set(AGENT_VERSION "${PROJECT_VERSION}")
endif()

# Derive comma-separated form (e.g. 5,0,0,0) for Windows VERSIONINFO resources
string(REPLACE "." "," _agent_ver_comma "${AGENT_VERSION}")
if(NOT _agent_ver_comma MATCHES "^[0-9]+,[0-9]+,[0-9]+,[0-9]+$")
    set(_agent_ver_comma "${_agent_ver_comma},0")
endif()
set(AGENT_VERSION_NUM "${_agent_ver_comma}")
set(AGENT_CONTAINER "Generic")

# Short git hash (may be absent for source tarballs)
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE AGENT_REVISION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
if(NOT AGENT_REVISION)
    set(AGENT_REVISION "unknown")
endif()

string(TIMESTAMP AGENT_IDENT_DATE "%d.%m.%y")
cmake_host_system_information(RESULT AGENT_BUILD_MACHINE QUERY HOSTNAME)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/version.template
    ${CMAKE_CURRENT_BINARY_DIR}/source/version.h
    @ONLY)

message(STATUS "Building OpenAM Web Agents ${AGENT_VERSION} (rev ${AGENT_REVISION})")

# -----------------------------------------------------------------------------
# System dependencies
# -----------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(EXPAT REQUIRED)
find_package(OpenSSL REQUIRED)

# libzip: prefer pkg-config. The Ubuntu 24.04 libzip-dev package ships a broken
# CMake config file that references /usr/bin/zipcmp (not actually installed),
# so find_package(libzip) fails there. pkg-config works everywhere libzip is
# installed and is the more portable route.
pkg_check_modules(LIBZIP REQUIRED IMPORTED_TARGET libzip)

# PCRE2: no standard Find module, locate by hand. Prefer pkg-config where
# available, fall back to find_path/find_library.
pkg_check_modules(PCRE2 IMPORTED_TARGET libpcre2-8)
if(NOT PCRE2_FOUND)
    find_path(PCRE2_INCLUDE_DIR pcre2.h REQUIRED)
    find_library(PCRE2_LIBRARY NAMES pcre2-8 REQUIRED)
endif()

# -----------------------------------------------------------------------------
# Core library (libopenam)
# -----------------------------------------------------------------------------
#
# Explicit source list. The old file(GLOB) pattern has two problems:
#   1. New files don't trigger reconfigure, so builds silently go stale.
#   2. Ordering is platform-dependent, which can mask bugs.
# Windows-only files (net_client_win.c) are gated internally via #ifdef _WIN32
# and compile to nothing on other platforms, so they stay in the list.

set(OPENAM_CORE_SOURCES
    source/agent_cache.c
    source/alloc.c
    source/audit.c
    source/cache_data.c
    source/config.c
    source/config_file.c
    source/config_xml.c
    source/http_parser.c
    source/init.c
    source/ip.c
    source/log.c
    source/naming_valid.c
    source/net_client.c
    source/net_client_ssl.c
    source/net_client_win.c
    source/net_ops.c
    source/policy.c
    source/policy_xml.c
    source/process.c
    source/property_map.c
    source/rwlock.c
    source/session_cache.c
    source/session_saml.c
    source/session_xml.c
    source/share.c
    source/shared.c
    source/thread.c
    source/utility.c
    source/worker.c)

add_library(openam SHARED ${OPENAM_CORE_SOURCES})
set_target_properties(openam PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

target_include_directories(openam PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/source>)

target_link_libraries(openam
    PUBLIC
        Threads::Threads
        ZLIB::ZLIB
        EXPAT::EXPAT
        OpenSSL::SSL
        OpenSSL::Crypto)

if(PCRE2_FOUND)
    target_link_libraries(openam PUBLIC PkgConfig::PCRE2)
else()
    target_include_directories(openam PUBLIC ${PCRE2_INCLUDE_DIR})
    target_link_libraries(openam PUBLIC ${PCRE2_LIBRARY})
endif()

# dl is needed on Linux (not macOS, not Windows)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(openam PUBLIC dl)
endif()

# -----------------------------------------------------------------------------
# Compiler / linker hardening
# -----------------------------------------------------------------------------

target_compile_definitions(openam PRIVATE _REENTRANT)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(openam PRIVATE _GNU_SOURCE LINUX)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(openam PRIVATE
        # Warnings
        -Wall
        -Wformat
        -Wformat-security
        # Security-critical: truncated format output is almost always a bug.
        # Upgrade to error once the existing warnings in admin.c are fixed.
        -Wformat-truncation

        # Hardening (active in all configs; not a perf hit)
        -fstack-protector-strong
        -fPIC

        # Build-type-specific: -g only in debug / relwithdebinfo, etc.
        # (CMake adds -O0/-g for Debug, -O3 for Release, -O2 -g for
        # RelWithDebInfo, -Os for MinSizeRel by default. Don't override.)
    )

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(openam PRIVATE
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack)
    endif()

    # Fortify only makes sense when optimising
    target_compile_definitions(openam PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)
endif()

# -----------------------------------------------------------------------------
# Admin tool
# -----------------------------------------------------------------------------

add_executable(agentadmin
    source/admin.c
    source/admin_iis.c)

target_link_libraries(agentadmin PRIVATE
    openam
    PkgConfig::LIBZIP)

# -----------------------------------------------------------------------------
# Apache module (Linux / macOS / optionally Windows with APR)
# -----------------------------------------------------------------------------

if(BUILD_APACHE_MODULE)
    find_program(APXS_EXECUTABLE NAMES apxs apxs2)
    if(APXS_EXECUTABLE)
        execute_process(
            COMMAND ${APXS_EXECUTABLE} -q INCLUDEDIR
            OUTPUT_VARIABLE APACHE_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE)

        # APR headers are not always in the Apache include dir (e.g. on
        # Debian/Ubuntu they're in /usr/include/apr-1.0). Discover them
        # via pkg-config when available.
        pkg_check_modules(APR apr-1)
        pkg_check_modules(APRUTIL apr-util-1)

        add_library(mod_openam MODULE source/apache/agent.c)
        target_include_directories(mod_openam PRIVATE
            ${APACHE_INCLUDE_DIR}
            ${APR_INCLUDE_DIRS}
            ${APRUTIL_INCLUDE_DIRS})
        target_link_libraries(mod_openam PRIVATE openam)
        set_target_properties(mod_openam PROPERTIES PREFIX "")

        message(STATUS "Apache module: enabled (apxs at ${APXS_EXECUTABLE})")
    else()
        message(STATUS "Apache module: disabled (apxs not found)")
    endif()
endif()

# -----------------------------------------------------------------------------
# IIS module (Windows only)
# -----------------------------------------------------------------------------

if(WIN32)
    add_library(mod_iis_openam MODULE source/iis/agent.c)
    target_link_libraries(mod_iis_openam PRIVATE openam)
    set_target_properties(mod_iis_openam PROPERTIES PREFIX "")
endif()

# -----------------------------------------------------------------------------
# Install rules
# -----------------------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS openam agentadmin
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(TARGET mod_openam)
    install(TARGETS mod_openam
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/openam)
endif()

if(TARGET mod_iis_openam)
    install(TARGETS mod_iis_openam
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/openam
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/openam)
endif()

install(DIRECTORY config/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openam/config
    FILES_MATCHING PATTERN "*.template" PATTERN "*.xml")

install(FILES LICENSE.md legal/CDDLv1.0.txt legal/THIRDPARTYREADME.txt
    DESTINATION ${CMAKE_INSTALL_DOCDIR})

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
