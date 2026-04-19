cmake_minimum_required(VERSION 3.12)
project(OpenAMWebAgent
    VERSION 5.0.0
    DESCRIPTION "OpenAM Web Policy Agents"
    LANGUAGES C CXX)

# -----------------------------------------------------------------------------
# C language standard.
#
# The codebase uses C99 features throughout (declarations inside for-loop
# initializers, mixed decls/statements, //-comments, etc). Modern compilers
# default to at least C99, but GCC 4.8.5 (shipped on RHEL 7) defaults to
# gnu89/c89 and rejects the code with "'for' loop initial declarations are
# only allowed in C99 mode". Force C99 everywhere so RHEL 7 builds clean.
#
# Using gnu99 (not c99) to keep GNU extensions like typeof, ({...}) blocks,
# and __attribute__ available — the code relies on some of these.
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable gnu99 over strict c99

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

# -----------------------------------------------------------------------------
# Core openam code is compiled once into an OBJECT library. Two consumers
# link against it:
#   - libopenam.so  (shared; used by agentadmin at runtime)
#   - mod_openam.so (Apache module; statically embeds the objects so the
#                    module has no runtime dependency on libopenam.so)
# On Windows, mod_iis_openam.dll does the same static-embed trick.
#
# This matches the upstream 4.1.1 layout where mod_openam.so is
# self-contained — a drop-in Apache module that doesn't require a
# separately-deployed libopenam.
# -----------------------------------------------------------------------------

add_library(openam_objects OBJECT ${OPENAM_CORE_SOURCES})

# PIC is essential: these objects are linked into libopenam.so (a shared
# lib) AND mod_openam.so / mod_iis_openam.dll (modules), both of which
# require position-independent code.
set_target_properties(openam_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(openam_objects PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/source>)

target_link_libraries(openam_objects
    PUBLIC
        Threads::Threads
        ZLIB::ZLIB
        EXPAT::EXPAT
        OpenSSL::SSL
        OpenSSL::Crypto)

if(PCRE2_FOUND)
    target_link_libraries(openam_objects PUBLIC PkgConfig::PCRE2)
else()
    target_include_directories(openam_objects PUBLIC ${PCRE2_INCLUDE_DIR})
    target_link_libraries(openam_objects PUBLIC ${PCRE2_LIBRARY})
endif()

# dl is needed on Linux (not macOS, not Windows)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(openam_objects PUBLIC dl)
endif()

# rt is needed for shm_open, timer_create, etc. on older glibc (<2.34).
# Modern glibc (Ubuntu 22.04+) folded these into libc, but RHEL 8 and
# earlier still require explicit -lrt. Detect and link conditionally.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(CheckLibraryExists)
    check_library_exists(rt shm_open "" HAVE_LIBRT)
    if(HAVE_LIBRT)
        target_link_libraries(openam_objects PUBLIC rt)
    endif()
endif()

# -----------------------------------------------------------------------------
# Compiler / linker hardening (applied to the object library so both
# consumers inherit the same flags).
# -----------------------------------------------------------------------------

target_compile_definitions(openam_objects PRIVATE _REENTRANT)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(openam_objects PRIVATE _GNU_SOURCE LINUX)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(openam_objects PRIVATE
        -Wall
        -Wformat
        -Wformat-security
        -fPIC)

    include(CheckCCompilerFlag)

    # -Wformat-truncation was added in GCC 7 and isn't available on older
    # toolchains (notably RHEL 7's GCC 4.8.5). Probe for support.
    check_c_compiler_flag(-Wformat-truncation HAS_WFORMAT_TRUNCATION)
    if(HAS_WFORMAT_TRUNCATION)
        target_compile_options(openam_objects PRIVATE -Wformat-truncation)
    endif()

    # -fstack-protector-strong was added in GCC 4.9 and Clang 3.5. Older
    # compilers (RHEL 6's GCC 4.4.7) only have -fstack-protector. Probe
    # for the stronger variant and fall back to the plain one.
    check_c_compiler_flag(-fstack-protector-strong HAS_STACK_PROTECTOR_STRONG)
    if(HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(openam_objects PRIVATE -fstack-protector-strong)
    else()
        check_c_compiler_flag(-fstack-protector HAS_STACK_PROTECTOR)
        if(HAS_STACK_PROTECTOR)
            target_compile_options(openam_objects PRIVATE -fstack-protector)
        endif()
    endif()

    # Fortify only makes sense when optimising
    target_compile_definitions(openam_objects PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)
endif()

# -----------------------------------------------------------------------------
# libopenam.so — thin shared-library wrapper around the object library.
# External consumers (agentadmin, user code) link against this.
# -----------------------------------------------------------------------------

add_library(openam SHARED $<TARGET_OBJECTS:openam_objects>)
# Inherit all the PUBLIC link/include requirements from the object library
target_link_libraries(openam PUBLIC openam_objects)
set_target_properties(openam PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(openam PRIVATE
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack)
endif()

# -----------------------------------------------------------------------------
# Admin tool.
#
# Also statically embeds openam_objects — matches the upstream 4.1.1
# distribution model where `agentadmin` is a standalone executable with
# no runtime dependency on libopenam.so. Only system libraries (libc,
# libssl, libpcre2-8, libz, libexpat, libzip) remain dynamic.
# -----------------------------------------------------------------------------

add_executable(agentadmin
    source/admin.c
    source/admin_iis.c
    $<TARGET_OBJECTS:openam_objects>)

target_link_libraries(agentadmin PRIVATE
    openam_objects
    PkgConfig::LIBZIP)

# -----------------------------------------------------------------------------
# Apache module (Linux / macOS / optionally Windows with APR).
#
# Statically embeds openam_objects so the resulting mod_openam.so is
# a self-contained Apache module — dropping it into httpd's modules/
# directory is enough, no libopenam.so needs to be present on the box.
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

        add_library(mod_openam MODULE
            source/apache/agent.c
            $<TARGET_OBJECTS:openam_objects>)
        target_include_directories(mod_openam PRIVATE
            ${APACHE_INCLUDE_DIR}
            ${APR_INCLUDE_DIRS}
            ${APRUTIL_INCLUDE_DIRS})
        # Link PRIVATE against the object lib to get its transitive
        # PUBLIC link dependencies (OpenSSL, zlib, pcre2, etc.) WITHOUT
        # dragging in libopenam.so as a runtime dependency.
        target_link_libraries(mod_openam PRIVATE openam_objects)

        # Link APR explicitly. On Linux the Apache server provides the
        # APR symbols at module load time via the runtime linker, so
        # leaving them unresolved works. macOS's ld is strict by default
        # and wants every undefined at link time — and being explicit is
        # harmless everywhere.
        if(APR_FOUND)
            target_link_libraries(mod_openam PRIVATE ${APR_LIBRARIES})
            target_link_directories(mod_openam PRIVATE ${APR_LIBRARY_DIRS})
        endif()
        if(APRUTIL_FOUND)
            target_link_libraries(mod_openam PRIVATE ${APRUTIL_LIBRARIES})
            target_link_directories(mod_openam PRIVATE ${APRUTIL_LIBRARY_DIRS})
        endif()

        # Apache's core symbols (ap_rprintf, ap_get_client_block, etc.)
        # are provided by the httpd binary at module load time, not by
        # a linkable .so/.dylib. On Linux this is fine — ld treats
        # unresolved symbols in shared modules as lazy by default. On
        # macOS ld is strict: every symbol must resolve at link time or
        # be explicitly marked as dynamic lookup.
        #
        # Use -undefined dynamic_lookup so the ap_* symbols defer to
        # httpd at module-load time, matching Linux behavior. This is
        # the standard pattern for Apache modules on macOS (mod_perl,
        # mod_php, etc. all do this).
        if(APPLE)
            target_link_options(mod_openam PRIVATE
                -Wl,-undefined,dynamic_lookup)
        endif()
        set_target_properties(mod_openam PROPERTIES PREFIX "")

        message(STATUS "Apache module: enabled (apxs at ${APXS_EXECUTABLE})")
    else()
        message(STATUS "Apache module: disabled (apxs not found)")
    endif()
endif()

# -----------------------------------------------------------------------------
# IIS module (Windows only) — same static-embed pattern as mod_openam.
#
# As of Windows 11 24H2 SDK (10.0.26100.x), IIS headers (httpserv.h etc)
# use C++ class declarations with __declspec(uuid(...)) attributes. These
# do not parse as C, so the .c source has to be compiled as C++. Forcing
# MSVC to treat source/iis/agent.c as C++ via the LANGUAGE property gives
# MSVC the /TP flag it needs. The file itself is carefully written to
# compile as both C and C++.
# -----------------------------------------------------------------------------

option(BUILD_IIS_MODULE "Build the IIS module on Windows" ON)

if(WIN32 AND BUILD_IIS_MODULE)
    add_library(mod_iis_openam MODULE
        source/iis/agent.c
        $<TARGET_OBJECTS:openam_objects>)
    target_link_libraries(mod_iis_openam PRIVATE openam_objects)
    set_target_properties(mod_iis_openam PROPERTIES PREFIX "")

    # Compile agent.c as C++ so MSVC can parse the IIS headers. A .c file
    # normally gets /TC (force-C); setting LANGUAGE CXX overrides this to
    # /TP.
    if(MSVC)
        set_source_files_properties(source/iis/agent.c
            PROPERTIES LANGUAGE CXX)
    endif()
endif()

# -----------------------------------------------------------------------------
# Install rules — match the upstream 4.1.1 distribution layout:
#
#   bin/agentadmin
#   lib/mod_openam.so  (or mod_iis_openam.dll on Windows)
#   config/<templates + xml schemas>
#   legal/CDDLv1.0.txt
#   legal/THIRDPARTYREADME.txt
#   log/          (empty - agent writes logs here)
#   instances/    (empty - per-agent state)
#
# libopenam.so is built for the test target but not shipped by default;
# opt in with -DINSTALL_SHARED_OPENAM=ON if you need it for downstream
# consumers.
# -----------------------------------------------------------------------------

option(INSTALL_SHARED_OPENAM "Install libopenam.so for external consumers" OFF)

install(TARGETS agentadmin
    RUNTIME DESTINATION bin)

if(INSTALL_SHARED_OPENAM)
    install(TARGETS openam
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
endif()

if(TARGET mod_openam)
    install(TARGETS mod_openam LIBRARY DESTINATION lib)
endif()

if(TARGET mod_iis_openam)
    install(TARGETS mod_iis_openam
        RUNTIME DESTINATION lib
        LIBRARY DESTINATION lib)
endif()

# Config templates — copy every .template and .xml schema file as-is.
install(DIRECTORY config/
    DESTINATION config
    FILES_MATCHING PATTERN "*.template" PATTERN "*.xml")

# License + third-party notices.
install(FILES legal/CDDLv1.0.txt legal/THIRDPARTYREADME.txt
    DESTINATION legal)

# Empty runtime directories the agent expects to exist. CMake creates
# these at install time via MESSAGE; the DIRECTORY install form only
# works with an existing source dir, so use CODE to mkdir.
install(CODE "
    file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/log\")
    file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/instances\")
")

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
