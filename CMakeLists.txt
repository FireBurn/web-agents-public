cmake_minimum_required(VERSION 3.10)
project(OpenAMWebAgent C)

# --- 1. Agent Version Variables ---
set(AGENT_VERSION "5.0.0")
set(AGENT_VERSION_NUM "5,0,0,0")
set(AGENT_CONTAINER "Generic")

# --- 2. Dynamic Build Variables ---
# Get Git Hash
execute_process(COMMAND git rev-parse --short HEAD
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE AGENT_REVISION
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
if(NOT AGENT_REVISION)
    set(AGENT_REVISION "unknown")
endif()

# Get Date
string(TIMESTAMP AGENT_IDENT_DATE "%d.%m.%y")

# Get Hostname
cmake_host_system_information(RESULT AGENT_BUILD_MACHINE QUERY HOSTNAME)

# Generate version.h from the template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/version.template
    ${CMAKE_CURRENT_BINARY_DIR}/source/version.h
    @ONLY
)

# --- 3. Find System Dependencies ---
find_package(ZLIB REQUIRED)
find_package(EXPAT REQUIRED)
find_package(Threads REQUIRED)
find_package(libzip REQUIRED)
find_package(OpenSSL REQUIRED)

# PCRE1 usually requires manual find_path/find_library
find_path(PCRE_INCLUDE_DIR pcre.h REQUIRED)
find_library(PCRE_LIBRARY pcre REQUIRED)

# --- 4. Gather Core Sources ---
file(GLOB CORE_SOURCES "source/*.c")

# Remove the admin tools (they are compiled as standalone executables later)
list(REMOVE_ITEM CORE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/source/admin.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/admin_iis.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/apache/agent.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/iis/agent.c"
)

# --- 5. Build Core Library ---
add_library(openam SHARED ${CORE_SOURCES})

# Add include directories (so it can find our newly generated version.h and pcre)
target_include_directories(openam PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/source
    ${CMAKE_CURRENT_BINARY_DIR}/source
    ${PCRE_INCLUDE_DIR}
)

# Link the system libraries
target_link_libraries(openam PRIVATE 
    ZLIB::ZLIB 
    EXPAT::EXPAT 
    ${PCRE_LIBRARY} 
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Link 'dl' (dynamic loader) on Unix systems
if(UNIX AND NOT APPLE)
    target_link_libraries(openam PRIVATE dl)
endif()

# --- 6. Security Hardening & Compiler Flags ---
target_compile_options(openam PRIVATE -fstack-protector-all -g -O2)
target_compile_definitions(openam PRIVATE -D_GNU_SOURCE -D_REENTRANT -DLINUX)

if(UNIX AND NOT APPLE)
    # Protect the Global Offset Table (GOT) against buffer overflows
    target_link_options(openam PRIVATE -Wl,-z,now -Wl,-z,relro)
endif()

# --- 7. Build Admin Tool ---
add_executable(agentadmin source/admin.c source/admin_iis.c)
target_include_directories(agentadmin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/source
    ${CMAKE_CURRENT_BINARY_DIR}/source)
target_link_libraries(agentadmin PRIVATE openam libzip::zip)

# --- 8. Build Web Agents ---

# Apache (Linux/macOS/Windows)
find_program(APXS_EXECUTABLE NAMES apxs apxs2)
if(APXS_EXECUTABLE)
    execute_process(COMMAND ${APXS_EXECUTABLE} -q INCLUDEDIR OUTPUT_VARIABLE APACHE_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    add_library(mod_openam MODULE source/apache/agent.c)
    target_include_directories(mod_openam PRIVATE ${APACHE_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/source ${CMAKE_CURRENT_BINARY_DIR}/source)
    target_link_libraries(mod_openam PRIVATE openam)
    set_target_properties(mod_openam PROPERTIES PREFIX "")
endif()

# IIS (Windows Only)
if(WIN32)
    add_library(mod_iis_openam MODULE source/iis/agent.c)
    target_include_directories(mod_iis_openam PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source ${CMAKE_CURRENT_BINARY_DIR}/source)
    target_link_libraries(mod_iis_openam PRIVATE openam)
    set_target_properties(mod_iis_openam PROPERTIES PREFIX "")
endif()
