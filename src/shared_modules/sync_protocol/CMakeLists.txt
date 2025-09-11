cmake_minimum_required(VERSION 3.12.4)
project(agent_sync_protocol)

# Default to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Try C++17 first, fallback to C++14 if needed
include(CheckCXXSourceCompiles)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -fPIC"
)
set(CMAKE_CXX_FLAGS_DEBUG "-g")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif()

# Address/UB sanitizer (optional)
if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif()

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Build native flatc using ExternalProject
# -----------------------------------------------------------------------------
include(ExternalProject)

set(FLATBUFFERS_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../external/flatbuffers")

find_program(HOST_C_COMPILER NAMES cc gcc)
find_program(HOST_CXX_COMPILER NAMES c++ g++)

if(NOT HOST_C_COMPILER OR NOT HOST_CXX_COMPILER)
  message(FATAL_ERROR "Could not find native C/C++ compilers for host tools.")
endif()

message(STATUS "Using native host C compiler: ${HOST_C_COMPILER}")
message(STATUS "Using native host CXX compiler: ${HOST_CXX_COMPILER}")

ExternalProject_Add(
  flatc_host_tool
  SOURCE_DIR ${FLATBUFFERS_ROOT_DIR}
  CMAKE_ARGS -DCMAKE_C_COMPILER=${HOST_C_COMPILER}
             -DCMAKE_CXX_COMPILER=${HOST_CXX_COMPILER}
             -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF
             -DFLATBUFFERS_BUILD_FLATLIB=OFF -DFLATBUFFERS_BUILD_FLATC=ON
             -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
  BUILD_ALWAYS 1
  BUILD_BYPRODUCTS <INSTALL_DIR>/bin/flatc)

ExternalProject_Get_Property(flatc_host_tool install_dir)
set(FLATC_EXECUTABLE ${install_dir}/bin/flatc)

# -----------------------------------------------------------------------------
# Use flatc to generate schema
# -----------------------------------------------------------------------------
set(SCHEMA_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils/flatbuffers/schemas/inventorySync.fbs
)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/inventorySync_generated.h)

add_custom_command(
  OUTPUT ${GENERATED_HEADER}
  COMMAND ${FLATC_EXECUTABLE} --cpp --scoped-enums --gen-object-api -o
          ${CMAKE_CURRENT_BINARY_DIR} ${SCHEMA_FILE}
  DEPENDS ${SCHEMA_FILE} flatc_host_tool
  COMMENT "Generating FlatBuffers schema"
  VERBATIM)

add_custom_target(generate_flatbuffers ALL DEPENDS ${GENERATED_HEADER})

# -----------------------------------------------------------------------------
# Build FlatBuffers library (only needed headers/lib, not flatc)
# -----------------------------------------------------------------------------
# Disable sample builds to avoid INTERFACE_LIBRARY issues
set(FLATBUFFERS_BUILD_SAMPLES OFF CACHE BOOL "Build the samples" FORCE)
set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "Build the unit tests" FORCE)
add_subdirectory(${FLATBUFFERS_ROOT_DIR} flatbuffers_build EXCLUDE_FROM_ALL)

# -----------------------------------------------------------------------------
# Build the agent_sync_protocol library
# -----------------------------------------------------------------------------
add_library(agent_sync_protocol SHARED
  src/agent_sync_protocol.cpp
  src/persistent_queue.cpp
  src/persistent_queue_storage.cpp
  ${GENERATED_HEADER}
  src/agent_sync_protocol_c_interface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../${RESOURCE_OBJ}
)
add_dependencies(agent_sync_protocol generate_flatbuffers)

target_include_directories(agent_sync_protocol
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${FLATBUFFERS_ROOT_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils/
    ${CMAKE_SOURCE_DIR}/../../headers
)

target_link_libraries(agent_sync_protocol
  PRIVATE
    flatbuffers
    ${CMAKE_CURRENT_SOURCE_DIR}/../../external/sqlite/libsqlite3.a
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    agent_sync_protocol PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -Wl,--output-def,libagent_sync_protocol.def")

  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(TARGET agent_sync_protocol POST_BUILD
    COMMAND "${DLLTOOL}" -D "libagent_sync_protocol.dll" --def "libagent_sync_protocol.def" --output-delaylib "libagent_sync_protocol.lib"
    COMMAND cp "libagent_sync_protocol.lib" "${CMAKE_BINARY_DIR}/bin/libagent_sync_protocol.lib"
    COMMENT "Creating delayed load library for agent_sync_protocol.")
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX" AND NOT CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX" AND NOT CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)
