cmake_minimum_required(VERSION 3.12.4)
project(agent_sync_protocol)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# Try C++17 first, fallback to C++14 if needed
include(CheckCXXSourceCompiles)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -fPIC"
)

# Address/UB sanitizer (optional)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Use pre-built flatc from src/Makefile
# -----------------------------------------------------------------------------
set(FLATBUFFERS_ROOT_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../external/flatbuffers")
set(FLATC_EXECUTABLE ${FLATBUFFERS_ROOT_DIR}/build/flatc)

# Verify flatc exists
if(NOT EXISTS ${FLATC_EXECUTABLE})
  message(FATAL_ERROR "flatc not found at ${FLATC_EXECUTABLE}.")
endif()

message(STATUS "Using flatc from: ${FLATC_EXECUTABLE}")

# -----------------------------------------------------------------------------
# Use flatc to generate schema
# -----------------------------------------------------------------------------
set(SCHEMA_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils/flatbuffers/schemas/inventorySync.fbs)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/inventorySync_generated.h)

add_custom_command(
  OUTPUT ${GENERATED_HEADER}
  COMMAND ${FLATC_EXECUTABLE} --cpp --scoped-enums -o
          ${CMAKE_CURRENT_BINARY_DIR} ${SCHEMA_FILE}
  DEPENDS ${SCHEMA_FILE}
  COMMENT "Generating FlatBuffers schema"
  VERBATIM)

add_custom_target(generate_flatbuffers ALL DEPENDS ${GENERATED_HEADER})

# -----------------------------------------------------------------------------
# Build FlatBuffers library (only needed headers/lib, not flatc)
# -----------------------------------------------------------------------------
set(FLATBUFFERS_BUILD_SAMPLES
    OFF
    CACHE BOOL "Build the samples" FORCE)
set(FLATBUFFERS_BUILD_TESTS
    OFF
    CACHE BOOL "Build the unit tests" FORCE)
set(FLATBUFFERS_BUILD_FLATC
    OFF
    CACHE BOOL "Build flatc compiler" FORCE)
add_subdirectory(${FLATBUFFERS_ROOT_DIR} flatbuffers_build EXCLUDE_FROM_ALL)

# -----------------------------------------------------------------------------
# Build the agent_sync_protocol library
# -----------------------------------------------------------------------------
add_library(
  agent_sync_protocol SHARED
  src/agent_sync_protocol.cpp
  src/persistent_queue.cpp
  src/persistent_queue_storage.cpp
  ${GENERATED_HEADER}
  src/agent_sync_protocol_c_interface.cpp
  src/sync_message_transport.cpp
  src/mqueue_transport.cpp
  ${RESOURCE_OBJ_DLL})

add_dependencies(agent_sync_protocol generate_flatbuffers)

target_include_directories(
  agent_sync_protocol
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
          ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${CMAKE_CURRENT_BINARY_DIR}
          ${FLATBUFFERS_ROOT_DIR}/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../
          ${CMAKE_CURRENT_SOURCE_DIR}/../utils/
          ${SRC_FOLDER}/shared/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../file_helper/filesystem/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../agent_metadata/include)

target_link_directories(
  agent_sync_protocol PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../file_helper/build/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/../agent_metadata/build/lib)

target_link_libraries(
  agent_sync_protocol
  PRIVATE flatbuffers FilesystemWrapper agent_metadata
          ${CMAKE_CURRENT_SOURCE_DIR}/../../external/sqlite/libsqlite3.a)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    agent_sync_protocol
    PROPERTIES
      LINK_FLAGS
      "-Wl,--add-stdcall-alias -Wl,--output-def,libagent_sync_protocol.def")

  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(
    TARGET agent_sync_protocol
    POST_BUILD
    COMMAND
      "${DLLTOOL}" -D "libagent_sync_protocol.dll" --def
      "libagent_sync_protocol.def" --output-delaylib
      "libagent_sync_protocol.lib"
    COMMAND cp "libagent_sync_protocol.lib"
            "${CMAKE_BINARY_DIR}/bin/libagent_sync_protocol.lib"
    COMMENT "Creating delayed load library for agent_sync_protocol.")
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(agent_sync_protocol)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)
