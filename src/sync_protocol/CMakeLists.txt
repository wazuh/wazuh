cmake_minimum_required(VERSION 3.12.4)
project(agent_sync_protocol)

# Default to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Try C++17 first, fallback to C++14 if needed
include(CheckCXXSourceCompiles)
set(CMAKE_CXX_STANDARD 17)

check_cxx_source_compiles(
  "
  #include <optional>
  int main() {
      std::optional<int> o;
      return 0;
  }
"
  HAS_OPTIONAL)

if(NOT HAS_OPTIONAL)
  set(CMAKE_CXX_STANDARD 14)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2"
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

set(FLATBUFFERS_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../external/flatbuffers")

ExternalProject_Add(
  flatc_host_tool
  SOURCE_DIR ${FLATBUFFERS_ROOT_DIR}
  CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared_modules/utils/flatbuffers/schemas/inventorySync.fbs
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
add_subdirectory(${FLATBUFFERS_ROOT_DIR} flatbuffers_build EXCLUDE_FROM_ALL)

# -----------------------------------------------------------------------------
# Build the static library
# -----------------------------------------------------------------------------
add_library(agent_sync_protocol STATIC
  src/agent_sync_protocol.cpp
  src/persistent_queue.cpp
  src/persistent_queue_storage.cpp
  ${GENERATED_HEADER}
  src/agent_sync_protocol_c_interface.cpp
)
add_dependencies(agent_sync_protocol generate_flatbuffers)

target_include_directories(agent_sync_protocol
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${FLATBUFFERS_ROOT_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared_modules/utils/
    ${CMAKE_SOURCE_DIR}/../headers
)

target_link_libraries(agent_sync_protocol
  PRIVATE
    flatbuffers
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/sqlite/libsqlite3.a
)

if(UNIT_TEST)
  add_subdirectory(tests)
endif()
