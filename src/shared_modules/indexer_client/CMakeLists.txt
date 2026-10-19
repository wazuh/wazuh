# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(indexer_client)

# Indexer client: the process-wide runtime that replaces indexer_connector (wazuh/wazuh#39933).

if(NOT DEFINED SRC_FOLDER)
  get_filename_component(SRC_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# Same output layout as indexer_connector (src/shared_modules/indexer_connector/CMakeLists.txt:10-12): the standalone
# bundle and the installer pick shared modules up from ${CMAKE_BINARY_DIR}/lib.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads REQUIRED)

# The full E1 source list is fixed here so that the parallel steps never edit this file.
add_library(
  indexer_client SHARED
  src/types.cpp
  src/config/runtimeConfig.cpp
  src/config/keyValueConfigSource.cpp
  src/runtime/runtime.cpp
  src/runtime/client.cpp
  src/runtime/tickets.cpp)

# C++17 floor and pin, as uds_http_server (src/shared_modules/uds_http_server/CMakeLists.txt:16-17): the tree-wide
# standard is 20, and strict-C++17 consumers must be able to include these headers.
target_compile_features(indexer_client PUBLIC cxx_std_17)
set_target_properties(indexer_client PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

target_include_directories(
  indexer_client
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${SRC_FOLDER}/external/nlohmann
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Only INDEXER_CLIENT_API symbols are exported. asio's headers force default visibility unless
# ASIO_DISABLE_VISIBILITY is set (measured in the E0 spike: 159 asio symbols exported without it), and
# --exclude-libs localizes whatever arrives from static archives.
target_compile_options(indexer_client PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_compile_definitions(indexer_client PRIVATE ASIO_STANDALONE ASIO_DISABLE_VISIBILITY)
target_link_options(indexer_client PRIVATE "LINKER:--exclude-libs,ALL" "LINKER:--no-undefined")

# No curl and no manager_config in E1: curl arrives with the transport (E2); configuration comes through
# IConfigSource only (I26c).
target_link_libraries(indexer_client PRIVATE ext_asio Threads::Threads)

if(UNIT_TEST)
  add_subdirectory(tests)
endif()
