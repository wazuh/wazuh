# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(content_manager_utest)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# The fakes live beside the suites that use them, and are reached as "fakes/...".
include_directories(${CMAKE_CURRENT_LIST_DIR})

file(GLOB PROJECT_SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

# The pre-compiled rocksdb dependency (packages.wazuh.com) was built with GCC 14,
# which emits references to std::ios_base_library_init() not present in GCC 11's
# libstdc++ (Ubuntu 22). This flag suppresses the link-time check for undefined
# symbols in shared libraries; the symbol is harmlessly absent at runtime.
target_link_options(${PROJECT_NAME} PRIVATE -Wl,--allow-shlib-undefined)

target_link_libraries(
  ${PROJECT_NAME}
  content_manager
  debug
  gtestd
  debug
  gmockd
  optimized
  gtest
  optimized
  gmock
  wazuhext
  rocksdb
  # contentIndexerClientAdapter_test.cpp and contentCycleOnClientAdapter_test.cpp drive the real adapter on a real
  # runtime of the client library; the .so is the one content_manager links, so the process holds a single runtime.
  # Never indexer_client_testing.
  indexer_client
  pthread)

# The client library's public headers (RuntimeOwner, Client, Pit) and its in-process fake indexer (header-only test
# fixture: rules, PIT responder, node health), which the adapter suites serve their runtime from, and its gmock mocks
# (a health view no real node gives). httplib is what the fake is written on.
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${SRC_FOLDER}/shared_modules/indexer_client/include
          ${SRC_FOLDER}/shared_modules/indexer_client/tests/fake
          ${SRC_FOLDER}/shared_modules/indexer_client/tests/mocks
          ${SRC_FOLDER}/external/cpp-httplib)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})
