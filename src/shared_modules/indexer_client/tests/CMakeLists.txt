# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(indexer_client_tests)

# Every test TU compiles at C++17, so a C++20-ism entering a public header fails here first.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(indexer_client_utest ${UNIT_SRC_FILES})

target_link_libraries(
  indexer_client_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  indexer_client
  ext_httplib
  Threads::Threads)

# Header-only test helpers: gmock mocks of the public interfaces and the in-process fake indexer.
target_include_directories(
  indexer_client_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mocks
          ${CMAKE_CURRENT_LIST_DIR}/fake
          ${CMAKE_CURRENT_LIST_DIR}/../src
          ${SRC_FOLDER}/external/cpp-httplib)

# The visibility test inspects the built library.
target_compile_definitions(indexer_client_utest PRIVATE INDEXER_CLIENT_SO_PATH="$<TARGET_FILE:indexer_client>")

add_test(NAME indexer_client_utest COMMAND indexer_client_utest)
set_tests_properties(indexer_client_utest PROPERTIES LABELS indexer_client_utest)
