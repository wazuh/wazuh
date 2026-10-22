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

# The pure query classifiers (E4a, queryResponse_test) are hidden in the .so: the suite compiles their TU itself.
target_sources(indexer_client_utest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src/query/queryResponse.cpp)

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

# Component suite (E2a-1): the transport and the fake over real sockets. It links the testing build of the library
# (indexer_client_testing, with the seams) and never the .so, so the process holds a single runtime (I45b).
file(GLOB COMPONENT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/component/*.cpp)

add_executable(indexer_client_component_test ${COMPONENT_SRC_FILES})

target_link_libraries(
  indexer_client_component_test
  debug gtestd
  debug gmockd
  debug gtest_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  indexer_client_testing
  ext_httplib
  Threads::Threads
  dl)

# The fake's TLS/mTLS servers (E2a-2): cpp-httplib's SSLServer over the OpenSSL that libwazuhext exports (I44); only
# this executable compiles them, so the unit suite never touches OpenSSL.
target_compile_definitions(indexer_client_component_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

# zlib (transportGzip_test, E6b): the headers of the copy libwazuhext links, declared here rather than inherited.
target_include_directories(
  indexer_client_component_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/fake ${CMAKE_CURRENT_LIST_DIR}/../src
                                        ${SRC_FOLDER}/external/cpp-httplib ${SRC_FOLDER}/external/zlib)

# -rdynamic lets the test executable interpose getaddrinfo for the hung-resolver case (T20); the link map proves that
# no static copy of curl or OpenSSL entered the executable.
target_link_options(indexer_client_component_test PRIVATE -rdynamic
                    "LINKER:-Map=${CMAKE_CURRENT_BINARY_DIR}/indexer_client_component_test.map")

add_test(NAME indexer_client_component_test COMMAND indexer_client_component_test)
set_tests_properties(indexer_client_component_test PROPERTIES LABELS indexer_client_component_test)

# Suite against a real OpenSearch (plan 18, E6b, I110): skipped without INDEXER_CLIENT_OPENSEARCH_URL, failed without it
# under GITHUB_ACTIONS. It links the public .so like the unit suite; fake/ only for testTimeScale.hpp, ../src only for
# the constant Painless sources of write/encoding.hpp, cpp-httplib for the raw requests.
file(GLOB OPENSEARCH_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/opensearch/*.cpp)

add_executable(indexer_client_opensearch_test ${OPENSEARCH_SRC_FILES})

target_link_libraries(
  indexer_client_opensearch_test
  debug gtestd
  debug gmockd
  debug gtest_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  indexer_client
  ext_httplib
  Threads::Threads)

target_include_directories(
  indexer_client_opensearch_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/fake ${CMAKE_CURRENT_LIST_DIR}/../src
                                         ${SRC_FOLDER}/external/cpp-httplib)

add_test(NAME indexer_client_opensearch_test COMMAND indexer_client_opensearch_test)
set_tests_properties(indexer_client_opensearch_test PROPERTIES LABELS indexer_client_opensearch_test)
