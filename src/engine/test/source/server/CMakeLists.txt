# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(SERVER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/server)
set(SERVER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/server)

CPMAddPackage(
  NAME libuv
  GITHUB_REPOSITORY libuv/libuv
  GIT_TAG v1.34.2
  VERSION 1.34.2
  OPTIONS
      "BUILD_SHARED_LIBS ON"
      "BUILD_TESTS OFF"
      "BUILD_EXAMPLES OFF"
)
list(APPEND EXTERNAL_DEPS "libuv")

CPMAddPackage(
  NAME uvw
  GITHUB_REPOSITORY skypjack/uvw
  GIT_TAG v2.3.1_libuv-v1.34
  VERSION 2.3.1
  OPTIONS
      "BUILD_UVW_LIBS OFF"
      "BUILD_DOCS OFF"
      "BUILD_TESTING OFF"
)

# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(SOURCES
    ${SERVER_ENGINE_SOURCE_DIR}/engineserver.cpp
)

include_directories(
    ${SERVER_ENGINE_SOURCE_DIR}
    ${SERVER_TEST_SOURCE_DIR}
)
add_executable(engine_server_test ${SERVER_TEST_SOURCE_DIR}/engineserver_test.cpp ${SOURCES})
target_include_directories(engine_server_test PUBLIC ${uvw_SOURCE_DIR}/src/ ${uvw_SOURCE_DIR}/src/uvw/)
target_link_libraries(engine_server_test gtest_main uv)
include(GoogleTest)
gtest_discover_tests(engine_server_test)
