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

CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)

include_directories(
    ${RapidJSON_SOURCE_DIR}/include/
    ${ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/
    ${SERVER_TEST_SOURCE_DIR}
    ${SERVER_TEST_SOURCE_DIR}/endpoints/
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
    ${ENGINE_SOURCE_DIR}/json
)

add_executable(serverTest ${SERVER_ENGINE_SOURCE_DIR}/engineServer.cpp ${SERVER_TEST_SOURCE_DIR}/testsEngineServer.cpp)
target_link_libraries(serverTest gtest_main uv rxcpp)
gtest_discover_tests(serverTest)

add_executable(tcpTest ${SERVER_TEST_SOURCE_DIR}/endpoints/testsTCPEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/tcpEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp)
target_link_libraries(tcpTest gtest_main uv rxcpp)
gtest_discover_tests(tcpTest)

add_executable(socketTest ${SERVER_TEST_SOURCE_DIR}/endpoints/testsSocketEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/socketEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp)
target_link_libraries(socketTest gtest_main uv rxcpp)
gtest_discover_tests(socketTest)
