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

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)



# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(SOURCES
  ${SERVER_ENGINE_SOURCE_DIR}/engineServer.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/endpoints/tcpEndpoint.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/endpoints/udpEndpoint.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/endpoints/socketEndpoint.cpp
  ${SERVER_ENGINE_SOURCE_DIR}/endpoints/endpointFactory.cpp
)

include_directories(
    ${ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/
    ${SERVER_TEST_SOURCE_DIR}
    ${SERVER_TEST_SOURCE_DIR}/endpoints/
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)

add_executable(server_test ${SOURCES} ${SERVER_TEST_SOURCE_DIR}/testsEngineServer.cpp)
target_link_libraries(server_test gtest_main uv rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(server_test)

add_executable(tcptest ${SOURCES} ${SERVER_TEST_SOURCE_DIR}/endpoints/testsTCPEndpoint.cpp)
target_link_libraries(tcptest gtest_main uv rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(tcptest)

add_executable(udptest ${SOURCES} ${SERVER_TEST_SOURCE_DIR}/endpoints/testsUDPEndpoint.cpp)
target_link_libraries(udptest gtest_main uv rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(udptest)

add_executable(sockettest ${SOURCES} ${SERVER_TEST_SOURCE_DIR}/endpoints/testsSocketEndpoint.cpp)
target_link_libraries(sockettest gtest_main uv rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(sockettest)
