# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

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
    GIT_TAG v1.1.0
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

# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(SERVER_SOURCES
    ${SERVER_ENGINE_SOURCE_DIR}/engineServer.cpp
    ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/tcpEndpoint.cpp
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/udpEndpoint.cpp
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/socketEndpoint.cpp
)

include_directories(
    ${SERVER_ENGINE_SOURCE_DIR}
)

add_executable(engine_server ${SERVER_SOURCES})
target_include_directories(engine_server PUBLIC
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
    ${RapidJSON_SOURCE_DIR}/include/
)
target_link_libraries(engine_server uv)
target_sources(main PUBLIC ${SERVER_SOURCES})

