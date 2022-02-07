# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(ENGINE_SERVER_SOURCE_DIR ${ENGINE_SOURCE_DIR}/server)

####################################################################################################
# Dependencies
####################################################################################################
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
# wazuh/src/engine/build/_deps/libuv-src/src/unix/core.c:1211: warning: Using 'getpwuid_r' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
list(APPEND EXTERNAL_DEPS "uv_a")

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
  NAME json
  GITHUB_REPOSITORY nlohmann/json
  GIT_TAG v3.10.4
  VERSION 3.10.4
  OPTIONS
      "JSON_BuildTests OFF"
      "JSON_Install OFF"
)
list(APPEND EXTERNAL_DEPS "nlohmann_json::nlohmann_json")

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
list(APPEND EXTERNAL_DEPS "rxcpp")

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
    ${ENGINE_SERVER_SOURCE_DIR}/engineServer.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/protocolHandler.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/baseEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/tcpEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/socketEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/endpointFactory.cpp
)

target_include_directories(main PUBLIC
    ${ENGINE_SERVER_SOURCE_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)
