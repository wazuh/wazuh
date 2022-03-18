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
  EXCLUDE_FROM_ALL YES
)
# wazuh/src/engine/build/_deps/libuv-src/src/unix/core.c:1211: warning: Using 'getpwuid_r' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking

CPMAddPackage(
  NAME uvw
  GITHUB_REPOSITORY skypjack/uvw
  GIT_TAG v2.3.1_libuv-v1.34
  VERSION 2.3.1
  OPTIONS
      "BUILD_UVW_LIBS OFF"
      "BUILD_DOCS OFF"
      "BUILD_TESTING OFF"
  EXCLUDE_FROM_ALL YES
)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
    ${ENGINE_SERVER_SOURCE_DIR}/engineServer.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/protocolHandler.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/baseEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/tcpEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/endpointFactory.cpp
)

target_include_directories(main PUBLIC
    ${ENGINE_SERVER_SOURCE_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)

#TODO do this better
target_link_libraries(main uv_a)
