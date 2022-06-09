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
add_library(server STATIC
    ${ENGINE_SERVER_SOURCE_DIR}/engineServer.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/protocolHandler.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/baseEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/tcpEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/udpEndpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/datagramSocketEndpoint.cpp
)

#TODO do this better
target_link_libraries(server base uv_a)

target_include_directories(server PUBLIC
    ${CameronQueue_SOURCE_DIR}
    ${ENGINE_SERVER_SOURCE_DIR}
    ${ENGINE_SOURCE_DIR}/json
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
    ${ENGINE_SERVER_SOURCE_DIR}/base
)
