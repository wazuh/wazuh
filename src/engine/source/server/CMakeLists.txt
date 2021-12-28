# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

# CPMAddPackage(
#   NAME libuv
#   GITHUB_REPOSITORY libuv/libuv
#   GIT_TAG v1.34.2
#   VERSION 1.34.2
#   OPTIONS
#       "BUILD_SHARED_LIBS ON"
#       "BUILD_TESTS OFF"
#       "BUILD_EXAMPLES OFF"
# )
# list(APPEND EXTERNAL_DEPS "libuv")

CPMAddPackage(
  NAME uvw
  GITHUB_REPOSITORY skypjack/uvw
  GIT_TAG v2.3.1_libuv-v1.34
  VERSION 2.3.1
  OPTIONS
      "BUILD_UVW_LIBS ON"
      "BUILD_TESTING OFF"
)
list(APPEND EXTERNAL_DEPS "uvw::uvw-static")
list(APPEND EXTERNAL_DEPS "uv::uv-static")

# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(SERVER_SOURCES
    engineserver.cpp
    engineserver.hpp
)

#target_sources(main PRIVATE ${SERVER_SOURCES})
target_sources(main PUBLIC ${SERVER_SOURCES})

