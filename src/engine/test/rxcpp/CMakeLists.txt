#  Copyright (C) 2015-2021, Wazuh Inc.
#  All rights reserved.
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Project settings
project(wazuh-engine)

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)

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

link_libraries(
  gtest_main
  rxcpp
  uv
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)

add_executable(rxcppThreadingTest
    ${CMAKE_CURRENT_LIST_DIR}/threadingTest.cpp
)
gtest_discover_tests(rxcppThreadingTest)
