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

link_libraries(
  gtest_main
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${ENGINE_SOURCE_DIR}/threadPool
    ${RxCpp_SOURCE_DIR}/Rx/v2/src/
)

add_executable(threadPoolTest
    ${ENGINE_SOURCE_DIR}/threadPool/threadPool.cpp
    ${CMAKE_CURRENT_LIST_DIR}/threadPoolTest.cpp
)
gtest_discover_tests(threadPoolTest)
