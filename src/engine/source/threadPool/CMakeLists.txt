#  Copyright (C) 2015-2021, Wazuh Inc.
#  All rights reserved.
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.

# Minimum 3.20 required
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

# set(SERVER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/server)
set(THREAD_POOL_SOURCE_DIR ${ENGINE_SOURCE_DIR}/threadPool)

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)

include_directories(
    ${THREAD_POOL_SOURCE_DIR}
)

add_executable(threadPool ${THREAD_POOL_SOURCE_DIR}/threadPool.cpp)
target_link_libraries(threadPool gtest_main rxcpp)
gtest_discover_tests(threadPool)
