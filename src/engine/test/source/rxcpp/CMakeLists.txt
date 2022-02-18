#  Copyright (C) 2015-2021, Wazuh Inc.
#  All rights reserved.
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

# ------------------------------- Set Variables -------------------------------

set(THREAD_POOL_SOURCE_DIR ${ENGINE_SOURCE_DIR}/threadPool/)

# ------------------------- CPM Packages dependencies -------------------------

CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
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
)


# ----------------------------- Configure Targets -----------------------------

# Configuration rxcpp test
add_executable(rxcpp_test
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.cpp
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.hpp
)
target_include_directories(rxcpp_test PRIVATE ${ENGINE_SOURCE_DIR} ${RapidJSON_SOURCE_DIR}/include/ )
target_link_libraries(rxcpp_test gtest_main benchmark::benchmark_main rxcpp)
gtest_discover_tests(rxcpp_test)

# Configuration to test the thread pool
add_executable(rxcppThreadingTest
    ${THREAD_POOL_SOURCE_DIR}/threadPool.cpp
    ${TEST_SOURCE_DIR}/rxcpp/threadingTest.cpp
)
target_include_directories(rxcppThreadingTest PRIVATE
    ${TEST_SOURCE_DIR}/rxcpp/
    ${THREAD_POOL_SOURCE_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)
target_link_libraries(rxcppThreadingTest gtest_main rxcpp uv)
gtest_discover_tests(rxcppThreadingTest)
