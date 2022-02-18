
#  Copyright (C) 2015-2021, Wazuh Inc.
#  All rights reserved.
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.

set(THREAD_POOL_SOURCE_DIR ${ENGINE_SOURCE_DIR}/threadPool/)

# dependencies
# Processor test
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
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# Configuration rxcpp test
add_executable(rxcpp_test
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.cpp
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.hpp
)
target_include_directories(rxcpp_test PRIVATE "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/" )
target_link_libraries(rxcpp_test gtest_main benchmark::benchmark_main rxcpp)
gtest_discover_tests(rxcpp_test)


add_executable(rxcppThreadingTest
    ${THREAD_POOL_SOURCE_DIR}/threadPool.cpp
    ${THREAD_POOL_SOURCE_DIR}/threadPool.hpp
    ${TEST_SOURCE_DIR}/rxcpp/threadingTest.cpp
    ${TEST_SOURCE_DIR}/rxcpp/threadingTest.hpp
)
target_include_directories(rxcppThreadingTest PRIVATE
    ${TEST_SOURCE_DIR}/rxcpp/
    ${THREAD_POOL_SOURCE_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
)
target_link_libraries(rxcppThreadingTest gtest_main rxcpp uv)
gtest_discover_tests(rxcppThreadingTest)
