# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(BENCHMARK_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)

# Add google benchmark as CPM dependency
include(../cmake/CPM.cmake)
CPMAddPackage(
  NAME benchmark
  GITHUB_REPOSITORY google/benchmark
  VERSION 1.5.6
  OPTIONS
   "BENCHMARK_ENABLE_TESTING Off"
)

add_subdirectory(${BENCHMARK_SOURCE_DIR}/regex)