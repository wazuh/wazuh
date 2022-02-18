# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(TEST_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)

# Add googletest as CPM dependency
include(../cmake/CPM.cmake)
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG release-1.11.0
  VERSION 1.11.0
  OPTIONS
      "INSTALL_GTEST OFF"
)

include(GoogleTest)

add_subdirectory(${TEST_SOURCE_DIR}/server)
add_subdirectory(${TEST_SOURCE_DIR}/router)
add_subdirectory(${TEST_SOURCE_DIR}/json)
add_subdirectory(${TEST_SOURCE_DIR}/builder)
add_subdirectory(${TEST_SOURCE_DIR}/graph)
add_subdirectory(${TEST_SOURCE_DIR}/catalog)
add_subdirectory(${TEST_SOURCE_DIR}/cliParser)
add_subdirectory(${TEST_SOURCE_DIR}/shared)
