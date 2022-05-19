#  Copyright (C) 2015-2021, Wazuh Inc.
#  All rights reserved.
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.

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
  EXCLUDE_FROM_ALL YES
)

add_library(engine_test_main
    OBJECT
    engineTestMain.cpp
    )

target_link_libraries(engine_test_main
    PUBLIC
    gtest
    base
    kvdb
    )

include(GoogleTest)

#TODO: Fix server tests
#add_subdirectory(${TEST_SOURCE_DIR}/server)
add_subdirectory(${TEST_SOURCE_DIR}/base)
add_subdirectory(${TEST_SOURCE_DIR}/builder)
add_subdirectory(${TEST_SOURCE_DIR}/catalog)
add_subdirectory(${TEST_SOURCE_DIR}/hlp)
add_subdirectory(${TEST_SOURCE_DIR}/json)
add_subdirectory(${TEST_SOURCE_DIR}/kvdb)
add_subdirectory(${TEST_SOURCE_DIR}/router)
add_subdirectory(${TEST_SOURCE_DIR}/logicExpression)
add_subdirectory(${TEST_SOURCE_DIR}/wdb)
