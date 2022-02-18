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


# ------------------------- CPM Packages dependencies -------------------------

CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
list(APPEND EXTERNAL_DEPS "rxcpp")

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)


# ----------------------------- Configure Targets -----------------------------

target_sources(main PRIVATE ${CMAKE_CURRENT_LIST_DIR}/threadPool.cpp)
target_include_directories(main PUBLIC ${CMAKE_CURRENT_LIST_DIR})
